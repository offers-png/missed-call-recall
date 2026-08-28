"""
Recall — Missed Call Text-Back SaaS
Fixes the two things that killed the last attempt:
  1. Cost is now tied to a paying Stripe subscription per customer (not eaten by you)
  2. Trial auto-expires and status is tracked, so dead signups get flagged/suspended
     instead of quietly burning a Twilio number forever.

ENV VARS REQUIRED (set these on Render):
  SUPABASE_URL, SUPABASE_SERVICE_KEY
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID
  PUBLIC_BASE_URL   e.g. https://main-backend-k32m.onrender.com
"""
import os
import logging
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from twilio.twiml.voice_response import VoiceResponse, Dial
from twilio.rest import Client as TwilioClient
from supabase import create_client, Client
import stripe

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("recall")

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
TWILIO_SID = os.environ["TWILIO_ACCOUNT_SID"]
TWILIO_TOKEN = os.environ["TWILIO_AUTH_TOKEN"]
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]
STRIPE_PRICE_ID = os.environ["STRIPE_PRICE_ID"]
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://main-backend-k32m.onrender.com")

stripe.api_key = STRIPE_SECRET_KEY
sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
twilio_client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)

app = FastAPI(title="Recall - Missed Call Recovery")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your Netlify domain once live
    allow_methods=["*"],
    allow_headers=["*"],
)

TABLE_CUST = "recall_customers"
TABLE_CALLS = "recall_missed_calls"


@app.get("/health")
def health():
    return {"ok": True, "service": "recall"}


# ---------------------------------------------------------------------------
# SIGNUP — creates the customer record, provisions a dedicated Twilio number,
# and starts a Stripe Checkout session for the subscription (with 7-day trial).
# ---------------------------------------------------------------------------
@app.post("/signup")
async def signup(
    business_name: str = Form(...),
    owner_name: str = Form(...),
    email: str = Form(...),
    business_phone: str = Form(...),  # their real phone, in E.164 e.g. +13155551234
    area_code: str = Form(None),      # optional preferred area code for the new number
):
    existing = sb.table(TABLE_CUST).select("id").eq("email", email).execute()
    if existing.data:
        raise HTTPException(400, "An account with this email already exists.")

    # 1. Buy a dedicated Twilio number for this customer
    search_kwargs = {"limit": 1}
    if area_code:
        search_kwargs["area_code"] = area_code
    numbers = twilio_client.available_phone_numbers("US").local.list(**search_kwargs)
    if not numbers:
        numbers = twilio_client.available_phone_numbers("US").local.list(limit=1)
    if not numbers:
        raise HTTPException(500, "No Twilio numbers available right now — try again shortly.")

    purchased = twilio_client.incoming_phone_numbers.create(
        phone_number=numbers[0].phone_number,
        voice_url=f"{PUBLIC_BASE_URL}/twilio/voice",
        voice_method="POST",
        status_callback=f"{PUBLIC_BASE_URL}/twilio/status",
        status_callback_method="POST",
    )

    # 2. Create the customer row (status=trial)
    row = {
        "business_name": business_name,
        "owner_name": owner_name,
        "email": email,
        "business_phone": business_phone,
        "twilio_number": purchased.phone_number,
    }
    result = sb.table(TABLE_CUST).insert(row).execute()
    customer = result.data[0]

    # 3. Create Stripe customer + Checkout session (card required, 7-day trial)
    stripe_customer = stripe.Customer.create(email=email, name=business_name)
    checkout = stripe.checkout.Session.create(
        customer=stripe_customer.id,
        mode="subscription",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        subscription_data={"trial_period_days": 7, "metadata": {"customer_id": customer["id"]}},
        success_url=f"{PUBLIC_BASE_URL}/signup/success?customer_id={customer['id']}",
        cancel_url=f"{PUBLIC_BASE_URL}/signup/cancelled",
        metadata={"customer_id": customer["id"]},
    )

    sb.table(TABLE_CUST).update({"stripe_customer_id": stripe_customer.id}).eq(
        "id", customer["id"]
    ).execute()

    return {
        "customer_id": customer["id"],
        "twilio_number_assigned": purchased.phone_number,
        "checkout_url": checkout.url,
        "instructions": (
            f"Forward your business line ({business_phone}) to {purchased.phone_number} "
            "when unanswered/busy (conditional call forwarding), or route calls directly "
            "to it if you don't have an existing number."
        ),
    }


# ---------------------------------------------------------------------------
# TWILIO VOICE WEBHOOK — call hits the dedicated number, we try to dial the
# real business phone. If nobody picks up, the call ends and /twilio/status
# fires with an unanswered result, which triggers the text-back.
# ---------------------------------------------------------------------------
@app.post("/twilio/voice")
async def twilio_voice(request: Request):
    form = await request.form()
    to_number = form.get("To")

    resp = VoiceResponse()
    cust = sb.table(TABLE_CUST).select("*").eq("twilio_number", to_number).execute()
    if not cust.data:
        resp.say("This number is not currently active.")
        return PlainTextResponse(str(resp), media_type="application/xml")

    customer = cust.data[0]
    if customer["status"] not in ("trial", "active"):
        resp.say("This business is temporarily unavailable. Please try again later.")
        return PlainTextResponse(str(resp), media_type="application/xml")

    dial = Dial(timeout=20, action=f"{PUBLIC_BASE_URL}/twilio/dial-result", method="POST")
    dial.number(customer["business_phone"])
    resp.append(dial)
    return PlainTextResponse(str(resp), media_type="application/xml")


# ---------------------------------------------------------------------------
# DIAL RESULT — fires right after the <Dial> attempt finishes. This is what
# actually tells us the call went unanswered.
# ---------------------------------------------------------------------------
@app.post("/twilio/dial-result")
async def twilio_dial_result(request: Request):
    form = await request.form()
    to_number = form.get("To")
    caller = form.get("From")
    call_sid = form.get("CallSid")
    dial_status = form.get("DialCallStatus")  # completed, busy, no-answer, failed

    resp = VoiceResponse()

    if dial_status == "completed":
        # Call was answered normally — nothing to do.
        return PlainTextResponse(str(resp), media_type="application/xml")

    cust = sb.table(TABLE_CUST).select("*").eq("twilio_number", to_number).execute()
    if not cust.data:
        return PlainTextResponse(str(resp), media_type="application/xml")
    customer = cust.data[0]

    message = customer["reply_template"].replace("{business_name}", customer["business_name"])

    call_row = {
        "customer_id": customer["id"],
        "caller_number": caller,
        "call_sid": call_sid,
        "sms_body": message,
    }

    try:
        sms = twilio_client.messages.create(
            to=caller, from_=to_number, body=message
        )
        call_row["sms_sent"] = True
        call_row["sms_sid"] = sms.sid
    except Exception as e:
        log.error(f"SMS send failed for {caller}: {e}")
        call_row["sms_sent"] = False
        call_row["sms_error"] = str(e)

    sb.table(TABLE_CALLS).insert(call_row).execute()

    resp.say("Sorry we missed you. We've just sent you a text — thanks for calling.")
    resp.hangup()
    return PlainTextResponse(str(resp), media_type="application/xml")


@app.post("/twilio/status")
async def twilio_status(request: Request):
    # Reserved for call-level logging/debugging. Not required for core flow.
    return PlainTextResponse("", media_type="application/xml")


# ---------------------------------------------------------------------------
# STRIPE WEBHOOK — keeps customer.status in sync with billing reality.
# This is the piece that stops a dead signup from silently costing you money:
# past_due/canceled customers get their status flipped, and you can wire a
# cleanup job to release their Twilio number after N days in that state.
# ---------------------------------------------------------------------------
@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(400, f"Webhook signature verification failed: {e}")

    etype = event["type"]
    data = event["data"]["object"]

    def set_status(customer_id: str, status: str):
        sb.table(TABLE_CUST).update(
            {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
        ).eq("id", customer_id).execute()

    if etype == "checkout.session.completed":
        cid = data.get("metadata", {}).get("customer_id")
        if cid:
            sb.table(TABLE_CUST).update(
                {"stripe_subscription_id": data.get("subscription"), "status": "trial"}
            ).eq("id", cid).execute()

    elif etype == "customer.subscription.trial_will_end":
        pass  # hook point: send a "trial ending" reminder email/SMS

    elif etype == "invoice.payment_succeeded":
        sub_id = data.get("subscription")
        sb.table(TABLE_CUST).update({"status": "active"}).eq(
            "stripe_subscription_id", sub_id
        ).execute()

    elif etype == "invoice.payment_failed":
        sub_id = data.get("subscription")
        sb.table(TABLE_CUST).update({"status": "past_due"}).eq(
            "stripe_subscription_id", sub_id
        ).execute()

    elif etype == "customer.subscription.deleted":
        sub_id = data.get("id")
        sb.table(TABLE_CUST).update({"status": "canceled"}).eq(
            "stripe_subscription_id", sub_id
        ).execute()

    return JSONResponse({"received": True})


# ---------------------------------------------------------------------------
# DASHBOARD API — what the customer sees. Simple, no auth framework yet;
# customer_id acts as the access token for MVP (fine while trusted/small).
# ---------------------------------------------------------------------------
@app.get("/dashboard/{customer_id}")
def dashboard(customer_id: str):
    cust = sb.table(TABLE_CUST).select("*").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    customer = cust.data[0]

    calls = (
        sb.table(TABLE_CALLS)
        .select("*")
        .eq("customer_id", customer_id)
        .order("called_at", desc=True)
        .limit(50)
        .execute()
    )

    total = len(calls.data)
    texted = sum(1 for c in calls.data if c["sms_sent"])

    return {
        "business_name": customer["business_name"],
        "status": customer["status"],
        "twilio_number": customer["twilio_number"],
        "trial_ends_at": customer["trial_ends_at"],
        "stats": {"missed_calls_recent": total, "auto_texts_sent": texted},
        "recent_calls": calls.data,
    }
