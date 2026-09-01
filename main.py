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
import hmac
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta

import jwt
import requests
from fastapi import FastAPI, Request, Form, HTTPException, Header, UploadFile, File
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from twilio.twiml.voice_response import VoiceResponse, Dial
from twilio.rest import Client as TwilioClient
from supabase import create_client, Client
import stripe

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("recall")

# Required to boot at all — the app has nothing to do without a database.
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

# Optional at startup — not configured yet is fine. Endpoints that need these
# will return a clear 503 instead of crashing the whole server on boot.
TWILIO_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")
# Separate, higher-priced Stripe price for the Pro (AI voice) tier.
STRIPE_PRICE_ID_PRO = os.environ.get("STRIPE_PRICE_ID_PRO")
# ElevenLabs Conversational AI — powers the Pro tier's AI voice receptionist.
ELEVENLABS_API_KEY = os.environ.get("ELEVENLABS_API_KEY")
# The LLM the AI voice agent runs on. ElevenLabs periodically deprecates
# models — if a "deprecated LLM" warning shows up in their dashboard again,
# just update this env var in Render (no code change needed) and re-save
# every affected agent so the new model actually takes effect.
ELEVENLABS_LLM_MODEL = os.environ.get("ELEVENLABS_LLM_MODEL", "gemini-3.5-flash")
ELEVENLABS_BASE = "https://api.elevenlabs.io/v1"
# Google OAuth — powers the Elite tier's Calendar booking + Business Profile sync.
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_SCOPES = {
    "calendar": "https://www.googleapis.com/auth/calendar",
    "business": "https://www.googleapis.com/auth/business.manage",
}
# The approved A2P 10DLC campaign's Messaging Service — new numbers get added
# to this automatically so texts aren't blocked as unregistered.
TWILIO_MESSAGING_SERVICE_SID = os.environ.get("TWILIO_MESSAGING_SERVICE_SID", "MGb2dbff5d0714aae51d6c9b5dc42114d0")
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://main-backend-k32m.onrender.com")
# The Netlify site where index.html / dashboard.html actually live. This is
# what customers should land on after paying — the backend has no UI of its own.
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "https://glowing-hotteok-00a881.netlify.app")
# Shared secret ElevenLabs sends back on every tool webhook call, so random
# strangers can't hit these booking endpoints just by guessing the URL.
ELEVENLABS_TOOL_SECRET = os.environ.get("ELEVENLABS_TOOL_SECRET")
if not ELEVENLABS_TOOL_SECRET:
    ELEVENLABS_TOOL_SECRET = secrets.token_hex(24)
    log.warning("ELEVENLABS_TOOL_SECRET not set — using a random per-restart value. Set it in Render, "
                "then re-save any Elite customer's AI agent settings so the new secret takes effect.")

stripe.api_key = STRIPE_SECRET_KEY  # fine if None — just can't call Stripe yet
sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
twilio_client = TwilioClient(TWILIO_SID, TWILIO_TOKEN) if TWILIO_SID and TWILIO_TOKEN else None

# Signs login tokens. Falls back to a random value so the app still boots,
# but that means old sessions/tokens invalidate on every restart until you
# set a real one — set JWT_SECRET in Render as soon as you can.
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_hex(32)
    log.warning("JWT_SECRET not set — using a random per-restart value. Set JWT_SECRET in Render env vars.")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
        return hmac.compare_digest(check, digest)
    except Exception:
        return False


def make_token(customer_id: str) -> str:
    payload = {"customer_id": customer_id, "exp": datetime.now(timezone.utc) + timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_auth(customer_id: str, authorization: str = Header(None)):
    """Checks the Bearer token in the Authorization header matches this customer_id."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not logged in.")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired — please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid session.")
    if payload.get("customer_id") != customer_id:
        raise HTTPException(403, "Not authorized for this account.")


def require_twilio():
    if twilio_client is None:
        raise HTTPException(503, "Twilio isn't configured yet — add TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN.")


def require_stripe():
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        raise HTTPException(503, "Stripe isn't configured yet — add STRIPE_SECRET_KEY/STRIPE_PRICE_ID.")


def require_elevenlabs():
    if not ELEVENLABS_API_KEY:
        raise HTTPException(503, "ElevenLabs isn't configured yet — add ELEVENLABS_API_KEY.")


def el_headers():
    return {"xi-api-key": ELEVENLABS_API_KEY}

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
    password: str = Form(...),
    business_phone: str = Form(...),  # their real phone, in E.164 e.g. +13155551234
    tier: str = Form("basic"),        # "basic" or "pro"
    area_code: str = Form(None),      # optional preferred area code for the new number
    reply_template: str = Form(None), # optional custom auto-reply text
):
    require_twilio()
    require_stripe()
    if tier not in ("basic", "pro"):
        raise HTTPException(400, "tier must be 'basic' or 'pro'.")
    price_id = STRIPE_PRICE_ID_PRO if tier == "pro" else STRIPE_PRICE_ID
    if tier == "pro" and not price_id:
        raise HTTPException(503, "Pro tier isn't configured yet — add STRIPE_PRICE_ID_PRO.")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
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

    # Register this number under the approved A2P 10DLC campaign so texts from
    # it aren't silently blocked by US carriers as "unregistered" (error 30034).
    if TWILIO_MESSAGING_SERVICE_SID:
        try:
            twilio_client.messaging.v1.services(TWILIO_MESSAGING_SERVICE_SID).phone_numbers.create(
                phone_number_sid=purchased.sid
            )
        except Exception as e:
            log.error(f"Failed to add {purchased.phone_number} to A2P sender pool: {e}")

    # 2. Create the customer row (status=trial)
    row = {
        "business_name": business_name,
        "owner_name": owner_name,
        "email": email,
        "password_hash": hash_password(password),
        "business_phone": business_phone,
        "twilio_number": purchased.phone_number,
        "tier": tier,
    }
    if reply_template and reply_template.strip():
        row["reply_template"] = reply_template.strip()
    result = sb.table(TABLE_CUST).insert(row).execute()
    customer = result.data[0]

    # 3. Create Stripe customer + Checkout session (card required, 7-day trial)
    stripe_customer = stripe.Customer.create(email=email, name=business_name)
    checkout = stripe.checkout.Session.create(
        customer=stripe_customer.id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        subscription_data={"trial_period_days": 7, "metadata": {"customer_id": customer["id"]}},
        success_url=f"{FRONTEND_BASE_URL}/dashboard.html?customer_id={customer['id']}",
        cancel_url=f"{FRONTEND_BASE_URL}/index.html",
        metadata={"customer_id": customer["id"]},
    )

    sb.table(TABLE_CUST).update({"stripe_customer_id": stripe_customer.id}).eq(
        "id", customer["id"]
    ).execute()

    return {
        "customer_id": customer["id"],
        "token": make_token(customer["id"]),
        "twilio_number_assigned": purchased.phone_number,
        "checkout_url": checkout.url,
        "instructions": (
            f"Forward your business line ({business_phone}) to {purchased.phone_number} "
            "when unanswered/busy (conditional call forwarding), or route calls directly "
            "to it if you don't have an existing number."
        ),
    }


# ---------------------------------------------------------------------------
# LOGIN — email + password, returns a bearer token good for 30 days.
# ---------------------------------------------------------------------------
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    cust = sb.table(TABLE_CUST).select("id, password_hash").eq("email", email).execute()
    if not cust.data or not cust.data[0].get("password_hash"):
        raise HTTPException(401, "Incorrect email or password.")
    customer = cust.data[0]
    if not verify_password(password, customer["password_hash"]):
        raise HTTPException(401, "Incorrect email or password.")
    return {"customer_id": customer["id"], "token": make_token(customer["id"])}


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
    require_stripe()
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
# SETTINGS — lets a customer view/edit their own auto-reply message without
# re-signing-up. Same customer_id-as-access-token model as the dashboard.
# ---------------------------------------------------------------------------
MAX_REPLY_LENGTH = 300  # ~2 SMS segments; keeps costs and readability sane

@app.get("/settings/{customer_id}")
def get_settings(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select(
        "business_name, reply_template"
    ).eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    return {**cust.data[0], "max_length": MAX_REPLY_LENGTH}


@app.post("/settings/{customer_id}")
async def update_settings(customer_id: str, reply_template: str = Form(...), authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    reply_template = reply_template.strip()
    if not reply_template:
        raise HTTPException(400, "Message can't be empty.")
    if len(reply_template) > MAX_REPLY_LENGTH:
        raise HTTPException(
            400,
            f"Message is {len(reply_template)} characters — please keep it under {MAX_REPLY_LENGTH} "
            "(longer messages cost more to send and can arrive as multiple texts)."
        )
    cust = sb.table(TABLE_CUST).select("id").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    sb.table(TABLE_CUST).update({"reply_template": reply_template}).eq("id", customer_id).execute()
    return {"ok": True, "reply_template": reply_template}


# ---------------------------------------------------------------------------
# DASHBOARD API — what the customer sees. Simple, no auth framework yet;
# customer_id acts as the access token for MVP (fine while trusted/small).
# ---------------------------------------------------------------------------
@app.get("/dashboard/{customer_id}")
def dashboard(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
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
        "tier": customer.get("tier", "basic"),
        "twilio_number": customer["twilio_number"],
        "trial_ends_at": customer["trial_ends_at"],
        "stats": {"missed_calls_recent": total, "auto_texts_sent": texted},
        "recent_calls": calls.data,
    }


# ---------------------------------------------------------------------------
# AI VOICE AGENT (Pro tier) — pick a voice, upload a PDF knowledge base, and
# wire the customer's Twilio number to an ElevenLabs Conversational AI agent.
# ---------------------------------------------------------------------------
@app.get("/voices")
def list_voices():
    require_elevenlabs()
    resp = requests.get(f"{ELEVENLABS_BASE}/voices", headers=el_headers(), timeout=20)
    if not resp.ok:
        raise HTTPException(502, f"Couldn't fetch voices from ElevenLabs: {resp.text[:200]}")
    voices = resp.json().get("voices", [])
    return [
        {"voice_id": v["voice_id"], "name": v["name"], "preview_url": v.get("preview_url")}
        for v in voices
    ]


@app.get("/agent/{customer_id}")
def get_agent(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select(
        "tier, elevenlabs_agent_id, elevenlabs_voice_id, elevenlabs_kb_doc_id, fallback_behavior"
    ).eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    row = cust.data[0]
    if row["tier"] not in ("pro", "elite"):
        raise HTTPException(403, "This account needs the Pro or Elite tier for the AI voice agent.")
    return {
        "voice_id": row.get("elevenlabs_voice_id"),
        "has_pdf": bool(row.get("elevenlabs_kb_doc_id")),
        "agent_configured": bool(row.get("elevenlabs_agent_id")),
        "fallback_behavior": row.get("fallback_behavior", "message"),
    }


@app.post("/agent/{customer_id}/setup")
async def setup_agent(
    customer_id: str,
    voice_id: str = Form(...),
    fallback_behavior: str = Form("message"),  # "message" | "transfer" | "try_harder"
    pdf: UploadFile = File(None),
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    require_elevenlabs()
    require_twilio()

    if fallback_behavior not in ("message", "transfer", "try_harder"):
        raise HTTPException(400, "fallback_behavior must be 'message', 'transfer', or 'try_harder'.")

    cust = sb.table(TABLE_CUST).select("*").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    customer = cust.data[0]
    if customer["tier"] not in ("pro", "elite"):
        raise HTTPException(403, "This account needs the Pro or Elite tier — upgrade to use the AI voice agent.")

    update = {"elevenlabs_voice_id": voice_id, "fallback_behavior": fallback_behavior}

    # 1. Upload the PDF as a knowledge base document, if one was provided.
    kb_doc_id = customer.get("elevenlabs_kb_doc_id")
    if pdf is not None:
        files = {"file": (pdf.filename, await pdf.read(), pdf.content_type or "application/pdf")}
        resp = requests.post(
            f"{ELEVENLABS_BASE}/convai/knowledge-base/file",
            headers=el_headers(),
            files=files,
            data={"name": f"{customer['business_name']} info"},
            timeout=60,
        )
        if not resp.ok:
            raise HTTPException(502, f"Couldn't upload PDF to ElevenLabs: {resp.text[:300]}")
        kb_doc_id = resp.json().get("id")
        update["elevenlabs_kb_doc_id"] = kb_doc_id

    # 2. Create or update the ElevenLabs agent for this business.
    # NOTE: "transfer" currently behaves like "message" — the real live-transfer
    # tool needs ElevenLabs' built_in_tools.transfer_to_number config, which
    # failed twice with an undocumented schema. Rather than tell the AI it can
    # transfer when it can't, it takes a message honestly until that's fixed.
    fallback_instructions = {
        "message": "If you don't know the answer, politely ask for their name and phone number so someone can call them back — don't guess.",
        "transfer": "If you don't know the answer, politely ask for their name and phone number so someone can call them back — don't guess. Do not offer to transfer the call; you don't have that ability.",
        "try_harder": "Check the knowledge base carefully before giving up — rephrase the question in your head and look again. Only if you're truly certain the answer isn't in the knowledge base, ask for their name and number for a callback.",
    }
    system_prompt = (
        f"You are the phone receptionist for {customer['business_name']}. "
        "Be friendly, concise, and helpful. Answer questions using the knowledge base provided. "
        + fallback_instructions[fallback_behavior]
    )
    calendar_connected = customer.get("tier") == "elite" and customer.get("google_calendar_connected")
    if calendar_connected:
        from zoneinfo import ZoneInfo
        today_str = datetime.now(ZoneInfo(BUSINESS_TZ)).strftime("%A, %B %d, %Y")
        system_prompt += (
            f" Today's actual date is {today_str}. Always use this as the reference point when the "
            "caller says things like 'tomorrow', 'next Monday', or 'this Friday' — calculate the real "
            "calendar date from it rather than guessing."
        )
        system_prompt += (
            " You can also book appointments. If the caller wants to schedule something, use the "
            "check_availability tool to find open times on the date they want, tell them the options, "
            "then use book_appointment once they confirm a specific date and time. Always get their "
            "name and callback phone number before booking. Only tell the caller an appointment is "
            "confirmed if the book_appointment tool actually returns success — never say it's booked "
            "if the tool failed or you didn't call it; if that happens, apologize and offer to take a "
            "message instead."
        )
    conversation_config = {
        "agent": {
            "first_message": f"Hi, thanks for calling {customer['business_name']}! How can I help you today?",
            "language": "en",
            "prompt": {"prompt": system_prompt, "llm": ELEVENLABS_LLM_MODEL, "temperature": 0.5},
        },
        "tts": {"voice_id": voice_id},
    }
    if kb_doc_id:
        conversation_config["agent"]["prompt"]["knowledge_base"] = [
            {"id": kb_doc_id, "type": "file", "name": f"{customer['business_name']} info"}
        ]

    webhook_tools = []
    if calendar_connected:
        tool_secret_header = {"X-Tool-Secret": ELEVENLABS_TOOL_SECRET}
        webhook_tools.extend([
            {
                "type": "webhook",
                "name": "check_availability",
                "description": "Check the business's calendar for open appointment times on a given date.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/check-availability/{customer_id}",
                    "method": "POST",
                    "request_headers": tool_secret_header,
                    "request_body_schema": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string", "description": "Date to check, format YYYY-MM-DD"}
                        },
                        "required": ["date"],
                    },
                },
            },
            {
                "type": "webhook",
                "name": "book_appointment",
                "description": "Book an appointment on the business's calendar once the caller confirms a date and time.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/book-appointment/{customer_id}",
                    "method": "POST",
                    "request_headers": tool_secret_header,
                    "request_body_schema": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string", "description": "Date, format YYYY-MM-DD"},
                            "time": {"type": "string", "description": "24-hour time, format HH:MM"},
                            "caller_name": {"type": "string", "description": "The caller's name"},
                            "caller_phone": {"type": "string", "description": "The caller's callback phone number"},
                        },
                        "required": ["date", "time", "caller_name", "caller_phone"],
                    },
                },
            },
        ])
    if webhook_tools:
        conversation_config["agent"]["prompt"]["tools"] = webhook_tools

    # transfer_to_number system tool intentionally not attached — see note
    # above fallback_instructions. Revisit once the schema is confirmed
    # against real ElevenLabs docs/testing, not search-result guesses.

    def save_agent(existing_agent_id):
        if existing_agent_id:
            r = requests.patch(
                f"{ELEVENLABS_BASE}/convai/agents/{existing_agent_id}",
                headers={**el_headers(), "Content-Type": "application/json"},
                json={"conversation_config": conversation_config},
                timeout=30,
            )
        else:
            r = requests.post(
                f"{ELEVENLABS_BASE}/convai/agents/create",
                headers={**el_headers(), "Content-Type": "application/json"},
                json={"name": customer["business_name"], "conversation_config": conversation_config},
                timeout=30,
            )
        return r

    agent_id = customer.get("elevenlabs_agent_id")
    resp = save_agent(agent_id)
    if not resp.ok and "tools" in conversation_config["agent"]["prompt"]:
        # The transfer tool's schema might not match what this ElevenLabs
        # account expects — drop ONLY that one tool and retry, so calendar
        # tools (check_availability, book_appointment) survive intact.
        log.error(f"Agent save failed, retrying with transfer tool removed: {resp.text[:300]}")
        conversation_config["agent"]["prompt"]["tools"] = [
            t for t in conversation_config["agent"]["prompt"]["tools"] if t.get("name") != "transfer_to_number"
        ]
        if not conversation_config["agent"]["prompt"]["tools"]:
            del conversation_config["agent"]["prompt"]["tools"]
        resp = save_agent(agent_id)
    if not resp.ok:
        raise HTTPException(502, f"Couldn't save ElevenLabs agent: {resp.text[:300]}")
    if not agent_id:
        agent_id = resp.json().get("agent_id")
        update["elevenlabs_agent_id"] = agent_id

    # 3. Import the Twilio number into ElevenLabs (first time only) and assign the agent.
    phone_id = customer.get("elevenlabs_phone_id")
    if not phone_id:
        resp = requests.post(
            f"{ELEVENLABS_BASE}/convai/phone-numbers",
            headers={**el_headers(), "Content-Type": "application/json"},
            json={
                "provider": "twilio",
                "phone_number": customer["twilio_number"],
                "label": customer["business_name"],
                "sid": TWILIO_SID,
                "token": TWILIO_TOKEN,
            },
            timeout=30,
        )
        if not resp.ok:
            raise HTTPException(
                502,
                f"Couldn't import your number into ElevenLabs: {resp.text[:300]} "
                "(this is a newer integration — if this keeps failing, send this exact "
                "message and we'll fix the field names)."
            )
        phone_id = resp.json().get("phone_number_id")
        update["elevenlabs_phone_id"] = phone_id

    resp = requests.patch(
        f"{ELEVENLABS_BASE}/convai/phone-numbers/{phone_id}",
        headers={**el_headers(), "Content-Type": "application/json"},
        json={"agent_id": agent_id},
        timeout=30,
    )
    if not resp.ok:
        raise HTTPException(502, f"Couldn't assign the agent to your number: {resp.text[:300]}")

    sb.table(TABLE_CUST).update(update).eq("id", customer_id).execute()
    return {"ok": True, "agent_id": agent_id, "voice_id": voice_id, "has_pdf": bool(kb_doc_id)}


# ---------------------------------------------------------------------------
# GOOGLE OAUTH (Elite tier) — Calendar booking + Business Profile sync.
# One OAuth app registered under Recall's own Google Cloud project; each
# customer authorizes their own Google account via the real Google consent
# screen. We never see or store their Google password — only a refresh token
# scoped to whichever single permission (calendar or business) they granted.
# ---------------------------------------------------------------------------
def require_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(503, "Google integration isn't configured yet — add GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET.")


def require_elite(customer: dict):
    if customer.get("tier") != "elite":
        raise HTTPException(403, "This account isn't on the Elite tier.")


@app.get("/google/auth-url")
def google_auth_url(customer_id: str, service: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    require_google()
    if service not in GOOGLE_SCOPES:
        raise HTTPException(400, "service must be 'calendar' or 'business'.")

    cust = sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    require_elite(cust.data[0])

    # Short-lived signed state — carries which customer/service this is for
    # through Google's redirect, since Google can't send our auth header back.
    state = jwt.encode(
        {"customer_id": customer_id, "service": service, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        JWT_SECRET,
        algorithm="HS256",
    )
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{PUBLIC_BASE_URL}/google/callback",
        "response_type": "code",
        "scope": GOOGLE_SCOPES[service],
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    from urllib.parse import urlencode
    return {"url": f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"}


@app.get("/google/callback")
def google_callback(code: str = None, state: str = None, error: str = None):
    if error:
        return PlainTextResponse(f"Google sign-in was cancelled or denied ({error}). You can close this tab and try again.")
    require_google()
    try:
        payload = jwt.decode(state, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(400, "This connection link expired or is invalid — go back and try connecting again.")

    customer_id = payload["customer_id"]
    service = payload["service"]

    token_resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": f"{PUBLIC_BASE_URL}/google/callback",
            "grant_type": "authorization_code",
        },
        timeout=20,
    )
    if not token_resp.ok:
        raise HTTPException(502, f"Google didn't accept that authorization: {token_resp.text[:300]}")
    tokens = token_resp.json()
    refresh_token = tokens.get("refresh_token")

    if refresh_token:
        col = "google_calendar_refresh_token" if service == "calendar" else "google_business_refresh_token"
        flag = "google_calendar_connected" if service == "calendar" else "google_business_connected"
        sb.table(TABLE_CUST).update({col: refresh_token, flag: True}).eq("id", customer_id).execute()

    from fastapi.responses import RedirectResponse
    return RedirectResponse(f"{FRONTEND_BASE_URL}/elite-setup.html?customer_id={customer_id}&connected={service}")


@app.get("/elite/{customer_id}")
def get_elite_status(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select(
        "tier, google_calendar_connected, google_business_connected"
    ).eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    row = cust.data[0]
    require_elite(row)
    return {
        "calendar_connected": row.get("google_calendar_connected", False),
        "business_connected": row.get("google_business_connected", False),
    }


# ---------------------------------------------------------------------------
# CALENDAR TOOL ENDPOINTS — called live, mid-call, by the ElevenLabs agent
# (not by the browser). Protected by a shared secret header instead of the
# customer's login token, since ElevenLabs' servers are the caller here.
# Business hours are hardcoded 9am-5pm Eastern for now — a per-customer
# hours setting is a natural next step, not required for this to work.
# ---------------------------------------------------------------------------
BUSINESS_TZ = "America/New_York"
BUSINESS_HOURS = (9, 17)  # 9am–5pm
SLOT_MINUTES = 30


def check_tool_secret(request_headers: dict):
    if request_headers.get("x-tool-secret") != ELEVENLABS_TOOL_SECRET:
        raise HTTPException(401, "Invalid tool secret.")


def google_access_token(refresh_token: str) -> str:
    resp = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=20,
    )
    if not resp.ok:
        log.error(f"Google token refresh failed: {resp.status_code} {resp.text[:400]}")
        raise HTTPException(502, f"Couldn't refresh Google access: {resp.text[:200]}")
    return resp.json()["access_token"]


def get_calendar_customer(customer_id: str) -> dict:
    cust = sb.table(TABLE_CUST).select("*").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Customer not found")
    customer = cust.data[0]
    if not customer.get("google_calendar_refresh_token"):
        raise HTTPException(400, "Google Calendar isn't connected for this business.")
    return customer


@app.post("/tools/check-availability/{customer_id}")
async def tool_check_availability(customer_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"check-availability request body: {body}")
    date_str = body.get("date") or body.get("parameters", {}).get("date")
    if not date_str:
        return {"result": "I need a specific date (YYYY-MM-DD) to check availability."}

    try:
        customer = get_calendar_customer(customer_id)
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(BUSINESS_TZ)
        day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=tz)
        day_start = day.replace(hour=BUSINESS_HOURS[0], minute=0, second=0, microsecond=0)
        day_end = day.replace(hour=BUSINESS_HOURS[1], minute=0, second=0, microsecond=0)

        access_token = google_access_token(customer["google_calendar_refresh_token"])
        resp = requests.post(
            "https://www.googleapis.com/calendar/v3/freeBusy",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={
                "timeMin": day_start.isoformat(),
                "timeMax": day_end.isoformat(),
                "items": [{"id": "primary"}],
            },
            timeout=20,
        )
        if not resp.ok:
            log.error(f"Google freeBusy failed for {customer_id}: {resp.status_code} {resp.text[:400]}")
            return {"result": "I couldn't check the calendar right now — please offer to take a message instead."}

        busy = resp.json().get("calendars", {}).get("primary", {}).get("busy", [])
        busy_ranges = [(datetime.fromisoformat(b["start"]), datetime.fromisoformat(b["end"])) for b in busy]

        free_slots = []
        slot = day_start
        while slot + timedelta(minutes=SLOT_MINUTES) <= day_end:
            slot_end = slot + timedelta(minutes=SLOT_MINUTES)
            overlaps = any(slot < be and slot_end > bs for bs, be in busy_ranges)
            if not overlaps:
                free_slots.append(slot.strftime("%-I:%M %p"))
            slot = slot_end
            if len(free_slots) >= 5:
                break

        if not free_slots:
            result = f"There's nothing open on {date_str} during business hours — offer another date."
        else:
            result = f"Available times on {date_str}: " + ", ".join(free_slots)
        log.info(f"check-availability result: {result}")
        return {"result": result}
    except ValueError:
        return {"result": "That date didn't look right — please use YYYY-MM-DD format."}
    except Exception:
        log.exception(f"check-availability crashed for {customer_id}")
        return {"result": "I couldn't check the calendar right now — please offer to take a message instead."}


@app.post("/tools/book-appointment/{customer_id}")
async def tool_book_appointment(customer_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"book-appointment request body: {body}")
    p = body if "date" in body else body.get("parameters", {})
    date_str, time_str = p.get("date"), p.get("time")
    caller_name, caller_phone = p.get("caller_name"), p.get("caller_phone")
    if not all([date_str, time_str, caller_name, caller_phone]):
        return {"result": "I'm missing some details — I need the date, time, the caller's name, and their phone number."}

    try:
        customer = get_calendar_customer(customer_id)
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(BUSINESS_TZ)
        start = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
        end = start + timedelta(minutes=SLOT_MINUTES)

        access_token = google_access_token(customer["google_calendar_refresh_token"])
        resp = requests.post(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={
                "summary": f"{caller_name} — {customer['business_name']} appointment",
                "description": f"Booked by Recall AI. Caller phone: {caller_phone}",
                "start": {"dateTime": start.isoformat()},
                "end": {"dateTime": end.isoformat()},
            },
            timeout=20,
        )
        if not resp.ok:
            log.error(f"Google event creation failed for {customer_id}: {resp.status_code} {resp.text[:400]}")
            return {"result": "I couldn't book that — please offer to take a message instead."}
        log.info(f"book-appointment success, event id: {resp.json().get('id')}")
        return {"result": f"Booked for {caller_name} on {date_str} at {time_str}. Confirmed."}
    except ValueError:
        return {"result": "That date or time didn't look right — date as YYYY-MM-DD, time as HH:MM."}
    except Exception:
        log.exception(f"book-appointment crashed for {customer_id}")
        return {"result": "I couldn't book that — please offer to take a message instead."}
