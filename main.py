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
import re
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
# Powers the SMS text-back AI (all tiers) — separate from the ElevenLabs voice
# AI (Pro/Elite only), since Basic tier has no ElevenLabs setup at all.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
SMS_HISTORY_LIMIT = 10  # recent messages of context per conversation
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


ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET:
    ADMIN_SECRET = secrets.token_hex(24)
    log.warning("ADMIN_SECRET not set — using a random per-restart value. Set it in Render.")


def require_admin(authorization: str = Header(None)):
    """For Saleh-only internal endpoints — not tied to any customer account."""
    if not authorization or authorization.removeprefix("Bearer ").strip() != ADMIN_SECRET:
        raise HTTPException(401, "Not authorized.")


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
TABLE_LOC = "recall_locations"
TABLE_CALLS = "recall_missed_calls"


# ---------------------------------------------------------------------------
# LOCATION HELPERS — recall_customers is the ACCOUNT (login, billing, tier).
# recall_locations is where the actual number/AI/booking config lives — one
# account can have 1+ locations. Most existing endpoints are customer_id-
# authenticated but operate on a single location; unless a location_id is
# explicitly passed, they default to that account's PRIMARY location (the
# earliest-created one) so old frontend calls keep working unchanged.
# ---------------------------------------------------------------------------
def get_primary_location(customer_id: str) -> dict:
    loc = (
        sb.table(TABLE_LOC)
        .select("*")
        .eq("customer_id", customer_id)
        .order("created_at")
        .limit(1)
        .execute()
    )
    if not loc.data:
        raise HTTPException(404, "This account has no location set up yet.")
    return loc.data[0]


def get_location_for_customer(customer_id: str, location_id: str = None) -> dict:
    """Returns the requested location if it belongs to this customer, else
    the account's primary location. Use this in every customer_id-authed
    endpoint that touches per-location config."""
    if location_id:
        loc = sb.table(TABLE_LOC).select("*").eq("id", location_id).execute()
        if not loc.data or loc.data[0]["customer_id"] != customer_id:
            raise HTTPException(404, "Location not found for this account.")
        return loc.data[0]
    return get_primary_location(customer_id)


def get_location_by_number(twilio_number: str) -> dict:
    """Twilio webhooks identify the call/text by number, not customer_id —
    joins back to recall_customers for account-level fields (tier, status,
    business_name) so callers get one flat dict either way."""
    loc = sb.table(TABLE_LOC).select("*, recall_customers(*)").eq("twilio_number", twilio_number).execute()
    if not loc.data:
        return None
    row = loc.data[0]
    customer = row.pop("recall_customers", None) or {}
    merged = {**customer, **row}  # location fields win on any name overlap (e.g. business_phone)
    merged["customer_id"] = row["customer_id"]
    merged["location_id"] = row["id"]
    return merged


@app.get("/health")
def health():
    return {"ok": True, "service": "recall"}


# ---------------------------------------------------------------------------
# LOCATIONS — list an account's locations (for the dashboard switcher) and
# add a new one to an ALREADY-LOGGED-IN account. This is deliberately a
# separate endpoint from /signup: /signup creates the account (email must be
# unique); this only ever buys a number + creates a recall_locations row
# under an account that already exists. Email and phone number are unrelated
# — one identifies the login, the other identifies a location's number.
# ---------------------------------------------------------------------------
@app.get("/locations/{customer_id}")
def list_locations(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    locs = (
        sb.table(TABLE_LOC)
        .select("id, location_label, business_phone, twilio_number, created_at")
        .eq("customer_id", customer_id)
        .order("created_at")
        .execute()
    )
    return {"locations": locs.data}


@app.post("/locations/add")
async def add_location(
    customer_id: str = Form(...),
    location_label: str = Form(...),
    business_phone: str = Form(...),
    area_code: str = Form(None),
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    require_twilio()

    cust = sb.table(TABLE_CUST).select("id, business_name, tier, status").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Account not found")
    customer = cust.data[0]
    if customer["status"] not in ("trial", "active"):
        raise HTTPException(403, "This account's subscription isn't active — can't add a location right now.")

    # Same warmed-pool-first logic as signup, so a new location doesn't get
    # hit with A2P propagation delay on top of everything else.
    pooled = get_warmed_number()
    if pooled:
        class _Purchased:
            phone_number = pooled["phone_number"]
            sid = pooled["twilio_sid"]
        purchased = _Purchased()
    else:
        log.warning(f"Number pool empty — buying a fresh number for a new location on account {customer_id}.")
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
            sms_url=f"{PUBLIC_BASE_URL}/twilio/sms",
            sms_method="POST",
        )
        if TWILIO_MESSAGING_SERVICE_SID:
            try:
                twilio_client.messaging.v1.services(TWILIO_MESSAGING_SERVICE_SID).phone_numbers.create(
                    phone_number_sid=purchased.sid
                )
            except Exception as e:
                log.error(f"Failed to add {purchased.phone_number} to A2P sender pool: {e}")

    loc_row = {
        "customer_id": customer_id,
        "location_label": location_label.strip() or "New location",
        "business_phone": business_phone,
        "twilio_number": purchased.phone_number,
    }
    result = sb.table(TABLE_LOC).insert(loc_row).execute()
    location = result.data[0]

    if pooled:
        sb.table("recall_number_pool").update({
            "assigned_to_customer_id": customer_id,
            "assigned_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", pooled["id"]).execute()

    return {
        "location_id": location["id"],
        "twilio_number_assigned": purchased.phone_number,
        "instructions": (
            f"Forward this location's business line ({business_phone}) to {purchased.phone_number} "
            "when unanswered/busy (conditional call forwarding), or route calls directly to it."
        ),
    }


# ---------------------------------------------------------------------------
# SIGNUP — creates the ACCOUNT (email/password/Stripe/tier) plus its first
# location (Twilio number + business phone). This is the only place email
# uniqueness is enforced — every location added after this goes through
# /locations/add instead, which never touches email at all.
# ---------------------------------------------------------------------------
@app.post("/signup")
async def signup(
    business_name: str = Form(...),
    owner_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    business_phone: str = Form(...),  # their real phone, in E.164 e.g. +13155551234
    tier: str = Form("basic"),        # "basic", "pro", or "elite"
    area_code: str = Form(None),      # optional preferred area code for the new number
    reply_template: str = Form(None), # optional custom auto-reply text
):
    require_twilio()
    require_stripe()
    if tier not in ("basic", "pro", "elite"):
        raise HTTPException(400, "tier must be 'basic', 'pro', or 'elite'.")
    price_id = STRIPE_PRICE_ID_PRO if tier in ("pro", "elite") else STRIPE_PRICE_ID
    if tier in ("pro", "elite") and not price_id:
        raise HTTPException(503, "This tier isn't configured yet — add STRIPE_PRICE_ID_PRO.")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    existing = sb.table(TABLE_CUST).select("id").eq("email", email).execute()
    if existing.data:
        raise HTTPException(400, "An account with this email already exists.")

    # 1. Get a phone number — prefer an already-warmed one from the pool
    # (fully registered, no A2P propagation delay) over buying fresh.
    pooled = get_warmed_number()
    if pooled:
        class _Purchased:  # shim so the rest of the function can treat this like a fresh purchase
            phone_number = pooled["phone_number"]
            sid = pooled["twilio_sid"]
        purchased = _Purchased()
    else:
        log.warning(f"Number pool empty — buying a fresh number for {email}; texts may be delayed by A2P propagation.")
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
            sms_url=f"{PUBLIC_BASE_URL}/twilio/sms",
            sms_method="POST",
        )
        # Register this number under the approved A2P 10DLC campaign so texts
        # from it aren't silently blocked by US carriers (error 30034) — though
        # since it's fresh, it still needs real propagation time regardless.
        if TWILIO_MESSAGING_SERVICE_SID:
            try:
                twilio_client.messaging.v1.services(TWILIO_MESSAGING_SERVICE_SID).phone_numbers.create(
                    phone_number_sid=purchased.sid
                )
            except Exception as e:
                log.error(f"Failed to add {purchased.phone_number} to A2P sender pool: {e}")

    # 2. Create the account row (status=trial) — account-level fields only.
    row = {
        "business_name": business_name,
        "owner_name": owner_name,
        "email": email,
        "password_hash": hash_password(password),
        "tier": tier,
    }
    result = sb.table(TABLE_CUST).insert(row).execute()
    customer = result.data[0]

    # 2b. Create its first location row — this is where the number/config lives.
    loc_row = {
        "customer_id": customer["id"],
        "location_label": "Main location",
        "business_phone": business_phone,
        "twilio_number": purchased.phone_number,
    }
    if reply_template and reply_template.strip():
        loc_row["reply_template"] = reply_template.strip()
    loc_result = sb.table(TABLE_LOC).insert(loc_row).execute()
    location = loc_result.data[0]

    if pooled:
        sb.table("recall_number_pool").update({
            "assigned_to_customer_id": customer["id"],
            "assigned_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", pooled["id"]).execute()

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
        "location_id": location["id"],
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
# TWILIO VOICE WEBHOOK — call hits a location's dedicated number, we try to
# dial that location's real business phone. If nobody picks up, the call
# ends and /twilio/status fires with an unanswered result, triggering the
# text-back for that specific location.
# ---------------------------------------------------------------------------
@app.post("/twilio/voice")
async def twilio_voice(request: Request):
    form = await request.form()
    to_number = form.get("To")

    resp = VoiceResponse()
    location = get_location_by_number(to_number)
    if not location:
        resp.say("This number is not currently active.")
        return PlainTextResponse(str(resp), media_type="application/xml")

    if location["status"] not in ("trial", "active"):
        resp.say("This business is temporarily unavailable. Please try again later.")
        return PlainTextResponse(str(resp), media_type="application/xml")

    dial = Dial(timeout=20, action=f"{PUBLIC_BASE_URL}/twilio/dial-result", method="POST")
    dial.number(location["business_phone"])
    resp.append(dial)
    return PlainTextResponse(str(resp), media_type="application/xml")


# ---------------------------------------------------------------------------
# DIAL RESULT — fires right after the <Dial> attempt finishes. This is what
# actually tells us the call went unanswered.
# ---------------------------------------------------------------------------
async def send_missed_call_text(to_number: str, caller: str, call_sid: str):
    """Sends the auto-reply text for a missed call and logs it. Shared by the
    Basic/Pro <Dial> flow and the Elite AI-agent safety net."""
    if call_sid:
        existing = sb.table(TABLE_CALLS).select("id").eq("call_sid", call_sid).execute()
        if existing.data:
            return  # already texted for this call — avoid double-sending

    location = get_location_by_number(to_number)
    if not location:
        return

    message = location["reply_template"].replace("{business_name}", location["business_name"])
    call_row = {
        "location_id": location["location_id"],
        "caller_number": caller,
        "call_sid": call_sid,
        "sms_body": message,
    }
    try:
        sms = twilio_client.messages.create(to=caller, from_=to_number, body=message)
        call_row["sms_sent"] = True
        call_row["sms_sid"] = sms.sid
    except Exception as e:
        log.error(f"SMS send failed for {caller}: {e}")
        call_row["sms_sent"] = False
        call_row["sms_error"] = str(e)
    sb.table(TABLE_CALLS).insert(call_row).execute()


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

    await send_missed_call_text(to_number, caller, call_sid)

    resp.say("Sorry we missed you. We've just sent you a text — thanks for calling.")
    resp.hangup()
    return PlainTextResponse(str(resp), media_type="application/xml")


@app.post("/twilio/status")
async def twilio_status(request: Request):
    """Fires on every call to this number regardless of who answered it —
    Twilio calls this independently of the voice webhook, so it still fires
    even for Elite/Pro numbers where ElevenLabs owns the voice URL. This is
    the safety net: if a call ends without being answered (by us OR by the
    AI), text the caller so nobody falls through the cracks."""
    form = await request.form()
    to_number = form.get("To")
    caller = form.get("From")
    call_sid = form.get("CallSid")
    call_status = form.get("CallStatus")  # completed, no-answer, busy, failed
    duration = int(form.get("CallDuration") or 0)

    # "completed" with a real duration means someone (human or AI) actually
    # engaged. Anything else — or a suspiciously instant "completed" — means
    # the caller never got through to anyone.
    if call_status == "completed" and duration > 3:
        return PlainTextResponse("", media_type="application/xml")

    await send_missed_call_text(to_number, caller, call_sid)
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
# SETTINGS — lets a customer view/edit a location's auto-reply message.
# Optional location_id (query/form param) selects which location; defaults
# to the account's primary location if omitted, so old frontend calls keep
# working unchanged.
# ---------------------------------------------------------------------------
MAX_REPLY_LENGTH = 300  # ~2 SMS segments; keeps costs and readability sane

@app.get("/settings/{customer_id}")
def get_settings(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select("business_name").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    loc = get_location_for_customer(customer_id, location_id)
    return {
        "business_name": cust.data[0]["business_name"],
        "reply_template": loc["reply_template"],
        "location_id": loc["id"],
        "max_length": MAX_REPLY_LENGTH,
    }


@app.post("/settings/{customer_id}")
async def update_settings(
    customer_id: str,
    reply_template: str = Form(...),
    location_id: str = Form(None),
    authorization: str = Header(None),
):
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
    loc = get_location_for_customer(customer_id, location_id)
    sb.table(TABLE_LOC).update({"reply_template": reply_template}).eq("id", loc["id"]).execute()
    return {"ok": True, "reply_template": reply_template, "location_id": loc["id"]}


# ---------------------------------------------------------------------------
# DASHBOARD API — what the customer sees. Simple, no auth framework yet;
# customer_id acts as the access token for MVP (fine while trusted/small).
# Defaults to the primary location if location_id isn't passed, so the
# existing dashboard.html keeps working without changes.
# ---------------------------------------------------------------------------
@app.get("/dashboard/{customer_id}")
def dashboard(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select("*").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    customer = cust.data[0]
    loc = get_location_for_customer(customer_id, location_id)

    calls = (
        sb.table(TABLE_CALLS)
        .select("*")
        .eq("location_id", loc["id"])
        .order("called_at", desc=True)
        .limit(50)
        .execute()
    )

    total = len(calls.data)
    texted = sum(1 for c in calls.data if c["sms_sent"])

    messages = (
        sb.table("recall_messages")
        .select("*")
        .eq("customer_id", customer_id)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )

    all_locations = (
        sb.table(TABLE_LOC)
        .select("id, location_label, twilio_number")
        .eq("customer_id", customer_id)
        .order("created_at")
        .execute()
    )

    return {
        "business_name": customer["business_name"],
        "status": customer["status"],
        "tier": customer.get("tier", "basic"),
        "location_id": loc["id"],
        "location_label": loc.get("location_label"),
        "twilio_number": loc["twilio_number"],
        "locations": all_locations.data,
        "trial_ends_at": customer.get("trial_ends_at"),
        "stats": {"missed_calls_recent": total, "auto_texts_sent": texted},
        "recent_calls": calls.data,
        "messages": messages.data,
    }


@app.post("/messages/{message_id}/resolve")
def resolve_message(message_id: str, customer_id: str = Form(...), authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    msg = sb.table("recall_messages").select("customer_id").eq("id", message_id).execute()
    if not msg.data or msg.data[0]["customer_id"] != customer_id:
        raise HTTPException(404, "Not found")
    sb.table("recall_messages").update({"resolved": True}).eq("id", message_id).execute()
    return {"ok": True}


# ---------------------------------------------------------------------------
# SMS TEXT-BACK AI (all tiers) — lets a customer reply to the missed-call text
# and get a real AI answer, grounded in their own uploaded business info.
# Independent of the ElevenLabs voice AI (Pro/Elite only) since Basic tier
# has no ElevenLabs setup at all — this uses Claude directly instead.
# business_info_text and google_calendar_refresh_token now live per-location.
# ---------------------------------------------------------------------------
def require_anthropic():
    if not ANTHROPIC_API_KEY:
        raise HTTPException(503, "SMS AI isn't configured yet — add ANTHROPIC_API_KEY.")


@app.post("/settings/{customer_id}/business-info")
async def upload_business_info(
    customer_id: str,
    pdf: UploadFile = File(...),
    location_id: str = None,
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    loc = get_location_for_customer(customer_id, location_id)

    try:
        import pypdf
        from io import BytesIO
        reader = pypdf.PdfReader(BytesIO(await pdf.read()))
        text = "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except Exception as e:
        raise HTTPException(400, f"Couldn't read that PDF: {e}")
    if not text:
        raise HTTPException(400, "Couldn't find any readable text in that PDF.")

    sb.table(TABLE_LOC).update({"business_info_text": text[:20000]}).eq("id", loc["id"]).execute()

    # Make sure this number can actually receive replies — set the inbound
    # SMS webhook now in case it wasn't set at signup (e.g. older accounts).
    if twilio_client and loc.get("twilio_number"):
        try:
            numbers = twilio_client.incoming_phone_numbers.list(phone_number=loc["twilio_number"], limit=1)
            if numbers:
                numbers[0].update(sms_url=f"{PUBLIC_BASE_URL}/twilio/sms", sms_method="POST")
        except Exception as e:
            log.error(f"Couldn't set sms_url for {loc['twilio_number']}: {e}")

    return {"ok": True, "characters_saved": len(text[:20000]), "location_id": loc["id"]}


@app.get("/settings/{customer_id}/business-info")
def get_business_info(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    loc = get_location_for_customer(customer_id, location_id)
    text = loc.get("business_info_text") or ""
    return {"has_info": bool(text), "preview": text[:200], "location_id": loc["id"]}


@app.post("/twilio/sms")
async def twilio_sms(request: Request):
    require_anthropic()
    form = await request.form()
    to_number = form.get("To")
    from_number = form.get("From")
    body = (form.get("Body") or "").strip()
    if not body:
        return PlainTextResponse("", media_type="application/xml")

    location = get_location_by_number(to_number)
    if not location:
        return PlainTextResponse("", media_type="application/xml")

    sb.table("recall_sms_messages").insert({
        "location_id": location["location_id"], "direction": "inbound",
        "from_number": from_number, "body": body,
    }).execute()

    history = (
        sb.table("recall_sms_messages")
        .select("direction, body")
        .eq("location_id", location["location_id"])
        .order("created_at", desc=True)
        .limit(SMS_HISTORY_LIMIT)
        .execute()
    )
    turns = list(reversed(history.data))

    business_info = location.get("business_info_text") or "No business information has been provided yet."
    can_book = location.get("tier") == "elite" and bool(location.get("google_calendar_refresh_token"))

    system_prompt = (
        f"You are the text-message assistant for {location['business_name']}. "
        "Answer questions using the business info below. Be brief and friendly — "
        "this is a text message, not a phone call, so keep replies short (under "
        "400 characters when possible). If you don't know the answer, say so "
        "honestly and suggest calling the store directly.\n\n"
        f"Business info:\n{business_info}"
    )
    tools = None
    if can_book:
        system_prompt += (
            "\n\nYou can also check availability and book appointments directly in this "
            "text conversation using the tools provided. Today's date is "
            f"{datetime.now().strftime('%Y-%m-%d')}. Get the date and time the customer "
            "wants, confirm their name, then book it — you already have their phone number "
            "from this text conversation, so don't ask for it."
        )
        tools = [
            {
                "name": "check_availability",
                "description": "Check open appointment slots on a given date, optionally near a specific time.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "date": {"type": "string", "description": "YYYY-MM-DD"},
                        "time": {"type": "string", "description": "Optional specific time, 24-hour HH:MM"},
                    },
                    "required": ["date"],
                },
            },
            {
                "name": "book_appointment",
                "description": "Book an appointment once the customer has confirmed a date, time, and their name.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "date": {"type": "string", "description": "YYYY-MM-DD"},
                        "time": {"type": "string", "description": "24-hour HH:MM"},
                        "caller_name": {"type": "string"},
                    },
                    "required": ["date", "time", "caller_name"],
                },
            },
        ]

    messages = [
        {"role": "user" if t["direction"] == "inbound" else "assistant", "content": t["body"]}
        for t in turns
    ]

    def call_booking_tool(name: str, tool_input: dict) -> str:
        payload = dict(tool_input)
        if name == "book_appointment":
            payload["caller_phone"] = from_number
        try:
            endpoint = "check-availability" if name == "check_availability" else "book-appointment"
            resp = requests.post(
                f"{PUBLIC_BASE_URL}/tools/{endpoint}/{location['location_id']}",
                headers={"X-Tool-Secret": ELEVENLABS_TOOL_SECRET, "Content-Type": "application/json"},
                json=payload,
                timeout=20,
            )
            return resp.json().get("result", "Something went wrong checking that — try again.")
        except Exception as e:
            log.error(f"SMS booking tool '{name}' failed for location {location['location_id']}: {e}")
            return "Something went wrong checking that — try again shortly."

    try:
        reply_text = ""
        for _ in range(5):  # hard cap so a stuck tool loop can't run forever
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 300,
                    "system": system_prompt,
                    "messages": messages,
                    **({"tools": tools} if tools else {}),
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["content"]
            reply_text = "\n".join(b["text"] for b in content if b["type"] == "text").strip()

            if data.get("stop_reason") != "tool_use":
                break

            messages.append({"role": "assistant", "content": content})
            tool_results = []
            for block in content:
                if block["type"] == "tool_use":
                    result_text = call_booking_tool(block["name"], block["input"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": result_text,
                    })
            messages.append({"role": "user", "content": tool_results})

        if not reply_text:
            reply_text = "Got it — let me know if there's anything else I can help with."
    except Exception as e:
        log.error(f"SMS AI failed for location {location['location_id']}: {e}")
        reply_text = "Sorry, I'm having trouble answering right now — please call us directly."

    try:
        twilio_client.messages.create(to=from_number, from_=to_number, body=reply_text)
        sb.table("recall_sms_messages").insert({
            "location_id": location["location_id"], "direction": "outbound",
            "from_number": to_number, "body": reply_text,
        }).execute()
    except Exception as e:
        log.error(f"SMS AI reply send failed for location {location['location_id']}: {e}")

    return PlainTextResponse("", media_type="application/xml")


# ---------------------------------------------------------------------------
# APPOINTMENT REMINDERS (Elite tier) — a text/call sent before each booked
# appointment. recall_appointments now joins through recall_locations for
# its per-location settings (twilio_number, reminder lead times), and
# through recall_locations.recall_customers for business_name.
# ---------------------------------------------------------------------------
REMINDER_JOB_SECRET = os.environ.get("REMINDER_JOB_SECRET")
if not REMINDER_JOB_SECRET:
    REMINDER_JOB_SECRET = secrets.token_hex(24)
    log.warning("REMINDER_JOB_SECRET not set — using a random per-restart value. Set it in Render.")
REMINDER_MIN_DELAY_SECONDS = int(os.environ.get("REMINDER_MIN_DELAY_SECONDS", "120"))


def business_local_time_str(appointment_start) -> str:
    """Format a stored appointment_start as a human-readable LOCAL time.

    Supabase/Postgres normalizes timestamptz columns to UTC on write, so
    reading appointment_start back and calling .strftime() directly on it
    prints the UTC clock time, not the business's local time (e.g. a 9:30 PM
    EDT appointment round-trips as ~1:30 AM UTC the next day). Always
    re-localize to BUSINESS_TZ before formatting.
    """
    from zoneinfo import ZoneInfo
    dt = appointment_start if isinstance(appointment_start, datetime) else datetime.fromisoformat(appointment_start)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZoneInfo(BUSINESS_TZ)).strftime("%-I:%M %p")


@app.post("/internal/send-reminders")
async def send_reminders(request: Request):
    if request.headers.get("x-job-secret") != REMINDER_JOB_SECRET:
        raise HTTPException(401, "Invalid job secret.")

    now = datetime.now(timezone.utc)
    # Pull any still-upcoming appointment with at least one reminder still
    # pending — text and call fire independently, each on its own lead time.
    due = (
        sb.table("recall_appointments")
        .select(
            "*, recall_locations(business_name:location_label, reminder_text_minutes_before, "
            "reminder_call_minutes_before, twilio_number, customer_id, recall_customers(business_name))"
        )
        .or_("reminder_text_sent.eq.false,reminder_call_sent.eq.false")
        .gt("appointment_start", now.isoformat())
        .execute()
    )

    sent = 0
    for appt in due.data:
        loc = appt.get("recall_locations")
        if not loc:
            continue
        customer_info = loc.get("recall_customers") or {}
        business_name = customer_info.get("business_name") or loc.get("business_name") or "the business"
        appt_time = datetime.fromisoformat(appt["appointment_start"])
        minutes_until = (appt_time - now).total_seconds() / 60

        # Give the customer at least a couple minutes after booking before
        # ANY reminder can fire — otherwise a short-notice booking (e.g. made
        # 10 minutes out with a 15-minute call lead time) triggers a callback
        # before they've even hung up the original booking call.
        created_at = appt.get("created_at")
        if created_at:
            seconds_since_booked = (now - datetime.fromisoformat(created_at)).total_seconds()
            if seconds_since_booked < REMINDER_MIN_DELAY_SECONDS:
                continue  # too soon after booking — wait for a later run

        local_time = business_local_time_str(appt_time)
        updates = {}

        text_lead = loc.get("reminder_text_minutes_before", 60)
        if not appt.get("reminder_text_sent") and minutes_until <= text_lead:
            message = (
                f"Reminder: you have an appointment with {business_name} "
                f"today at {local_time}. See you soon!"
            )
            try:
                twilio_client.messages.create(
                    to=appt["caller_phone"], from_=loc["twilio_number"], body=message
                )
                updates["reminder_text_sent"] = True
            except Exception as e:
                log.error(f"Reminder text failed for appointment {appt['id']}: {e}")

        call_lead = loc.get("reminder_call_minutes_before", 15)
        if not appt.get("reminder_call_sent") and minutes_until <= call_lead:
            try:
                twilio_client.calls.create(
                    to=appt["caller_phone"],
                    from_=loc["twilio_number"],
                    url=f"{PUBLIC_BASE_URL}/twilio/reminder-twiml/{appt['id']}",
                    method="POST",
                )
                updates["reminder_call_sent"] = True
            except Exception as e:
                log.error(f"Reminder call failed for appointment {appt['id']}: {e}")

        if updates:
            sb.table("recall_appointments").update(updates).eq("id", appt["id"]).execute()
            sent += 1

    return {"checked": len(due.data), "reminders_sent": sent}


@app.post("/twilio/reminder-twiml/{appointment_id}")
async def reminder_twiml(appointment_id: str):
    """Twilio fetches this when a reminder call connects (including to voicemail —
    Twilio still plays <Say> content even if a machine picks up)."""
    vr = VoiceResponse()
    appt = (
        sb.table("recall_appointments")
        .select("*, recall_locations(recall_customers(business_name))")
        .eq("id", appointment_id)
        .execute()
    )
    if not appt.data:
        vr.say("Sorry, we couldn't find your appointment details.")
        return PlainTextResponse(str(vr), media_type="application/xml")

    row = appt.data[0]
    loc = row.get("recall_locations") or {}
    customer = loc.get("recall_customers") or {}
    local_time = business_local_time_str(row["appointment_start"])
    business_name = customer.get("business_name", "the business")
    vr.say(
        f"Hi, this is a reminder from {business_name}. "
        f"You have an appointment today at {local_time}. We look forward to seeing you. Goodbye."
    )
    return PlainTextResponse(str(vr), media_type="application/xml")


# ---------------------------------------------------------------------------
# NUMBER POOL — keeps a small standing supply of Twilio numbers bought and
# added to the A2P sender pool WELL BEFORE any customer needs them, since
# carrier registration propagation can take real hours-to-days. New signups
# AND new locations pull an already-warmed number instead of waiting on one.
# ---------------------------------------------------------------------------
NUMBER_POOL_TARGET_SIZE = int(os.environ.get("NUMBER_POOL_TARGET_SIZE", "3"))
NUMBER_POOL_MIN_WARM_HOURS = int(os.environ.get("NUMBER_POOL_MIN_WARM_HOURS", "24"))
POOL_JOB_SECRET = os.environ.get("POOL_JOB_SECRET")
if not POOL_JOB_SECRET:
    POOL_JOB_SECRET = secrets.token_hex(24)
    log.warning("POOL_JOB_SECRET not set — using a random per-restart value. Set it in Render.")


@app.post("/internal/refill-number-pool")
async def refill_number_pool(request: Request):
    if request.headers.get("x-job-secret") != POOL_JOB_SECRET:
        raise HTTPException(401, "Invalid job secret.")
    require_twilio()

    available = (
        sb.table("recall_number_pool").select("id", count="exact")
        .is_("assigned_to_customer_id", "null").execute()
    )
    current_size = available.count or 0
    to_buy = max(0, NUMBER_POOL_TARGET_SIZE - current_size)

    bought = []
    for _ in range(to_buy):
        try:
            numbers = twilio_client.available_phone_numbers("US").local.list(limit=1)
            if not numbers:
                break
            purchased = twilio_client.incoming_phone_numbers.create(
                phone_number=numbers[0].phone_number,
                voice_url=f"{PUBLIC_BASE_URL}/twilio/voice",
                voice_method="POST",
                status_callback=f"{PUBLIC_BASE_URL}/twilio/status",
                status_callback_method="POST",
                sms_url=f"{PUBLIC_BASE_URL}/twilio/sms",
                sms_method="POST",
            )
            try:
                twilio_client.messaging.v1.services(TWILIO_MESSAGING_SERVICE_SID).phone_numbers.create(
                    phone_number_sid=purchased.sid
                )
            except Exception as e:
                log.error(f"Couldn't add pooled number {purchased.phone_number} to A2P sender pool: {e}")

            sb.table("recall_number_pool").insert({
                "phone_number": purchased.phone_number,
                "twilio_sid": purchased.sid,
            }).execute()
            bought.append(purchased.phone_number)
        except Exception as e:
            log.error(f"Number pool refill failed on purchase: {e}")
            break

    return {"pool_size_before": current_size, "bought": bought, "target": NUMBER_POOL_TARGET_SIZE}


def get_warmed_number():
    """Returns an already-registered spare number from the pool if one has
    been sitting long enough to be fully propagated with carriers, else None."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=NUMBER_POOL_MIN_WARM_HOURS)).isoformat()
    result = (
        sb.table("recall_number_pool").select("*")
        .is_("assigned_to_customer_id", "null")
        .lte("added_to_sender_pool_at", cutoff)
        .order("added_to_sender_pool_at")
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


# ---------------------------------------------------------------------------
# AI VOICE AGENT (Pro/Elite tier) — pick a voice, upload a PDF knowledge
# base, and wire a LOCATION's Twilio number to an ElevenLabs Conversational
# AI agent. Everything here now reads/writes recall_locations, keyed off the
# account's primary location unless location_id is supplied.
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
def get_agent(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    if cust.data[0]["tier"] not in ("pro", "elite"):
        raise HTTPException(403, "This account needs the Pro or Elite tier for the AI voice agent.")
    loc = get_location_for_customer(customer_id, location_id)
    return {
        "location_id": loc["id"],
        "voice_id": loc.get("elevenlabs_voice_id"),
        "has_pdf": bool(loc.get("elevenlabs_kb_doc_id")),
        "agent_configured": bool(loc.get("elevenlabs_agent_id")),
        "fallback_behavior": loc.get("fallback_behavior", "message"),
    }


@app.post("/agent/{customer_id}/setup")
async def setup_agent(
    customer_id: str,
    voice_id: str = Form(...),
    fallback_behavior: str = Form("message"),  # "message" | "transfer" | "try_harder"
    location_id: str = Form(None),
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
    location = get_location_for_customer(customer_id, location_id)

    update = {"elevenlabs_voice_id": voice_id, "fallback_behavior": fallback_behavior}

    # 1. Upload the PDF as a knowledge base document, if one was provided.
    kb_doc_id = location.get("elevenlabs_kb_doc_id")
    if pdf is not None:
        files = {"file": (pdf.filename, await pdf.read(), pdf.content_type or "application/pdf")}
        resp = requests.post(
            f"{ELEVENLABS_BASE}/convai/knowledge-base/file",
            headers=el_headers(),
            files=files,
            data={"name": f"{customer['business_name']} — {location.get('location_label', 'info')}"},
            timeout=60,
        )
        if not resp.ok:
            raise HTTPException(502, f"Couldn't upload PDF to ElevenLabs: {resp.text[:300]}")
        kb_doc_id = resp.json().get("id")
        update["elevenlabs_kb_doc_id"] = kb_doc_id

    # 2. Create or update the ElevenLabs agent for this location.
    transfer_target = location.get("transfer_phone") or location.get("business_phone")
    fallback_instructions = {
        "message": "If you don't know the answer, politely ask for their name and phone number, then call take_message with those details so someone actually gets notified — don't just say you'll pass it along without calling the tool.",
        "transfer": "If you don't know the answer, offer to connect them to a person using your transfer ability.",
        "try_harder": "Check the knowledge base carefully before giving up — rephrase the question in your head and look again. Only if you're truly certain the answer isn't in the knowledge base, ask for their name and number, then call take_message with those details.",
    }
    system_prompt = (
        f"You are the phone receptionist for {customer['business_name']}. "
        "Be friendly, concise, and helpful. Answer questions using the knowledge base provided. "
        + fallback_instructions[fallback_behavior]
    )
    if transfer_target:
        system_prompt += (
            " If the caller explicitly asks to speak to a person, a manager, or customer service, "
            "or describes any kind of emergency or urgent situation, do exactly this, in order: "
            "(1) call notify_owner (set is_emergency to true only for genuine emergencies, with a "
            "one-sentence reason), (2) IMMEDIATELY call your transfer tool in that same turn to "
            "actually connect the call. Calling notify_owner is not the transfer — it only sends a "
            "text. You must still call the separate transfer tool right after. Never say phrases like "
            "'connecting you now', 'please hold', 'one moment', or 'you should be connected shortly' "
            "unless you have already called the transfer tool — if you catch yourself about to say "
            "any of those without having called it, call it first. Do not narrate a transfer that "
            "hasn't actually happened."
        )
    calendar_connected = customer.get("tier") == "elite" and location.get("google_calendar_connected")
    if calendar_connected:
        from zoneinfo import ZoneInfo
        today_str = datetime.now(ZoneInfo(BUSINESS_TZ)).strftime("%A, %B %d, %Y")
        system_prompt += (
            f" Today's actual date is {today_str}. Always use this as the reference point when the "
            "caller says things like 'tomorrow', 'next Monday', or 'this Friday' — calculate the real "
            "calendar date from it rather than guessing."
        )
        system_prompt += (
            " You can also book appointments. If the caller mentions a specific time (like '3pm'), "
            "always pass that exact time to check_availability so it checks that slot directly — "
            "never just call check_availability with only the date, since that only returns a few "
            "early options and can wrongly suggest a free time is taken. If the caller hasn't given a "
            "time yet, call check_availability with just the date to see general openings. Once you "
            "have a confirmed date and time, use book_appointment. Always get their name and callback "
            "phone number before booking. Only tell the caller an appointment is confirmed if the "
            "book_appointment tool actually returns success — never say it's booked if the tool failed "
            "or you didn't call it; if that happens, apologize and offer to take a message instead. "
            "If a time isn't available, never guess or invent a reason why (like 'it's booked by "
            "another customer') unless the tool's response actually told you that reason — if you don't "
            "know why, just say it's not available and offer the alternative times the tool gave you."
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

    # Tool URLs now key off location_id, not customer_id, since a call comes
    # in on a specific location's number.
    webhook_tools = []
    tool_secret_header = {"X-Tool-Secret": ELEVENLABS_TOOL_SECRET}
    if calendar_connected:
        webhook_tools.extend([
            {
                "type": "webhook",
                "name": "check_availability",
                "description": "Check whether a specific time is open on a given date. Always pass 'time' when the caller mentions a specific time (e.g. '3pm') so it checks that exact slot — don't omit it and just browse the morning.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/check-availability/{location['id']}",
                    "method": "POST",
                    "request_headers": tool_secret_header,
                    "request_body_schema": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string", "description": "Date to check, format YYYY-MM-DD"},
                            "time": {"type": "string", "description": "Optional. 24-hour time HH:MM. Include this whenever the caller mentioned a specific time — checks that exact slot instead of just listing morning openings."},
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
                    "url": f"{PUBLIC_BASE_URL}/tools/book-appointment/{location['id']}",
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
    webhook_tools.append({
        "type": "webhook",
        "name": "take_message",
        "description": "Log a callback request when you can't help the caller directly — always call this rather than just telling the caller you'll pass their info along.",
        "api_schema": {
            "url": f"{PUBLIC_BASE_URL}/tools/take-message/{location['id']}",
            "method": "POST",
            "request_headers": tool_secret_header,
            "request_body_schema": {
                "type": "object",
                "properties": {
                    "caller_name": {"type": "string", "description": "The caller's name, if given"},
                    "caller_phone": {"type": "string", "description": "The caller's callback phone number"},
                    "note": {"type": "string", "description": "One short sentence on what they need"},
                },
                "required": ["caller_phone"],
            },
        },
    })
    if transfer_target:
        webhook_tools.append({
            "type": "webhook",
            "name": "notify_owner",
            "description": "Send a text heads-up to the business before transferring a call to them — call this right before connecting the caller, always.",
            "api_schema": {
                "url": f"{PUBLIC_BASE_URL}/tools/notify-owner/{location['id']}",
                "method": "POST",
                "request_headers": tool_secret_header,
                "request_body_schema": {
                    "type": "object",
                    "properties": {
                        "is_emergency": {"type": "boolean", "description": "True only for a genuine emergency or urgent situation."},
                        "reason": {"type": "string", "description": "One short sentence on why the caller wants to be connected."},
                    },
                    "required": ["is_emergency"],
                },
            },
        })
    if webhook_tools:
        conversation_config["agent"]["prompt"]["tools"] = webhook_tools

    # NOTE: transfer_to_number is intentionally NOT set here. ElevenLabs'
    # agent PATCH endpoint accepts a built_in_tools field without error but
    # doesn't actually apply it — confirmed by testing: sending it here wipes
    # out a transfer tool that was correctly configured manually in the
    # ElevenLabs UI, without the API version ever showing as active either.
    # So: configure "Transfer to number" once, by hand, in the ElevenLabs UI
    # (Tools tab → System tools → Transfer to number), and never send it from
    # here — every previous attempt to manage this via API silently broke it.

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
                json={"name": f"{customer['business_name']} — {location.get('location_label', '')}".strip(" —"),
                      "conversation_config": conversation_config},
                timeout=30,
            )
        return r

    agent_id = location.get("elevenlabs_agent_id")
    resp = save_agent(agent_id)
    if not resp.ok:
        raise HTTPException(502, f"Couldn't save ElevenLabs agent: {resp.text[:300]}")
    if not agent_id:
        agent_id = resp.json().get("agent_id")
        update["elevenlabs_agent_id"] = agent_id

    # 3. Import the location's Twilio number into ElevenLabs (first time
    # only) and assign the agent.
    phone_id = location.get("elevenlabs_phone_id")
    if not phone_id:
        resp = requests.post(
            f"{ELEVENLABS_BASE}/convai/phone-numbers",
            headers={**el_headers(), "Content-Type": "application/json"},
            json={
                "provider": "twilio",
                "phone_number": location["twilio_number"],
                "label": f"{customer['business_name']} — {location.get('location_label', '')}".strip(" —"),
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

    # Re-apply our own status callback on the Twilio number itself — ElevenLabs'
    # import may have overwritten it. This is what lets send_missed_call_text
    # fire as a safety net even when ElevenLabs owns the voice webhook.
    try:
        numbers = twilio_client.incoming_phone_numbers.list(phone_number=location["twilio_number"], limit=1)
        if numbers:
            numbers[0].update(
                status_callback=f"{PUBLIC_BASE_URL}/twilio/status",
                status_callback_method="POST",
            )
    except Exception as e:
        log.error(f"Couldn't re-apply status callback for {location['twilio_number']}: {e}")

    sb.table(TABLE_LOC).update(update).eq("id", location["id"]).execute()
    return {"ok": True, "location_id": location["id"], "agent_id": agent_id, "voice_id": voice_id, "has_pdf": bool(kb_doc_id)}


# ---------------------------------------------------------------------------
# GOOGLE OAUTH (Elite tier) — Calendar booking + Business Profile sync.
# One OAuth app registered under Recall's own Google Cloud project; each
# customer authorizes their own Google account via the real Google consent
# screen. We never see or store their Google password — only a refresh token
# scoped to whichever single permission (calendar or business) they granted.
# Tokens are stored per-LOCATION now, since a multi-location Elite account
# may connect a different Calendar/listing for each site.
# ---------------------------------------------------------------------------
def require_google():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(503, "Google integration isn't configured yet — add GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET.")


def require_elite(customer: dict):
    if customer.get("tier") != "elite":
        raise HTTPException(403, "This account isn't on the Elite tier.")


@app.get("/google/auth-url")
def google_auth_url(customer_id: str, service: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    require_google()
    if service not in GOOGLE_SCOPES:
        raise HTTPException(400, "service must be 'calendar' or 'business'.")

    cust = sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    require_elite(cust.data[0])
    location = get_location_for_customer(customer_id, location_id)

    # Short-lived signed state — carries which location/service this is for
    # through Google's redirect, since Google can't send our auth header back.
    state = jwt.encode(
        {
            "customer_id": customer_id,
            "location_id": location["id"],
            "service": service,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
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
    location_id = payload["location_id"]
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
        sb.table(TABLE_LOC).update({col: refresh_token, flag: True}).eq("id", location_id).execute()

    from fastapi.responses import RedirectResponse
    return RedirectResponse(
        f"{FRONTEND_BASE_URL}/elite-setup.html?customer_id={customer_id}&location_id={location_id}&connected={service}"
    )


@app.get("/elite/{customer_id}")
def get_elite_status(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    require_elite(cust.data[0])
    loc = get_location_for_customer(customer_id, location_id)
    return {
        "location_id": loc["id"],
        "calendar_connected": loc.get("google_calendar_connected", False),
        "business_connected": loc.get("google_business_connected", False),
        "booking_hours_start": loc.get("booking_hours_start", DEFAULT_BUSINESS_HOURS[0]),
        "booking_hours_end": loc.get("booking_hours_end", DEFAULT_BUSINESS_HOURS[1]),
    }


@app.post("/elite/{customer_id}/hours")
async def update_booking_hours(
    customer_id: str,
    hours_start: int = Form(...),
    hours_end: int = Form(...),
    location_id: str = Form(None),
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    if not (0 <= hours_start < hours_end <= 24):
        raise HTTPException(400, "Hours must be 0-24, and start must be before end.")
    cust = sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    require_elite(cust.data[0])
    loc = get_location_for_customer(customer_id, location_id)
    sb.table(TABLE_LOC).update(
        {"booking_hours_start": hours_start, "booking_hours_end": hours_end}
    ).eq("id", loc["id"]).execute()
    return {"ok": True, "location_id": loc["id"], "booking_hours_start": hours_start, "booking_hours_end": hours_end}


# ---------------------------------------------------------------------------
# CALENDAR TOOL ENDPOINTS — called live, mid-call, by the ElevenLabs agent
# (not by the browser). Protected by a shared secret header instead of the
# customer's login token, since ElevenLabs' servers are the caller here.
# Now keyed by location_id (a call comes in on a specific location's
# number), not customer_id.
# ---------------------------------------------------------------------------
BUSINESS_TZ = "America/New_York"
DEFAULT_BUSINESS_HOURS = (9, 17)  # 9am–5pm
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


def get_calendar_location(location_id: str) -> dict:
    loc = sb.table(TABLE_LOC).select("*, recall_customers(business_name)").eq("id", location_id).execute()
    if not loc.data:
        raise HTTPException(404, "Location not found")
    row = loc.data[0]
    customer = row.pop("recall_customers", None) or {}
    merged = {**customer, **row}
    if not merged.get("google_calendar_refresh_token"):
        raise HTTPException(400, "Google Calendar isn't connected for this location.")
    return merged


@app.post("/tools/check-availability/{location_id}")
async def tool_check_availability(location_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"check-availability request body: {body}")
    date_str = body.get("date") or body.get("parameters", {}).get("date")
    time_str = body.get("time") or body.get("parameters", {}).get("time")  # optional, "HH:MM"
    if not date_str:
        return {"result": "I need a specific date (YYYY-MM-DD) to check availability."}

    try:
        location = get_calendar_location(location_id)
        hours_start = location.get("booking_hours_start", DEFAULT_BUSINESS_HOURS[0])
        hours_end = location.get("booking_hours_end", DEFAULT_BUSINESS_HOURS[1])
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(BUSINESS_TZ)
        day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=tz)
        day_start = day.replace(hour=hours_start, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(hours=(hours_end - hours_start))  # handles hours_end=24 (midnight) safely

        access_token = google_access_token(location["google_calendar_refresh_token"])
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
            log.error(f"Google freeBusy failed for location {location_id}: {resp.status_code} {resp.text[:400]}")
            return {"result": "I couldn't check the calendar right now — please offer to take a message instead."}

        busy = resp.json().get("calendars", {}).get("primary", {}).get("busy", [])
        busy_ranges = [(datetime.fromisoformat(b["start"]), datetime.fromisoformat(b["end"])) for b in busy]

        def is_free(slot_start):
            slot_end = slot_start + timedelta(minutes=SLOT_MINUTES)
            return not any(slot_start < be and slot_end > bs for bs, be in busy_ranges)

        # Build the full list of business-hours slots once, in order.
        all_slots = []
        slot = day_start
        while slot + timedelta(minutes=SLOT_MINUTES) <= day_end:
            all_slots.append(slot)
            slot += timedelta(minutes=SLOT_MINUTES)

        if time_str:
            # Caller asked about a SPECIFIC time — check that exact slot first,
            # rather than only ever looking at the start of the day.
            try:
                requested = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
            except ValueError:
                return {"result": "That time didn't look right — please use 24-hour HH:MM format."}
            if requested in all_slots and is_free(requested):
                result = f"Yes, {requested.strftime('%-I:%M %p')} on {date_str} is available."
            else:
                free = [s for s in all_slots if is_free(s)]
                nearby = sorted(free, key=lambda s: abs((s - requested).total_seconds()))[:5]
                nearby.sort()  # present them in chronological order once selected
                if nearby:
                    times_str = ", ".join(s.strftime("%-I:%M %p") for s in nearby)
                    result = f"{time_str} on {date_str} isn't available. Closest open times: {times_str}"
                else:
                    result = f"There's nothing open on {date_str} during business hours — offer another date."
        else:
            free_slots = [s.strftime("%-I:%M %p") for s in all_slots if is_free(s)][:5]
            if not free_slots:
                result = f"There's nothing open on {date_str} during business hours — offer another date."
            else:
                result = f"Available times on {date_str}: " + ", ".join(free_slots)
        log.info(f"check-availability result: {result}")
        return {"result": result}
    except ValueError:
        return {"result": "That date didn't look right — please use YYYY-MM-DD format."}
    except Exception:
        log.exception(f"check-availability crashed for location {location_id}")
        return {"result": "I couldn't check the calendar right now — please offer to take a message instead."}


@app.post("/tools/book-appointment/{location_id}")
async def tool_book_appointment(location_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"book-appointment request body: {body}")
    p = body if "date" in body else body.get("parameters", {})
    date_str, time_str = p.get("date"), p.get("time")
    caller_name, caller_phone = p.get("caller_name"), p.get("caller_phone")
    if not all([date_str, time_str, caller_name, caller_phone]):
        return {"result": "I'm missing some details — I need the date, time, the caller's name, and their phone number."}

    try:
        location = get_calendar_location(location_id)
        hours_start = location.get("booking_hours_start", DEFAULT_BUSINESS_HOURS[0])
        hours_end = location.get("booking_hours_end", DEFAULT_BUSINESS_HOURS[1])
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(BUSINESS_TZ)
        start = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
        end = start + timedelta(minutes=SLOT_MINUTES)
        day_start = start.replace(hour=hours_start, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(hours=(hours_end - hours_start))  # handles hours_end=24 (midnight) safely
        if not (day_start <= start and end <= day_end):
            return {"result": f"That time is outside booking hours ({hours_start}:00–{hours_end}:00) — offer a time within that window."}

        access_token = google_access_token(location["google_calendar_refresh_token"])
        resp = requests.post(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={
                "summary": f"{caller_name} — {location['business_name']} appointment",
                "description": f"Booked by Recall AI. Caller phone: {caller_phone}",
                "start": {"dateTime": start.isoformat()},
                "end": {"dateTime": end.isoformat()},
            },
            timeout=20,
        )
        if not resp.ok:
            log.error(f"Google event creation failed for location {location_id}: {resp.status_code} {resp.text[:400]}")
            return {"result": "I couldn't book that — please offer to take a message instead."}
        log.info(f"book-appointment success, event id: {resp.json().get('id')}")

        try:
            sb.table("recall_appointments").insert({
                "location_id": location_id,
                "caller_name": caller_name,
                "caller_phone": caller_phone,
                "appointment_start": start.isoformat(),
            }).execute()
        except Exception as e:
            # Booking itself already succeeded on the real calendar — don't
            # fail the whole tool call just because the reminder record failed.
            log.error(f"Couldn't save appointment record for reminders (location {location_id}): {e}")

        return {"result": f"Booked for {caller_name} on {date_str} at {time_str}. Confirmed."}
    except ValueError:
        return {"result": "That date or time didn't look right — date as YYYY-MM-DD, time as HH:MM."}
    except Exception:
        log.exception(f"book-appointment crashed for location {location_id}")
        return {"result": "I couldn't book that — please offer to take a message instead."}


@app.post("/tools/notify-owner/{location_id}")
async def tool_notify_owner(location_id: str, request: Request):
    """Called by the AI right before it transfers a call, so the owner gets a
    text heads-up even if they don't pick up the actual transferred call —
    a live warm-transfer message only reaches them if they answer; this
    doesn't depend on that."""
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    p = body if "is_emergency" in body or "reason" in body else body.get("parameters", {})
    is_emergency = bool(p.get("is_emergency"))
    reason = (p.get("reason") or "").strip()

    loc = sb.table(TABLE_LOC).select("*, recall_customers(business_name)").eq("id", location_id).execute()
    if not loc.data:
        return {"result": "Couldn't send the notification — proceed with the transfer anyway."}
    row = loc.data[0]
    customer = row.pop("recall_customers", None) or {}
    location = {**customer, **row}
    target = location.get("transfer_phone") or location.get("business_phone")
    if not target:
        return {"result": "No transfer contact number is configured — proceed with the transfer anyway."}

    business_name = location.get("business_name", "the business")
    if is_emergency:
        message = f"🚨 URGENT call for {business_name} being connected to you now"
    else:
        message = f"Heads up: a caller is being connected to you now for {business_name}"
    if reason:
        message += f" — {reason}."
    else:
        message += "."

    try:
        twilio_client.messages.create(to=target, from_=location["twilio_number"], body=message)
        return {"result": "Notified. Proceed with the transfer."}
    except Exception as e:
        log.error(f"notify-owner SMS failed for location {location_id}: {e}")
        return {"result": "Notification failed to send — proceed with the transfer anyway."}


@app.post("/tools/take-message/{location_id}")
async def tool_take_message(location_id: str, request: Request):
    """Called when the AI can't help and needs to take a callback message.
    Stores it AND texts the owner immediately — previously the AI would only
    say 'I'll pass this along' with nothing actually behind that promise."""
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    p = body if "caller_phone" in body else body.get("parameters", {})
    caller_name = (p.get("caller_name") or "").strip()
    caller_phone = (p.get("caller_phone") or "").strip()
    note = (p.get("note") or "").strip()
    if not caller_phone:
        return {"result": "I need a callback phone number before I can log this."}

    loc = sb.table(TABLE_LOC).select("*, recall_customers(business_name)").eq("id", location_id).execute()
    if not loc.data:
        return {"result": "Couldn't save that message — apologize and let them know someone will follow up."}
    row = loc.data[0]
    customer = row.pop("recall_customers", None) or {}
    location = {**customer, **row}

    try:
        sb.table("recall_messages").insert({
            "customer_id": location["customer_id"],
            "caller_name": caller_name or None,
            "caller_phone": caller_phone,
            "note": note or None,
        }).execute()
    except Exception as e:
        log.error(f"take-message save failed for location {location_id}: {e}")
        return {"result": "Couldn't save that message — apologize and let them know someone will follow up."}

    target = location.get("transfer_phone") or location.get("business_phone")
    if target:
        sms = f"📋 Callback request for {location.get('business_name', 'your business')}: {caller_name or 'no name given'}, {caller_phone}"
        if note:
            sms += f" — {note}"
        try:
            twilio_client.messages.create(to=target, from_=location["twilio_number"], body=sms)
        except Exception as e:
            log.error(f"take-message owner SMS failed for location {location_id}: {e}")

    return {"result": "Logged. Let the caller know someone will follow up soon."}


# ---------------------------------------------------------------------------
# NUMBER SETUP OPTIONS — a customer can either forward their existing number
# to the AI's Twilio number (instant, self-serve) or request a full port-in
# (their real number moves into Twilio — takes days to weeks, can be
# rejected, requires carrier account details). Per-location now.
# ---------------------------------------------------------------------------

FORWARDING_CARRIERS = {
    "verizon": {"label": "Verizon", "activate_fmt": "*72{n}", "deactivate": "*73", "note": "Dial *72 followed by the 10-digit number, then Call. Wait for the confirmation tone."},
    "att": {"label": "AT&T", "activate_fmt": "*21*{n}#", "deactivate": "##21#", "note": "Dial *21* followed by the 10-digit number, then #, then Call."},
    "tmobile": {"label": "T-Mobile", "activate_fmt": "*21*{n}#", "deactivate": "##21#", "note": "Dial *21* followed by the 10-digit number, then #, then Call."},
    "spectrum": {"label": "Spectrum Business", "activate_fmt": "*72{n}", "deactivate": "*73", "note": "Dial *72 followed by the 10-digit number, then Call. You can also manage this from your Spectrum Business online account."},
    "optimum": {"label": "Optimum", "activate_fmt": "*72{n}", "deactivate": "*73", "note": "Dial *72 followed by the 10-digit number, then Call. You can also manage this from your Optimum online account."},
    "other": {"label": "Other / not sure", "activate_fmt": "*72{n}", "deactivate": "*73", "note": "*72 to forward and *73 to cancel works on most US carriers. If it doesn't work on yours, ask your carrier for their 'call forwarding' or 'call diversion' feature."},
}


@app.get("/setup/forwarding-instructions/{customer_id}")
def forwarding_instructions(customer_id: str, carrier: str = "other", location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    loc = get_location_for_customer(customer_id, location_id)
    info = FORWARDING_CARRIERS.get(carrier, FORWARDING_CARRIERS["other"])
    ai_number = loc["twilio_number"]
    ten_digit = ai_number[2:] if ai_number.startswith("+1") else ai_number
    return {
        "location_id": loc["id"],
        "carrier": info["label"],
        "ai_number": ai_number,
        "activate_code": info["activate_fmt"].format(n=ten_digit),
        "deactivate_code": info["deactivate"],
        "instructions": info["note"],
        "caveat": "This only forwards calls, not texts — your AI number handles texts either way. Some very basic landline plans need a small add-on from the carrier to enable forwarding at all.",
        "current_transfer_phone": loc.get("transfer_phone") or loc.get("business_phone"),
    }


def normalize_us_phone(raw: str) -> str:
    """Best-effort E.164 normalization for a US number typed in any common format."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    raise HTTPException(400, "That doesn't look like a valid 10-digit US phone number.")


@app.post("/setup/transfer-phone/{customer_id}")
async def set_transfer_phone(customer_id: str, request: Request, authorization: str = Header(None)):
    """The number a customer is forwarding to their AI line — used for live
    call transfers and emergency/callback SMS. Deliberately separate from
    business_phone (which is just the signup contact) since a customer may
    forward a completely different line than the one they signed up with.
    Per-location; pass location_id in the JSON body for a multi-location
    account, else it applies to the primary location."""
    require_auth(customer_id, authorization)
    body = await request.json()
    raw = (body.get("transfer_phone") or "").strip()
    if not raw:
        raise HTTPException(400, "Missing transfer_phone.")
    e164 = normalize_us_phone(raw)
    loc = get_location_for_customer(customer_id, body.get("location_id"))
    sb.table(TABLE_LOC).update({"transfer_phone": e164}).eq("id", loc["id"]).execute()
    return {
        "location_id": loc["id"],
        "transfer_phone": e164,
        "note": (
            "If your AI voice agent is already set up, re-save it on the AI voice agent "
            "setup page so live transfers use this number."
        ),
    }


@app.post("/porting/request/{customer_id}")
async def request_port_in(customer_id: str, request: Request, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    body = await request.json()
    required = ["number_to_port", "authorized_name", "service_address_line1",
                "service_address_city", "service_address_state", "service_address_zip", "losing_carrier"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        raise HTTPException(400, f"Missing required fields: {', '.join(missing)}")

    row = {f: body[f] for f in required}
    row["customer_id"] = customer_id
    row["account_number"] = body.get("account_number")
    row["account_pin"] = body.get("account_pin")
    sb.table("recall_port_requests").insert(row).execute()

    return {
        "status": "submitted_by_customer",
        "message": (
            "Your port-in request has been submitted for review. Porting a phone number "
            "typically takes anywhere from a few days to about 4 weeks, and your current "
            "carrier can reject the request if any details don't match their records exactly "
            "— we'll follow up either way. Your existing number keeps working normally the "
            "entire time; nothing changes until the port actually completes."
        ),
    }


@app.get("/porting/requests")
def list_port_requests(authorization: str = Header(None)):
    """Internal review list — Saleh checks this before manually submitting
    qualifying requests through Twilio's porting console."""
    require_admin(authorization)
    rows = sb.table("recall_port_requests").select("*, recall_customers(business_name)").order("created_at", desc=True).execute()
    return rows.data
