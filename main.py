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
from fastapi import FastAPI, Request, Form, HTTPException, Header, UploadFile, File, BackgroundTasks
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
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
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "https://callskept.com")
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

app = FastAPI(title="CallsKept - Missed Call Recovery")
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


# ---------------------------------------------------------------------------
# CRM CORE — every caller/texter becomes one recall_contacts row with a
# timeline in recall_contact_activities. The heavy lifting (E.164 normalize,
# upsert on (customer_id, phone), dedupe by source_ref, never-backward status
# rules, STOP/START handling, status_change logging) lives in the Postgres
# function recall_crm_log_event so it's atomic and shared with the backfill.
#
# RULE: every text to a CUSTOMER (not the owner) goes through
# send_customer_sms() — that's the single opt-out guard. Future follow-up /
# quote-recovery features must use it too.
# ---------------------------------------------------------------------------
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
OPT_OUT_WORDS = {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}
OPT_IN_WORDS = {"START", "UNSTOP"}


def sms_keyword(body: str) -> str:
    return re.sub(r"[^A-Za-z]", "", body or "").upper()


def normalize_e164(raw: str) -> str:
    """Mirrors the SQL recall_normalize_phone(). Returns None if unusable."""
    raw = (raw or "").strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10:
        return None
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    if raw.startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    return None


def upsert_contact_and_log(customer_id, phone, activity_type, body=None, metadata=None,
                           source=None, location_id=None, name=None, source_ref=None,
                           created_at=None):
    """Find-or-create the contact, add a timeline entry, apply status rules.
    Returns contact_id, or None. Never raises — CRM logging must not break
    call/SMS handling."""
    if not customer_id or not phone:
        return None
    try:
        r = sb.rpc("recall_crm_log_event", {
            "p_customer_id": customer_id,
            "p_phone": phone,
            "p_type": activity_type,
            "p_body": body,
            "p_metadata": metadata or {},
            "p_source": source,
            "p_location_id": location_id,
            "p_name": name,
            "p_source_ref": source_ref,
            "p_created_at": created_at,
        }).execute()
        return r.data
    except Exception as e:
        log.error(f"CRM log failed ({activity_type}, customer {customer_id}): {e}")
        return None


def send_customer_sms(customer_id: str, to: str, from_: str, body: str,
                      location_id: str = None, kind: str = "manual", name: str = None):
    """The ONE outbound path for texts to a customer's contacts. Checks the
    opt-out guard first (blocked sends are logged on the contact's timeline),
    then sends via Twilio and logs an sms_out activity.
    Returns the Twilio message SID, or None if blocked.
    Raises on Twilio errors so callers keep their existing error handling."""
    try:
        allowed = sb.rpc("recall_crm_can_text", {
            "p_customer_id": customer_id, "p_phone": to, "p_body": body, "p_reason": kind,
        }).execute().data
    except Exception as e:
        # Fail closed: texting someone who opted out is a carrier/TCPA problem.
        log.error(f"Opt-out check failed for customer {customer_id} — not sending: {e}")
        raise RuntimeError("opt-out check unavailable")
    if allowed is False:
        log.info(f"Blocked {kind} text to opted-out contact (customer {customer_id})")
        return None

    sms = twilio_client.messages.create(to=to, from_=from_, body=body)
    upsert_contact_and_log(customer_id, to, "sms_out", body=body,
                           metadata={"kind": kind, "twilio_sid": sms.sid},
                           location_id=location_id, name=name, source_ref=f"tw:{sms.sid}")
    return sms.sid


# ---------------------------------------------------------------------------
# CALLER MEMORY — each contact (one phone number) has a short profile the AI
# reads at the start of a call/text and updates as it learns things ("John,
# 2018 Camry, Oct 5 four tires $450"). Identity = the caller's phone number
# from the carrier, never a spoken name, so two "Johns" can't be mixed up.
# The profile is rewritten by Claude to stay short; if that fails, the new
# fact is appended so nothing is lost.
# ---------------------------------------------------------------------------
MEMORY_MAX_CHARS = 1200
MEMORY_TYPE_LABEL = {
    "missed_call": "Missed call", "sms_in": "They texted", "sms_out": "We texted",
    "ai_call": "AI call", "note": "Note", "booking": "Booked", "call_out": "We called",
}
MEMORY_PROMPT = (
    " CALLER MEMORY: you can remember returning customers. Right after the caller's first reply, "
    "call lookup_caller (it already knows their phone number) before answering anything else. If it "
    "returns a record, greet them by name and naturally bring up their last visit or open item — for "
    "example 'Good to hear from you again, John — how are the new tires holding up?'. If the record "
    "lists more than one person, or the caller gives a different name than the one on file, ask who "
    "you're speaking with and do not share anything from the record until the name matches. Never "
    "read the record out word for word and never mention files, notes, or records. Whenever the caller "
    "tells you something worth remembering for next time — their name, their vehicle or equipment, "
    "what service they need or had done, preferences, other people in their household — call "
    "remember_caller with a short factual note. Never save health or medical details, payment card "
    "numbers, or ID numbers."
)


def memory_tools(location_id: str, headers: dict) -> list:
    """The two ElevenLabs webhook tools that give the voice agent per-caller memory."""
    caller = {"type": "string", "value_type": "dynamic_variable",
              "dynamic_variable": "system__caller_id", "description": ""}
    return [
        {
            "type": "webhook", "name": "lookup_caller",
            "description": "Look up what we know about this caller (name, past visits, open items, upcoming appointments). Call it right after the caller's first reply.",
            "api_schema": {
                "url": f"{PUBLIC_BASE_URL}/tools/lookup-caller/{location_id}",
                "method": "POST", "request_headers": headers,
                "request_body_schema": {"type": "object", "properties": {"caller_phone": caller},
                                        "required": ["caller_phone"]},
            },
        },
        {
            "type": "webhook", "name": "remember_caller",
            "description": "Save something worth remembering about this caller for next time (name, vehicle/equipment, service needed or done, preferences, household members). Not health details, card numbers, or ID numbers.",
            "api_schema": {
                "url": f"{PUBLIC_BASE_URL}/tools/remember-caller/{location_id}",
                "method": "POST", "request_headers": headers,
                "request_body_schema": {
                    "type": "object",
                    "properties": {
                        "caller_phone": caller,
                        "caller_name": {"type": "string", "value_type": "llm_prompt",
                                        "description": "The caller's name, if known"},
                        "details": {"type": "string", "value_type": "llm_prompt",
                                    "description": "One or two short factual sentences to remember, e.g. 'Drives a 2018 Toyota Camry. Needs four new tires today.'"},
                    },
                    "required": ["caller_phone", "details"],
                },
            },
        },
    ]


def _contact_for_phone(customer_id: str, phone: str) -> dict:
    p = normalize_e164(phone or "")
    if not p:
        return None
    r = (sb.table("recall_contacts").select("*")
         .eq("customer_id", customer_id).eq("phone", p).limit(1).execute())
    return r.data[0] if r.data else None


def caller_context(customer_id: str, phone: str) -> str:
    """Plain-text briefing the AI reads about this caller. Never raises."""
    try:
        c = _contact_for_phone(customer_id, phone)
        if not c:
            return "New caller — there is no record for this phone number yet. Get their name when it comes up naturally."
        if c.get("opted_out") or c.get("status") == "do_not_contact":
            dnc = " They asked not to be contacted by text — don't offer to text them."
        else:
            dnc = ""
        lines = [f"Returning caller. Name on file: {c.get('name') or 'unknown'}.{dnc}"]
        if c.get("memory"):
            lines.append("What we know about them:\n" + c["memory"].strip())
        acts = (sb.table("recall_contact_activities").select("type, body, created_at")
                .eq("contact_id", c["id"]).neq("type", "status_change")
                .order("created_at", desc=True).limit(6).execute()).data
        if acts:
            lines.append("Recent history (newest first):")
            for a in acts:
                when = (a.get("created_at") or "")[:10]
                body = (a.get("body") or "").replace("\n", " ").strip()[:140]
                lines.append(f"- {when} {MEMORY_TYPE_LABEL.get(a['type'], a['type'])}" + (f": {body}" if body else ""))
        now_iso = datetime.now(timezone.utc).isoformat()
        appts = (sb.table("recall_appointments").select("appointment_start, caller_phone")
                 .eq("customer_id", customer_id).eq("canceled", False)
                 .gt("appointment_start", now_iso).order("appointment_start").limit(10).execute()).data
        mine = [a for a in appts if normalize_e164(a.get("caller_phone") or "") == c["phone"]]
        if mine:
            lines.append("Upcoming appointment: " + business_local_time_str(mine[0]["appointment_start"])
                         + " on " + mine[0]["appointment_start"][:10] + ".")
        return "\n".join(lines)[:2500]
    except Exception as e:
        log.error(f"caller_context failed: {e}")
        return "No record available right now — treat them as a new caller."


def _merge_memory(business: str, current: str, new_info: str, source: str) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    fallback = ((current or "").strip() + f"\n- {today}: {new_info.strip()}").strip()[-MEMORY_MAX_CHARS:]
    if not ANTHROPIC_API_KEY:
        return fallback
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                     "Content-Type": "application/json"},
            json={
                "model": ANTHROPIC_MODEL, "max_tokens": 500,
                "system": (
                    f"You keep a short customer profile for {business}, used by its phone receptionist to "
                    "remember returning customers. Rewrite the profile to include the new information. "
                    "Rules: plain lines starting with '- '; at most 12 lines and 900 characters; stable facts "
                    "first (name, household members, vehicle/equipment, preferences), then visits and open "
                    "items with dates (YYYY-MM-DD), newest first; drop chit-chat and anything no longer true; "
                    "never include health or medical details, payment card numbers, account numbers, ID numbers "
                    "or passwords. Output only the profile."
                ),
                "messages": [{"role": "user", "content":
                              f"Current profile:\n{(current or '(empty)').strip()}\n\n"
                              f"New information ({source}, {today}):\n{new_info.strip()}"}],
            },
            timeout=25,
        )
        resp.raise_for_status()
        text = "".join(b.get("text", "") for b in resp.json().get("content", []) if b.get("type") == "text").strip()
        return text[:MEMORY_MAX_CHARS] if text else fallback
    except Exception as e:
        log.error(f"Memory merge failed, appending instead: {e}")
        return fallback


def update_contact_memory(customer_id: str, phone: str = None, new_info: str = "", source: str = "call",
                          name: str = None, contact_id: str = None, location_id: str = None):
    """Folds new_info into the contact's memory. Creates the contact if this
    phone has never been seen. Safe to run in a background task; never raises."""
    try:
        new_info = (new_info or "").strip()[:1000]
        if not new_info:
            return
        if contact_id:
            r = sb.table("recall_contacts").select("*").eq("id", contact_id).eq("customer_id", customer_id).execute()
            c = r.data[0] if r.data else None
        else:
            c = _contact_for_phone(customer_id, phone)
            if not c and phone:
                cid = upsert_contact_and_log(customer_id, phone, "note", body=f"AI noted: {new_info}",
                                             metadata={"by": "ai"}, source="ai_call",
                                             location_id=location_id, name=name)
                c = _contact_for_phone(customer_id, phone) if cid else None
        if not c:
            return
        biz = (sb.table(TABLE_CUST).select("business_name").eq("id", customer_id).execute().data or [{}])[0].get("business_name") or "the business"
        merged = _merge_memory(biz, c.get("memory") or "", new_info, source)
        upd = {"memory": merged, "memory_updated_at": datetime.now(timezone.utc).isoformat()}
        if name and not c.get("name"):
            upd["name"] = name.strip()[:120]
        sb.table("recall_contacts").update(upd).eq("id", c["id"]).execute()
    except Exception as e:
        log.error(f"update_contact_memory failed for customer {customer_id}: {e}")


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


@app.post("/locations/{location_id}/update")
def update_location(
    location_id: str,
    customer_id: str = Form(...),
    location_label: str = Form(...),
    business_phone: str = Form(...),
    authorization: str = Header(None),
):
    """Renames a location and/or updates the business phone it forwards
    from. Lets the location-setup page be one continuous flow — the same
    place you create a location is the same place you can fix its name or
    forwarding number later, no separate admin screen needed."""
    require_auth(customer_id, authorization)
    loc = sb.table(TABLE_LOC).select("id, customer_id").eq("id", location_id).execute()
    if not loc.data or loc.data[0]["customer_id"] != customer_id:
        raise HTTPException(404, "Location not found for this account.")
    location_label = location_label.strip()
    if not location_label:
        raise HTTPException(400, "Location name can't be empty.")
    sb.table(TABLE_LOC).update({
        "location_label": location_label,
        "business_phone": business_phone,
    }).eq("id", location_id).execute()
    return {"ok": True, "location_id": location_id, "location_label": location_label, "business_phone": business_phone}


@app.post("/locations/{location_id}/delete")
def delete_location(location_id: str, customer_id: str = Form(...), permanent: bool = Form(True), authorization: str = Header(None)):
    """Removes a location. Two modes:
    - permanent=True (default): releases the Twilio number and deletes the
      ElevenLabs agent too — irreversible, matches manually deleting them
      in those consoles.
    - permanent=False: only removes the location from Recall. The Twilio
      number and ElevenLabs agent are left exactly as they are, so the same
      number can be reattached to a new location later without buying a
      fresh one — useful while testing.
    Either way, refuses to delete an account's LAST location — that's not
    "delete a location," that's "reset the whole account.\""""
    require_auth(customer_id, authorization)

    loc = sb.table(TABLE_LOC).select("*").eq("id", location_id).execute()
    if not loc.data or loc.data[0]["customer_id"] != customer_id:
        raise HTTPException(404, "Location not found for this account.")
    location = loc.data[0]

    all_locs = sb.table(TABLE_LOC).select("id").eq("customer_id", customer_id).execute()
    if len(all_locs.data) <= 1:
        raise HTTPException(
            400,
            "Can't delete your only location — that would leave the account with no number at "
            "all. Add another location first if you want to replace this one."
        )

    twilio_number = location.get("twilio_number")
    agent_id = location.get("elevenlabs_agent_id")

    if permanent:
        if twilio_number and twilio_client is not None:
            try:
                matches = twilio_client.incoming_phone_numbers.list(phone_number=twilio_number, limit=1)
                if matches:
                    matches[0].delete()
            except Exception as e:
                log.error(f"Couldn't release {twilio_number} from Twilio while deleting location {location_id}: {e}")

        if agent_id and ELEVENLABS_API_KEY:
            try:
                requests.delete(f"{ELEVENLABS_BASE}/convai/agents/{agent_id}", headers=el_headers(), timeout=20)
            except Exception as e:
                log.error(f"Couldn't delete ElevenLabs agent {agent_id} while deleting location {location_id}: {e}")

    sb.table(TABLE_LOC).delete().eq("id", location_id).execute()
    return {
        "ok": True,
        "deleted_location_id": location_id,
        "permanent": permanent,
        "released_number": twilio_number if permanent else None,
        "kept_number": None if permanent else twilio_number,
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
        "customer_id": location["customer_id"],  # NOT NULL — was missing, so every insert failed
        "location_id": location["location_id"],
        "caller_number": caller,
        "call_sid": call_sid,
        "sms_body": message,
    }

    upsert_contact_and_log(
        location["customer_id"], caller, "missed_call",
        metadata={"call_sid": call_sid, "to_number": to_number},
        source="missed_call", location_id=location["location_id"],
        source_ref=f"call:{call_sid}" if call_sid else None,
    )

    try:
        sid = send_customer_sms(location["customer_id"], caller, to_number, message,
                                location_id=location["location_id"], kind="missed_call_text")
        call_row["sms_sent"] = bool(sid)
        call_row["sms_sid"] = sid
        if not sid:
            call_row["sms_error"] = "skipped: contact opted out"
    except Exception as e:
        log.error(f"SMS send failed for {caller}: {e}")
        call_row["sms_sent"] = False
        call_row["sms_error"] = str(e)
    try:
        sb.table(TABLE_CALLS).insert(call_row).execute()
    except Exception as e:
        log.error(f"Couldn't save missed-call row for {call_sid}: {e}")


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
# ACCOUNT — the customer's own account-level info: business name, owner
# name, contact phone, and business address. Distinct from per-location
# /settings (auto-reply) and /locations (phone numbers) — this is the one
# place that maps to "my account" rather than "this location."
# Also handles password changes (separate endpoint, requires current
# password) so account.html can be a single self-service page instead of
# something only Saleh can do via direct DB access.
# ---------------------------------------------------------------------------
@app.get("/account/{customer_id}")
def get_account(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    cust = sb.table(TABLE_CUST).select(
        "business_name, owner_name, email, business_phone, "
        "address_line1, address_city, address_state, address_zip, tier, status"
    ).eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    return cust.data[0]


@app.post("/account/{customer_id}")
def update_account(
    customer_id: str,
    business_name: str = Form(...),
    owner_name: str = Form(...),
    business_phone: str = Form(...),
    address_line1: str = Form(""),
    address_city: str = Form(""),
    address_state: str = Form(""),
    address_zip: str = Form(""),
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    business_name = business_name.strip()
    owner_name = owner_name.strip()
    if not business_name or not owner_name:
        raise HTTPException(400, "Business name and your name can't be empty.")
    sb.table(TABLE_CUST).update({
        "business_name": business_name,
        "owner_name": owner_name,
        "business_phone": business_phone.strip(),
        "address_line1": address_line1.strip(),
        "address_city": address_city.strip(),
        "address_state": address_state.strip(),
        "address_zip": address_zip.strip(),
    }).eq("id", customer_id).execute()
    return {"ok": True}


@app.post("/account/{customer_id}/password")
def change_password(
    customer_id: str,
    current_password: str = Form(...),
    new_password: str = Form(...),
    authorization: str = Header(None),
):
    require_auth(customer_id, authorization)
    if len(new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters.")
    cust = sb.table(TABLE_CUST).select("password_hash").eq("id", customer_id).execute()
    if not cust.data or not cust.data[0].get("password_hash"):
        raise HTTPException(404, "Not found")
    if not verify_password(current_password, cust.data[0]["password_hash"]):
        raise HTTPException(401, "Your current password is incorrect.")
    sb.table(TABLE_CUST).update({"password_hash": hash_password(new_password)}).eq("id", customer_id).execute()
    return {"ok": True}



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

    appointments = (
        sb.table("recall_appointments")
        .select("*")
        .eq("location_id", loc["id"])
        .eq("canceled", False)
        .gt("appointment_start", datetime.now(timezone.utc).isoformat())
        .order("appointment_start")
        .limit(50)
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
        "appointments": appointments.data,
    }


@app.post("/messages/{message_id}/resolve")
def resolve_message(message_id: str, customer_id: str = Form(...), authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    msg = sb.table("recall_messages").select("customer_id").eq("id", message_id).execute()
    if not msg.data or msg.data[0]["customer_id"] != customer_id:
        raise HTTPException(404, "Not found")
    sb.table("recall_messages").update({"resolved": True}).eq("id", message_id).execute()
    return {"ok": True}


@app.post("/appointments/{appointment_id}/update")
async def update_appointment(appointment_id: str, request: Request):
    """One endpoint for every way an owner might need to notify a customer
    about their appointment — cancel, reschedule (delayed or moved up), or
    a free-typed message — always sent from the AI number since that's the
    only number that can actually text, regardless of whether the real
    business line is a landline or a cell."""
    form = await request.form()
    customer_id = form.get("customer_id")
    action = form.get("action")  # "cancel" | "reschedule" | "custom"
    new_start = form.get("new_start")  # ISO datetime, for reschedule
    custom_message = form.get("custom_message")  # for custom
    require_auth(customer_id, request.headers.get("authorization"))

    appt = sb.table("recall_appointments").select("*").eq("id", appointment_id).execute()
    if not appt.data or appt.data[0]["customer_id"] != customer_id:
        raise HTTPException(404, "Not found")
    row = appt.data[0]

    try:
        loc = sb.table(TABLE_LOC).select("twilio_number, recall_customers(business_name)").eq("id", row["location_id"]).execute()
        if not loc.data:
            raise HTTPException(404, "Location not found for this appointment.")
        twilio_number = loc.data[0]["twilio_number"]
        business_name = (loc.data[0].get("recall_customers") or {}).get("business_name") or "the business"

        def local_when(iso_str: str) -> str:
            from zoneinfo import ZoneInfo
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(ZoneInfo(BUSINESS_TZ)).strftime("%A, %B %-d at %-I:%M %p")

        caller_first = (row.get("caller_name") or "").split(" ")[0]
        greeting = f"Hi {caller_first}, " if caller_first else "Hi, "

        if action == "cancel":
            sb.table("recall_appointments").update({"canceled": True}).eq("id", appointment_id).execute()
            message = (
                f"{greeting}your appointment with {business_name} on {local_when(row['appointment_start'])} "
                "has been canceled. Please call us if you'd like to reschedule."
            )
        elif action == "reschedule":
            if not new_start:
                raise HTTPException(400, "Missing new_start for a reschedule.")
            sb.table("recall_appointments").update({"appointment_start": new_start}).eq("id", appointment_id).execute()
            message = (
                f"{greeting}your appointment with {business_name} has been moved to "
                f"{local_when(new_start)}. Call us if that doesn't work for you."
            )
        elif action == "custom":
            if not custom_message:
                raise HTTPException(400, "Missing custom_message.")
            message = custom_message
        else:
            raise HTTPException(400, "action must be 'cancel', 'reschedule', or 'custom'.")
    except HTTPException:
        raise
    except Exception:
        log.exception(f"appointment update crashed for {appointment_id}")
        raise HTTPException(500, "Something went wrong updating that appointment — please try again.")

    sent = False
    if row.get("caller_phone"):
        try:
            sent = bool(send_customer_sms(customer_id, row["caller_phone"], twilio_number, message,
                                          location_id=row.get("location_id"), kind=f"appointment_{action}",
                                          name=row.get("caller_name")))
        except Exception as e:
            log.error(f"Appointment-update SMS failed for appointment {appointment_id}: {e}")

    called = False
    if action == "cancel" and row.get("caller_phone"):
        try:
            twilio_client.calls.create(
                to=row["caller_phone"],
                from_=twilio_number,
                url=f"{PUBLIC_BASE_URL}/twilio/cancellation-twiml/{appointment_id}",
                method="POST",
            )
            called = True
        except Exception as e:
            log.error(f"Appointment-cancellation call failed for appointment {appointment_id}: {e}")

    return {"ok": True, "customer_notified": sent, "customer_called": called}


@app.post("/twilio/cancellation-twiml/{appointment_id}")
async def cancellation_twiml(appointment_id: str):
    """Twilio fetches this when the cancellation call connects (including to
    voicemail — Twilio still plays <Say> content even if a machine picks up).
    Reuses the exact same pattern as the reminder-call TwiML."""
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
    business_name = customer.get("business_name", "the business")

    from zoneinfo import ZoneInfo
    dt = row["appointment_start"]
    dt = dt if isinstance(dt, datetime) else datetime.fromisoformat(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    when_str = dt.astimezone(ZoneInfo(BUSINESS_TZ)).strftime("%A, %B %-d at %-I:%M %p")

    vr.say(
        f"Hi, this is {business_name}. We're calling to let you know your appointment "
        f"on {when_str} has been canceled. Please call us back if you'd like to "
        f"reschedule. Sorry for the inconvenience. Goodbye."
    )
    return PlainTextResponse(str(vr), media_type="application/xml")


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
        "location_id": location["location_id"], "customer_id": location["customer_id"],
        "direction": "inbound", "from_number": from_number, "body": body,
    }).execute()

    message_sid = form.get("MessageSid") or form.get("SmsSid")
    contact_id = upsert_contact_and_log(
        location["customer_id"], from_number, "sms_in", body=body,
        metadata={"twilio_sid": message_sid}, source="sms",
        location_id=location["location_id"],
        source_ref=f"tw:{message_sid}" if message_sid else None,
    )

    # Opt-out / opt-in keywords: the CRM call above already flipped opted_out
    # and logged it. Twilio sends the carrier-required confirmation itself, so
    # the AI must NOT reply to these.
    if sms_keyword(body) in OPT_OUT_WORDS | OPT_IN_WORDS:
        return PlainTextResponse("", media_type="application/xml")

    # Conversation history for THIS caller only. (Previously this pulled the
    # last N texts for the whole location, so two customers texting the same
    # number would see each other's messages in the AI's context.)
    turns = []
    if contact_id:
        try:
            hist = (
                sb.table("recall_contact_activities")
                .select("type, body")
                .eq("contact_id", contact_id)
                .in_("type", ["sms_in", "sms_out"])
                .order("created_at", desc=True)
                .limit(SMS_HISTORY_LIMIT)
                .execute()
            )
            turns = [{"direction": "inbound" if h["type"] == "sms_in" else "outbound", "body": h["body"]}
                     for h in reversed(hist.data) if h.get("body")]
        except Exception as e:
            log.error(f"SMS history lookup failed for contact {contact_id}: {e}")
    if not turns or turns[-1]["direction"] != "inbound":
        turns.append({"direction": "inbound", "body": body})
    # Anthropic requires the conversation to start with a user turn
    while turns and turns[0]["direction"] != "inbound":
        turns.pop(0)

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
    system_prompt += (
        "\n\nAbout the person texting (identified by their phone number):\n"
        + caller_context(location["customer_id"], from_number)
        + "\n\nIf they're a returning customer, greet them by name and bring up their last visit or open "
        "item when it's relevant. If the name they give doesn't match the one on file, don't share anything "
        "from their history until it does. Never mention files or records. When they tell you something "
        "worth remembering for next time (name, vehicle or equipment, service needed or done, preferences, "
        "household members), call remember_caller. Never save health details, card numbers, or ID numbers."
    )
    remember_tool = {
        "name": "remember_caller",
        "description": "Save something worth remembering about this person for next time (name, vehicle/equipment, service needed or done, preferences, household members).",
        "input_schema": {
            "type": "object",
            "properties": {
                "details": {"type": "string", "description": "One or two short factual sentences to remember."},
                "caller_name": {"type": "string", "description": "Their name, if known."},
            },
            "required": ["details"],
        },
    }
    tools = [remember_tool]
    if can_book:
        system_prompt += (
            "\n\nYou can also check availability and book appointments directly in this "
            "text conversation using the tools provided. Today's date is "
            f"{datetime.now().strftime('%Y-%m-%d')}. You already have their phone number "
            "from this text conversation, so don't ask for it. If the caller gives a date, "
            "time, and their name (in this message or earlier), call check_availability with "
            "all of that — if the time is free, it books it immediately in that same call and "
            "returns a confirmation. Do NOT call book_appointment afterward in that case — "
            "check_availability already completed the booking, and calling book_appointment "
            "again would try to double-book the same slot. Only call book_appointment "
            "separately if check_availability returned availability without booking (for "
            "example, because you didn't have their name yet when you checked)."
        )
        tools = [
            remember_tool,
            {
                "name": "check_availability",
                "description": "Check open appointment slots on a given date, optionally near a specific time. If the caller already gave their name and phone number and the exact time they asked about is free, this books it immediately — you don't need to call book_appointment separately in that case. Only call book_appointment afterward if this returns availability without booking (e.g. they didn't give their name/phone yet).",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "date": {"type": "string", "description": "YYYY-MM-DD"},
                        "time": {"type": "string", "description": "Optional specific time, 24-hour HH:MM"},
                        "caller_name": {"type": "string", "description": "Optional. Include if the caller already gave their name — enables direct booking."},
                        "caller_phone": {"type": "string", "description": "Optional. Include if the caller already gave their phone number — enables direct booking."},
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

    async def call_booking_tool(name: str, tool_input: dict) -> str:
        if name == "remember_caller":
            import asyncio
            asyncio.get_running_loop().run_in_executor(
                None, update_contact_memory, location["customer_id"], from_number,
                tool_input.get("details") or "", "text message",
                (tool_input.get("caller_name") or "").strip() or None, None, location["location_id"])
            return "Saved."
        # Calls the booking logic directly in-process instead of over the
        # network to our own server — a self-HTTP-call here previously hit
        # real timeouts (worse on Render's free tier, which spins down when
        # idle), where the call gave up on a slow response that then
        # succeeded moments later anyway — updating the calendar for real
        # while telling the caller it had failed. Calling the function
        # directly removes that whole failure mode.
        caller_phone = from_number if name in ("book_appointment", "check_availability") else None
        if name == "check_availability":
            return await _check_availability_core(
                location["location_id"], tool_input.get("date"), tool_input.get("time"),
                tool_input.get("caller_name"), caller_phone,
            )
        else:
            return await _book_appointment_core(
                location["location_id"], tool_input.get("date"), tool_input.get("time"),
                tool_input.get("caller_name"), caller_phone,
            )

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
                    result_text = await call_booking_tool(block["name"], block["input"])
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
        sid = send_customer_sms(location["customer_id"], from_number, to_number, reply_text,
                                location_id=location["location_id"], kind="ai_sms_reply")
        if not sid:
            return PlainTextResponse("", media_type="application/xml")
        sb.table("recall_sms_messages").insert({
            "location_id": location["location_id"], "customer_id": location["customer_id"],
            "direction": "outbound", "from_number": to_number, "body": reply_text,
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
                # Marked sent even if blocked by opt-out, so a blocked reminder isn't retried every run.
                send_customer_sms(appt["customer_id"], appt["caller_phone"], loc["twilio_number"], message,
                                  location_id=appt.get("location_id"), kind="appointment_reminder")
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


def _el_assign(phone_id: str, agent_id: str):
    return requests.patch(
        f"{ELEVENLABS_BASE}/convai/phone-numbers/{phone_id}",
        headers={**el_headers(), "Content-Type": "application/json"},
        json={"agent_id": agent_id}, timeout=30,
    )


def _ensure_el_phone_assigned(customer: dict, location: dict, agent_id: str, phone_id: str) -> str:
    """Assigns agent_id to this location's number in ElevenLabs and returns the
    (possibly new) ElevenLabs phone_number_id. Raises HTTPException on failure."""
    if phone_id:
        resp = _el_assign(phone_id, agent_id)
        if resp.ok:
            return phone_id
        if resp.status_code not in (404, 422) and "not_found" not in resp.text:
            raise HTTPException(502, f"Couldn't assign the agent to your number: {resp.text[:300]}")
        log.warning(f"ElevenLabs phone id {phone_id} is stale for {location['twilio_number']} — re-linking")

    # Look for the number already imported under a different id.
    found = None
    try:
        lst = requests.get(f"{ELEVENLABS_BASE}/convai/phone-numbers", headers=el_headers(), timeout=30)
        if lst.ok:
            rows = lst.json()
            rows = rows.get("phone_numbers", rows) if isinstance(rows, dict) else rows
            want = normalize_e164(location["twilio_number"])
            for row in rows or []:
                if normalize_e164(row.get("phone_number") or "") == want:
                    found = row.get("phone_number_id")
                    break
    except Exception as e:
        log.error(f"Couldn't list ElevenLabs phone numbers: {e}")

    if not found:
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
            raise HTTPException(502, f"Couldn't import your number into ElevenLabs: {resp.text[:300]}")
        found = resp.json().get("phone_number_id")

    resp = _el_assign(found, agent_id)
    if not resp.ok:
        raise HTTPException(502, f"Couldn't assign the agent to your number: {resp.text[:300]}")
    return found


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
            "time yet, call check_availability with just the date to see general openings. "
            "IMPORTANT: checking availability is never the end of the task if the caller actually "
            "wants to book (not just asking what's open) — if the slot is available AND you already "
            "have their name and callback phone number (they may have given these upfront in the same "
            "message), immediately call book_appointment in that same turn. Do not stop after telling "
            "them a time is available and wait for them to ask again — that is treating confirmation "
            "as if it were the booking, and it isn't. Only ask them for name/phone if they genuinely "
            "haven't given it yet. Only tell the caller an appointment is confirmed if the "
            "book_appointment tool actually returns success — never say it's booked if the tool failed "
            "or you didn't call it; if that happens, apologize and offer to take a message instead. "
            "If a time isn't available, never guess or invent a reason why (like 'it's booked by "
            "another customer') unless the tool's response actually told you that reason — if you don't "
            "know why, just say it's not available and offer the alternative times the tool gave you."
        )
    system_prompt += MEMORY_PROMPT
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
                "description": "Check whether a specific time is open on a given date. Always pass 'time' when the caller mentions a specific time (e.g. '3pm') so it checks that exact slot — don't omit it and just browse the morning. If the caller already gave their name and phone number (in this message or earlier), pass those too — this books the appointment immediately when the slot is free, so you don't need to call book_appointment separately in that case.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/check-availability/{location['id']}",
                    "method": "POST",
                    "request_headers": tool_secret_header,
                    "request_body_schema": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string", "value_type": "llm_prompt", "description": "Date to check, format YYYY-MM-DD"},
                            "time": {"type": "string", "value_type": "llm_prompt", "description": "Optional. 24-hour time HH:MM. Include this whenever the caller mentioned a specific time — checks that exact slot instead of just listing morning openings."},
                            "caller_name": {"type": "string", "value_type": "llm_prompt", "description": "Optional. The caller's name, if already given — enables direct booking when the slot is free."},
                            "caller_phone": {"type": "string", "value_type": "dynamic_variable", "dynamic_variable": "system__caller_id", "description": ""},
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
                    "caller_name": {"type": "string", "value_type": "llm_prompt",
                                    "description": "The caller's name, if given"},
                    "caller_phone": {"type": "string", "value_type": "dynamic_variable",
                                     "dynamic_variable": "system__caller_id", "description": ""},
                    "note": {"type": "string", "value_type": "llm_prompt",
                             "description": "One short sentence on what they need"},
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
                        "is_emergency": {"type": "boolean", "value_type": "llm_prompt",
                                          "description": "True only for a genuine emergency or urgent situation."},
                        "reason": {"type": "string", "value_type": "llm_prompt",
                                   "description": "One short sentence on why the caller wants to be connected."},
                        "caller_phone": {"type": "string", "value_type": "dynamic_variable",
                                         "dynamic_variable": "system__caller_id", "description": ""},
                    },
                    "required": ["is_emergency", "caller_phone"],
                },
            },
        })
    webhook_tools.extend(memory_tools(location['id'], tool_secret_header))
    if webhook_tools:
        conversation_config["agent"]["prompt"]["tools"] = webhook_tools

    # ElevenLabs' agent PATCH replaces the entire `prompt` object rather than
    # merging into it — any field we don't include (like built_in_tools) gets
    # silently cleared, even though we never touched it. This is what kept
    # wiping "Transfer to number" every time this endpoint saved: we simply
    # never sent that field, and PATCH treated that as "delete it." Fix:
    # fetch whatever's currently live and carry it forward untouched.
    existing_agent_id = location.get("elevenlabs_agent_id")
    if existing_agent_id:
        try:
            current = requests.get(
                f"{ELEVENLABS_BASE}/convai/agents/{existing_agent_id}",
                headers=el_headers(),
                timeout=20,
            )
            if current.ok:
                existing_built_in_tools = (
                    current.json().get("conversation_config", {}).get("agent", {}).get("prompt", {}).get("built_in_tools")
                )
                if existing_built_in_tools:
                    conversation_config["agent"]["prompt"]["built_in_tools"] = existing_built_in_tools
        except Exception as e:
            log.error(f"Couldn't fetch existing agent config for {existing_agent_id}, built_in_tools may reset: {e}")

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

    # 3. Link the location's Twilio number to the agent in ElevenLabs.
    # Self-healing: if the saved phone-number id no longer exists in ElevenLabs
    # (number re-imported or removed there), find the number by its digits,
    # re-import only if it's truly missing, and save the new id.
    phone_id = _ensure_el_phone_assigned(customer, location, agent_id, location.get("elevenlabs_phone_id"))
    if phone_id != location.get("elevenlabs_phone_id"):
        update["elevenlabs_phone_id"] = phone_id

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
# BULK ADMIN TOOL — re-save every existing Elite agent's ElevenLabs config.
#
# Why this exists: changes to an individual agent's ElevenLabs config (like
# the LLM model after a deprecation, or a system-prompt wording tweak) are
# per-agent, not global — a fix to ELEVENLABS_LLM_MODEL in Render only takes
# effect for a given customer once their agent is re-saved. Before this,
# that meant manually opening every Elite customer's dashboard and clicking
# "Save AI agent settings" one at a time. This re-saves all of them in one
# call, using each location's *already stored* voice/fallback/PDF — nothing
# about the customer's own settings changes, only the agent config Twilio/
# ElevenLabs actually runs gets refreshed against current env vars.
#
# Only re-PATCHes agents that already exist (elevenlabs_agent_id is set).
# Never creates a new agent and never imports/re-imports a phone number —
# both of those are one-time, first-setup actions and stay in setup_agent.
# ---------------------------------------------------------------------------
def _resave_agent_for_location(customer: dict, location: dict) -> dict:
    """Rebuilds and re-PATCHes one location's ElevenLabs agent from its
    already-saved settings. Returns a small result dict; never raises —
    callers collect per-location results so one failure doesn't stop the
    batch."""
    agent_id = location.get("elevenlabs_agent_id")
    if not agent_id:
        return {"location_id": location["id"], "status": "skipped", "detail": "No agent set up yet."}

    voice_id = location.get("elevenlabs_voice_id")
    fallback_behavior = location.get("fallback_behavior") or "message"
    kb_doc_id = location.get("elevenlabs_kb_doc_id")
    transfer_target = location.get("transfer_phone") or location.get("business_phone")

    fallback_instructions = {
        "message": "If you don't know the answer, politely ask for their name and phone number, then call take_message with those details so someone actually gets notified — don't just say you'll pass it along without calling the tool.",
        "transfer": "If you don't know the answer, offer to connect them to a person using your transfer ability.",
        "try_harder": "Check the knowledge base carefully before giving up — rephrase the question in your head and look again. Only if you're truly certain the answer isn't in the knowledge base, ask for their name and number, then call take_message with those details.",
    }
    system_prompt = (
        f"You are the phone receptionist for {customer['business_name']}. "
        "Be friendly, concise, and helpful. Answer questions using the knowledge base provided. "
        + fallback_instructions.get(fallback_behavior, fallback_instructions["message"])
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
            "time yet, call check_availability with just the date to see general openings. "
            "IMPORTANT: checking availability is never the end of the task if the caller actually "
            "wants to book (not just asking what's open) — if the slot is available AND you already "
            "have their name and callback phone number (they may have given these upfront in the same "
            "message), immediately call book_appointment in that same turn. Do not stop after telling "
            "them a time is available and wait for them to ask again — that is treating confirmation "
            "as if it were the booking, and it isn't. Only ask them for name/phone if they genuinely "
            "haven't given it yet. Only tell the caller an appointment is confirmed if the "
            "book_appointment tool actually returns success — never say it's booked if the tool failed "
            "or you didn't call it; if that happens, apologize and offer to take a message instead. "
            "If a time isn't available, never guess or invent a reason why (like 'it's booked by "
            "another customer') unless the tool's response actually told you that reason — if you don't "
            "know why, just say it's not available and offer the alternative times the tool gave you."
        )

    system_prompt += MEMORY_PROMPT
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

    tool_secret_header = {"X-Tool-Secret": ELEVENLABS_TOOL_SECRET}
    webhook_tools = []
    if calendar_connected:
        webhook_tools.extend([
            {
                "type": "webhook", "name": "check_availability",
                "description": "Check whether a specific time is open on a given date. Always pass 'time' when the caller mentions a specific time (e.g. '3pm') so it checks that exact slot — don't omit it and just browse the morning. If the caller already gave their name and phone number (in this message or earlier), pass those too — this books the appointment immediately when the slot is free, so you don't need to call book_appointment separately in that case.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/check-availability/{location['id']}",
                    "method": "POST", "request_headers": tool_secret_header,
                    "request_body_schema": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string", "value_type": "llm_prompt", "description": "Date to check, format YYYY-MM-DD"},
                            "time": {"type": "string", "value_type": "llm_prompt", "description": "Optional. 24-hour time HH:MM. Include this whenever the caller mentioned a specific time — checks that exact slot instead of just listing morning openings."},
                            "caller_name": {"type": "string", "value_type": "llm_prompt", "description": "Optional. The caller's name, if already given — enables direct booking when the slot is free."},
                            "caller_phone": {"type": "string", "value_type": "dynamic_variable", "dynamic_variable": "system__caller_id", "description": ""},
                        },
                        "required": ["date"],
                    },
                },
            },
            {
                "type": "webhook", "name": "book_appointment",
                "description": "Book an appointment on the business's calendar once the caller confirms a date and time.",
                "api_schema": {
                    "url": f"{PUBLIC_BASE_URL}/tools/book-appointment/{location['id']}",
                    "method": "POST", "request_headers": tool_secret_header,
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
        "type": "webhook", "name": "take_message",
        "description": "Log a callback request when you can't help the caller directly — always call this rather than just telling the caller you'll pass their info along.",
        "api_schema": {
            "url": f"{PUBLIC_BASE_URL}/tools/take-message/{location['id']}",
            "method": "POST", "request_headers": tool_secret_header,
            "request_body_schema": {
                "type": "object",
                "properties": {
                    "caller_name": {"type": "string", "value_type": "llm_prompt", "description": "The caller's name, if given"},
                    "caller_phone": {"type": "string", "value_type": "dynamic_variable", "dynamic_variable": "system__caller_id", "description": ""},
                    "note": {"type": "string", "value_type": "llm_prompt", "description": "One short sentence on what they need"},
                },
                "required": ["caller_phone"],
            },
        },
    })
    if transfer_target:
        webhook_tools.append({
            "type": "webhook", "name": "notify_owner",
            "description": "Send a text heads-up to the business before transferring a call to them — call this right before connecting the caller, always.",
            "api_schema": {
                "url": f"{PUBLIC_BASE_URL}/tools/notify-owner/{location['id']}",
                "method": "POST", "request_headers": tool_secret_header,
                "request_body_schema": {
                    "type": "object",
                    "properties": {
                        "is_emergency": {"type": "boolean", "value_type": "llm_prompt", "description": "True only for a genuine emergency or urgent situation."},
                        "reason": {"type": "string", "value_type": "llm_prompt", "description": "One short sentence on why the caller wants to be connected."},
                        "caller_phone": {"type": "string", "value_type": "dynamic_variable", "dynamic_variable": "system__caller_id", "description": ""},
                    },
                    "required": ["is_emergency", "caller_phone"],
                },
            },
        })
    webhook_tools.extend(memory_tools(location['id'], tool_secret_header))
    if webhook_tools:
        conversation_config["agent"]["prompt"]["tools"] = webhook_tools

    # Same built_in_tools preservation as setup_agent — PATCH replaces the
    # whole prompt object, so anything we don't carry forward gets wiped.
    try:
        current = requests.get(f"{ELEVENLABS_BASE}/convai/agents/{agent_id}", headers=el_headers(), timeout=20)
        if current.ok:
            existing_built_in_tools = (
                current.json().get("conversation_config", {}).get("agent", {}).get("prompt", {}).get("built_in_tools")
            )
            if existing_built_in_tools:
                conversation_config["agent"]["prompt"]["built_in_tools"] = existing_built_in_tools
    except Exception as e:
        log.error(f"Bulk resave: couldn't fetch existing built_in_tools for agent {agent_id}: {e}")

    try:
        resp = requests.patch(
            f"{ELEVENLABS_BASE}/convai/agents/{agent_id}",
            headers={**el_headers(), "Content-Type": "application/json"},
            json={"conversation_config": conversation_config},
            timeout=30,
        )
        if not resp.ok:
            return {"location_id": location["id"], "agent_id": agent_id, "status": "failed", "detail": resp.text[:300]}
        return {"location_id": location["id"], "agent_id": agent_id, "status": "resaved"}
    except Exception as e:
        return {"location_id": location["id"], "agent_id": agent_id, "status": "failed", "detail": str(e)}


@app.post("/admin/resave-elite-agents")
def resave_elite_agents(tiers: str = "elite", authorization: str = Header(None)):
    """Saleh-only. Loops every Elite customer's location that already has an
    ElevenLabs agent and re-saves it against current env vars (e.g. a new
    ELEVENLABS_LLM_MODEL after a deprecation). Use after changing a shared
    env var, not after an individual customer's own settings change — those
    still save normally through their own dashboard."""
    require_admin(authorization)
    require_elevenlabs()

    # ?tiers=all re-saves Pro AND Elite agents (needed after adding new agent
    # tools like caller memory, which every voice agent should get).
    wanted = ["pro", "elite"] if tiers == "all" else ["elite"]
    customers = sb.table(TABLE_CUST).select("*").in_("tier", wanted).execute().data
    results = []
    for customer in customers:
        locations = sb.table(TABLE_LOC).select("*").eq("customer_id", customer["id"]).execute().data
        for location in locations:
            result = _resave_agent_for_location(customer, location)
            result["business_name"] = customer.get("business_name")
            result["location_label"] = location.get("location_label")
            results.append(result)

    resaved = sum(1 for r in results if r["status"] == "resaved")
    failed = sum(1 for r in results if r["status"] == "failed")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    return {"ok": True, "resaved": resaved, "failed": failed, "skipped": skipped, "results": results}


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


def _create_calendar_booking(location: dict, location_id: str, date_str: str, time_str: str, caller_name: str, caller_phone: str) -> str:
    """Actually creates the calendar event + appointment record. Shared by
    book_appointment and by check_availability's direct-booking shortcut
    (used when the caller already gave their name/phone in the same message
    — relying on the model to always make a second tool call afterward
    proved unreliable in practice, so the common case is handled in one
    call instead of two)."""
    hours_start = location.get("booking_hours_start", DEFAULT_BUSINESS_HOURS[0])
    hours_end = location.get("booking_hours_end", DEFAULT_BUSINESS_HOURS[1])
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(BUSINESS_TZ)
    start = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    end = start + timedelta(minutes=SLOT_MINUTES)
    day_start = start.replace(hour=hours_start, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(hours=(hours_end - hours_start))
    if not (day_start <= start and end <= day_end):
        return f"That time is outside booking hours ({hours_start}:00–{hours_end}:00) — offer a time within that window."

    access_token = google_access_token(location["google_calendar_refresh_token"])
    resp = requests.post(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={
            "summary": f"{caller_name} — {location['business_name']} appointment",
            "description": f"Booked by CallsKept AI. Caller phone: {caller_phone}",
            "start": {"dateTime": start.isoformat()},
            "end": {"dateTime": end.isoformat()},
        },
        timeout=20,
    )
    if not resp.ok:
        log.error(f"Google event creation failed for location {location_id}: {resp.status_code} {resp.text[:400]}")
        return "I couldn't book that — please offer to take a message instead."
    log.info(f"book-appointment success, event id: {resp.json().get('id')}")

    appt_id = None
    try:
        ins = sb.table("recall_appointments").insert({
            "location_id": location_id,
            "customer_id": location["customer_id"],
            "caller_name": caller_name,
            "caller_phone": caller_phone,
            "appointment_start": start.isoformat(),
        }).execute()
        appt_id = (ins.data or [{}])[0].get("id")
    except Exception as e:
        # Booking itself already succeeded on the real calendar — don't
        # fail the whole tool call just because the reminder record failed.
        log.error(f"Couldn't save appointment record for reminders (location {location_id}): {e}")

    upsert_contact_and_log(
        location["customer_id"], caller_phone, "booking",
        body=f"Appointment booked for {start.strftime('%a %b %-d, %-I:%M %p')}",
        metadata={"appointment_start": start.isoformat(), "appointment_id": appt_id,
                  "calendar_event_id": resp.json().get("id")},
        source="ai_call", location_id=location_id, name=caller_name,
        source_ref=f"appt:{appt_id}" if appt_id else None,
    )
    import threading
    threading.Thread(target=update_contact_memory, daemon=True, args=(
        location["customer_id"], caller_phone,
        f"Booked an appointment for {start.strftime('%Y-%m-%d %-I:%M %p')}.", "booking", caller_name, None, location_id,
    )).start()

    return f"Booked for {caller_name} on {date_str} at {time_str}. Confirmed."


async def _check_availability_core(location_id: str, date_str: str, time_str: str, caller_name: str, caller_phone: str) -> str:
    """The actual availability-check logic, with no dependency on an HTTP
    Request object — callable directly in-process (no network round-trip,
    no timeout risk) as well as from the /tools/check-availability endpoint."""
    if not date_str:
        return "I need a specific date (YYYY-MM-DD) to check availability."

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
            return "I couldn't check the calendar right now — please offer to take a message instead."

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
                return "That time didn't look right — please use 24-hour HH:MM format."
            if requested in all_slots and is_free(requested):
                if caller_name and caller_phone:
                    # Already have everything needed — book it directly instead
                    # of just confirming and hoping a second tool call follows.
                    result = _create_calendar_booking(location, location_id, date_str, time_str, caller_name, caller_phone)
                else:
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
        return result
    except ValueError:
        return "That date didn't look right — please use YYYY-MM-DD format."
    except Exception:
        log.exception(f"check-availability crashed for location {location_id}")
        return "I couldn't check the calendar right now — please offer to take a message instead."


@app.post("/tools/check-availability/{location_id}")
async def tool_check_availability(location_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"check-availability request body: {body}")
    p = body if "date" in body else body.get("parameters", {})
    result = await _check_availability_core(
        location_id, p.get("date"), p.get("time"), p.get("caller_name"), p.get("caller_phone")
    )
    return {"result": result}


async def _book_appointment_core(location_id: str, date_str: str, time_str: str, caller_name: str, caller_phone: str) -> str:
    """Same idea as _check_availability_core — no Request dependency, so
    the SMS handler can call this directly in-process."""
    if not all([date_str, time_str, caller_name, caller_phone]):
        return "I'm missing some details — I need the date, time, the caller's name, and their phone number."
    try:
        location = get_calendar_location(location_id)
        return _create_calendar_booking(location, location_id, date_str, time_str, caller_name, caller_phone)
    except ValueError:
        return "That date or time didn't look right — date as YYYY-MM-DD, time as HH:MM."
    except Exception:
        log.exception(f"book-appointment crashed for location {location_id}")
        return "I couldn't book that — please offer to take a message instead."


@app.post("/tools/book-appointment/{location_id}")
async def tool_book_appointment(location_id: str, request: Request):
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    log.info(f"book-appointment request body: {body}")
    p = body if "date" in body else body.get("parameters", {})
    result = await _book_appointment_core(
        location_id, p.get("date"), p.get("time"), p.get("caller_name"), p.get("caller_phone")
    )
    return {"result": result}


@app.post("/tools/notify-owner/{location_id}")
async def tool_notify_owner(location_id: str, request: Request):
    """Called by the AI right before it transfers a call, so the owner gets a
    text heads-up even if they don't pick up the actual transferred call —
    a live warm-transfer message only reaches them if they answer; this
    doesn't depend on that. Also logs the call as a recall_messages row so
    it's visible on the dashboard, with the real caller number (sent via the
    system__caller_id dynamic variable, not something the LLM has to hear
    and transcribe)."""
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    p = body if "is_emergency" in body or "reason" in body else body.get("parameters", {})
    is_emergency = bool(p.get("is_emergency"))
    reason = (p.get("reason") or "").strip()
    caller_phone = (p.get("caller_phone") or "").strip() or None

    loc = sb.table(TABLE_LOC).select("*, recall_customers(business_name)").eq("id", location_id).execute()
    if not loc.data:
        return {"result": "Couldn't send the notification — proceed with the transfer anyway."}
    row = loc.data[0]
    customer = row.pop("recall_customers", None) or {}
    location = {**customer, **row}
    target = location.get("transfer_phone") or location.get("business_phone")

    note_text = (reason or "Caller requested to be connected.") + (" (EMERGENCY)" if is_emergency else "")
    msg_id = None
    try:
        ins = sb.table("recall_messages").insert({
            "customer_id": location["customer_id"],
            "caller_phone": caller_phone or "unknown",
            "note": note_text,
        }).execute()
        msg_id = (ins.data or [{}])[0].get("id")
    except Exception as e:
        log.error(f"notify-owner recall_messages insert failed for location {location_id}: {e}")
    upsert_contact_and_log(
        location["customer_id"], caller_phone, "ai_call",
        body=f"AI transferred the call to the owner — {note_text}",
        metadata={"kind": "transfer", "is_emergency": is_emergency, "message_id": msg_id},
        source="ai_call", location_id=location_id,
        source_ref=f"msg:{msg_id}" if msg_id else None,
    )

    if not target:
        return {"result": "No transfer contact number is configured — proceed with the transfer anyway."}

    business_name = location.get("business_name", "the business")
    if is_emergency:
        message = f"🚨 URGENT call for {business_name} being connected to you now"
    else:
        message = f"Heads up: a caller is being connected to you now for {business_name}"
    if caller_phone:
        message += f" ({caller_phone})"
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
        ins = sb.table("recall_messages").insert({
            "customer_id": location["customer_id"],
            "caller_name": caller_name or None,
            "caller_phone": caller_phone,
            "note": note or None,
        }).execute()
        msg_id = (ins.data or [{}])[0].get("id")
    except Exception as e:
        log.error(f"take-message save failed for location {location_id}: {e}")
        return {"result": "Couldn't save that message — apologize and let them know someone will follow up."}
    upsert_contact_and_log(
        location["customer_id"], caller_phone, "ai_call",
        body=f"AI took a callback request — {note}" if note else "AI took a callback request.",
        metadata={"kind": "take_message", "message_id": msg_id},
        source="ai_call", location_id=location_id, name=caller_name or None,
        source_ref=f"msg:{msg_id}" if msg_id else None,
    )

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


def _location_customer(location_id: str) -> str:
    if not UUID_RE.match(location_id or ""):
        return None
    r = sb.table(TABLE_LOC).select("customer_id").eq("id", location_id).execute()
    return r.data[0]["customer_id"] if r.data else None


@app.post("/tools/lookup-caller/{location_id}")
async def tool_lookup_caller(location_id: str, request: Request):
    """Voice agent asks: who is this caller and what do we know about them?"""
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    p = body if "caller_phone" in body else body.get("parameters", {})
    customer_id = _location_customer(location_id)
    if not customer_id:
        return {"result": "No record available — treat them as a new caller."}
    return {"result": caller_context(customer_id, p.get("caller_phone"))}


@app.post("/tools/remember-caller/{location_id}")
async def tool_remember_caller(location_id: str, request: Request, background: BackgroundTasks):
    """Voice agent saves something about the caller. Answers instantly; the
    profile rewrite happens after the response so the caller never waits."""
    check_tool_secret({k.lower(): v for k, v in request.headers.items()})
    body = await request.json()
    p = body if "details" in body or "caller_phone" in body else body.get("parameters", {})
    customer_id = _location_customer(location_id)
    details = (p.get("details") or "").strip()
    if customer_id and details and p.get("caller_phone"):
        background.add_task(update_contact_memory, customer_id, p.get("caller_phone"), details,
                            "phone call", (p.get("caller_name") or "").strip() or None, None, location_id)
    return {"result": "Saved."}


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


# ---------------------------------------------------------------------------
# LEGAL PAGES — Privacy Policy & Terms for SMS, one per customer.
#
# Twilio requires a live, publicly accessible Privacy Policy and Terms &
# Conditions URL for every A2P 10DLC registration — this applies to the
# CURRENT shared-number setup just as much as any future per-customer ISV
# registration, so this doesn't wait on the EIN or anything else. Each page
# names the real business (not "Recall") since that's who's actually
# texting the caller. Content follows Twilio/CTIA's own required-clause
# checklist: message purpose, frequency, data rates, STOP/HELP, carrier
# non-liability, and — the single most-checked clause — an explicit "we
# never sell or share your opt-in data" statement in the privacy policy.
# ---------------------------------------------------------------------------
def _get_customer_for_legal(customer_id: str) -> dict:
    cust = sb.table(TABLE_CUST).select("business_name, owner_name, email, business_phone").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Not found")
    return cust.data[0]


def _legal_page_shell(title: str, business_name: str, body_html: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{title} — {business_name}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 680px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }}
  h1 {{ font-size: 24px; margin-bottom: 4px; }}
  h2 {{ font-size: 16px; margin-top: 28px; }}
  .updated {{ color: #777; font-size: 13px; margin-bottom: 24px; }}
  a {{ color: #1f5fa8; }}
</style>
</head>
<body>
{body_html}
</body>
</html>"""


@app.get("/legal/sms-terms/{customer_id}", response_class=HTMLResponse)
def sms_terms(customer_id: str):
    c = _get_customer_for_legal(customer_id)
    business_name = c["business_name"]
    contact = c.get("email") or c.get("business_phone") or "our office"
    body = f"""
<h1>SMS Terms &amp; Conditions</h1>
<p class="updated">{business_name}</p>
<p>These terms apply to text messages sent and received between you and <strong>{business_name}</strong> through our missed-call and appointment messaging service.</p>

<h2>What you'll receive</h2>
<p>Messages related to missed calls, appointment confirmations, reminders, and responses to questions you text us. These are service messages, not marketing.</p>

<h2>Message frequency</h2>
<p>Message frequency varies based on your interactions with us (for example, missing a call or booking an appointment).</p>

<h2>Cost</h2>
<p>Message and data rates may apply. Carriers are not liable for delayed or undelivered messages.</p>

<h2>Opt out</h2>
<p>Reply <strong>STOP</strong> at any time to cancel. After you send STOP, we will send one final message confirming you've been unsubscribed, and you will not receive further messages from us. If you want to start again, just text us or opt in again the same way you did the first time.</p>

<h2>Help</h2>
<p>Reply <strong>HELP</strong> for help, or contact us directly at {contact}.</p>

<h2>Privacy</h2>
<p>See our <a href="{PUBLIC_BASE_URL}/legal/sms-privacy/{customer_id}">Privacy Policy</a> for how we handle your information.</p>
"""
    return _legal_page_shell("SMS Terms & Conditions", business_name, body)


@app.get("/legal/sms-privacy/{customer_id}", response_class=HTMLResponse)
def sms_privacy(customer_id: str):
    c = _get_customer_for_legal(customer_id)
    business_name = c["business_name"]
    contact = c.get("email") or c.get("business_phone") or "our office"
    body = f"""
<h1>SMS Privacy Policy</h1>
<p class="updated">{business_name}</p>
<p>This policy explains how <strong>{business_name}</strong> handles information collected through text messaging.</p>

<h2>What we collect</h2>
<p>Your mobile phone number, your name if you provide it, and the content of the messages you send us.</p>

<h2>How we use it</h2>
<p>Solely to respond to your calls and texts — sending missed-call replies, confirming or reminding you about appointments, and answering questions you ask us directly.</p>

<h2>We do not sell or share your data</h2>
<p><strong>No mobile information will be shared with third parties or affiliates for marketing or promotional purposes at any time.</strong> All other categories exclude text messaging originator opt-in data and consent; this information will not be shared with any third parties.</p>

<h2>How long we keep it</h2>
<p>For as long as needed to provide this service and to comply with applicable recordkeeping requirements.</p>

<h2>Questions</h2>
<p>Contact us at {contact}. See also our <a href="{PUBLIC_BASE_URL}/legal/sms-terms/{customer_id}">SMS Terms &amp; Conditions</a>.</p>
"""
    return _legal_page_shell("SMS Privacy Policy", business_name, body)


# ===========================================================================
# CRM — Phase 1. Contacts, timeline, notes, tasks, job value.
# All /crm/{customer_id}/... routes use the same Bearer-token check as
# /account/{customer_id}, and every query is pinned to that customer_id, so
# one account can never read another's contacts (mismatched ids → 404).
# ===========================================================================
from typing import Optional
from pydantic import BaseModel

CRM_STATUSES = ("new", "contacted", "qualified", "booked", "won", "lost", "do_not_contact")


def _require_uuid(value: str, what: str = "Not found"):
    if not value or not UUID_RE.match(value):
        raise HTTPException(404, what)


def _get_contact_or_404(customer_id: str, contact_id: str) -> dict:
    _require_uuid(contact_id, "Contact not found")
    r = (sb.table("recall_contacts").select("*")
         .eq("id", contact_id).eq("customer_id", customer_id).limit(1).execute())
    if not r.data:
        raise HTTPException(404, "Contact not found")
    return r.data[0]


class ContactCreate(BaseModel):
    phone: str
    name: Optional[str] = None
    email: Optional[str] = None
    location_id: Optional[str] = None
    note: Optional[str] = None


class ContactPatch(BaseModel):
    memory: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    job_value: Optional[float] = None
    lost_reason: Optional[str] = None


class NoteCreate(BaseModel):
    body: str


class TaskCreate(BaseModel):
    title: Optional[str] = None
    due_at: Optional[str] = None  # ISO 8601
    kind: str = "owner"           # owner (reminder for you) | ai_text | ai_call
    message: Optional[str] = None  # what the AI texts/says, for ai_* kinds


class TaskPatch(BaseModel):
    title: Optional[str] = None
    due_at: Optional[str] = None
    message: Optional[str] = None
    done: Optional[bool] = None


@app.get("/crm/{customer_id}/contacts")
def crm_list_contacts(customer_id: str, status: str = None, q: str = None, location_id: str = None,
                      page: int = 1, limit: int = 50, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    if status and status not in CRM_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(CRM_STATUSES)}")
    if location_id:
        get_location_for_customer(customer_id, location_id)  # 404s if not theirs
    limit = max(1, min(int(limit or 50), 200))
    page = max(1, int(page or 1))
    r = sb.rpc("recall_crm_list_contacts", {
        "p_customer_id": customer_id, "p_status": status, "p_q": (q or "")[:80] or None,
        "p_location_id": location_id, "p_limit": limit, "p_offset": (page - 1) * limit,
    }).execute()
    data = r.data or {}
    return {**data, "page": page, "limit": limit}


@app.post("/crm/{customer_id}/contacts")
def crm_create_contact(customer_id: str, payload: ContactCreate, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    phone = normalize_e164(payload.phone)
    if not phone:
        raise HTTPException(422, "That phone number doesn't look right — include the area code.")
    if payload.location_id:
        get_location_for_customer(customer_id, payload.location_id)
    existing = (sb.table("recall_contacts").select("id")
                .eq("customer_id", customer_id).eq("phone", phone).limit(1).execute())
    if existing.data:
        raise HTTPException(409, {"message": "A contact with that phone number already exists.",
                                  "contact_id": existing.data[0]["id"]})
    row = {
        "customer_id": customer_id, "phone": phone, "source": "manual",
        "name": (payload.name or "").strip() or None,
        "email": (payload.email or "").strip() or None,
        "location_id": payload.location_id,
    }
    created = sb.table("recall_contacts").insert(row).execute().data[0]
    if (payload.note or "").strip():
        sb.table("recall_contact_activities").insert({
            "contact_id": created["id"], "customer_id": customer_id,
            "type": "note", "body": payload.note.strip()[:5000],
        }).execute()
    return created


@app.get("/crm/{customer_id}/contacts/{contact_id}")
def crm_get_contact(customer_id: str, contact_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    contact = _get_contact_or_404(customer_id, contact_id)
    activities = (sb.table("recall_contact_activities")
                  .select("id, type, body, metadata, created_at")
                  .eq("contact_id", contact_id).eq("customer_id", customer_id)
                  .order("created_at", desc=True).limit(500).execute())
    tasks = (sb.table("recall_tasks").select("*")
             .eq("contact_id", contact_id).eq("customer_id", customer_id)
             .order("done_at", desc=False, nullsfirst=True).order("due_at").execute())
    return {"contact": contact, "activities": activities.data, "tasks": tasks.data}


@app.patch("/crm/{customer_id}/contacts/{contact_id}")
def crm_update_contact(customer_id: str, contact_id: str, payload: ContactPatch, background: BackgroundTasks,
                       authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    _require_uuid(contact_id, "Contact not found")
    patch = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    if not patch:
        raise HTTPException(422, "Nothing to update.")
    if "memory" in patch:
        _get_contact_or_404(customer_id, contact_id)
        mem = (patch.pop("memory") or "").strip()[:MEMORY_MAX_CHARS] or None
        sb.table("recall_contacts").update({
            "memory": mem, "memory_updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", contact_id).eq("customer_id", customer_id).execute()
        if not patch:
            return _get_contact_or_404(customer_id, contact_id)
    if "status" in patch and patch["status"] not in CRM_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(CRM_STATUSES)}")
    if patch.get("email") and "@" not in patch["email"]:
        raise HTTPException(422, "That email address doesn't look right.")
    try:
        r = sb.rpc("recall_crm_update_contact", {
            "p_customer_id": customer_id, "p_contact_id": contact_id, "p_patch": patch,
        }).execute()
    except Exception as e:
        msg = str(e)
        if "contact_not_found" in msg:
            raise HTTPException(404, "Contact not found")
        if "job_value_required_for_won" in msg:
            raise HTTPException(422, "Enter the job amount to mark this contact Won.")
        if "job_value_negative" in msg:
            raise HTTPException(422, "Job value can't be negative.")
        if "invalid_status" in msg:
            raise HTTPException(422, "Invalid status.")
        log.exception(f"CRM update failed for contact {contact_id}")
        raise HTTPException(500, "Couldn't save that change — please try again.")
    if patch.get("status") == "won" and (r.data or {}).get("job_value") is not None:
        background.add_task(update_contact_memory, customer_id, None,
                            f"Job completed and paid: ${float(r.data['job_value']):,.2f}.", "owner update",
                            None, contact_id)
    return r.data


class SmsCreate(BaseModel):
    body: str


@app.post("/crm/{customer_id}/contacts/{contact_id}/sms")
def crm_send_sms(customer_id: str, contact_id: str, payload: SmsCreate, authorization: str = Header(None)):
    """Owner texts a contact from the CallsKept number, so the reply comes
    back into the same thread (and the AI sees it as context). Goes through
    send_customer_sms, so opted-out contacts are blocked and logged."""
    require_auth(customer_id, authorization)
    require_twilio()
    contact = _get_contact_or_404(customer_id, contact_id)
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(422, "Write a message first.")
    if len(body) > 1000:
        raise HTTPException(422, "That message is too long — keep it under 1,000 characters.")
    if contact.get("opted_out"):
        raise HTTPException(409, "This contact texted STOP, so CallsKept can't text them until they reply START.")
    try:
        loc = get_location_for_customer(customer_id, contact.get("location_id"))
    except HTTPException:
        loc = get_primary_location(customer_id)
    if not loc.get("twilio_number"):
        raise HTTPException(409, "This location doesn't have a CallsKept number yet.")
    try:
        sid = send_customer_sms(customer_id, contact["phone"], loc["twilio_number"], body,
                                location_id=loc["id"], kind="owner_manual")
    except Exception as e:
        log.error(f"Owner SMS failed for contact {contact_id}: {e}")
        raise HTTPException(502, "The text couldn't be sent — please try again in a minute.")
    if not sid:
        raise HTTPException(409, "This contact texted STOP, so CallsKept can't text them until they reply START.")
    try:
        sb.table("recall_sms_messages").insert({
            "location_id": loc["id"], "customer_id": customer_id,
            "direction": "outbound", "from_number": loc["twilio_number"], "body": body,
        }).execute()
    except Exception as e:
        log.error(f"Couldn't mirror owner SMS into recall_sms_messages: {e}")
    return {"ok": True, "sid": sid, "from_number": loc["twilio_number"]}


# ---------------------------------------------------------------------------
# OUTBOUND CALLS FROM THE CRM — two modes, both from the CallsKept number:
#   ai_message: the AI voice calls the contact, reads the owner's message,
#               and offers "press 1" to connect them to the business.
#   connect:    rings the OWNER's phone first, then bridges to the contact —
#               click-to-call for owners on a computer.
# Each call is one call_out activity; Twilio status callbacks update it.
# ---------------------------------------------------------------------------
CALL_VOICE = os.environ.get("CALL_VOICE", "Polly.Joanna-Neural")
CALL_HOURS = (8, 21)  # local 8am–9pm — never robo-call people at night


class CallCreate(BaseModel):
    mode: str  # "ai_message" | "connect"
    message: Optional[str] = None


def _owner_phone(loc: dict, customer_id: str) -> str:
    if loc.get("transfer_phone"):
        return loc["transfer_phone"]
    if loc.get("business_phone"):
        return loc["business_phone"]
    cust = sb.table(TABLE_CUST).select("business_phone").eq("id", customer_id).execute()
    return (cust.data or [{}])[0].get("business_phone")


def _call_activity(activity_id: str) -> dict:
    if not UUID_RE.match(activity_id or ""):
        return None
    r = (sb.table("recall_contact_activities")
         .select("id, contact_id, customer_id, body, metadata, recall_contacts(phone, name)")
         .eq("id", activity_id).eq("type", "call_out").limit(1).execute())
    return r.data[0] if r.data else None


def _place_crm_call(customer_id: str, contact: dict, mode: str, message: str = None, kind: str = None) -> dict:
    """Shared by the Call button, scheduled AI follow-ups and the automatic
    follow-up sequence. Raises HTTPException on anything the caller should see."""
    if contact.get("opted_out") or contact.get("status") == "do_not_contact":
        raise HTTPException(409, "This contact is marked Do Not Contact.")
    if mode not in ("ai_message", "connect"):
        raise HTTPException(422, "mode must be 'ai_message' or 'connect'.")
    try:
        loc = get_location_for_customer(customer_id, contact.get("location_id"))
    except HTTPException:
        loc = get_primary_location(customer_id)
    if not loc.get("twilio_number"):
        raise HTTPException(409, "This location doesn't have a CallsKept number yet.")
    owner = normalize_e164(_owner_phone(loc, customer_id) or "")

    message = (message or "").strip()
    if mode == "ai_message":
        if not message:
            raise HTTPException(422, "Write the message the AI should say.")
        if len(message) > 600:
            raise HTTPException(422, "Keep the message under 600 characters — about 40 seconds spoken.")
        from zoneinfo import ZoneInfo
        hour = datetime.now(ZoneInfo(BUSINESS_TZ)).hour
        if not (CALL_HOURS[0] <= hour < CALL_HOURS[1]):
            raise HTTPException(409, "AI calls only go out between 8 AM and 9 PM. Schedule it for tomorrow instead.")
    else:
        if not owner:
            raise HTTPException(409, "Add your phone number in Phone connection first, so we know which phone to ring.")
        if owner == contact["phone"]:
            raise HTTPException(409, "That's your own number.")

    meta = {"kind": mode, "call_status": "queued", "location_id": loc["id"]}
    if kind:
        meta["trigger"] = kind
    act = sb.table("recall_contact_activities").insert({
        "contact_id": contact["id"], "customer_id": customer_id, "type": "call_out",
        "body": message or None, "metadata": meta,
    }).execute().data[0]

    to = contact["phone"] if mode == "ai_message" else owner
    try:
        call = twilio_client.calls.create(
            to=to, from_=loc["twilio_number"],
            url=f"{PUBLIC_BASE_URL}/twilio/crm-call/{act['id']}", method="POST",
            status_callback=f"{PUBLIC_BASE_URL}/twilio/crm-call-status/{act['id']}",
            status_callback_event=["completed"], status_callback_method="POST",
            timeout=25,
        )
    except Exception as e:
        log.error(f"CRM call failed for contact {contact['id']}: {e}")
        sb.table("recall_contact_activities").update({
            "metadata": {**meta, "call_status": "failed", "error": str(e)[:200]},
        }).eq("id", act["id"]).execute()
        raise HTTPException(502, "The call couldn't be placed — please try again in a minute.")

    sb.table("recall_contact_activities").update({
        "metadata": {**meta, "call_status": "ringing", "call_sid": call.sid},
    }).eq("id", act["id"]).execute()
    sb.table("recall_contacts").update({"last_activity_at": datetime.now(timezone.utc).isoformat()}).eq("id", contact["id"]).execute()
    if contact.get("status") == "new":
        sb.rpc("recall_crm_update_contact", {"p_customer_id": customer_id, "p_contact_id": contact["id"],
                                             "p_patch": {"status": "contacted"}}).execute()
    return {"ok": True, "activity_id": act["id"], "dialing": to}


@app.post("/crm/{customer_id}/contacts/{contact_id}/call")
def crm_call(customer_id: str, contact_id: str, payload: CallCreate, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    require_twilio()
    contact = _get_contact_or_404(customer_id, contact_id)
    return _place_crm_call(customer_id, contact, payload.mode, payload.message)


@app.post("/twilio/crm-call/{activity_id}")
async def crm_call_twiml(activity_id: str):
    vr = VoiceResponse()
    act = _call_activity(activity_id)
    if not act:
        vr.hangup()
        return PlainTextResponse(str(vr), media_type="application/xml")
    meta = act.get("metadata") or {}
    contact = act.get("recall_contacts") or {}
    loc = sb.table(TABLE_LOC).select("*, recall_customers(business_name)").eq("id", meta.get("location_id")).execute()
    row = (loc.data or [{}])[0]
    business = (row.get("recall_customers") or {}).get("business_name") or "the business"

    if meta.get("kind") == "connect":
        name = contact.get("name") or "your customer"
        vr.say(f"CallsKept. Connecting you to {name} now.", voice=CALL_VOICE)
        dial = Dial(caller_id=row.get("twilio_number"), timeout=25)
        dial.number(contact.get("phone"))
        vr.append(dial)
        return PlainTextResponse(str(vr), media_type="application/xml")

    first = (contact.get("name") or "").split(" ")[0]
    greeting = f"Hi {first}, this" if first else "Hi, this"
    gather = vr.gather(num_digits=1, action=f"{PUBLIC_BASE_URL}/twilio/crm-call-gather/{activity_id}",
                       method="POST", timeout=6)
    gather.say(f"{greeting} is an automated call from {business}.", voice=CALL_VOICE)
    gather.pause(length=1)
    gather.say(act.get("body") or "", voice=CALL_VOICE)
    gather.pause(length=1)
    gather.say("To talk with someone now, press 1. Or text this number any time. Thank you.", voice=CALL_VOICE)
    vr.say("Goodbye.", voice=CALL_VOICE)
    return PlainTextResponse(str(vr), media_type="application/xml")


@app.post("/twilio/crm-call-gather/{activity_id}")
async def crm_call_gather(activity_id: str, request: Request):
    form = await request.form()
    vr = VoiceResponse()
    act = _call_activity(activity_id)
    if not act or form.get("Digits") != "1":
        vr.say("Thank you. Goodbye.", voice=CALL_VOICE)
        return PlainTextResponse(str(vr), media_type="application/xml")
    meta = act.get("metadata") or {}
    loc = sb.table(TABLE_LOC).select("*").eq("id", meta.get("location_id")).execute()
    row = (loc.data or [{}])[0]
    owner = _owner_phone(row, act["customer_id"])
    try:
        sb.table("recall_contact_activities").update({"metadata": {**meta, "pressed_1": True}}).eq("id", activity_id).execute()
    except Exception:
        pass
    if not owner:
        vr.say("Sorry, no one is available right now. We'll call you back soon.", voice=CALL_VOICE)
        return PlainTextResponse(str(vr), media_type="application/xml")
    vr.say("Connecting you now.", voice=CALL_VOICE)
    dial = Dial(caller_id=row.get("twilio_number"), timeout=25)
    dial.number(owner)
    vr.append(dial)
    return PlainTextResponse(str(vr), media_type="application/xml")


@app.post("/twilio/crm-call-status/{activity_id}")
async def crm_call_status(activity_id: str, request: Request):
    form = await request.form()
    act = _call_activity(activity_id)
    if act:
        meta = act.get("metadata") or {}
        sb.table("recall_contact_activities").update({"metadata": {
            **meta, "call_status": form.get("CallStatus"),
            "duration_secs": int(form.get("CallDuration") or 0),
            "answered_by": form.get("AnsweredBy"),
        }}).eq("id", activity_id).execute()
    return PlainTextResponse("", media_type="application/xml")


@app.post("/crm/{customer_id}/contacts/{contact_id}/notes")
def crm_add_note(customer_id: str, contact_id: str, payload: NoteCreate, background: BackgroundTasks,
                 authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    _get_contact_or_404(customer_id, contact_id)
    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(422, "Note can't be empty.")
    note = sb.table("recall_contact_activities").insert({
        "contact_id": contact_id, "customer_id": customer_id, "type": "note", "body": body[:5000],
    }).execute().data[0]
    sb.table("recall_contacts").update({"last_activity_at": note["created_at"]}).eq("id", contact_id).execute()
    background.add_task(update_contact_memory, customer_id, None, f"Owner's note: {body}", "owner note",
                        None, contact_id)
    return note


def _parse_due(due_at: Optional[str]):
    if not due_at:
        return None
    try:
        dt = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, "due_at must be an ISO date/time.")
    if dt.tzinfo is None:
        from zoneinfo import ZoneInfo
        dt = dt.replace(tzinfo=ZoneInfo(BUSINESS_TZ))
    return dt.isoformat()


@app.post("/crm/{customer_id}/contacts/{contact_id}/tasks")
def crm_create_task(customer_id: str, contact_id: str, payload: TaskCreate, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    contact = _get_contact_or_404(customer_id, contact_id)
    kind = payload.kind or "owner"
    if kind not in ("owner", "ai_text", "ai_call"):
        raise HTTPException(422, "kind must be owner, ai_text or ai_call.")
    message = (payload.message or "").strip()
    title = (payload.title or "").strip()
    due = _parse_due(payload.due_at)
    if kind == "owner":
        if not title:
            raise HTTPException(422, "Task needs a title.")
    else:
        if contact.get("opted_out") or contact.get("status") == "do_not_contact":
            raise HTTPException(409, "This contact is marked Do Not Contact.")
        if not message:
            raise HTTPException(422, "Write what the AI should " + ("text." if kind == "ai_text" else "say."))
        limit = 1000 if kind == "ai_text" else 600
        if len(message) > limit:
            raise HTTPException(422, f"Keep the message under {limit} characters.")
        if not due:
            due = datetime.now(timezone.utc).isoformat()
        title = title or (("AI texts: " if kind == "ai_text" else "AI calls: ") + message[:80])
    return sb.table("recall_tasks").insert({
        "contact_id": contact_id, "customer_id": customer_id, "kind": kind,
        "title": title[:300], "message": message or None, "due_at": due,
    }).execute().data[0]


@app.patch("/crm/{customer_id}/tasks/{task_id}")
def crm_update_task(customer_id: str, task_id: str, payload: TaskPatch, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    _require_uuid(task_id, "Task not found")
    existing = (sb.table("recall_tasks").select("id, kind, status")
                .eq("id", task_id).eq("customer_id", customer_id).limit(1).execute())
    if not existing.data:
        raise HTTPException(404, "Task not found")
    task = existing.data[0]
    fields = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    is_ai = task["kind"] != "owner"
    if is_ai and task["status"] != "pending" and set(fields) - {"done"}:
        raise HTTPException(409, "This follow-up already ran, so it can't be edited.")
    updates = {}
    if "title" in fields:
        if not (fields["title"] or "").strip():
            raise HTTPException(422, "Task needs a title.")
        updates["title"] = fields["title"].strip()[:300]
    if "message" in fields and is_ai:
        if not (fields["message"] or "").strip():
            raise HTTPException(422, "The message can't be empty.")
        updates["message"] = fields["message"].strip()[:1000]
    if "due_at" in fields:
        updates["due_at"] = _parse_due(fields["due_at"])
    if "done" in fields:
        now = datetime.now(timezone.utc).isoformat()
        if is_ai:
            # Checking off a pending AI follow-up cancels it; unchecking a canceled one re-arms it.
            if fields["done"] and task["status"] == "pending":
                updates.update({"status": "skipped", "done_at": now, "result": "Canceled by you"})
            elif not fields["done"] and task["status"] == "skipped":
                updates.update({"status": "pending", "done_at": None, "result": None, "executed_at": None})
        else:
            updates["done_at"] = now if fields["done"] else None
            updates["status"] = "done" if fields["done"] else "pending"
    if not updates:
        raise HTTPException(422, "Nothing to update.")
    return (sb.table("recall_tasks").update(updates)
            .eq("id", task_id).eq("customer_id", customer_id).execute()).data[0]


@app.get("/crm/{customer_id}/tasks")
def crm_list_tasks(customer_id: str, open: bool = True, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    qry = (sb.table("recall_tasks")
           .select("*, recall_contacts(id, name, phone, status)")
           .eq("customer_id", customer_id))
    if open:
        qry = qry.is_("done_at", "null").order("due_at", nullsfirst=False).order("created_at")
    else:
        qry = qry.order("created_at", desc=True)
    return {"tasks": qry.limit(200).execute().data}


@app.get("/crm/{customer_id}/summary")
def crm_summary(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    return sb.rpc("recall_crm_summary", {"p_customer_id": customer_id}).execute().data


@app.post("/admin/crm-backfill")
def admin_crm_backfill(authorization: str = Header(None)):
    """One-time import of existing calls/texts/messages/appointments into the
    CRM. Safe to run any number of times — every imported event has a dedupe
    key, and only history older than each account's first live-logged event
    is replayed."""
    require_admin(authorization)
    return sb.rpc("recall_crm_backfill", {}).execute().data


# ---------------------------------------------------------------------------
# ELEVENLABS POST-CALL WEBHOOK — logs every AI-answered call (with its
# summary) onto the caller's contact timeline. Configure in ElevenLabs as a
# post-call transcription webhook pointing at
#   {PUBLIC_BASE_URL}/elevenlabs/post-call
# and put its signing secret in Render as ELEVENLABS_WEBHOOK_SECRET.
# ---------------------------------------------------------------------------
ELEVENLABS_WEBHOOK_SECRET = os.environ.get("ELEVENLABS_WEBHOOK_SECRET")


def _verify_elevenlabs_signature(raw: bytes, header: str) -> bool:
    if not ELEVENLABS_WEBHOOK_SECRET or not header:
        return False
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    ts, sig = parts.get("t"), parts.get("v0")
    if not ts or not sig:
        return False
    try:
        if abs(datetime.now(timezone.utc).timestamp() - int(ts)) > 30 * 60:
            return False
    except ValueError:
        return False
    expected = hmac.new(ELEVENLABS_WEBHOOK_SECRET.encode(), f"{ts}.".encode() + raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


@app.post("/elevenlabs/post-call")
async def elevenlabs_post_call(request: Request, background: BackgroundTasks):
    raw = await request.body()
    if not ELEVENLABS_WEBHOOK_SECRET:
        raise HTTPException(503, "ELEVENLABS_WEBHOOK_SECRET isn't set.")
    if not _verify_elevenlabs_signature(raw, request.headers.get("elevenlabs-signature")):
        raise HTTPException(401, "Invalid signature.")
    import json as _json
    try:
        event = _json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Bad JSON.")
    if event.get("type") != "post_call_transcription":
        return {"ok": True, "ignored": event.get("type")}

    data = event.get("data") or {}
    conv_id = data.get("conversation_id")
    meta = data.get("metadata") or {}
    phone_call = meta.get("phone_call") or {}
    dyn = ((data.get("conversation_initiation_client_data") or {}).get("dynamic_variables")) or {}
    caller = phone_call.get("external_number") or dyn.get("system__caller_id")
    agent_number = phone_call.get("agent_number") or dyn.get("system__called_number")

    location = get_location_by_number(agent_number) if agent_number else None
    if not location and data.get("agent_id"):
        loc = (sb.table(TABLE_LOC).select("id, customer_id")
               .eq("elevenlabs_agent_id", data["agent_id"]).limit(1).execute())
        if loc.data:
            location = {"customer_id": loc.data[0]["customer_id"], "location_id": loc.data[0]["id"]}
    if not location or not caller:
        log.info(f"post-call {conv_id}: no matching location/caller (agent {data.get('agent_id')})")
        return {"ok": True, "logged": False}

    analysis = data.get("analysis") or {}
    summary = (analysis.get("transcript_summary") or "").strip() or "AI answered the call."
    collected = analysis.get("data_collection_results") or {}
    name = None
    for key in ("caller_name", "customer_name", "name"):
        val = (collected.get(key) or {}).get("value") if isinstance(collected.get(key), dict) else None
        if val:
            name = str(val).strip()
            break

    upsert_contact_and_log(
        location["customer_id"], caller, "ai_call", body=summary,
        metadata={"conversation_id": conv_id, "duration_secs": meta.get("call_duration_secs"),
                  "call_successful": analysis.get("call_successful")},
        source="ai_call", location_id=location.get("location_id"), name=name,
        source_ref=f"el:{conv_id}" if conv_id else None,
    )
    if summary and summary != "AI answered the call.":
        background.add_task(update_contact_memory, location["customer_id"], caller,
                            f"Phone call summary: {summary}", "phone call", name, None, location.get("location_id"))
    return {"ok": True, "logged": True}


# ===========================================================================
# FOLLOW-UP RUNNER — Supabase pg_cron POSTs here every 5 minutes with a
# secret kept in Supabase Vault (read via the recall_job_secret() RPC, so no
# Render env var is needed). It does two jobs:
#   1. AI follow-ups the owner scheduled on a contact (ai_text / ai_call tasks)
#   2. The automatic sequence for missed callers who never replied
#      (text after N hours, AI call after M hours) — off unless the location
#      turned it on. Eligibility lives in recall_crm_due_auto_followups().
# Every send goes through the same opt-out guard and calling-hours rules.
# ===========================================================================
_job_secret_cache = {"value": None, "at": 0.0}


def _job_secret() -> str:
    import time
    if not _job_secret_cache["value"] or time.time() - _job_secret_cache["at"] > 600:
        _job_secret_cache["value"] = sb.rpc("recall_job_secret", {}).execute().data
        _job_secret_cache["at"] = time.time()
    return _job_secret_cache["value"]


def _location_sms_number(customer_id: str, contact: dict) -> dict:
    try:
        return get_location_for_customer(customer_id, contact.get("location_id"))
    except HTTPException:
        return get_primary_location(customer_id)


def _run_text(customer_id: str, contact: dict, message: str, kind: str) -> str:
    loc = _location_sms_number(customer_id, contact)
    if not loc.get("twilio_number"):
        raise RuntimeError("no CallsKept number on this location")
    sid = send_customer_sms(customer_id, contact["phone"], loc["twilio_number"], message,
                            location_id=loc["id"], kind=kind)
    if not sid:
        return "skipped: contact opted out"
    try:
        sb.table("recall_sms_messages").insert({
            "location_id": loc["id"], "customer_id": customer_id,
            "direction": "outbound", "from_number": loc["twilio_number"], "body": message,
        }).execute()
    except Exception:
        pass
    return "sent"


@app.post("/internal/run-followups")
async def run_followups(request: Request):
    secret = request.headers.get("x-job-secret") or ""
    try:
        expected = _job_secret()
    except Exception as e:
        log.error(f"Couldn't read job secret: {e}")
        raise HTTPException(503, "Job secret unavailable.")
    if not expected or not hmac.compare_digest(secret, expected):
        raise HTTPException(401, "Invalid job secret.")
    if twilio_client is None:
        return {"ok": False, "reason": "twilio not configured"}

    now = datetime.now(timezone.utc)
    out = {"tasks_done": 0, "tasks_failed": 0, "tasks_waiting": 0, "auto_texts": 0, "auto_calls": 0, "auto_failed": 0}

    # 1. Scheduled AI follow-ups
    due = (sb.table("recall_tasks").select("*, recall_contacts(*)")
           .neq("kind", "owner").eq("status", "pending").is_("executed_at", "null")
           .lte("due_at", now.isoformat()).order("due_at").limit(40).execute()).data
    for t in due:
        claimed = (sb.table("recall_tasks").update({"executed_at": now.isoformat()})
                   .eq("id", t["id"]).is_("executed_at", "null").eq("status", "pending").execute()).data
        if not claimed:
            continue  # another run took it
        contact = t.get("recall_contacts") or {}
        status, result = "done", ""
        try:
            if contact.get("opted_out") or contact.get("status") == "do_not_contact":
                status, result = "skipped", "Contact is marked Do Not Contact"
            elif t["kind"] == "ai_text":
                r = _run_text(t["customer_id"], contact, t["message"], "scheduled_followup")
                status, result = ("skipped", "Contact opted out") if r.startswith("skipped") else ("done", "Text sent")
            else:
                _place_crm_call(t["customer_id"], contact, "ai_message", t["message"], kind="scheduled_followup")
                result = "AI call placed"
        except HTTPException as e:
            if e.status_code == 409 and "8 AM" in str(e.detail):
                # Outside calling hours: put it back and try again on a later run.
                sb.table("recall_tasks").update({"executed_at": None}).eq("id", t["id"]).execute()
                out["tasks_waiting"] += 1
                continue
            status, result = "failed", str(e.detail)[:200]
        except Exception as e:
            log.error(f"Follow-up task {t['id']} failed: {e}")
            status, result = "failed", "Couldn't send — " + str(e)[:150]
        sb.table("recall_tasks").update({
            "status": status, "result": result, "done_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", t["id"]).execute()
        out["tasks_done" if status == "done" else "tasks_failed"] += 1

    # 2. Automatic sequence for missed callers
    try:
        rows = sb.rpc("recall_crm_due_auto_followups", {}).execute().data or []
    except Exception as e:
        log.error(f"Auto follow-up query failed: {e}")
        rows = []
    for r in rows[:40]:
        cutoff = (now - timedelta(minutes=30)).isoformat()
        prev = (sb.table("recall_contacts").select("*").eq("id", r["contact_id"]).execute().data or [{}])[0]
        sent_before = prev.get("auto_followups_sent", 0) if prev.get("auto_followup_anchor_at") and \
            prev["auto_followup_anchor_at"][:19] == str(r["anchor"])[:19] else 0
        claimed = (sb.table("recall_contacts").update({
            "auto_followup_anchor_at": r["anchor"], "auto_followups_sent": sent_before + 1,
            "last_auto_followup_at": now.isoformat(),
        }).eq("id", r["contact_id"]).or_(f"last_auto_followup_at.is.null,last_auto_followup_at.lt.{cutoff}").execute()).data
        if not claimed:
            continue
        try:
            if r["step"] == "text":
                _run_text(r["customer_id"], prev, r["message"], "auto_followup")
                out["auto_texts"] += 1
            else:
                _place_crm_call(r["customer_id"], prev, "ai_message", r["message"], kind="auto_followup")
                out["auto_calls"] += 1
        except Exception as e:
            log.error(f"Auto follow-up for contact {r['contact_id']} failed: {getattr(e, 'detail', e)}")
            out["auto_failed"] += 1
    if any(out.values()):
        log.info(f"run-followups: {out}")
    return out


class FollowupSettings(BaseModel):
    enabled: Optional[bool] = None
    text_after_hours: Optional[int] = None
    call_after_hours: Optional[int] = None
    call_enabled: Optional[bool] = None
    text_message: Optional[str] = None
    call_message: Optional[str] = None


def _followup_view(loc: dict) -> dict:
    return {
        "location_id": loc["id"], "location_label": loc.get("location_label"),
        "enabled": loc.get("auto_followup_enabled", False),
        "text_after_hours": loc.get("followup_text_after_hours", 3),
        "call_after_hours": loc.get("followup_call_after_hours", 24),
        "call_enabled": loc.get("followup_call_enabled", True),
        "text_message": loc.get("followup_text_message"),
        "call_message": loc.get("followup_call_message"),
    }


@app.get("/crm/{customer_id}/followup-settings")
def get_followup_settings(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    return _followup_view(get_location_for_customer(customer_id, location_id))


@app.post("/crm/{customer_id}/followup-settings")
def save_followup_settings(customer_id: str, payload: FollowupSettings, location_id: str = None,
                           authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    loc = get_location_for_customer(customer_id, location_id)
    f = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    upd = {}
    if "enabled" in f:
        upd["auto_followup_enabled"] = bool(f["enabled"])
        if f["enabled"] and not loc.get("auto_followup_enabled"):
            # Only missed calls from now on — never blast old callers when it's switched on.
            upd["auto_followup_enabled_at"] = datetime.now(timezone.utc).isoformat()
    if "text_after_hours" in f:
        if not (1 <= int(f["text_after_hours"]) <= 72):
            raise HTTPException(422, "Text delay must be between 1 and 72 hours.")
        upd["followup_text_after_hours"] = int(f["text_after_hours"])
    if "call_after_hours" in f:
        if not (2 <= int(f["call_after_hours"]) <= 168):
            raise HTTPException(422, "Call delay must be between 2 hours and 7 days.")
        upd["followup_call_after_hours"] = int(f["call_after_hours"])
    th = upd.get("followup_text_after_hours", loc.get("followup_text_after_hours", 3))
    ch = upd.get("followup_call_after_hours", loc.get("followup_call_after_hours", 24))
    if ch <= th:
        raise HTTPException(422, "The AI call should come after the text — set a longer call delay.")
    if "call_enabled" in f:
        upd["followup_call_enabled"] = bool(f["call_enabled"])
    for k, col, lim in (("text_message", "followup_text_message", 1000), ("call_message", "followup_call_message", 600)):
        if k in f:
            upd[col] = (f[k] or "").strip()[:lim] or None
    if upd:
        loc = sb.table(TABLE_LOC).update(upd).eq("id", loc["id"]).execute().data[0]
    return _followup_view(loc)
