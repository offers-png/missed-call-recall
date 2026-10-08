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
import time
import html
import hmac
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta

import jwt
import requests
from starlette.concurrency import run_in_threadpool
from fastapi import FastAPI, Request, Form, HTTPException, Header, UploadFile, File, BackgroundTasks, Depends
from fastapi.responses import PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from twilio.twiml.voice_response import VoiceResponse, Dial
from twilio.rest import Client as TwilioClient
from supabase import create_client, Client
import stripe
from typing import Optional
from pydantic import BaseModel

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
# Elite (AI voice + calendar booking + Google profile). Falls back to the Pro
# price only if Elite's own price hasn't been added yet.
STRIPE_PRICE_ID_ELITE = os.environ.get("STRIPE_PRICE_ID_ELITE")
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


def customer_messaging_service() -> str:
    """Messaging Service that new customer numbers join (the one on the approved
    A2P campaign). Switchable at runtime via app setting customer_messaging_service_sid;
    platform notices keep using TWILIO_MESSAGING_SERVICE_SID."""
    return app_setting("customer_messaging_service_sid") or TWILIO_MESSAGING_SERVICE_SID
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://missed-call-recall.onrender.com")
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
if STRIPE_SECRET_KEY and not STRIPE_SECRET_KEY.startswith(("sk_", "rk_")):
    log.error("STRIPE_SECRET_KEY is not a secret key (it should start with sk_test_ or sk_live_, "
              "not pk_). Billing will fail until it's fixed in Render.")
# The database client's default shared HTTP/2 connection breaks under
# concurrent requests ("httpx.ReadError: [Errno 11] Resource temporarily
# unavailable" → random 500s on dashboard pages). Plain HTTP/1.1 with a
# connection pool is stable across threads.
def _make_supabase() -> Client:
    try:
        import httpx
        from supabase.lib.client_options import SyncClientOptions
        http = httpx.Client(http2=False, timeout=30, follow_redirects=True,
                            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20))
        return create_client(SUPABASE_URL, SUPABASE_KEY, options=SyncClientOptions(httpx_client=http))
    except Exception as e:
        log.warning(f"Falling back to default Supabase client: {e}")
        return create_client(SUPABASE_URL, SUPABASE_KEY)


sb: Client = _make_supabase()
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
    now = datetime.now(timezone.utc)
    payload = {"customer_id": customer_id, "typ": "session", "iat": int(now.timestamp()),
               "exp": now + timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def make_purpose_token(customer_id: str, typ: str, minutes: int, **extra) -> str:
    """Single-purpose signed links (email verification, password reset). They
    carry a typ that require_auth refuses, so they can never act as a login."""
    payload = {"customer_id": customer_id, "typ": typ,
               "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes), **extra}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def read_purpose_token(token: str, typ: str) -> dict:
    try:
        payload = jwt.decode(token or "", JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(400, "This link has expired — please request a new one.")
    except jwt.InvalidTokenError:
        raise HTTPException(400, "This link isn't valid.")
    if payload.get("typ") != typ:
        raise HTTPException(400, "This link isn't valid.")
    return payload


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
    if payload.get("typ") not in (None, "session"):
        raise HTTPException(401, "Invalid session.")
    if payload.get("customer_id") != customer_id:
        raise HTTPException(403, "Not authorized for this account.")
    changed = _password_changed_ts(customer_id)
    if changed and int(payload.get("iat") or 0) < changed - 2:
        raise HTTPException(401, "Your password was changed — please log in again.")


_PWD_CHANGED_CACHE: dict = {}


def _password_changed_ts(customer_id: str) -> int:
    """When this account's password last changed (cached 60s). Sessions issued
    before that are signed out."""
    hit = _PWD_CHANGED_CACHE.get(customer_id)
    if hit and hit[1] > time.time():
        return hit[0]
    ts = 0
    try:
        rows = sb.table(TABLE_CUST).select("password_changed_at").eq("id", customer_id).limit(1).execute().data
        if rows and rows[0].get("password_changed_at"):
            ts = int(datetime.fromisoformat(str(rows[0]["password_changed_at"]).replace("Z", "+00:00")).timestamp())
    except Exception as e:
        log.warning(f"Couldn't check password change time for {customer_id}: {e}")
        return hit[0] if hit else 0  # don't cache a failed lookup
    _PWD_CHANGED_CACHE[customer_id] = (ts, time.time() + 60)
    return ts


def _derived_secret(name: str) -> str:
    """Stable fallback for an unset internal secret: derived from JWT_SECRET so
    it survives restarts (a random per-restart value silently broke things)."""
    return hmac.new(JWT_SECRET.encode(), f"callskept:{name}".encode(), hashlib.sha256).hexdigest()


def secret_ok(given, expected) -> bool:
    return bool(expected) and hmac.compare_digest(str(given or ""), str(expected))


ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET:
    ADMIN_SECRET = _derived_secret("admin")
    log.warning("ADMIN_SECRET not set — using a value derived from JWT_SECRET. Set it in Render.")


def require_admin(authorization: str = Header(None)):
    """For Saleh-only internal endpoints — not tied to any customer account."""
    if not authorization or not secret_ok(authorization.removeprefix("Bearer ").strip(), ADMIN_SECRET):
        raise HTTPException(401, "Not authorized.")


# ---------------------------------------------------------------------------
# LAUNCH HARDENING — app settings, rate limits, Twilio signature checks,
# account-status gating and send caps.
# ---------------------------------------------------------------------------
_settings_cache = {"at": 0.0, "values": {}}


def app_setting(key: str, default=None):
    """Small runtime switches kept in recall_app_settings (no redeploy needed)."""
    import time
    if time.time() - _settings_cache["at"] > 60:
        try:
            rows = sb.table("recall_app_settings").select("key, value").execute().data or []
            _settings_cache["values"] = {r["key"]: r["value"] for r in rows}
        except Exception as e:
            log.error(f"Couldn't load app settings: {e}")
        _settings_cache["at"] = time.time()
    val = _settings_cache["values"].get(key)
    return default if val is None else val


_rate_buckets: dict = {}


def client_ip(request: Request) -> str:
    # Render sits behind Cloudflare, which overwrites CF-Connecting-IP / True-Client-IP,
    # so those can't be forged. X-Forwarded-For's first entry can, so only the
    # right-most hop (added by the proxy) is used as a fallback.
    for h in ("cf-connecting-ip", "true-client-ip"):
        v = (request.headers.get(h) or "").strip()
        if v:
            return v
    fwd = [x.strip() for x in (request.headers.get("x-forwarded-for") or "").split(",") if x.strip()]
    return (fwd[-1] if fwd else (request.client.host if request.client else "")) or "unknown"


def rate_limit(bucket: str, key: str, limit: int, window_secs: int, message: str = None):
    """In-memory sliding-window limiter (single Render instance). Raises 429."""
    import time
    now = time.time()
    k = (bucket, (key or "").lower())
    hits = [t for t in _rate_buckets.get(k, []) if now - t < window_secs]
    if len(hits) >= limit:
        _rate_buckets[k] = hits
        raise HTTPException(429, message or "Too many attempts — please wait a few minutes and try again.")
    hits.append(now)
    _rate_buckets[k] = hits
    if len(_rate_buckets) > 50000:  # keep memory bounded
        for old in list(_rate_buckets)[:10000]:
            _rate_buckets.pop(old, None)


async def verify_twilio(request: Request):
    """Rejects webhook calls that weren't signed by our Twilio account, so
    nobody can fake a missed call / text and make us send messages."""
    mode = app_setting("twilio_signature_check", "enforce")
    if mode == "off" or not TWILIO_TOKEN:
        return
    from twilio.request_validator import RequestValidator
    sig = request.headers.get("x-twilio-signature", "")
    form = await request.form()
    params = {k: v for k, v in form.multi_items()}
    q = ("?" + request.url.query) if request.url.query else ""
    candidates = {PUBLIC_BASE_URL.rstrip("/") + request.url.path + q}
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if host:
        candidates.add(f"https://{host}{request.url.path}{q}")
    validator = RequestValidator(TWILIO_TOKEN)
    if sig and any(validator.validate(u, params, sig) for u in candidates):
        return
    log.warning(f"Twilio signature check failed for {request.url.path} (mode={mode})")
    if mode == "enforce":
        raise HTTPException(403, "Invalid signature.")


ACTIVE_STATUSES = ("trial", "active")


def customer_status(customer_id: str) -> str:
    r = sb.table(TABLE_CUST).select("status").eq("id", customer_id).limit(1).execute().data
    return (r[0].get("status") if r else None) or "canceled"


def require_active(customer_id: str):
    st = customer_status(customer_id)
    if st == "pending_payment":
        raise HTTPException(402, "Finish checkout to start your trial — open Plans & billing.")
    if st not in ACTIVE_STATUSES:
        raise HTTPException(402, "Your subscription isn't active — update billing in Plans & billing to keep using CallsKept.")


def sends_today(customer_id: str, activity_type: str) -> int:
    from zoneinfo import ZoneInfo
    start = datetime.now(ZoneInfo("America/New_York")).replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        r = (sb.table("recall_contact_activities").select("id", count="exact")
             .eq("customer_id", customer_id).eq("type", activity_type)
             .gte("created_at", start.astimezone(timezone.utc).isoformat()).limit(1).execute())
        return r.count or 0
    except Exception as e:
        log.error(f"Send-cap count failed for {customer_id}: {e}")
        return 0


def is_us_number(e164: str) -> bool:
    return bool(re.fullmatch(r"\+1[2-9]\d{2}[2-9]\d{6}", e164 or ""))


PDF_MAX_BYTES = 5 * 1024 * 1024


async def _read_pdf_upload(pdf) -> bytes:
    data = await pdf.read(PDF_MAX_BYTES + 1)
    if len(data) > PDF_MAX_BYTES:
        raise HTTPException(413, "That PDF is larger than 5 MB — please upload a smaller file.")
    if not data.startswith(b"%PDF"):
        raise HTTPException(415, "That file isn't a PDF.")
    return data


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


@app.exception_handler(stripe.error.StripeError)
async def stripe_error_handler(request: Request, exc):
    """Stripe problems come back as a readable message (with CORS headers, so the
    page shows it) instead of a bare 500 that the browser reports as 'Failed to fetch'."""
    log.error(f"Stripe error on {request.url.path}: {exc}")
    msg = "Billing is temporarily unavailable — please try again in a few minutes."
    if isinstance(exc, (stripe.error.PermissionError, stripe.error.AuthenticationError)):
        msg = "Billing isn't set up correctly yet. We've been alerted — please try again shortly."
        try:
            alert_platform_owner(f"⚠️ CallsKept billing key problem: {str(exc)[:160]}")
        except Exception:
            pass
    elif isinstance(exc, stripe.error.CardError):
        msg = exc.user_message or "Your card was declined."
    return JSONResponse({"detail": msg}, status_code=502)
app.add_middleware(
    CORSMiddleware,
    # Only CallsKept's own site (and its Netlify previews) may call the API from a browser.
    allow_origins=["https://callskept.com", "https://www.callskept.com",
                   "https://glowing-hotteok-00a881.netlify.app"],
    allow_origin_regex=r"https://[a-z0-9-]+--glowing-hotteok-00a881\.netlify\.app",
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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


def sms_plain(text: str, limit: int = 480) -> str:
    """Phones show markdown literally (**bold**), so AI replies are flattened to
    plain text and kept to about three SMS segments."""
    t = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: m.group(1) or m.group(2), text or "")
    t = re.sub(r"(?m)^[ \t]{0,3}#{1,6}[ \t]*", "", t)
    t = re.sub(r"`+", "", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"\1", t)
    t = re.sub(r"\n{3,}", "\n\n", t).strip()
    if len(t) > limit:
        cut = t[:limit].rsplit(" ", 1)[0].rstrip(",;:—- ")
        t = cut + "…"
    return t


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


def texting_ready(from_number: str) -> bool:
    """Carriers only deliver texts from numbers on an approved A2P campaign.
    While approval is pending, app setting sms_live_numbers lists the numbers
    that can text; when it's empty/unset every number is treated as live."""
    live = app_setting("sms_live_numbers")
    if not live:
        return True
    return normalize_e164(from_number or "") in {normalize_e164(n) for n in live}


def _first_text_to(customer_id: str, phone: str) -> bool:
    try:
        c = sb.table("recall_contacts").select("id").eq("customer_id", customer_id) \
            .eq("phone", normalize_e164(phone)).limit(1).execute().data
        if not c:
            return True
        sent = sb.table("recall_contact_activities").select("id").eq("contact_id", c[0]["id"]) \
            .eq("type", "sms_out").limit(1).execute().data
        return not sent
    except Exception:
        return False


def send_customer_sms(customer_id: str, to: str, from_: str, body: str,
                      location_id: str = None, kind: str = "manual", name: str = None):
    """The ONE outbound path for texts to a customer's contacts. Checks the
    opt-out guard first (blocked sends are logged on the contact's timeline),
    then sends via Twilio and logs an sms_out activity.
    Returns the Twilio message SID, or None if blocked.
    Raises on Twilio errors so callers keep their existing error handling."""
    if not is_us_number(normalize_e164(to or "")):
        log.info(f"Skipped {kind} text to non-US/invalid number (customer {customer_id})")
        return None
    st = customer_status(customer_id)
    if st not in ACTIVE_STATUSES:
        log.info(f"Skipped {kind} text — account {customer_id} is {st}")
        return None
    if sends_today(customer_id, "sms_out") >= int(app_setting("daily_sms_cap", 300)):
        log.warning(f"Daily text cap reached for customer {customer_id} — {kind} text not sent")
        return None
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
    if not texting_ready(from_):
        log.info(f"Skipped {kind} text — {from_} is waiting for carrier texting approval")
        return None
    if "STOP" not in body.upper() and _first_text_to(customer_id, to):
        body = body.rstrip() + " Reply STOP to opt out."  # carriers require it on the first text

    sms = twilio_client.messages.create(to=to, from_=from_, body=body,
                                        status_callback=f"{PUBLIC_BASE_URL}/twilio/sms-status")
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


def with_transfer_tool(existing, transfer_target: str) -> dict:
    """ElevenLabs' built-in 'Transfer to number' tool, pointed at the
    location's transfer number. Without it the agent can only SAY it's
    transferring. Other built-in tools already on the agent are kept."""
    tools = dict(existing or {})
    target = normalize_e164(transfer_target or "")
    if not target:
        tools.pop("transfer_to_number", None)
        return tools
    tools["transfer_to_number"] = {
        "type": "system", "name": "transfer_to_number",
        "description": "Connect the caller to a real person at the business.",
        "params": {
            "system_tool_type": "transfer_to_number",
            "transfers": [{
                "transfer_destination": {"type": "phone", "phone_number": target},
                "condition": "The caller asks for a person, a manager or customer service, or has an emergency or urgent problem.",
                "transfer_type": "conference",
            }],
        },
    }
    return tools


def _agent_has_transfer(agent_json: dict) -> bool:
    prompt = ((agent_json or {}).get("conversation_config") or {}).get("agent", {}).get("prompt", {}) or {}
    if (prompt.get("built_in_tools") or {}).get("transfer_to_number"):
        return True
    return any((t or {}).get("name") == "transfer_to_number" or
               ((t or {}).get("params") or {}).get("system_tool_type") == "transfer_to_number"
               for t in (prompt.get("tools") or []))


def save_el_agent(agent_id: str, conversation_config: dict, name: str = None):
    """Creates or updates an ElevenLabs agent and makes sure the transfer tool
    actually sticks. ElevenLabs has stored system tools in two different
    places over time (prompt.built_in_tools vs. the prompt.tools list), and a
    save in the wrong shape is accepted but silently drops the tool — so try
    the tools-list shape first, fall back to built_in_tools, and verify by
    reading the agent back. Returns (response, agent_id)."""
    import copy
    prompt = conversation_config["agent"]["prompt"]
    transfer = (prompt.get("built_in_tools") or {}).get("transfer_to_number")
    variants = []
    if transfer:
        a = copy.deepcopy(conversation_config)
        ap = a["agent"]["prompt"]
        ap["tools"] = [t for t in (ap.get("tools") or []) if t.get("name") != "transfer_to_number"] + [copy.deepcopy(transfer)]
        ap["built_in_tools"] = {k: v for k, v in (ap.get("built_in_tools") or {}).items() if k != "transfer_to_number"}
        variants.append(("tools-list", a))
    variants.append(("built_in_tools", conversation_config))
    headers = {**el_headers(), "Content-Type": "application/json"}
    resp = None
    for label, cfg in variants:
        if agent_id:
            resp = requests.patch(f"{ELEVENLABS_BASE}/convai/agents/{agent_id}", headers=headers,
                                  json={"conversation_config": cfg}, timeout=30)
        else:
            resp = requests.post(f"{ELEVENLABS_BASE}/convai/agents/create", headers=headers,
                                 json={"name": name or "CallsKept agent", "conversation_config": cfg}, timeout=30)
        if not resp.ok:
            log.warning(f"Agent save ({label}) rejected: {resp.status_code} {resp.text[:200]}")
            continue
        if not agent_id:
            agent_id = resp.json().get("agent_id")
        if not transfer:
            break
        try:
            check = requests.get(f"{ELEVENLABS_BASE}/convai/agents/{agent_id}", headers=el_headers(), timeout=20)
            if check.ok and _agent_has_transfer(check.json()):
                log.info(f"Agent {agent_id}: transfer tool saved ({label})")
                break
            log.warning(f"Agent {agent_id}: transfer tool didn't stick with {label} shape")
        except Exception as e:
            log.error(f"Couldn't verify transfer tool on agent {agent_id}: {e}")
            break
    return resp, agent_id


CONFIRMATION_COOLDOWN = timedelta(minutes=10)


def send_caller_confirmation(location: dict, caller_phone: str, note: str = "") -> bool:
    """Texts the caller proof that their call/request reached the business.
    At most one per caller every 10 minutes, and never to someone who opted
    out (send_customer_sms checks). Never raises."""
    try:
        phone = normalize_e164(caller_phone or "")
        if not phone or not location.get("twilio_number") or phone == normalize_e164(location["twilio_number"]):
            return False
        c = _contact_for_phone(location["customer_id"], phone)
        if c:
            since = (datetime.now(timezone.utc) - CONFIRMATION_COOLDOWN).isoformat()
            recent = (sb.table("recall_contact_activities").select("id").eq("contact_id", c["id"])
                      .eq("type", "sms_out").gt("created_at", since)
                      .contains("metadata", {"kind": "caller_confirmation"}).limit(1).execute()).data
            if recent:
                return False
        biz = location.get("business_name") or "us"
        when = datetime.now(timezone.utc)
        try:
            from zoneinfo import ZoneInfo
            when = when.astimezone(ZoneInfo(BUSINESS_TZ))
        except Exception:
            pass
        stamp = when.strftime("%-I:%M %p on %b %-d")
        body = f"Thanks for calling {biz}. We got your message at {stamp}"
        note = (note or "").strip().rstrip(".")
        if note:
            body += f" ({note[:120]})"
        body += ". The team has been notified and will call you back as soon as possible. You can reply to this text too."
        return bool(send_customer_sms(location["customer_id"], phone, location["twilio_number"], body,
                                      location_id=location.get("id") or location.get("location_id"),
                                      kind="caller_confirmation"))
    except Exception as e:
        log.error(f"Caller confirmation text failed: {e}")
        return False


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
                    "or passwords. Also keep a short dated line for what they called or texted about when it was a "
                    "real request (e.g. '- 2026-10-05: asked about AC tune-up pricing and after-hours service'), "
                    "so staff can follow up. Only when the new information has nothing at all worth keeping "
                    "(a greeting, a one-word reply, a hang-up, small talk), output exactly NO_CHANGE. "
                    "Otherwise output only the profile."
                ),
                "messages": [{"role": "user", "content":
                              f"Current profile:\n{(current or '(empty)').strip()}\n\n"
                              f"New information ({source}, {today}):\n{new_info.strip()}"}],
            },
            timeout=25,
        )
        resp.raise_for_status()
        text = "".join(b.get("text", "") for b in resp.json().get("content", []) if b.get("type") == "text").strip()
        if text.startswith("NO_CHANGE"):
            return None
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
        upd = {"memory": merged, "memory_updated_at": datetime.now(timezone.utc).isoformat()} if merged else {}
        if name and not c.get("name"):
            upd["name"] = name.strip()[:120]
        if upd:
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
    business_phone = normalize_us_phone(business_phone)  # US numbers only (blocks premium/intl toll fraud)
    require_twilio()

    cust = sb.table(TABLE_CUST).select("id, business_name, tier, status").eq("id", customer_id).execute()
    if not cust.data:
        raise HTTPException(404, "Account not found")
    customer = cust.data[0]
    if customer["status"] not in ("trial", "active"):
        raise HTTPException(403, "This account's subscription isn't active — can't add a location right now.")
    existing_locs = sb.table(TABLE_LOC).select("id", count="exact").eq("customer_id", customer_id).limit(1).execute()
    if (existing_locs.count or 0) >= 10:
        raise HTTPException(403, "This account already has 10 locations — contact support@callskept.com to add more.")

    # Same warmed-pool-first logic as signup (pool numbers are claimed
    # atomically, so two requests can't be handed the same one).
    number, _sid, pool_id = acquire_number(area_code)

    class _Purchased:
        phone_number = number
    purchased = _Purchased()
    loc_row = {
        "customer_id": customer_id,
        "location_label": (location_label.strip() or "New location")[:80],
        "business_phone": business_phone,
        "twilio_number": number,
    }
    result = sb.table(TABLE_LOC).insert(loc_row).execute()
    location = result.data[0]
    if pool_id:
        sb.table("recall_number_pool").update({"assigned_to_customer_id": customer_id}).eq("id", pool_id).execute()

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
    business_phone = normalize_us_phone(business_phone)  # US numbers only (blocks premium/intl toll fraud)
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


PLAN_PRICES = {"basic": 35, "pro": 129, "elite": 199}
PLAN_NAMES = {"basic": "Basic", "pro": "Pro", "elite": "Elite"}
PLAN_RANK = {"basic": 0, "pro": 1, "elite": 2}


def price_for_tier(tier: str) -> str:
    return {"basic": STRIPE_PRICE_ID, "pro": STRIPE_PRICE_ID_PRO,
            "elite": STRIPE_PRICE_ID_ELITE}.get(tier)


def tier_for_price(price_id: str) -> Optional[str]:
    # Elite first: if Elite has no price of its own it shares Pro's, and the
    # subscription itself can't tell us which one they chose.
    if price_id and price_id == STRIPE_PRICE_ID_ELITE:
        return "elite"
    if price_id and price_id == STRIPE_PRICE_ID_PRO:
        return "pro"
    if price_id and price_id == STRIPE_PRICE_ID:
        return "basic"
    return None


def acquire_number(area_code: str = None):
    """A warmed pool number if one is free (claimed atomically so two signups
    can't get the same one), else a freshly bought number registered to our
    texting campaign. Returns (phone_number, twilio_sid, pool_row_id or None)."""
    for _ in range(3):
        pooled = get_warmed_number()
        if not pooled:
            break
        claimed = (sb.table("recall_number_pool").update({"assigned_at": datetime.now(timezone.utc).isoformat()})
                   .eq("id", pooled["id"]).is_("assigned_at", "null").execute()).data
        if claimed:
            return pooled["phone_number"], pooled.get("twilio_sid"), pooled["id"]
    log.warning("Number pool empty — buying a fresh number; texts may be delayed by A2P propagation.")
    search_kwargs = {"limit": 1}
    if area_code and re.fullmatch(r"[2-9]\d\d", area_code):
        search_kwargs["area_code"] = area_code
    numbers = twilio_client.available_phone_numbers("US").local.list(**search_kwargs)
    if not numbers:
        numbers = twilio_client.available_phone_numbers("US").local.list(limit=1)
    if not numbers:
        raise HTTPException(503, "No phone numbers are available right now — please try again shortly.")
    purchased = twilio_client.incoming_phone_numbers.create(
        phone_number=numbers[0].phone_number,
        voice_url=f"{PUBLIC_BASE_URL}/twilio/voice", voice_method="POST",
        status_callback=f"{PUBLIC_BASE_URL}/twilio/status", status_callback_method="POST",
        sms_url=f"{PUBLIC_BASE_URL}/twilio/sms", sms_method="POST",
    )
    if customer_messaging_service():
        try:
            twilio_client.messaging.v1.services(customer_messaging_service()).phone_numbers.create(
                phone_number_sid=purchased.sid)
        except Exception as e:
            log.error(f"Failed to add {purchased.phone_number} to A2P sender pool: {e}")
    return purchased.phone_number, purchased.sid, None


def _new_checkout_session(customer: dict) -> str:
    price_id = price_for_tier(customer["tier"])
    if not price_id:
        raise HTTPException(503, "This plan isn't available right now — please pick another plan or contact support@callskept.com.")
    stripe_customer_id = customer.get("stripe_customer_id")
    if stripe_customer_id:
        try:
            if stripe.Customer.retrieve(stripe_customer_id).get("deleted"):
                stripe_customer_id = None
        except stripe.error.InvalidRequestError:
            stripe_customer_id = None  # e.g. a test-mode customer after switching to live keys
    if not stripe_customer_id:
        stripe_customer_id = stripe.Customer.create(
            email=customer["email"], name=customer.get("business_name"),
            metadata={"customer_id": customer["id"]}).id
        sb.table(TABLE_CUST).update({"stripe_customer_id": stripe_customer_id}).eq("id", customer["id"]).execute()
    old_session = customer.get("checkout_session_id")
    if old_session:
        try:
            stripe.checkout.Session.expire(old_session)  # so an older tab can't start a 2nd subscription
        except Exception:
            pass  # already completed or expired
    sub_data = {"metadata": {"customer_id": customer["id"]}}
    if not (customer.get("trial_used_at") or customer.get("welcome_sent_at")):
        sub_data["trial_period_days"] = 7  # one free trial per account, not per restart
    checkout = stripe.checkout.Session.create(
        customer=stripe_customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        subscription_data=sub_data,
        allow_promotion_codes=True,
        success_url=f"{FRONTEND_BASE_URL}/dashboard.html?customer_id={customer['id']}&checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{FRONTEND_BASE_URL}/plans.html?customer_id={customer['id']}&checkout=canceled",
        metadata={"customer_id": customer["id"]},
    )
    sb.table(TABLE_CUST).update({"checkout_session_id": checkout.id}).eq("id", customer["id"]).execute()
    return checkout.url


# ---------------------------------------------------------------------------
# SIGNUP — creates the account and its first location, then sends the person
# to Stripe Checkout. Nothing that costs money (a phone number) is handed out
# until checkout succeeds — see finalize_account(). The account sits in
# status "pending_payment" until then and can't send texts or calls.
# ---------------------------------------------------------------------------
@app.post("/signup")
def signup(
    request: Request,
    business_name: str = Form(...),
    owner_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    business_phone: str = Form(...),
    tier: str = Form("basic"),
    area_code: str = Form(None),
    reply_template: str = Form(None),
    accept_terms: str = Form(None),
):
    require_twilio()
    require_stripe()
    rate_limit("signup-ip", client_ip(request), 5, 60 * 60,
               "Too many sign-ups from this connection — please try again in an hour.")
    email = (email or "").strip().lower()
    business_name = (business_name or "").strip()[:120]
    owner_name = (owner_name or "").strip()[:120]
    if tier not in PLAN_PRICES:
        raise HTTPException(400, "Please choose Basic, Pro or Elite.")
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,24}", email):
        raise HTTPException(400, "Please enter a valid email address.")
    if not business_name or not owner_name:
        raise HTTPException(400, "Please enter your name and your business name.")
    if len(password) < 8 or len(password) > 200:
        raise HTTPException(400, "Password must be at least 8 characters.")
    if (accept_terms or "").lower() not in ("on", "true", "1", "yes"):
        raise HTTPException(400, "Please agree to the Terms of Service and Privacy Policy to continue.")
    business_phone = normalize_us_phone(business_phone)
    if not price_for_tier(tier):
        log.error(f"Signup blocked: no Stripe price configured for the {tier} plan")
        raise HTTPException(503, "This plan isn't available right now — please pick another plan or contact support@callskept.com.")
    if sb.table(TABLE_CUST).select("id").eq("email", email).limit(1).execute().data:
        raise HTTPException(400, "An account with this email already exists — log in instead, or reset your password.")

    now = datetime.now(timezone.utc).isoformat()
    customer = sb.table(TABLE_CUST).insert({
        "business_name": business_name, "owner_name": owner_name, "email": email,
        "password_hash": hash_password(password), "tier": tier, "status": "pending_payment",
        "terms_accepted_at": now, "password_changed_at": now,
    }).execute().data[0]
    loc_row = {"customer_id": customer["id"], "location_label": "Main location", "business_phone": business_phone}
    if area_code and re.fullmatch(r"[2-9]\d\d", area_code.strip()):
        loc_row["preferred_area_code"] = area_code.strip()
    if reply_template and reply_template.strip():
        loc_row["reply_template"] = reply_template.strip()[:480]
    location = sb.table(TABLE_LOC).insert(loc_row).execute().data[0]

    try:
        checkout_url = _new_checkout_session(customer)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Checkout creation failed for new account {customer['id']}: {e}")
        raise HTTPException(502, "Your account was created, but checkout didn't open. Log in to finish checkout.")

    try:
        send_verification_email(customer)
    except Exception as e:
        log.error(f"Verification email failed for {customer['id']}: {e}")

    return {
        "customer_id": customer["id"],
        "location_id": location["id"],
        "token": make_token(customer["id"]),
        "checkout_url": checkout_url,
    }


def _assign_primary_number(customer: dict) -> Optional[str]:
    """Gives the main location a number if it doesn't have one yet. A 'claiming'
    marker on the row makes sure two simultaneous calls can't both buy one."""
    loc = get_primary_location(customer["id"])
    if loc.get("twilio_number") and loc["twilio_number"] != "claiming":
        return loc["twilio_number"]
    claimed = (sb.table(TABLE_LOC).update({"twilio_number": "claiming"}).eq("id", loc["id"])
               .is_("twilio_number", "null").execute()).data
    if not claimed:
        return None  # another request is assigning it right now
    try:
        number, sid, pool_id = acquire_number(loc.get("preferred_area_code"))
    except Exception as e:
        sb.table(TABLE_LOC).update({"twilio_number": None}).eq("id", loc["id"]).execute()
        log.error(f"Number assignment failed for {customer['id']}: {e}")
        alert_platform_owner(f"⚠️ CallsKept: {customer.get('business_name')} paid but didn't get a phone number yet "
                             f"(it retries automatically) — {str(e)[:120]}")
        return None
    sb.table(TABLE_LOC).update({"twilio_number": number}).eq("id", loc["id"]).execute()
    if pool_id:
        sb.table("recall_number_pool").update({"assigned_to_customer_id": customer["id"]}).eq("id", pool_id).execute()
    return number


def finalize_account(customer_id: str, subscription_id: str = None) -> dict:
    """Runs once checkout succeeds (from the Stripe webhook or the dashboard's
    confirm call — whichever lands first). Starts the trial, gives the main
    location its CallsKept number, and sends the welcome. Safe to call twice,
    and a later call finishes anything an earlier one couldn't."""
    now = datetime.now(timezone.utc).isoformat()
    claimed = (sb.table(TABLE_CUST).update({
        "status": "trial", "stripe_subscription_id": subscription_id, "checkout_session_id": None, "updated_at": now,
    }).eq("id", customer_id).eq("status", "pending_payment").execute()).data
    if not claimed:
        c = (sb.table(TABLE_CUST).select("*").eq("id", customer_id).limit(1).execute().data or [None])[0]
        if not c:
            return {"finalized": False}
        if subscription_id and not c.get("stripe_subscription_id"):
            sb.table(TABLE_CUST).update({"stripe_subscription_id": subscription_id}).eq("id", customer_id).execute()
        elif subscription_id and c.get("stripe_subscription_id") != subscription_id and c["status"] in ACTIVE_STATUSES:
            # A second checkout tab was completed: don't bill them twice.
            try:
                stripe.Subscription.cancel(subscription_id, prorate=True)
                log.warning(f"Canceled duplicate subscription {subscription_id} for {customer_id}")
                alert_platform_owner(f"CallsKept: canceled a duplicate subscription for {c.get('business_name')} — "
                                     "check Stripe in case a refund is needed.")
            except Exception as e:
                log.error(f"Couldn't cancel duplicate subscription {subscription_id}: {e}")
        # Finish setup if an earlier attempt stopped half-way (e.g. number purchase failed)
        if c["status"] in ACTIVE_STATUSES and not c.get("welcome_sent_at"):
            number = _assign_primary_number(c)
            if number:
                send_welcome(c, number, get_primary_location(customer_id).get("business_phone"))
            return {"finalized": True, "twilio_number": number, "recovered": True}
        return {"finalized": False}
    customer = claimed[0]
    if not customer.get("trial_used_at"):
        sb.table(TABLE_CUST).update({"trial_used_at": now}).eq("id", customer_id).execute()
    if subscription_id:
        try:
            sub = stripe.Subscription.retrieve(subscription_id)
            _sync_subscription(customer_id, sub)
        except Exception as e:
            log.error(f"Couldn't read subscription {subscription_id}: {e}")
    number = _assign_primary_number(customer)
    if customer.get("tier") in ("pro", "elite"):
        apply_tier_change(customer_id, None, customer["tier"])  # restarting Pro/Elite → voice back on
    if number and not customer.get("welcome_sent_at"):
        send_welcome(customer, number, get_primary_location(customer_id).get("business_phone"))
    first_time = not customer.get("welcome_sent_at")
    alert_platform_owner(f"{'🎉 New CallsKept sign-up' if first_time else '🔁 CallsKept restart'}: {customer.get('business_name')} "
                         f"({PLAN_NAMES.get(customer.get('tier'), '')}) — {customer.get('email')}")
    return {"finalized": True, "twilio_number": number}


def _sync_subscription(customer_id: str, sub) -> dict:
    """Copies Stripe's view of the subscription onto the account: plan, status,
    trial end, renewal date, and whether it's set to cancel."""
    status_map = {"trialing": "trial", "active": "active", "past_due": "past_due", "unpaid": "past_due",
                  "canceled": "canceled", "incomplete_expired": "canceled", "paused": "paused"}
    upd = {"cancel_at_period_end": bool(sub.get("cancel_at_period_end")),
           "updated_at": datetime.now(timezone.utc).isoformat()}
    st = status_map.get(sub.get("status"))
    if st:
        upd["status"] = st
    if sub.get("trial_end"):
        upd["trial_ends_at"] = datetime.fromtimestamp(sub["trial_end"], timezone.utc).isoformat()
    items = ((sub.get("items") or {}).get("data") or [])
    period_end = sub.get("current_period_end") or (items[0].get("current_period_end") if items else None)
    if period_end:
        upd["current_period_end"] = datetime.fromtimestamp(period_end, timezone.utc).isoformat()
    price_id = ((items[0].get("price") or {}).get("id")) if items else None
    new_tier = tier_for_price(price_id)
    before = (sb.table(TABLE_CUST).select("tier, status").eq("id", customer_id).execute().data or [{}])[0]
    if new_tier and not (new_tier == "pro" and before.get("tier") == "elite" and price_id == STRIPE_PRICE_ID_PRO
                         and not STRIPE_PRICE_ID_ELITE):
        upd["tier"] = new_tier
    sb.table(TABLE_CUST).update(upd).eq("id", customer_id).execute()
    off = ("canceled", "past_due", "paused")
    was_off, now_off = before.get("status") in off, upd.get("status", before.get("status")) in off
    tier = upd.get("tier") or before.get("tier")
    if now_off and not was_off:
        apply_tier_change(customer_id, before.get("tier"), tier, canceled=True)  # stop AI voice usage
    elif was_off and not now_off and before.get("status") != "pending_payment":
        apply_tier_change(customer_id, None, tier)  # paid again → voice back on
    elif not now_off and upd.get("tier") and upd["tier"] != before.get("tier"):
        apply_tier_change(customer_id, before.get("tier"), upd["tier"])
    return upd


def apply_tier_change(customer_id: str, old_tier: str, new_tier: str, canceled: bool = False):
    """Turns the AI voice off when an account drops to Basic (or cancels) and
    back on when it upgrades, and re-saves agents so Elite-only tools match."""
    customer = (sb.table(TABLE_CUST).select("*").eq("id", customer_id).execute().data or [None])[0]
    if not customer:
        return
    locations = sb.table(TABLE_LOC).select("*").eq("customer_id", customer_id).execute().data or []
    voice_on = new_tier in ("pro", "elite") and not canceled
    for loc in locations:
        try:
            if not voice_on and loc.get("elevenlabs_phone_id"):
                _detach_voice(loc)
            elif voice_on and loc.get("elevenlabs_agent_id") and loc.get("twilio_number") and ELEVENLABS_API_KEY:
                cust = {**customer, "tier": new_tier}
                _resave_agent_for_location(cust, loc)
                phone_id = _ensure_el_phone_assigned(cust, loc, loc["elevenlabs_agent_id"], loc.get("elevenlabs_phone_id"))
                if phone_id != loc.get("elevenlabs_phone_id"):
                    sb.table(TABLE_LOC).update({"elevenlabs_phone_id": phone_id}).eq("id", loc["id"]).execute()
        except Exception as e:
            log.error(f"Tier change {old_tier}->{new_tier} for location {loc.get('id')} failed: {e}")


def _detach_voice(loc: dict):
    """Unhooks the AI voice from a number: removes it from ElevenLabs and points
    Twilio back at our own call handling (ring the owner, then text back)."""
    phone_id = loc.get("elevenlabs_phone_id")
    if phone_id and ELEVENLABS_API_KEY:
        r = requests.delete(f"{ELEVENLABS_BASE}/convai/phone-numbers/{phone_id}", headers=el_headers(), timeout=30)
        if not r.ok and r.status_code != 404:
            log.error(f"Couldn't remove number from ElevenLabs ({phone_id}): {r.status_code} {r.text[:200]}")
    if twilio_client and loc.get("twilio_number"):
        nums = twilio_client.incoming_phone_numbers.list(phone_number=loc["twilio_number"], limit=1)
        if nums:
            nums[0].update(voice_url=f"{PUBLIC_BASE_URL}/twilio/voice", voice_method="POST",
                           status_callback=f"{PUBLIC_BASE_URL}/twilio/status", status_callback_method="POST",
                           sms_url=f"{PUBLIC_BASE_URL}/twilio/sms", sms_method="POST")
    sb.table(TABLE_LOC).update({"elevenlabs_phone_id": None}).eq("id", loc["id"]).execute()


# ---------------------------------------------------------------------------
# PLANS & BILLING — what the Plans & billing page uses.
# ---------------------------------------------------------------------------
def _customer_or_404(customer_id: str) -> dict:
    r = sb.table(TABLE_CUST).select("*").eq("id", customer_id).limit(1).execute().data
    if not r:
        raise HTTPException(404, "Account not found.")
    return r[0]


@app.get("/billing/{customer_id}")
def billing_overview(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    c = _customer_or_404(customer_id)
    return {
        "tier": c["tier"], "status": c["status"],
        "plans": [{"tier": t, "name": PLAN_NAMES[t], "price": PLAN_PRICES[t], "available": bool(price_for_tier(t))}
                  for t in ("basic", "pro", "elite")],
        "trial_ends_at": c.get("trial_ends_at"), "current_period_end": c.get("current_period_end"),
        "cancel_at_period_end": bool(c.get("cancel_at_period_end")),
        "has_subscription": bool(c.get("stripe_subscription_id")),
        "email": c.get("email"), "email_verified": bool(c.get("email_verified_at")),
        "texting_ready": _account_texting_ready(customer_id),
    }


def _account_texting_ready(customer_id: str) -> bool:
    try:
        loc = get_primary_location(customer_id)
        return not loc.get("twilio_number") or texting_ready(loc["twilio_number"])
    except Exception:
        return True


@app.post("/billing/{customer_id}/checkout")
def billing_checkout(customer_id: str, authorization: str = Header(None)):
    """For accounts that signed up but never finished paying (or whose
    subscription ended): opens a fresh Stripe Checkout for their plan."""
    require_auth(customer_id, authorization)
    require_stripe()
    c = _customer_or_404(customer_id)
    if c.get("stripe_subscription_id") and c["status"] in ACTIVE_STATUSES + ("past_due",):
        raise HTTPException(409, "You already have a subscription — use Change plan or Manage billing instead.")
    if c["status"] == "canceled":
        sb.table(TABLE_CUST).update({"status": "pending_payment", "stripe_subscription_id": None}).eq("id", customer_id).execute()
    return {"checkout_url": _new_checkout_session(c)}


class ConfirmIn(BaseModel):
    session_id: str


@app.post("/billing/{customer_id}/confirm")
def billing_confirm(customer_id: str, body: ConfirmIn, authorization: str = Header(None)):
    """The dashboard calls this right after Stripe sends the customer back, so
    the account starts immediately even if the webhook is slow."""
    require_auth(customer_id, authorization)
    require_stripe()
    if not re.fullmatch(r"cs_[A-Za-z0-9_]{10,200}", body.session_id or ""):
        raise HTTPException(400, "Invalid checkout session.")
    session = stripe.checkout.Session.retrieve(body.session_id)
    if (session.get("metadata") or {}).get("customer_id") != customer_id:
        raise HTTPException(403, "That checkout belongs to a different account.")
    if session.get("status") != "complete":
        return {"ok": False, "status": session.get("status")}
    result = finalize_account(customer_id, session.get("subscription"))
    c = _customer_or_404(customer_id)
    return {"ok": True, "status": c["status"], "tier": c["tier"], **result}


class PlanIn(BaseModel):
    tier: str


@app.post("/billing/{customer_id}/change-plan")
def billing_change_plan(customer_id: str, body: PlanIn, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    require_stripe()
    new_tier = body.tier
    if new_tier not in PLAN_PRICES:
        raise HTTPException(422, "Choose Basic, Pro or Elite.")
    rate_limit("plan-change", customer_id, 10, 60 * 60)
    c = _customer_or_404(customer_id)
    old_tier = c["tier"]
    price_id = price_for_tier(new_tier)
    if not price_id:
        raise HTTPException(503, "That plan isn't available right now — contact support@callskept.com.")
    if c["status"] in ("pending_payment", "canceled") or not c.get("stripe_subscription_id"):
        # No live subscription → the new plan only starts once checkout is paid.
        sb.table(TABLE_CUST).update({"tier": new_tier, "status": "pending_payment",
                                     "stripe_subscription_id": None}).eq("id", customer_id).execute()
        return {"ok": True, "tier": new_tier, "checkout_url": _new_checkout_session({**c, "tier": new_tier})}
    if new_tier == old_tier:
        return {"ok": True, "tier": new_tier, "unchanged": True}
    if c["status"] == "past_due":
        raise HTTPException(402, "Please update your card first (Manage billing), then change your plan.")
    sub = stripe.Subscription.retrieve(c["stripe_subscription_id"])
    item_id = sub["items"]["data"][0]["id"]
    upgrading = PLAN_RANK[new_tier] > PLAN_RANK[old_tier]
    sub = stripe.Subscription.modify(
        c["stripe_subscription_id"],
        items=[{"id": item_id, "price": price_id}],
        # Upgrades on a paid plan bill the difference now (otherwise upgrade-then-cancel
        # would get the higher plan free). During the trial nothing is charged either way.
        proration_behavior="always_invoice" if upgrading and sub.get("status") == "active" else "create_prorations",
        cancel_at_period_end=False,
        metadata={"customer_id": customer_id},
    )
    _sync_subscription(customer_id, sub)  # moves the tier and switches voice on/off
    if (sb.table(TABLE_CUST).select("tier").eq("id", customer_id).execute().data or [{}])[0].get("tier") != new_tier:
        # Pro and Elite can share a Stripe price; the choice they made wins.
        sb.table(TABLE_CUST).update({"tier": new_tier}).eq("id", customer_id).execute()
        apply_tier_change(customer_id, old_tier, new_tier)
    sb.table(TABLE_CUST).update({"plan_changed_at": datetime.now(timezone.utc).isoformat()}).eq("id", customer_id).execute()
    up = PLAN_RANK[new_tier] > PLAN_RANK[old_tier]
    notify_account(c, f"Your CallsKept plan is now {PLAN_NAMES[new_tier]}",
                   f"Your plan changed from {PLAN_NAMES[old_tier]} to {PLAN_NAMES[new_tier]} "
                   f"(${PLAN_PRICES[new_tier]}/month). "
                   + ("Your new features are on now. You've been charged only the difference for the rest of this period."
                      if up and c["status"] == "active" else "Your new features are on now."
                      if up else "Any unused time is credited on your next bill."))
    return {"ok": True, "tier": new_tier, "upgraded": up}


class CancelIn(BaseModel):
    reason: Optional[str] = None


@app.post("/billing/{customer_id}/cancel")
def billing_cancel(customer_id: str, body: Optional[CancelIn] = None, authorization: str = Header(None)):
    """Cancels at the end of the current period (or trial) — nothing is cut
    off early and they can undo it until then."""
    require_auth(customer_id, authorization)
    require_stripe()
    c = _customer_or_404(customer_id)
    if not c.get("stripe_subscription_id"):
        raise HTTPException(409, "There's no active subscription to cancel.")
    sub = stripe.Subscription.modify(c["stripe_subscription_id"], cancel_at_period_end=True)
    upd = _sync_subscription(customer_id, sub)
    end = upd.get("current_period_end") or upd.get("trial_ends_at") or c.get("trial_ends_at")
    when = _friendly_date(end)
    notify_account(c, "Your CallsKept subscription is set to cancel",
                   f"Your subscription will end on {when}. You keep full access until then, and you can "
                   "undo this anytime before that from Plans & billing.")
    reason = ((body.reason if body else None) or "").strip()[:2000]
    if reason:
        sb.table("recall_feedback").insert({"customer_id": customer_id, "kind": "cancel_reason", "message": reason,
                                            "page": "plans"}).execute()
    alert_platform_owner(f"CallsKept cancellation: {c.get('business_name')} ({c.get('email')}) — ends {when}"
                         + (f". Reason: {reason[:200]}" if reason else ""))
    return {"ok": True, "cancel_at_period_end": True, "ends_at": end}


@app.post("/billing/{customer_id}/resume")
def billing_resume(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    require_stripe()
    c = _customer_or_404(customer_id)
    if not c.get("stripe_subscription_id"):
        raise HTTPException(409, "There's no subscription to resume — start a new one from Plans & billing.")
    sub = stripe.Subscription.modify(c["stripe_subscription_id"], cancel_at_period_end=False)
    _sync_subscription(customer_id, sub)
    notify_account(c, "Your CallsKept subscription will continue",
                   "Good news — your cancellation is undone and your subscription continues as normal.")
    return {"ok": True, "cancel_at_period_end": False}


@app.post("/billing/{customer_id}/portal")
def billing_portal(customer_id: str, authorization: str = Header(None)):
    """Stripe's secure page for updating the card and downloading invoices."""
    require_auth(customer_id, authorization)
    require_stripe()
    c = _customer_or_404(customer_id)
    if not c.get("stripe_customer_id"):
        raise HTTPException(409, "There's no billing account yet — finish checkout first.")
    try:
        session = stripe.billing_portal.Session.create(
            customer=c["stripe_customer_id"],
            return_url=f"{FRONTEND_BASE_URL}/plans.html?customer_id={customer_id}")
    except Exception as e:
        log.error(f"Billing portal failed for {customer_id}: {e}")
        raise HTTPException(502, "The billing page isn't available right now — email support@callskept.com and we'll update it for you.")
    return {"url": session.url}


def _friendly_date(iso: str) -> str:
    if not iso:
        return "the end of your current billing period"
    try:
        from zoneinfo import ZoneInfo
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone(ZoneInfo("America/New_York"))
        return d.strftime("%B %-d, %Y")
    except Exception:
        return str(iso)[:10]


# ---------------------------------------------------------------------------
# ACCOUNT EMAILS + TEXTS — verification, welcome, billing notices, password
# reset, lifecycle follow-ups. Email goes through Resend (RESEND_API_KEY);
# without a key the app still runs and logs what it would have sent, and the
# important notices also go out by text to the owner's business phone.
# ---------------------------------------------------------------------------
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "CallsKept <hello@callskept.com>")
EMAIL_REPLY_TO = os.environ.get("EMAIL_REPLY_TO", "support@callskept.com")


def _email_html(heading: str, text: str, button_text: str = None, button_url: str = None, footer: str = None) -> str:
    esc = html.escape
    paras = "".join(f'<p style="margin:0 0 14px;line-height:1.55">{esc(p).replace(chr(10), "<br>")}</p>'
                    for p in text.split("\n\n") if p.strip())
    button = ""
    if button_text and button_url:
        button = (f'<p style="margin:22px 0"><a href="{esc(button_url, quote=True)}" style="background:#4f46e5;color:#fff;'
                  f'padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">{esc(button_text)}</a></p>'
                  f'<p style="font-size:12px;color:#6b7280;word-break:break-all">Or paste this link into your browser: {esc(button_url)}</p>')
    foot = esc(footer or "You're getting this because you have a CallsKept account.")
    return (f'<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb;padding:24px">'
            f'<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;padding:28px;color:#111827">'
            f'<div style="font-weight:700;font-size:18px;margin-bottom:18px">CallsKept</div>'
            f'<h1 style="font-size:20px;margin:0 0 16px">{esc(heading)}</h1>{paras}{button}</div>'
            f'<p style="max-width:560px;margin:14px auto 0;font-size:12px;color:#6b7280;text-align:center">{foot}</p></div>')


MARKETING_KINDS = {"broadcast", "winback", "checkout_reminder", "onboarding"}


def send_email(to: str, subject: str, text: str, *, kind: str = "notice", customer_id: str = None,
               button_text: str = None, button_url: str = None, footer: str = None) -> bool:
    """Sends one email. Never raises — a failed email must not break signup or billing.
    Non-essential emails (MARKETING_KINDS) carry an unsubscribe link + List-Unsubscribe
    header and are skipped for anyone who unsubscribed."""
    if not to:
        return False
    headers = {}
    if kind in MARKETING_KINDS and customer_id:
        try:
            row = (sb.table(TABLE_CUST).select("marketing_opt_out").eq("id", customer_id).limit(1).execute().data or [{}])[0]
            if row.get("marketing_opt_out"):
                return False
        except Exception:
            pass
        unsub = f"{PUBLIC_BASE_URL}/email/unsubscribe?token=" + make_purpose_token(customer_id, "unsubscribe", 60 * 24 * 365)
        footer = f"Don't want these emails? Unsubscribe: {unsub}"
        text = text + f"\n\n—\nUnsubscribe: {unsub}"
        headers = {"List-Unsubscribe": f"<{unsub}>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
    body_text = text + (f"\n\n{button_text}: {button_url}" if button_url else "")
    row = {"customer_id": customer_id, "to_email": to, "kind": kind, "subject": subject}
    if not RESEND_API_KEY:
        log.warning(f"[email not sent — RESEND_API_KEY missing] to={to} subject={subject!r}")
        row["error"] = "RESEND_API_KEY not set"
        ok = False
    else:
        try:
            r = requests.post("https://api.resend.com/emails", timeout=15,
                              headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                              json={"from": EMAIL_FROM, "to": [to], "subject": subject, "reply_to": EMAIL_REPLY_TO,
                                    **({"headers": headers} if headers else {}),
                                    "text": body_text,
                                    "html": _email_html(subject, text, button_text, button_url, footer)})
            if r.status_code >= 300:
                raise RuntimeError(f"Resend {r.status_code}: {r.text[:200]}")
            row["provider_id"] = (r.json() or {}).get("id")
            ok = True
        except Exception as e:
            log.error(f"Email to {to} failed: {e}")
            row["error"] = str(e)[:300]
            ok = False
    try:
        sb.table("recall_email_log").insert(row).execute()
    except Exception:
        pass
    return ok


def send_platform_sms(to: str, body: str) -> bool:
    """Texts from CallsKept itself (account notices), not from a customer's number."""
    if not to or twilio_client is None or not is_us_number(to):
        return False
    try:
        if not TWILIO_MESSAGING_SERVICE_SID:
            return False
        twilio_client.messages.create(to=to, body=body[:640], messaging_service_sid=TWILIO_MESSAGING_SERVICE_SID)
        return True
    except Exception as e:
        log.error(f"Platform SMS to {to} failed: {e}")
        return False


def _account_phone(customer: dict) -> Optional[str]:
    try:
        loc = get_primary_location(customer["id"])
        return loc.get("transfer_phone") or loc.get("business_phone")
    except Exception:
        return None


def notify_account(customer: dict, subject: str, text: str, *, sms: bool = True,
                   button_text: str = "Open Plans & billing", button_path: str = "plans.html") -> None:
    """Billing/account notices: email, plus a short text so it isn't missed."""
    url = f"{FRONTEND_BASE_URL}/{button_path}?customer_id={customer['id']}" if button_path else None
    send_email(customer.get("email"), subject, text, kind="account", customer_id=customer["id"],
               button_text=button_text if url else None, button_url=url)
    if sms:
        send_platform_sms(_account_phone(customer), f"CallsKept: {subject}. Details sent to {customer.get('email')}.")


def alert_platform_owner(text: str) -> None:
    """Pings the CallsKept owner (app setting owner_alert_phone / owner_alert_email)."""
    log.info(f"OWNER ALERT: {text}")
    phone = app_setting("owner_alert_phone")
    email = app_setting("owner_alert_email")
    if phone:
        send_platform_sms(str(phone), text)
    if email:
        send_email(str(email), "CallsKept alert", text, kind="owner_alert")


def send_verification_email(customer: dict) -> bool:
    token = make_purpose_token(customer["id"], "verify_email", 60 * 24 * 3, email=customer.get("email"))
    url = f"{FRONTEND_BASE_URL}/verify-email.html?token={token}"
    return send_email(customer.get("email"), "Confirm your email for CallsKept",
                      f"Hi {customer.get('owner_name') or 'there'},\n\nPlease confirm this is your email so we can send you "
                      "billing receipts, call summaries and password resets.\n\nThe link works for 3 days.",
                      kind="verify", customer_id=customer["id"], button_text="Confirm my email", button_url=url,
                      footer="If you didn't sign up for CallsKept, you can ignore this email.")


def _pretty_phone(e164: str) -> str:
    d = re.sub(r"\D", "", e164 or "")[-10:]
    return f"({d[:3]}) {d[3:6]}-{d[6:]}" if len(d) == 10 else (e164 or "")


def send_welcome(customer: dict, number: str, business_phone: str = None) -> None:
    tier = customer.get("tier", "basic")
    dash = f"{FRONTEND_BASE_URL}/dashboard.html?customer_id={customer['id']}"
    if number:
        n = _pretty_phone(number)
        ten = re.sub(r"\D", "", number)[-10:]
        steps = (f"Your CallsKept number is {n}.\n\n"
                 f"Step 1 — Forward missed calls to it. On most cell phones dial *61*{ten}# (AT&T / T-Mobile) "
                 f"or *71{ten} (Verizon) from your business line. The dashboard has instructions for every carrier.\n\n"
                 "Step 2 — Call your business line and let it ring out. You'll get the text-back within a minute.")
        if tier in ("pro", "elite"):
            steps += "\n\nStep 3 — Open Voice assistant in the dashboard to set your AI receptionist's greeting and hours."
    else:
        steps = ("We're finishing setting up your CallsKept phone number — it'll show on your dashboard shortly. "
                 "We'll text you as soon as it's ready.")
    text = (f"Welcome to CallsKept, {customer.get('owner_name') or customer.get('business_name')}!\n\n"
            f"Your 7-day free trial of the {PLAN_NAMES.get(tier, tier.title())} plan has started. "
            f"When it ends, your subscription renews automatically every month at ${PLAN_PRICES.get(tier, '')}/month "
            "(plus any tax) on the card you added, until you cancel. You can cancel online anytime in Plans & billing — "
            "cancel before the trial ends and you won't be charged.\n\n"
            + steps + "\n\nQuestions? Just reply to this email.")
    send_email(customer.get("email"), "Welcome to CallsKept — your number is ready" if number else "Welcome to CallsKept",
               text, kind="welcome", customer_id=customer["id"], button_text="Open my dashboard", button_url=dash)
    if business_phone and number:
        send_platform_sms(business_phone, f"Welcome to CallsKept! Your number is {_pretty_phone(number)}. "
                                          "Forward missed calls to it and you're live. Setup steps are in your email.")
    sb.table(TABLE_CUST).update({"welcome_sent_at": datetime.now(timezone.utc).isoformat()}).eq("id", customer["id"]).execute()


def subscriber_tags(c: dict) -> list:
    """Segments used for follow-ups and announcements — computed, so never stale."""
    tags = [f"plan:{c.get('tier')}", f"status:{c.get('status')}"]
    tags.append("email:verified" if c.get("email_verified_at") else "email:unverified")
    if c.get("cancel_at_period_end"):
        tags.append("canceling")
    if c.get("marketing_opt_out"):
        tags.append("no-marketing")
    return tags


class EmailIn(BaseModel):
    email: str


class TokenIn(BaseModel):
    token: str


class ResetIn(BaseModel):
    token: str
    new_password: str


def _pwd_fingerprint(password_hash: str) -> str:
    return hashlib.sha256((password_hash or "").encode()).hexdigest()[:16]


@app.post("/auth/verify-email")
def verify_email(body: TokenIn):
    p = read_purpose_token(body.token, "verify_email")
    rows = sb.table(TABLE_CUST).select("id, email, email_verified_at").eq("id", p["customer_id"]).limit(1).execute().data
    if not rows or rows[0]["email"] != p.get("email"):
        raise HTTPException(400, "This link is for an older email address — request a new one from your dashboard.")
    if not rows[0].get("email_verified_at"):
        sb.table(TABLE_CUST).update({"email_verified_at": datetime.now(timezone.utc).isoformat()}).eq("id", rows[0]["id"]).execute()
    return {"ok": True, "customer_id": rows[0]["id"]}


@app.post("/auth/resend-verification/{customer_id}")
def resend_verification(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    rate_limit("verify-resend", customer_id, 3, 60 * 60, "We've sent a few already — check your spam folder, or try again in an hour.")
    c = _customer_or_404(customer_id)
    if c.get("email_verified_at"):
        return {"ok": True, "already_verified": True}
    return {"ok": True, "sent": send_verification_email(c)}


@app.post("/auth/forgot-password")
def forgot_password(body: EmailIn, request: Request, background: BackgroundTasks):
    email = (body.email or "").strip().lower()
    rate_limit("forgot-ip", client_ip(request), 10, 60 * 60)
    rate_limit("forgot-email", email, 3, 60 * 60)
    rows = sb.table(TABLE_CUST).select("id, email, owner_name, password_hash").eq("email", email).limit(1).execute().data
    if rows:  # same answer (and timing) either way, so this can't reveal who has an account
        background.add_task(_send_reset_link, rows[0], email)
    return {"ok": True, "message": "If that email has a CallsKept account, a reset link is on its way."}


def _send_reset_link(c: dict, email: str):
    if True:
        token = make_purpose_token(c["id"], "pwd_reset", 60, fp=_pwd_fingerprint(c.get("password_hash")))
        url = f"{FRONTEND_BASE_URL}/reset-password.html?token={token}"
        sent = send_email(email, "Reset your CallsKept password",
                          "Someone (hopefully you) asked to reset your CallsKept password. The link works for 1 hour "
                          "and only once.\n\nIf this wasn't you, ignore this email — your password stays the same.",
                          kind="pwd_reset", customer_id=c["id"], button_text="Choose a new password", button_url=url)
        if not sent:  # email not set up yet → text the reset link to the business phone instead
            send_platform_sms(_account_phone(c), f"CallsKept password reset (valid 1 hour): {url}")


@app.post("/auth/reset-password")
def reset_password(body: ResetIn, request: Request):
    rate_limit("reset-ip", client_ip(request), 20, 60 * 60)
    p = read_purpose_token(body.token, "pwd_reset")
    if len(body.new_password or "") < 8:
        raise HTTPException(400, "New password must be at least 8 characters.")
    rows = sb.table(TABLE_CUST).select("id, email, password_hash").eq("id", p["customer_id"]).limit(1).execute().data
    if not rows or _pwd_fingerprint(rows[0].get("password_hash")) != p.get("fp"):
        raise HTTPException(400, "This reset link has already been used — request a new one.")
    now = datetime.now(timezone.utc).isoformat()
    sb.table(TABLE_CUST).update({"password_hash": hash_password(body.new_password), "password_changed_at": now,
                                 "email_verified_at": now}).eq("id", rows[0]["id"]).execute()
    _PWD_CHANGED_CACHE.pop(rows[0]["id"], None)
    send_email(rows[0]["email"], "Your CallsKept password was changed",
               "Your password was just changed and you've been signed out on other devices. "
               "If this wasn't you, reply to this email right away.", kind="security", customer_id=rows[0]["id"])
    return {"ok": True, "customer_id": rows[0]["id"], "token": make_token(rows[0]["id"])}


# ---------------------------------------------------------------------------
# YOUR DATA — download everything, or delete the account for good.
# ---------------------------------------------------------------------------
EXPORT_SECRET_FIELDS = {"password_hash", "google_calendar_refresh_token", "google_business_refresh_token",
                        "checkout_session_id", "account_pin", "ein"}


def _clean(rows):
    return [{k: v for k, v in (r or {}).items() if k not in EXPORT_SECRET_FIELDS} for r in (rows or [])]


@app.get("/account/{customer_id}/export")
def export_account(customer_id: str, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    rate_limit("export", customer_id, 5, 3600)
    out = {"exported_at": datetime.now(timezone.utc).isoformat(), "account": _clean([_customer_or_404(customer_id)])[0]}
    for key, table in [("locations", TABLE_LOC), ("contacts", "recall_contacts"),
                       ("timeline", "recall_contact_activities"), ("tasks", "recall_tasks"),
                       ("text_messages", "recall_sms_messages"), ("missed_calls", TABLE_CALLS),
                       ("appointments", "recall_appointments"), ("messages_taken", "recall_messages"),
                       ("feedback", "recall_feedback")]:
        try:
            out[key] = _clean(sb.table(table).select("*").eq("customer_id", customer_id).limit(20000).execute().data)
        except Exception as e:
            out[key] = {"error": f"couldn't export: {str(e)[:80]}"}
    return JSONResponse(out, headers={"Content-Disposition": 'attachment; filename="callskept-data.json"',
                                      "Cache-Control": "no-store"})


class DeleteIn(BaseModel):
    password: str
    confirm: str


@app.post("/account/{customer_id}/delete")
def delete_account(customer_id: str, body: DeleteIn, authorization: str = Header(None)):
    """Permanently deletes the account: stops billing, turns off the AI voice,
    releases the phone numbers, and removes all contacts, messages and history.
    Stripe keeps its own invoice records, as tax law requires."""
    require_auth(customer_id, authorization)
    rate_limit("delete-account", customer_id, 5, 3600)
    if (body.confirm or "").strip().upper() != "DELETE":
        raise HTTPException(400, 'Type DELETE to confirm.')
    c = _customer_or_404(customer_id)
    if not verify_password(body.password or "", c.get("password_hash") or ""):
        raise HTTPException(403, "That password isn't right.")
    problems = []
    if c.get("stripe_subscription_id") and STRIPE_SECRET_KEY:
        try:
            stripe.Subscription.cancel(c["stripe_subscription_id"])
        except Exception as e:
            if "No such subscription" not in str(e) and "canceled" not in str(e):
                problems.append(f"stripe: {e}")
    for loc in sb.table(TABLE_LOC).select("*").eq("customer_id", customer_id).execute().data or []:
        try:
            _detach_voice(loc)
        except Exception as e:
            problems.append(f"voice {loc['id']}: {e}")
        if loc.get("elevenlabs_agent_id") and ELEVENLABS_API_KEY:
            try:
                requests.delete(f"{ELEVENLABS_BASE}/convai/agents/{loc['elevenlabs_agent_id']}", headers=el_headers(), timeout=30)
            except Exception as e:
                problems.append(f"agent {loc['id']}: {e}")
        if loc.get("twilio_number") and loc["twilio_number"] != "claiming" and twilio_client:
            try:
                for n in twilio_client.incoming_phone_numbers.list(phone_number=loc["twilio_number"], limit=1):
                    n.delete()
            except Exception as e:
                problems.append(f"number {loc['twilio_number']}: {e}")
    try:
        sb.table("recall_number_pool").delete().eq("assigned_to_customer_id", customer_id).execute()
        sb.table(TABLE_CUST).delete().eq("id", customer_id).execute()  # cascades to all account data
    except Exception as e:
        log.error(f"Account deletion failed for {customer_id}: {e}")
        alert_platform_owner(f"⚠️ CallsKept: account deletion for {c.get('email')} failed — finish it by hand. {str(e)[:120]}")
        raise HTTPException(500, "We couldn't finish deleting your account — our team has been alerted and will complete it within 24 hours.")
    _PWD_CHANGED_CACHE.pop(customer_id, None)
    send_email(c.get("email"), "Your CallsKept account has been deleted",
               "Your CallsKept account and all of its contacts, messages and call history have been permanently deleted, "
               "your subscription has been canceled, and your CallsKept phone number has been released.\n\n"
               "Past invoices stay with our payment processor (Stripe) as required for tax records.")
    alert_platform_owner(f"CallsKept account deleted by owner: {c.get('business_name')} ({c.get('email')})"
                         + (f" — check: {'; '.join(problems)[:200]}" if problems else ""))
    return {"ok": True, "deleted": True}


# ---------------------------------------------------------------------------
# FEEDBACK — in-app "Send feedback" box. Stored, and the owner gets a text.
# ---------------------------------------------------------------------------
class FeedbackIn(BaseModel):
    message: str
    kind: str = "feedback"
    rating: Optional[int] = None
    page: Optional[str] = None


@app.post("/feedback/{customer_id}")
def submit_feedback(customer_id: str, body: FeedbackIn, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    rate_limit("feedback", customer_id, 10, 60 * 60)
    msg = (body.message or "").strip()[:4000]
    if not msg:
        raise HTTPException(400, "Please write a message.")
    kind = body.kind if body.kind in ("feedback", "bug", "idea", "question", "cancel_reason") else "feedback"
    rating = body.rating if body.rating and 1 <= body.rating <= 5 else None
    sb.table("recall_feedback").insert({"customer_id": customer_id, "kind": kind, "rating": rating,
                                        "message": msg, "page": (body.page or "")[:200] or None}).execute()
    c = _customer_or_404(customer_id)
    alert_platform_owner(f"💬 CallsKept {kind} from {c.get('business_name')}"
                         f"{f' ({rating}★)' if rating else ''}: {msg[:300]}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# ADMIN — subscriber list with tags, and announcements to a tag.
# ---------------------------------------------------------------------------
@app.get("/admin/subscribers")
def admin_subscribers(tag: str = None, authorization: str = Header(None)):
    require_admin(authorization)
    rows = sb.table(TABLE_CUST).select(
        "id, business_name, owner_name, email, tier, status, email_verified_at, cancel_at_period_end, "
        "marketing_opt_out, trial_ends_at, current_period_end, created_at").order("created_at", desc=True).limit(2000).execute().data
    out = [{**r, "tags": subscriber_tags(r)} for r in rows]
    return [r for r in out if not tag or tag in r["tags"]]


class BroadcastIn(BaseModel):
    tag: str
    subject: str
    message: str
    dry_run: bool = True


@app.post("/admin/broadcast")
def admin_broadcast(body: BroadcastIn, authorization: str = Header(None)):
    """Email everyone with a tag (e.g. plan:pro, status:trial). dry_run lists who
    would get it. Product/marketing news skips anyone who opted out."""
    require_admin(authorization)
    targets = [r for r in admin_subscribers(body.tag, authorization) if "no-marketing" not in r["tags"]]
    if body.dry_run:
        return {"would_send": len(targets), "emails": [t["email"] for t in targets][:200]}
    sent = 0
    for t in targets[:1000]:
        sent += send_email(t["email"], body.subject[:150], body.message[:5000], kind="broadcast", customer_id=t["id"])
    return {"sent": sent, "targets": len(targets)}


@app.post("/email/unsubscribe")
def email_unsubscribe_post(token: str):
    p = read_purpose_token(token, "unsubscribe")
    sb.table(TABLE_CUST).update({"marketing_opt_out": True}).eq("id", p["customer_id"]).execute()
    return {"ok": True}


@app.get("/email/unsubscribe", response_class=HTMLResponse)
def email_unsubscribe(token: str):
    try:
        p = read_purpose_token(token, "unsubscribe")
        sb.table(TABLE_CUST).update({"marketing_opt_out": True}).eq("id", p["customer_id"]).execute()
        msg = "You're unsubscribed from CallsKept product news. You'll still get billing and security emails."
    except HTTPException as e:
        msg = e.detail
    return HTMLResponse(f'<html><body style="font-family:sans-serif;max-width:520px;margin:60px auto;padding:0 16px">'
                        f'<h2>CallsKept</h2><p>{html.escape(str(msg))}</p></body></html>')


def run_lifecycle_followups(now: datetime) -> dict:
    """Account follow-ups, run from the 5-minute job. Each one sends once."""
    out = {"checkout_reminders": 0, "onboarding_nudges": 0, "winbacks": 0, "setups_finished": 0}
    # 0. Paid but setup didn't finish (number purchase failed etc.) → retry
    rows = (sb.table(TABLE_CUST).select("id").in_("status", list(ACTIVE_STATUSES)).is_("welcome_sent_at", "null")
            .lte("updated_at", (now - timedelta(minutes=5)).isoformat()).limit(5).execute()).data
    for c in rows:
        try:
            if finalize_account(c["id"]).get("twilio_number"):
                out["setups_finished"] += 1
        except Exception as e:
            log.error(f"Setup retry for {c['id']} failed: {e}")
    # 1. Signed up but never finished checkout (after 24h)
    rows = (sb.table(TABLE_CUST).select("*").eq("status", "pending_payment").is_("checkout_reminder_at", "null")
            .lte("created_at", (now - timedelta(hours=24)).isoformat())
            .gte("created_at", (now - timedelta(days=7)).isoformat()).limit(25).execute()).data
    for c in rows:
        sb.table(TABLE_CUST).update({"checkout_reminder_at": now.isoformat()}).eq("id", c["id"]).execute()
        send_email(c["email"], "Finish setting up CallsKept",
                   f"Hi {c.get('owner_name') or 'there'},\n\nYour CallsKept account for {c.get('business_name')} is almost ready — "
                   "you just need to start your free trial. You won't be charged for 7 days and can cancel anytime.",
                   kind="checkout_reminder", customer_id=c["id"], button_text="Start my free trial",
                   button_url=f"{FRONTEND_BASE_URL}/plans.html?customer_id={c['id']}")
        out["checkout_reminders"] += 1
    # 2. Trial started 48h ago but no calls have come in → forwarding probably isn't on
    rows = (sb.table(TABLE_CUST).select("*").in_("status", ["trial", "active"]).is_("onboarding_nudge_at", "null")
            .not_.is_("welcome_sent_at", "null").lte("welcome_sent_at", (now - timedelta(hours=48)).isoformat())
            .limit(25).execute()).data
    for c in rows:
        sb.table(TABLE_CUST).update({"onboarding_nudge_at": now.isoformat()}).eq("id", c["id"]).execute()
        calls = sb.table(TABLE_CALLS).select("id").eq("customer_id", c["id"]).limit(1).execute().data
        if calls:
            continue
        notify_account(c, "We haven't seen any calls yet",
                       "Your CallsKept number hasn't received a forwarded call yet, so missed callers aren't getting texts. "
                       "Most of the time call forwarding just needs to be turned on — the dashboard shows the exact code "
                       "for your carrier. It takes about a minute.\n\nReply to this email if you'd like us to help.",
                       button_text="Show me how", button_path="dashboard.html")
        out["onboarding_nudges"] += 1
    # 3. Canceled 14+ days ago → one win-back note (respects marketing opt-out)
    rows = (sb.table(TABLE_CUST).select("*").eq("status", "canceled").is_("winback_sent_at", "null")
            .eq("marketing_opt_out", False).lte("updated_at", (now - timedelta(days=14)).isoformat())
            .gte("updated_at", (now - timedelta(days=60)).isoformat()).limit(25).execute()).data
    for c in rows:
        sb.table(TABLE_CUST).update({"winback_sent_at": now.isoformat()}).eq("id", c["id"]).execute()
        send_email(c["email"], "Your CallsKept contacts are still saved",
                   "Since you left, missed calls aren't getting a text back. Your contacts, notes and settings are still "
                   "saved — restart anytime and everything picks up where it left off.\n\nIf something didn't work for you, "
                   "just reply and tell us. We read every reply.",
                   kind="winback", customer_id=c["id"], button_text="Restart CallsKept",
                   button_url=f"{FRONTEND_BASE_URL}/plans.html?customer_id={c['id']}")
        out["winbacks"] += 1
    return out


# ---------------------------------------------------------------------------
# LOGIN — email + password, returns a bearer token good for 30 days.
# ---------------------------------------------------------------------------
@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    email = (email or "").strip().lower()
    rate_limit("login-ip", client_ip(request), 30, 15 * 60)
    rate_limit("login-email", email, 10, 15 * 60,
               "Too many sign-in attempts for this email — wait 15 minutes or reset your password.")
    cust = sb.table(TABLE_CUST).select("id, password_hash").eq("email", email).limit(1).execute()
    if not cust.data or not cust.data[0].get("password_hash"):
        await run_in_threadpool(verify_password, password, "00$00")  # same timing either way
        raise HTTPException(401, "Incorrect email or password.")
    customer = cust.data[0]
    if not await run_in_threadpool(verify_password, password, customer["password_hash"]):
        raise HTTPException(401, "Incorrect email or password.")
    return {"customer_id": customer["id"], "token": make_token(customer["id"])}


# ---------------------------------------------------------------------------
# TWILIO VOICE WEBHOOK — call hits a location's dedicated number, we try to
# dial that location's real business phone. If nobody picks up, the call
# ends and /twilio/status fires with an unanswered result, triggering the
# text-back for that specific location.
# ---------------------------------------------------------------------------
@app.post("/twilio/voice", dependencies=[Depends(verify_twilio)])
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

    if not texting_ready(to_number):
        # Texting from this number isn't carrier-approved yet: text the OWNER
        # (from the approved CallsKept number) so they can call back right away.
        owner_phone = location.get("transfer_phone") or location.get("business_phone")
        if owner_phone and normalize_e164(owner_phone) != normalize_e164(caller):
            send_platform_sms(owner_phone, f"CallsKept: missed call at {location['business_name']} from "
                                           f"{_pretty_phone(caller)} — call them back. (Automatic text-back "
                                           "turns on as soon as carriers approve your number.)")
        call_row.update(sms_sent=False, sms_error="texting pending carrier approval — owner alerted")
        try:
            sb.table(TABLE_CALLS).insert(call_row).execute()
        except Exception as e:
            log.error(f"Couldn't save missed-call row for {call_sid}: {e}")
        return
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


@app.post("/twilio/dial-result", dependencies=[Depends(verify_twilio)])
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


CARRIER_BLOCK_CODES = {"30034", "30032", "30007", "30035", "30024"}


@app.post("/twilio/sms-status", dependencies=[Depends(verify_twilio)])
async def twilio_sms_status(request: Request):
    """Delivery receipts for texts we send. Carrier blocks are recorded on the
    message and the CallsKept owner is alerted (at most once a day per number)."""
    form = await request.form()
    status, code = form.get("MessageStatus"), str(form.get("ErrorCode") or "")
    sid, from_ = form.get("MessageSid"), form.get("From")
    if status in ("undelivered", "failed") and sid:
        def _record():
            try:
                rows = sb.table("recall_contact_activities").select("id, metadata") \
                    .eq("source_ref", f"tw:{sid}").limit(1).execute().data
                if rows:
                    meta = {**(rows[0].get("metadata") or {}), "delivery": status, "error_code": code}
                    sb.table("recall_contact_activities").update({"metadata": meta}).eq("id", rows[0]["id"]).execute()
            except Exception as e:
                log.error(f"Couldn't record delivery status for {sid}: {e}")
            if code in CARRIER_BLOCK_CODES:
                try:
                    rate_limit("carrier-block-alert", from_ or "", 1, 24 * 3600)
                except HTTPException:
                    return
                alert_platform_owner(f"⚠️ CallsKept: carriers are blocking texts from {from_} (error {code}). "
                                     "Check A2P registration / Messaging Service sender pool.")
        await run_in_threadpool(_record)
    return PlainTextResponse("", status_code=204)


@app.post("/twilio/status", dependencies=[Depends(verify_twilio)])
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
        log.warning(f"Stripe webhook signature check failed: {e}")
        raise HTTPException(400, "Webhook signature verification failed.")
    try:
        sb.table("recall_stripe_events").insert({"id": event["id"], "type": event["type"]}).execute()
    except Exception as e:
        if "23505" in str(e) or "duplicate" in str(e).lower():
            return JSONResponse({"received": True, "duplicate": True})  # Stripe retry of one we already handled
        log.error(f"Couldn't record Stripe event {event['id']}: {e}")
        raise HTTPException(500, "Try again.")  # Stripe will retry
    try:
        await run_in_threadpool(_handle_stripe_event, event)
    except Exception as e:
        log.error(f"Stripe webhook {event['type']} failed: {e}")
        try:
            sb.table("recall_stripe_events").delete().eq("id", event["id"]).execute()  # let Stripe retry
        except Exception as e2:
            log.error(f"Couldn't clear Stripe event {event['id']} for retry: {e2}")
            alert_platform_owner(f"⚠️ CallsKept: Stripe event {event['id']} ({event['type']}) failed and won't retry — check it.")
        raise HTTPException(500, "Webhook handling failed.")
    return JSONResponse({"received": True})


def _customer_for_stripe(obj: dict) -> Optional[dict]:
    cid = (obj.get("metadata") or {}).get("customer_id")
    q = sb.table(TABLE_CUST).select("*")
    rows = q.eq("id", cid).limit(1).execute().data if cid else None
    if not rows and obj.get("customer"):
        rows = sb.table(TABLE_CUST).select("*").eq("stripe_customer_id", obj["customer"]).limit(1).execute().data
    if not rows and obj.get("subscription"):
        rows = sb.table(TABLE_CUST).select("*").eq("stripe_subscription_id", obj["subscription"]).limit(1).execute().data
    return rows[0] if rows else None


def _handle_stripe_event(event: dict):
    etype = event["type"]
    data = event["data"]["object"]
    if etype == "checkout.session.completed":
        cid = (data.get("metadata") or {}).get("customer_id")
        if cid and data.get("status") == "complete":
            finalize_account(cid, data.get("subscription"))
        return
    c = _customer_for_stripe(data)
    if not c:
        log.info(f"Stripe {etype}: no matching CallsKept account")
        return
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        if c.get("stripe_subscription_id") in (None, data.get("id")):
            if not c.get("stripe_subscription_id"):
                sb.table(TABLE_CUST).update({"stripe_subscription_id": data.get("id")}).eq("id", c["id"]).execute()
            if c["status"] != "pending_payment":
                _sync_subscription(c["id"], stripe.Subscription.retrieve(data["id"]))
    elif etype == "customer.subscription.deleted":
        if c.get("stripe_subscription_id") == data.get("id"):
            _sync_subscription(c["id"], {**data, "status": "canceled"})
            notify_account(c, "Your CallsKept subscription has ended",
                           "Your subscription has ended, so CallsKept has stopped answering and texting for you. "
                           "Your contacts and history are saved — restart anytime from Plans & billing.")
    elif etype == "customer.subscription.trial_will_end":
        notify_account(c, "Your CallsKept trial ends in 3 days",
                       f"Your free trial ends on {_friendly_date(c.get('trial_ends_at'))}. Your {PLAN_NAMES.get(c['tier'], '')} "
                       f"plan (${PLAN_PRICES.get(c['tier'], '')}/month) starts then on the card you added. "
                       "To change plans or cancel, open Plans & billing.")
    elif etype == "invoice.payment_succeeded":
        if c["status"] in ("past_due", "trial", "paused") and (data.get("amount_paid") or 0) > 0 \
                and data.get("subscription") == c.get("stripe_subscription_id"):
            sb.table(TABLE_CUST).update({"status": "active"}).eq("id", c["id"]).execute()
            if c["status"] in ("past_due", "paused"):
                apply_tier_change(c["id"], None, c["tier"])  # voice back on
    elif etype == "invoice.payment_failed":
        if data.get("subscription") and data.get("subscription") != c.get("stripe_subscription_id"):
            return
        sb.table(TABLE_CUST).update({"status": "past_due"}).eq("id", c["id"]).execute()
        if c["status"] != "past_due":
            apply_tier_change(c["id"], c["tier"], c["tier"], canceled=True)  # pause AI voice minutes
        notify_account(c, "Action needed: your CallsKept payment didn't go through",
                       "We couldn't charge your card, so missed-call texts and AI answering are paused. "
                       "Update your card in Plans & billing → Manage billing and everything turns back on right away.")
        alert_platform_owner(f"CallsKept payment failed: {c.get('business_name')} ({c.get('email')})")


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
        "address_line1, address_city, address_state, address_zip, tier, status, email_verified_at, cancel_at_period_end"
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
    business_phone = normalize_us_phone(business_phone)  # US numbers only (blocks premium/intl toll fraud)
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
        raise HTTPException(403, "Your current password is incorrect.")
    sb.table(TABLE_CUST).update({"password_hash": hash_password(new_password),
                                 "password_changed_at": datetime.now(timezone.utc).isoformat()}).eq("id", customer_id).execute()
    _PWD_CHANGED_CACHE.pop(customer_id, None)
    return {"ok": True, "token": make_token(customer_id)}



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


@app.post("/twilio/cancellation-twiml/{appointment_id}", dependencies=[Depends(verify_twilio)])
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
    require_active(customer_id)
    loc = get_location_for_customer(customer_id, location_id)

    try:
        import pypdf
        from io import BytesIO
        data = await _read_pdf_upload(pdf)
        reader = pypdf.PdfReader(BytesIO(data))
        if len(reader.pages) > 60:
            raise HTTPException(413, "That PDF is too long — please keep it under 60 pages.")
        text = "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"PDF parse failed: {e}")
        raise HTTPException(400, "Couldn't read that PDF — try saving it again as a regular PDF.")
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


@app.post("/twilio/sms", dependencies=[Depends(verify_twilio)])
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

    if not texting_ready(to_number):
        # Can't reply from this number yet — pass the text to the owner instead.
        owner_phone = location.get("transfer_phone") or location.get("business_phone")
        if owner_phone and normalize_e164(owner_phone) != normalize_e164(from_number):
            try:
                rate_limit("fwd-text", f"{location['location_id']}:{from_number}", 5, 3600)
                send_platform_sms(owner_phone, f"CallsKept: text to {location['business_name']} from "
                                               f"{_pretty_phone(from_number)}: \"{body[:300]}\" — please call or "
                                               "text them back from your phone.")
            except HTTPException:
                pass
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

    sms_memory = {"saved": False}

    async def call_booking_tool(name: str, tool_input: dict) -> str:
        if name == "remember_caller":
            sms_memory["saved"] = True
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
            resp = await run_in_threadpool(
                requests.post,
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
        reply_text = sms_plain(reply_text)
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

    # Backstop for memory: if the AI didn't save anything itself and the text
    # has some substance, let the memory writer decide what's worth keeping.
    if not sms_memory["saved"] and len((body or "").strip()) >= 15:
        import asyncio
        asyncio.get_running_loop().run_in_executor(
            None, update_contact_memory, location["customer_id"], from_number,
            f"They texted: \"{body.strip()[:800]}\"", "text message", None, None, location["location_id"])

    return PlainTextResponse("", media_type="application/xml")


# ---------------------------------------------------------------------------
# APPOINTMENT REMINDERS (Elite tier) — a text/call sent before each booked
# appointment. recall_appointments now joins through recall_locations for
# its per-location settings (twilio_number, reminder lead times), and
# through recall_locations.recall_customers for business_name.
# ---------------------------------------------------------------------------
REMINDER_JOB_SECRET = os.environ.get("REMINDER_JOB_SECRET")
if not REMINDER_JOB_SECRET:
    REMINDER_JOB_SECRET = _derived_secret("reminder-job")
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
    if not secret_ok(request.headers.get("x-job-secret"), REMINDER_JOB_SECRET):
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


@app.post("/twilio/reminder-twiml/{appointment_id}", dependencies=[Depends(verify_twilio)])
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
    POOL_JOB_SECRET = _derived_secret("pool-job")
    log.warning("POOL_JOB_SECRET not set — using a random per-restart value. Set it in Render.")


@app.post("/internal/refill-number-pool")
async def refill_number_pool(request: Request):
    if not secret_ok(request.headers.get("x-job-secret"), POOL_JOB_SECRET):
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
                twilio_client.messaging.v1.services(customer_messaging_service()).phone_numbers.create(
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
        .is_("assigned_at", "null")
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
    require_active(customer_id)
    location = get_location_for_customer(customer_id, location_id)

    update = {"elevenlabs_voice_id": voice_id, "fallback_behavior": fallback_behavior}

    # 1. Upload the PDF as a knowledge base document, if one was provided.
    kb_doc_id = location.get("elevenlabs_kb_doc_id")
    if pdf is not None:
        files = {"file": ((pdf.filename or "business-info.pdf")[:120], await _read_pdf_upload(pdf), "application/pdf")}
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
            "hasn't actually happened. If the transfer doesn't go through or the caller is still with you "
            "after it, don't keep promising a transfer: call take_message with what they need, tell them "
            "the team has been texted and that they'll get a confirmation text on their phone right away, "
            "then offer to end the call."
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

    conversation_config["agent"]["prompt"]["built_in_tools"] = with_transfer_tool(
        conversation_config["agent"]["prompt"].get("built_in_tools"), transfer_target)

    agent_id = location.get("elevenlabs_agent_id")
    had_agent = bool(agent_id)
    resp, agent_id = save_el_agent(
        agent_id, conversation_config,
        name=f"{customer['business_name']} — {location.get('location_label', '')}".strip(" —"))
    if not resp.ok:
        raise HTTPException(502, f"Couldn't save ElevenLabs agent: {resp.text[:300]}")
    if not had_agent:
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
            "hasn't actually happened. If the transfer doesn't go through or the caller is still with you "
            "after it, don't keep promising a transfer: call take_message with what they need, tell them "
            "the team has been texted and that they'll get a confirmation text on their phone right away, "
            "then offer to end the call."
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

    conversation_config["agent"]["prompt"]["built_in_tools"] = with_transfer_tool(
        conversation_config["agent"]["prompt"].get("built_in_tools"), transfer_target)

    try:
        resp, _ = save_el_agent(agent_id, conversation_config)
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
            "typ": "oauth_state",
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
    if not secret_ok(request_headers.get("x-tool-secret"), ELEVENLABS_TOOL_SECRET):
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
        send_caller_confirmation(location, caller_phone, reason)
        return {"result": "Notified, and the caller was texted a confirmation. Now call transfer_to_number to connect them."}
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

    texted = send_caller_confirmation(location, caller_phone, note)
    if texted:
        return {"result": "Logged, the team was texted, and a confirmation text was just sent to the caller's phone. Tell them to check their texts and that someone will call back soon."}
    return {"result": "Logged and the team was notified. Let the caller know someone will follow up soon."}


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
    import html as _html
    c = _get_customer_for_legal(customer_id)
    business_name = _html.escape(c["business_name"] or "")
    contact = _html.escape(c.get("email") or c.get("business_phone") or "our office")
    customer_id = _html.escape(customer_id)
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
    import html as _html
    c = _get_customer_for_legal(customer_id)
    business_name = _html.escape(c["business_name"] or "")
    contact = _html.escape(c.get("email") or c.get("business_phone") or "our office")
    customer_id = _html.escape(customer_id)
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

CRM_STATUSES = ("new", "contacted", "qualified", "quoted", "booked", "won", "lost", "do_not_contact")


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
    require_active(customer_id)
    if not is_us_number(contact.get("phone") or ""):
        raise HTTPException(422, "CallsKept can only call US phone numbers.")
    if sends_today(customer_id, "call_out") >= int(app_setting("daily_call_cap", 100)):
        raise HTTPException(429, "Daily call limit reached — calls resume tomorrow. Contact support@callskept.com to raise it.")
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


@app.post("/twilio/crm-call/{activity_id}", dependencies=[Depends(verify_twilio)])
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


@app.post("/twilio/crm-call-gather/{activity_id}", dependencies=[Depends(verify_twilio)])
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


@app.post("/twilio/crm-call-status/{activity_id}", dependencies=[Depends(verify_twilio)])
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
    if summary and summary != "AI answered the call." and not _call_already_remembered(location["customer_id"], conv_id):
        background.add_task(_remember_voice_call, location["customer_id"], caller, conv_id, summary,
                            data.get("transcript") or [], name, location.get("location_id"))
    return {"ok": True, "logged": True}


# ---------------------------------------------------------------------------
# VOICE-CALL MEMORY SYNC — the voice agent can't be trusted to call
# remember_caller on its own, so after every finished call we read the
# conversation from ElevenLabs and fold what the caller said into their
# profile. Runs inside /internal/run-followups (every 5 min) and needs no
# webhook setup; the post-call webhook above, if configured, does the same
# thing sooner. Each conversation is processed once (memory_conv_ids).
# ---------------------------------------------------------------------------
VOICE_SYNC_LOOKBACK = timedelta(hours=6)


def _call_already_remembered(customer_id: str, conv_id: str) -> bool:
    if not conv_id:
        return False
    r = (sb.table("recall_contact_activities").select("id").eq("customer_id", customer_id)
         .eq("type", "ai_call").eq("source_ref", f"el:{conv_id}")
         .contains("metadata", {"memory_done": True}).limit(1).execute())
    return bool(r.data)


def _remember_voice_call(customer_id: str, caller: str, conv_id: str, summary: str,
                         transcript: list, name: str = None, location_id: str = None):
    """Builds the 'new information' from what the CALLER actually said (the
    summary can contain the agent's own guesses) and merges it into memory."""
    said = [str(t.get("message") or "").strip() for t in (transcript or [])
            if t.get("role") == "user" and (t.get("message") or "").strip()]
    if not said and not summary:
        return
    info = ""
    if said:
        info += "What the caller said on the phone today:\n" + "\n".join(f"- {s}" for s in said)[:2500] + "\n"
    if summary:
        info += f"Call summary (may include the receptionist's own words — trust the caller's lines above): {summary[:600]}"
    update_contact_memory(customer_id, caller, info, "phone call", name, None, location_id)
    try:
        acts = (sb.table("recall_contact_activities").select("id, metadata").eq("customer_id", customer_id)
                .eq("source_ref", f"el:{conv_id}").limit(1).execute()).data
        if acts:
            sb.table("recall_contact_activities").update(
                {"metadata": {**(acts[0].get("metadata") or {}), "memory_done": True}}).eq("id", acts[0]["id"]).execute()
    except Exception as e:
        log.error(f"Couldn't mark call {conv_id} as remembered: {e}")


def _sync_voice_calls(now: datetime, lookback: timedelta = VOICE_SYNC_LOOKBACK) -> int:
    """Pulls recently finished AI-answered calls from ElevenLabs, logs each on
    the caller's timeline and updates their memory. Returns calls processed."""
    if not ELEVENLABS_API_KEY:
        return 0
    locs = (sb.table(TABLE_LOC).select("id, customer_id, elevenlabs_agent_id")
            .not_.is_("elevenlabs_agent_id", "null").execute()).data or []
    after = int((now - lookback).timestamp())
    done = 0
    for loc in locs:
        try:
            r = requests.get("https://api.elevenlabs.io/v1/convai/conversations", headers=el_headers(),
                             params={"agent_id": loc["elevenlabs_agent_id"], "page_size": 30,
                                     "call_start_after_unix": after}, timeout=15)
            r.raise_for_status()
            convs = [c for c in (r.json().get("conversations") or [])
                     if c.get("status") == "done" and (c.get("message_count") or 0) >= 2]
        except Exception as e:
            log.error(f"Voice sync: couldn't list calls for location {loc['id']}: {e}")
            continue
        if not convs:
            continue
        refs = [f"el:{c['conversation_id']}" for c in convs]
        seen = (sb.table("recall_contact_activities").select("source_ref, metadata")
                .eq("customer_id", loc["customer_id"]).in_("source_ref", refs).execute()).data or []
        finished = {s["source_ref"] for s in seen if (s.get("metadata") or {}).get("memory_done")}
        for c in convs:
            conv_id = c["conversation_id"]
            if f"el:{conv_id}" in finished:
                continue
            try:
                d = requests.get(f"https://api.elevenlabs.io/v1/convai/conversations/{conv_id}",
                                 headers=el_headers(), timeout=15)
                d.raise_for_status()
                d = d.json()
            except Exception as e:
                log.error(f"Voice sync: couldn't read call {conv_id}: {e}")
                continue
            meta = d.get("metadata") or {}
            pc = meta.get("phone_call") or {}
            dyn = ((d.get("conversation_initiation_client_data") or {}).get("dynamic_variables")) or {}
            caller = normalize_e164(pc.get("external_number") or dyn.get("system__caller_id") or d.get("user_id") or "")
            if not caller:
                continue  # web/test-widget call — no phone number to remember it under
            analysis = d.get("analysis") or {}
            summary = (analysis.get("transcript_summary") or "").strip()
            started = meta.get("start_time_unix_secs") or c.get("start_time_unix_secs")
            upsert_contact_and_log(
                loc["customer_id"], caller, "ai_call", body=summary or "AI answered the call.",
                metadata={"conversation_id": conv_id, "duration_secs": meta.get("call_duration_secs"),
                          "call_successful": analysis.get("call_successful")},
                source="ai_call", location_id=loc["id"], source_ref=f"el:{conv_id}",
                created_at=datetime.fromtimestamp(started, timezone.utc).isoformat() if started else None,
            )
            _remember_voice_call(loc["customer_id"], caller, conv_id, summary,
                                 d.get("transcript") or [], None, loc["id"])
            done += 1
    return done


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


TASK_RETRY_WINDOW = timedelta(hours=24)
TASK_RETRY_EVERY = timedelta(minutes=30)


_RETRY_MARK = " (first try "


def _first_try_at(t: dict, now: datetime) -> datetime:
    res = t.get("result") or ""
    if _RETRY_MARK in res:
        try:
            return datetime.fromisoformat(res.split(_RETRY_MARK, 1)[1].rstrip(")"))
        except ValueError:
            pass
    return now


def _task_can_retry(t: dict, now: datetime) -> bool:
    """Temporary failures (Twilio outage, network) are retried every 30
    minutes for a day before the task is marked failed."""
    return now - _first_try_at(t, now) < TASK_RETRY_WINDOW


def _retry_task_later(t: dict, now: datetime, note: str):
    first = _first_try_at(t, now)
    sb.table("recall_tasks").update({
        "executed_at": None, "due_at": (now + TASK_RETRY_EVERY).isoformat(),
        "result": f"{note}{_RETRY_MARK}{first.isoformat()})",
    }).eq("id", t["id"]).execute()


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
    out = {"tasks_done": 0, "tasks_failed": 0, "tasks_waiting": 0, "auto_texts": 0, "auto_calls": 0, "auto_failed": 0,
           "stalled_texts": 0, "stalled_calls": 0, "stalled_failed": 0, "voice_calls_synced": 0}

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
            if e.status_code >= 500 and _task_can_retry(t, now):
                _retry_task_later(t, now, "Couldn't place the call yet — retrying")
                out["tasks_waiting"] += 1
                continue
        except Exception as e:
            log.error(f"Follow-up task {t['id']} failed: {e}")
            status, result = "failed", "Couldn't send — " + str(e)[:150]
            if _task_can_retry(t, now):
                _retry_task_later(t, now, "Couldn't send yet — retrying")
                out["tasks_waiting"] += 1
                continue
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
            # A send that never went out doesn't count as a step: undo the
            # counter so this step is retried on a run ~30 minutes from now.
            try:
                sb.table("recall_contacts").update({"auto_followups_sent": sent_before}).eq("id", r["contact_id"]).execute()
            except Exception:
                pass
    # 3. Stalled lead recovery
    try:
        stalled = sb.rpc("recall_crm_due_stalled", {}).execute().data or []
    except Exception as e:
        log.error(f"Stalled-lead query failed: {e}")
        stalled = []
    for r in stalled[:25]:
        cutoff = (now - timedelta(hours=1)).isoformat()
        claimed = (sb.table("recall_contacts").update({
            "stall_attempts": r["attempt"], "stall_last_at": now.isoformat(),
        }).eq("id", r["contact_id"]).or_(f"stall_last_at.is.null,stall_last_at.lt.{cutoff}").execute()).data
        if not claimed:
            continue
        contact = claimed[0]
        try:
            message = _stalled_message(r)
            if r["channel"] == "call":
                _place_crm_call(r["customer_id"], contact, "ai_message", message, kind="stalled_followup")
                out["stalled_calls"] += 1
            else:
                _run_text(r["customer_id"], contact, message, "stalled_followup")
                out["stalled_texts"] += 1
        except Exception as e:
            log.error(f"Stalled-lead follow-up for {r['contact_id']} failed: {getattr(e, 'detail', e)}")
            out["stalled_failed"] += 1
            # Didn't go out (e.g. Twilio down): give the attempt back. The
            # claim timestamp stays, so it's retried in about an hour.
            try:
                sb.table("recall_contacts").update({"stall_attempts": max(0, int(r["attempt"]) - 1)}).eq("id", r["contact_id"]).execute()
            except Exception:
                pass

    # 4. Remember what callers told the voice AI (see _sync_voice_calls)
    try:
        hours = request.query_params.get("voice_lookback_hours") or ""
        lookback = timedelta(hours=int(hours)) if hours.isdigit() and 1 <= int(hours) <= 24 * 30 else VOICE_SYNC_LOOKBACK
        out["voice_calls_synced"] = await run_in_threadpool(_sync_voice_calls, now, lookback)
    except Exception as e:
        log.error(f"Voice call sync failed: {e}")

    # 5. Account follow-ups (unfinished checkout, no calls yet, win-back)
    try:
        out.update(await run_in_threadpool(run_lifecycle_followups, now))
    except Exception as e:
        log.error(f"Lifecycle follow-ups failed: {e}")

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



# ===========================================================================
# STALLED LEAD RECOVERY — leads that were Contacted / Qualified / Quoted and
# then went quiet get a check-in written by the AI from what it remembers
# about them ("Hi Bob, just checking in on the $800 brake quote…").
# Attempt 1 = text, attempt 2 = AI call (if enabled), attempt 3 = last text.
# Eligibility lives in recall_crm_due_stalled(); runs in /internal/run-followups.
# ===========================================================================
def _stalled_fallback(r: dict) -> str:
    first = (r.get("name") or "").split(" ")[0]
    hi = f"Hi {first}, " if first else "Hi, "
    biz = r.get("business_name") or "us"
    amt = f" for ${float(r['quote_amount']):,.0f}" if r.get("quote_amount") else ""
    if r["channel"] == "call":
        what = f"the quote we sent you{amt}" if r.get("status") == "quoted" else "your recent request"
        return (f"We're following up on {what}. If you'd like to go ahead or have any questions, "
                "press 1 now to talk with us, or call us back any time.")
    if r.get("status") == "quoted":
        return (f"{hi}this is {biz} checking in on the quote we sent{amt}. Any questions, or would you like "
                "to get it on the schedule? Just reply here.")
    if r.get("attempt", 1) >= 3:
        return f"{hi}last check-in from {biz} — if you still need help, just reply here and we'll take care of you."
    return f"{hi}this is {biz} following up. Still need help? Reply here and we'll get you taken care of."


def _stalled_message(r: dict) -> str:
    """Short, personal check-in written from the contact's memory; falls back to a template."""
    fallback = _stalled_fallback(r)
    if not ANTHROPIC_API_KEY:
        return fallback
    is_call = r["channel"] == "call"
    try:
        context = [f"Business: {r.get('business_name')}", f"Customer name: {r.get('name') or 'unknown'}",
                   f"Lead status: {r.get('status')}", f"Days since last contact: {r.get('quiet_days')}",
                   f"This is follow-up attempt {r.get('attempt')} (3 = final)."]
        if r.get("quote_amount"):
            context.append(f"Quote sent: ${float(r['quote_amount']):,.2f}" + (f" — {r['quote_note']}" if r.get("quote_note") else ""))
        if r.get("memory"):
            context.append("What we know about them:\n" + r["memory"])
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
            json={
                "model": ANTHROPIC_MODEL, "max_tokens": 200,
                "system": (
                    "You write one short follow-up for a small local business to a customer who went quiet. "
                    + ("It will be READ ALOUD by an automated phone call right after the line 'Hi <name>, this is an "
                       "automated call from <business>.', so don't greet them again; 1–3 short spoken sentences; end by "
                       "saying they can press 1 to talk with someone now. "
                       if is_call else
                       "It is a text message: 1–2 sentences, under 280 characters, start with 'Hi <first name>,' when "
                       "the name is known and say which business it is. ")
                    + "Be warm and helpful, never pushy. Mention the specific thing they asked about or were quoted "
                    "when it's known. Never invent prices, discounts, dates or facts that aren't in the context. "
                    "Never mention health details. On a final attempt, make clear it's the last check-in. "
                    "Output only the message."
                ),
                "messages": [{"role": "user", "content": "\n".join(context)}],
            },
            timeout=20,
        )
        resp.raise_for_status()
        text = "".join(b.get("text", "") for b in resp.json().get("content", []) if b.get("type") == "text").strip().strip('"')
        limit = 600 if is_call else 320
        return text[:limit] if len(text) >= 20 else fallback
    except Exception as e:
        log.error(f"Stalled message generation failed, using template: {e}")
        return fallback


class QuoteCreate(BaseModel):
    amount: float
    note: Optional[str] = None


@app.post("/crm/{customer_id}/contacts/{contact_id}/quote")
def crm_quote(customer_id: str, contact_id: str, payload: QuoteCreate, background: BackgroundTasks,
              authorization: str = Header(None)):
    """Owner logs 'Quote sent: $X'. Moves the lead to Quoted (never backward from
    Booked/Won) so stalled-lead recovery knows to chase it."""
    require_auth(customer_id, authorization)
    contact = _get_contact_or_404(customer_id, contact_id)
    if payload.amount is None or payload.amount <= 0 or payload.amount > 10_000_000:
        raise HTTPException(422, "Enter the quote amount.")
    note = (payload.note or "").strip()[:300] or None
    now = datetime.now(timezone.utc).isoformat()
    sb.table("recall_contacts").update({
        "quote_amount": round(float(payload.amount), 2), "quote_sent_at": now, "quote_note": note,
        "last_activity_at": now, "stall_attempts": 0, "stall_last_at": None,
    }).eq("id", contact_id).eq("customer_id", customer_id).execute()
    body = f"Quote sent: ${payload.amount:,.2f}" + (f" — {note}" if note else "")
    sb.table("recall_contact_activities").insert({
        "contact_id": contact_id, "customer_id": customer_id, "type": "quote", "body": body,
        "metadata": {"amount": round(float(payload.amount), 2)},
    }).execute()
    if contact.get("status") in ("new", "contacted", "qualified", "lost"):
        sb.rpc("recall_crm_update_contact", {"p_customer_id": customer_id, "p_contact_id": contact_id,
                                             "p_patch": {"status": "quoted"}}).execute()
    background.add_task(update_contact_memory, customer_id, None, body + ".", "owner update", None, contact_id)
    return _get_contact_or_404(customer_id, contact_id)


class RecoverySettings(BaseModel):
    enabled: Optional[bool] = None
    after_days: Optional[int] = None
    quote_after_days: Optional[int] = None
    max_attempts: Optional[int] = None
    call_enabled: Optional[bool] = None


def _recovery_view(loc: dict) -> dict:
    return {"location_id": loc["id"], "enabled": loc.get("stall_enabled", False),
            "after_days": loc.get("stall_after_days", 3), "quote_after_days": loc.get("stall_quote_after_days", 2),
            "max_attempts": loc.get("stall_max_attempts", 2), "call_enabled": loc.get("stall_call_enabled", True)}


@app.get("/crm/{customer_id}/recovery-settings")
def get_recovery_settings(customer_id: str, location_id: str = None, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    return _recovery_view(get_location_for_customer(customer_id, location_id))


@app.post("/crm/{customer_id}/recovery-settings")
def save_recovery_settings(customer_id: str, payload: RecoverySettings, location_id: str = None,
                           authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    loc = get_location_for_customer(customer_id, location_id)
    f = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    upd = {}
    if "enabled" in f:
        upd["stall_enabled"] = bool(f["enabled"])
        if f["enabled"] and not loc.get("stall_enabled"):
            upd["stall_enabled_at"] = datetime.now(timezone.utc).isoformat()
    for k, col, lo, hi in (("after_days", "stall_after_days", 1, 30), ("quote_after_days", "stall_quote_after_days", 1, 30),
                           ("max_attempts", "stall_max_attempts", 1, 3)):
        if k in f:
            v = int(f[k])
            if not (lo <= v <= hi):
                raise HTTPException(422, f"{k.replace('_', ' ').capitalize()} must be between {lo} and {hi}.")
            upd[col] = v
    if "call_enabled" in f:
        upd["stall_call_enabled"] = bool(f["call_enabled"])
    if upd:
        loc = sb.table(TABLE_LOC).update(upd).eq("id", loc["id"]).execute().data[0]
    return _recovery_view(loc)


# ===========================================================================
# ROI DASHBOARD
# ===========================================================================
def _roi_range(period: str):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(BUSINESS_TZ)
    now_local = datetime.now(tz)
    end = (now_local + timedelta(minutes=1)).astimezone(timezone.utc)
    if period == "this_month":
        start = now_local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == "last_month":
        first = now_local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = (first - timedelta(days=1)).replace(day=1)
        end = first.astimezone(timezone.utc)
    elif period == "90d":
        start = now_local - timedelta(days=90)
    elif period == "all":
        start = now_local - timedelta(days=3650)
    else:
        start = now_local - timedelta(days=30)
    return start.astimezone(timezone.utc), end


@app.get("/crm/{customer_id}/roi")
def crm_roi(customer_id: str, period: str = "30d", authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    if period not in ("30d", "this_month", "last_month", "90d", "all"):
        raise HTTPException(422, "period must be 30d, this_month, last_month, 90d or all.")
    start, end = _roi_range(period)
    if period == "all":
        cust = sb.table(TABLE_CUST).select("created_at").eq("id", customer_id).execute().data
        if cust and cust[0].get("created_at"):
            start = max(start, datetime.fromisoformat(cust[0]["created_at"].replace("Z", "+00:00")))
    data = sb.rpc("recall_crm_roi", {"p_customer_id": customer_id, "p_from": start.isoformat(),
                                     "p_to": end.isoformat()}).execute().data
    return {**(data or {}), "period": period}


class RoiSettings(BaseModel):
    avg_job_value: Optional[float] = None
    monthly_cost: Optional[float] = None


@app.post("/crm/{customer_id}/roi-settings")
def save_roi_settings(customer_id: str, payload: RoiSettings, authorization: str = Header(None)):
    require_auth(customer_id, authorization)
    f = payload.model_dump(exclude_unset=True) if hasattr(payload, "model_dump") else payload.dict(exclude_unset=True)
    upd = {}
    for k in ("avg_job_value", "monthly_cost"):
        if k in f:
            v = f[k]
            if v is not None and (v < 0 or v > 1_000_000):
                raise HTTPException(422, "Enter a valid dollar amount.")
            upd[k] = round(float(v), 2) if v is not None else None
    if upd:
        sb.table(TABLE_CUST).update(upd).eq("id", customer_id).execute()
    return {"ok": True, **upd}
