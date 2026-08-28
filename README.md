# Recall — Missed Call Text-Back

Fixes the two things that killed the last version:
- **Money draining with no income:** every Twilio number is now tied to a Stripe
  subscription. `status` (`trial → active → past_due/canceled`) tracks who's
  actually paying, so dead signups are visible instead of silently costing you.
- **It kept breaking:** this is a single FastAPI service (matches your existing
  Render/Supabase stack), not a fragile chain of no-code steps.

## What's here
- `main.py` — backend: signup, Twilio voice webhook, auto-text on missed call,
  Stripe billing sync, dashboard API
- `site/index.html` — public signup page (deploy to Netlify)
- `site/dashboard.html` — customer-facing dashboard (deploy to Netlify)
- `requirements.txt`

## Setup (in order)

**1. Stripe**
- Create a Product ("Recall — Missed Call Recovery") with a monthly Price
  (e.g. $49/mo). Copy the Price ID → `STRIPE_PRICE_ID`.
- Add a webhook endpoint pointing to
  `https://<your-render-url>/stripe/webhook`, listening for:
  `checkout.session.completed`, `invoice.payment_succeeded`,
  `invoice.payment_failed`, `customer.subscription.deleted`,
  `customer.subscription.trial_will_end`.
- Copy the signing secret → `STRIPE_WEBHOOK_SECRET`.

**2. Twilio**
- Just needs your existing Account SID + Auth Token. The app buys a new
  local number automatically for each signup (~$1.15/mo — this cost is
  now covered by the subscription, not you).

**3. Deploy backend to Render**
- Push this folder to a repo, deploy as a Python web service on Render
  (same account as `main-backend-k32m.onrender.com`, or a new service).
- Env vars needed: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`,
  `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `STRIPE_SECRET_KEY`,
  `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID`, `PUBLIC_BASE_URL`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

**4. Deploy site/ to Netlify**
- Update `API_BASE` at the top of the `<script>` in both HTML files to your
  Render URL.
- Drag-and-drop `site/` onto Netlify, or connect the repo.

**5. Database**
- Already created in your Supabase project (`wzcuzyouymauokijaqjk`):
  `recall_customers`, `recall_missed_calls`.

## Customer flow
1. They fill out the signup form → backend buys them a dedicated Twilio
   number and creates a 7-day-trial Stripe subscription → they enter card
   info on Stripe Checkout.
2. They forward their business line to the new number when unanswered/busy
   (or route calls directly to it).
3. Missed call → auto-text goes out immediately → logged.
4. They check `dashboard.html?customer_id=...` to see missed calls & texts sent.
5. Trial ends → Stripe charges automatically → `status` flips to `active`.
   If payment fails, `status` flips to `past_due` and the voice webhook stops
   dialing out for them — no more silent cost.

## Not yet built (next steps when you're ready)
- Cron job to auto-release Twilio numbers for customers `canceled`/`past_due`
  more than ~14 days (this is what actually stops the bleeding long-term).
- Real auth on the dashboard (currently the customer_id in the URL is the
  only gate — fine for a handful of pilot customers, not for scale).
- Email/SMS reminder on `trial_will_end`.
