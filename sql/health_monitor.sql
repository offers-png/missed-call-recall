-- CallsKept Health Monitor (2026-10-07)
-- Run once in Supabase (SQL editor or a migration) before deploying main.py.

-- Failures recorded by the app (failed texts/calls, AI errors, ElevenLabs errors).
create table if not exists recall_health_events (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  component text not null,        -- twilio | delivery | elevenlabs | anthropic | supabase | job
  customer_id uuid,
  message text
);
create index if not exists recall_health_events_created_idx on recall_health_events (created_at desc);
create index if not exists recall_health_events_comp_idx on recall_health_events (component, created_at desc);

-- Latest result per check, plus what's needed to avoid repeat alerts.
create table if not exists recall_health_state (
  component text primary key,     -- server | twilio | elevenlabs | job | anthropic | supabase | morning_summary
  status text not null default 'green',
  detail text,
  data jsonb not null default '{}'::jsonb,
  checked_at timestamptz,
  changed_at timestamptz,
  alerted_at timestamptz
);

-- Only the backend (service key) touches these; no public access.
alter table recall_health_events enable row level security;
alter table recall_health_state enable row level security;

-- Where owner alerts go (used by alert_platform_owner()).
update recall_app_settings set value = '"+13474764576"'::jsonb, updated_at = now() where key = 'owner_alert_phone';
insert into recall_app_settings (key, value, updated_at)
select 'owner_alert_phone', '"+13474764576"'::jsonb, now()
where not exists (select 1 from recall_app_settings where key = 'owner_alert_phone');
