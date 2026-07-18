-- #546 — supabase/seed.sql inserts a N-BCRYPT-HASH-SEED fixture row into
-- public.legacy_accounts, but no migration ever created that table, so the full migration set
-- + seed never applied cleanly on a fresh DB (`relation "public.legacy_accounts" does not exist`).
-- This migration is the missing table, not a new fixture: N-BCRYPT-HASH-SEED
-- (src/scan/calibration/b9-secrets.entries.ts) is about the bcrypt digest string in seed.sql, not
-- this table's shape, so location/match there are unaffected.
--
-- RLS enabled + zero policies, same deny-all-by-design shape as public.service_state
-- (N-RLS-DENY-ALL, 20260708000001_schema.sql / 20260708000002_rls.sql): a legacy table with no
-- app code reading it, so checkMigrationRlsStatic sees the ENABLE and stays silent — this does
-- not introduce a new SB-RLS-STATIC finding.
create table public.legacy_accounts (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

alter table public.legacy_accounts enable row level security;
