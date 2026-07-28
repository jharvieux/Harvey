-- #1299 (finishing #140/#141/#142) — seeded-stack fixtures for the three connected-tier Supabase
-- classes that had no corpus row at all: PostgREST schema exposure, pg_graphql introspection, and
-- Realtime authorization. Two of the three are the ones a LOCAL-mode scan cannot reach and now
-- discloses as SB-SCOPE-00 (src/scan/supabase.ts); the Realtime one runs in both modes.
--
-- Every statement below was MEASURED on 2026-07-28 against a stock `supabase start` stack (Supabase
-- CLI 2.102.0) before it was written here — see docs/runbooks/dry-run-calibration.md §11 for the
-- psql transcript. The checks these feed read a LIVE database / the hosted PostgREST config, never
-- committed SQL, so their corpus rows are `expectedTier: "connected"` and are N/A in the static
-- gate; this file is what makes them reproducible on a stack rather than assertions on paper.

-- P-API-SCHEMA-WIDE (#141). checkExposedSchemas flags any schema in PostgREST's `db-schema`
-- allow-list beyond public/graphql_public. The allow-list itself is declared in
-- supabase/config.toml (`[api] schemas`) — that is the half PostgREST reads. This is the other
-- half: a real schema behind the name, so the exposure is a genuine reachable surface.
create schema if not exists internal_ops;

create table if not exists internal_ops.job_queue (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  kind text not null,
  created_at timestamptz not null default now()
);

alter table internal_ops.job_queue enable row level security;

create policy job_queue_tenant_read on internal_ops.job_queue
  for select to authenticated
  using (tenant_id = public.current_tenant_id());

-- N-API-SCHEMA-INTERNAL (#141 boundary). A schema that exists in the database and is deliberately
-- absent from `[api] schemas`. checkExposedSchemas reads the allow-list, not pg_namespace, so it
-- must stay silent here — the discriminator against internal_ops is the config file, not this SQL,
-- which is exactly the distinction the check is claimed to make.
create schema if not exists analytics_private;

create table if not exists analytics_private.rollup_daily (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  total integer not null default 0
);

alter table analytics_private.rollup_daily enable row level security;

create policy rollup_daily_tenant_read on analytics_private.rollup_daily
  for select to authenticated
  using (tenant_id = public.current_tenant_id());

-- P-GRAPHQL-INTROSPECTION (#142). pg_graphql is AVAILABLE but NOT installed by a stock
-- `supabase start` — MEASURED 2026-07-28: pg_available_extensions reports default_version 1.5.11
-- with a null installed_version, and pg_extension has no row. hasPgGraphql() requires the extension
-- present WITH a version, and `graphql_public` is already in the default allow-list, so installing
-- it here is the whole plant. (It is also why the ATC live run recorded this class as a clean
-- negative: pg_graphql was simply not installed there either.)
create extension if not exists pg_graphql;

-- P-REALTIME-NO-AUTHZ (#140). Realtime Authorization is enforced by RLS on realtime.messages, which
-- ships ENABLED and is owned by supabase_realtime_admin — so this looked unplantable from a project
-- migration. It is not: `postgres` is a member of supabase_realtime_admin, and MEASURED 2026-07-28
-- the statement below returns ALTER TABLE and leaves relrowsecurity = false. That is precisely the
-- misconfiguration checkRealtimeAuthorization exists to catch, and the only way to seed it.
alter table realtime.messages disable row level security;
