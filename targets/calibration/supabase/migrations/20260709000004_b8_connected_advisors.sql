-- Batch B8 (#71) — Supabase connected-tier advisor fixtures. Everything below is a DELIBERATE
-- plant so a live `get_advisors(type: "security")` run WOULD catch it (Splinter lints, see
-- GROUND-TRUTH.md §"Batch B8"). This batch is offline-built and offline-tested only: no Docker/
-- live Supabase project was started to confirm these fire — that confirmation is a deferred
-- main-session pass. All of these score as `connected` tier in src/scan/calibration.ts (N/A on
-- a static run, never a free-count claim).

-- BUG (PLANTED, connected/B8) — Splinter `0002 auth_users_exposed`. A public-schema view selects
-- from auth.users and is granted to anon/authenticated, exposing every user's id/email/created_at
-- through PostgREST regardless of any RLS on auth.users itself (auth.users has no RLS by design).
create view public.user_directory as
  select id, email, created_at from auth.users;

grant select on public.user_directory to anon, authenticated;

-- BUG (PLANTED, connected/B8) — Splinter `0010 security_definer_view`. A view with no
-- `security_invoker = true` option runs with the privileges of its owner (the migration role),
-- not the querying user — it silently bypasses the RLS policies on `invoices` for whoever reads
-- the view, the same way a SECURITY DEFINER function would.
create view public.tenant_totals as
  select tenant_id, sum(amount_cents) as total_cents
  from public.invoices
  group by tenant_id;

-- BUG (PLANTED, connected/B8) — Splinter `0011 function_search_path_mutable`. No
-- `set search_path`, unlike public.current_tenant_id() above (20260708000001_schema.sql), which
-- sets it correctly and is this fixture's negative (N-DEFINER-SCOPED). A mutable search_path lets
-- a caller who can create objects in an earlier schema on their search_path shadow an
-- unqualified reference inside the function body.
create or replace function public.get_invoice_total(p_tenant_id uuid)
returns bigint
language sql
stable
as $$
  select coalesce(sum(amount_cents), 0) from public.invoices where tenant_id = p_tenant_id;
$$;

-- BUG (PLANTED, connected/B8) — Splinter `0015 rls_references_user_metadata`. `user_metadata` is
-- a claim any authenticated user can set on themselves via the client SDK
-- (supabase.auth.updateUser({ data: { is_admin: true } })) — a policy that trusts it for an
-- authorization decision is self-service privilege escalation.
create table public.internal_notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.internal_notes enable row level security;
create policy internal_notes_admin_read on public.internal_notes
  for select
  using ((auth.jwt() -> 'user_metadata' ->> 'is_admin')::boolean is true);

-- BUG (PLANTED, connected/B8) — Splinter `0023 sensitive_columns_exposed`. `customer_ssn` is a
-- known-sensitive column name pattern reachable via PostgREST for any tenant member, even though
-- row-level access is correctly tenant-scoped — the column itself, not just the row set, is the
-- exposure the lint flags.
create table public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  subject text not null,
  customer_ssn text,
  -- #1424: the column 20260719000002's SECURITY DEFINER readers filter on. Added here, where the
  -- table is declared, rather than as a later ALTER, so M10's migration-SQL classifier sees it.
  requester_email text,
  created_at timestamptz not null default now()
);

alter table public.support_tickets enable row level security;
create policy support_tickets_rw_own_tenant on public.support_tickets
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());

-- BUG (PLANTED, connected/B8) — Splinter `0008/rls_enabled_no_policy`, the RISKY case (contrast
-- N-RLS-DENY-ALL / service_state in 20260708000002_rls.sql, a service-role-only table where zero
-- policies is deliberate deny-all-by-design). `reports` is meant to be tenant-readable — the
-- missing policy means the feature silently 403s for everyone, a "forgot to finish the RLS setup"
-- signal an advisor run should surface, not a safe default.
create table public.reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  title text not null,
  created_at timestamptz not null default now()
);

alter table public.reports enable row level security;

-- BUG (PLANTED, connected/B8) — dangerous extension (pg_net), matching checkDangerousExtensions
-- in src/scan/supabase-config.ts. Enabling the extension alone is the deterministic fact the
-- checker flags; the SECURITY DEFINER wrapper below is what makes it exploitable rather than
-- dormant — any authenticated caller can make the database issue an outbound HTTP request to a
-- URL of their choosing (DB-originated SSRF).
create extension if not exists pg_net with schema extensions;

create or replace function public.fetch_webhook_preview(p_url text)
returns bigint
language plpgsql
security definer
set search_path = extensions
as $$
declare
  request_id bigint;
begin
  select net.http_get(p_url) into request_id;
  return request_id;
end;
$$;

grant execute on function public.fetch_webhook_preview(text) to authenticated;
