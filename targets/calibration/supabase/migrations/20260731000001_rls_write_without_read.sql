-- #1370 POSITIVE for SB-RLS-CMDGAP-<table> — the one permission-matrix cell the rule reports: a
-- table whose policy set grants the client a WRITE and no SELECT.
--
-- Read is the weakest privilege in every access model, so a set that hands out INSERT/UPDATE/DELETE
-- while withholding SELECT is internally contradictory: either the read policy is missing by
-- oversight, or reads run over a service-role connection whose tenant filtering is application code
-- this RLS pass never reads. The write policies here are all correctly tenant-scoped on purpose —
-- the finding is about the SHAPE OF THE SET, not about a bad predicate, and a plant with a leaky
-- predicate would be caught by usingTrueReview instead and prove nothing about this rule.
--
-- The negative twin is 20260731000002_rls_stripe_sync_readonly.sql: the mirror-image shape (read
-- policed, every write server-side), which must stay silent.
create table public.device_pings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  emitted_at timestamptz not null default now(),
  payload jsonb
);

alter table public.device_pings enable row level security;

create policy device_pings_insert_own_tenant on public.device_pings
  for insert to authenticated with check (tenant_id = public.current_tenant_id());
create policy device_pings_update_own_tenant on public.device_pings
  for update to authenticated using (tenant_id = public.current_tenant_id());
create policy device_pings_delete_own_tenant on public.device_pings
  for delete to authenticated using (tenant_id = public.current_tenant_id());
