-- Row-level security for the calibration target.
-- Some policies here are DELIBERATELY WRONG. See GROUND-TRUTH.md for the answer key.

-- profiles: a user may read only their own row. (Correct.)
alter table public.profiles enable row level security;
create policy profiles_select_self on public.profiles
  for select using (id = auth.uid());

-- tenants: a member may read only their own tenant. (Correct.)
alter table public.tenants enable row level security;
create policy tenants_select_own on public.tenants
  for select using (id = public.current_tenant_id());

-- notes: fully tenant-scoped read/write. (Correct — true-negative for the scanner.)
alter table public.notes enable row level security;
create policy notes_rw_own_tenant on public.notes
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());

-- counters: tenant-scoped. (Correct — the counter bug is in the API route, not the policy.)
alter table public.counters enable row level security;
create policy counters_rw_own_tenant on public.counters
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());

-- documents: BUG (PLANTED) — USING (true) makes every row readable by everyone,
-- including the anon role. Cross-tenant read of all documents.
alter table public.documents enable row level security;
create policy documents_select_all on public.documents
  for select using (true);

-- invoices: BUG (PLANTED) — auth.role() = 'authenticated' looks locked down but only
-- checks that the caller is logged in, not WHICH tenant. Any authenticated user reads
-- every tenant's invoices.
alter table public.invoices enable row level security;
create policy invoices_select_authenticated on public.invoices
  for select using (auth.role() = 'authenticated');

-- audit_logs: BUG (PLANTED) — row level security is never enabled on this table, so the
-- PostgREST API exposes all tenants' audit trails to anyone with the anon key.
-- (Intentionally NO "alter table public.audit_logs enable row level security;")
