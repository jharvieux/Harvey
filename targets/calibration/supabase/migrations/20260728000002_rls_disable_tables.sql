-- #1425 setup migration — the "before" half of the protect-then-unprotect shape. Nothing here is a
-- defect: both tables are created correctly, with row security on and a tenant-scoped policy. What
-- makes one of them a Critical is migration 20260728000003, which turns row security back off and
-- never reverts it. Split across files on purpose: the whole point of #1425 is that
-- checkMigrationRlsStatic aggregated `enable row level security` across the WHOLE migration set, so
-- an enable in an EARLIER file made the table look protected forever.

-- The table that will be un-protected and left that way (P-RLS-DISABLE-NOT-REVERTED).
create table public.billing_exports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  exported_at timestamptz not null default now(),
  row_count integer not null default 0
);
alter table public.billing_exports enable row level security;
create policy billing_exports_rw_own_tenant on public.billing_exports
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());

-- The benign twin (N-RLS-DISABLE-REVERTED): identical shape, un-protected by the same hotfix
-- migration, but re-enabled by 20260728000004. Its final state is protected, so it must stay clean.
create table public.import_staging (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  row_count integer not null default 0,
  imported_at timestamptz not null default now()
);
alter table public.import_staging enable row level security;
create policy import_staging_rw_own_tenant on public.import_staging
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());

-- SCOPE CONTROL (P-RLS-DISABLE-SCOPE-CONTROL) — a file that is never read reports zero findings,
-- exactly like one that is read and missed. The two #1425 entries cannot serve as this file's
-- control: they are decided by the disable in 20260728000003 and the re-enable in 20260728000004,
-- and SB-RLS-DISABLED-STATIC does not require having seen the `create table`, so BOTH would still
-- score correctly if this file were skipped entirely. public.export_audit is created here and gets
-- row security nowhere, so checkMigrationRlsStatic must emit SB-RLS-STATIC-export_audit at high
-- tier — a failure here means this file was not read and the two entries beside it prove nothing.
create table public.export_audit (
  id uuid primary key default gen_random_uuid(),
  export_id uuid,
  actor text,
  created_at timestamptz not null default now()
);
