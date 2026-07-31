-- #1492: P-SENSITIVE-COLS could never fire. Splinter's `sensitive_columns_exposed` lint
-- (src/scan/rules/splinter.sql) requires the table to be exposed via the API *without RLS* — but
-- the original plant, public.support_tickets.customer_ssn (20260709000004), has RLS enabled, so
-- the lint's own `exposed_tables` CTE (`and not c.relrowsecurity`) excludes it before the column
-- pattern is ever checked. Re-checked against the whole live schema on 2026-07-28: none of the
-- tables that DO have RLS off (audit_logs, billing_exports, coupon_redemptions, export_audit,
-- mt_invoices) carries a sensitive-pattern column either, so nothing in this target could ever
-- reach the class. This migration plants it correctly: RLS off + a sensitive-pattern column, and a
-- same-shape RLS-on twin as the boundary negative.

-- PLANTED BUG (P-SENSITIVE-COLS) — RLS is deliberately never enabled here, unlike
-- support_tickets/reports elsewhere in this schema. compliance_case_notes is exposed via
-- PostgREST (default anon/authenticated table privileges, same as audit_logs) with no RLS, and
-- carries a column matching the lint's sensitive-pattern list ("national_id").
create table public.compliance_case_notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  national_id text,
  note text,
  created_at timestamptz not null default now()
);
-- (Intentionally NO "alter table ... enable row level security;" — the plant.)

-- N-SENSITIVE-COLS-RLS-ON: the boundary negative. Identical sensitive column, RLS enabled and
-- tenant-scoped — the lint's `not c.relrowsecurity` guard must clear this one.
create table public.compliance_case_notes_archived (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  national_id text,
  note text,
  archived_at timestamptz not null default now()
);
alter table public.compliance_case_notes_archived enable row level security;
create policy compliance_case_notes_archived_rw_own_tenant on public.compliance_case_notes_archived
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());
