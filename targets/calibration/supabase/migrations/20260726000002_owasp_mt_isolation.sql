-- OWASP Multi-Tenant Application Security Cheat Sheet, section 2 (Database Isolation Strategies),
-- pinned at CheatSheetSeries commit 46f8d0456686f4d1ef523c7cc65be58bd221ffed.
--
-- The sheet's row-level recipe is: ENABLE ROW LEVEL SECURITY, a policy keyed on
-- current_setting('app.current_tenant'), and FORCE ROW LEVEL SECURITY. This fixture plants the
-- three ways that recipe is incompletely applied in practice, plus the correct form as a negative.

-- (1) Tenant table with NO row security at all. The sheet's first instruction. Every row of every
-- tenant is readable by any role that can reach the table.
create table public.mt_invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  amount_cents bigint not null
);

-- (2) Row security enabled and a correct tenant policy, but FORCE ROW LEVEL SECURITY is absent, so
-- the table OWNER still bypasses every policy below. The sheet flags this one ("Force RLS for table
-- owners too (important!)") and it is the case its own example gets right.
create table public.mt_ledger (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  memo text
);
alter table public.mt_ledger enable row level security;
create policy mt_ledger_tenant_isolation on public.mt_ledger
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);

-- (3) The gap we proposed adding to the sheet (CheatSheetSeries#2309 item 1): FORCE ROW LEVEL
-- SECURITY binds the table owner only. A role holding BYPASSRLS bypasses row security
-- unconditionally, per the PostgreSQL documentation -- "Superusers and roles with the BYPASSRLS
-- attribute always bypass the row security system when accessing a table." Granting it to the role
-- the application connects as voids every policy in this file.
create role mt_app_worker login bypassrls;
grant select, insert, update, delete on public.mt_ledger to mt_app_worker;

-- (4) NEGATIVE: the complete form -- enabled, policy, and forced. Nothing should fire here.
create table public.mt_contracts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  body text
);
alter table public.mt_contracts enable row level security;
alter table public.mt_contracts force row level security;
create policy mt_contracts_tenant_isolation on public.mt_contracts
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);
