-- Read-side `USING (true)` fixtures — the benign twins of the RLS-USING-TRUE plant
-- (documents_select_all, 20260708000002_rls.sql, GROUND-TRUTH row 1).
--
-- The positive already exists; what was missing is the pair that pins the rule's FP behavior. A
-- rule that flags EVERY `USING (true)` — including a catalog that is world-readable on purpose —
-- is a rule users learn to ignore, so both shapes below must stay out of the free count.

-- N-RLS-PUBLIC-CATALOG-USING-TRUE — benign lookalike: a published price list. Byte-for-byte the
-- same `for select using (true)` as the documents plant, and world-readable BY DESIGN: a pricing
-- page renders it to logged-out visitors. It declares NO tenant column — the rows belong to the
-- product, not to a tenant — which is the one static fact separating it from the plant. Contrast
-- documents_select_all, whose table declares tenant_id and therefore contradicts itself.
create table public.plans (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  name text not null,
  price_cents integer not null,
  created_at timestamptz not null default now()
);

alter table public.plans enable row level security;
create policy plans_select_public on public.plans
  for select using (true);

-- N-RLS-TENANT-SCOPED-READ — benign lookalike: the correct shape a tenant-scoped READ takes. Same
-- table shape and same `for select` as the documents plant, but the USING clause constrains rows
-- to the caller's tenant instead of admitting all of them. Guards against a rule matching the
-- command rather than the clause.
--
-- Named `tenant_reports` (not `reports`) to avoid colliding with the UNRELATED `public.reports`
-- planted in 20260709000004_b8_connected_advisors.sql (P-RLS-ENABLED-NO-POLICY, a connected-tier
-- Splinter fixture keyed on that literal live table name — #546). The policy name
-- `reports_select_own_tenant` is kept unchanged: N-RLS-TENANT-SCOPED-READ
-- (src/scan/calibration/rls-static-semantics.entries.ts) matches on the POLICY name, not the
-- table name, so the answer key is unaffected by this rename.
create table public.tenant_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  title text not null,
  created_at timestamptz not null default now()
);

alter table public.tenant_reports enable row level security;
create policy reports_select_own_tenant on public.tenant_reports
  for select using (tenant_id = public.current_tenant_id());
