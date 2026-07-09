-- M7 calibration fixture (#72, spec §M7) — Supabase performance-advisor corpus. These lints
-- (unindexed_foreign_keys, auth_rls_initplan, unused_index) are CONNECTED tier: only detectable
-- by Splinter running against a LIVE schema (+ pg_stat_user_indexes usage history for
-- unused_index) — see GROUND-TRUTH.md "M7" for the two-layer gate. This migration plants the
-- schema; a throwaway-branch `pnpm perf-scan` / `get_advisors(performance)` pull is the deferred
-- Layer-2 live validation. Layer 1 (this batch's `pnpm verify` gate) is
-- src/perf-scan.test.ts's "M7 calibration corpus" block, scoring parseAdvisorFindings against a
-- RECORDED advisor JSON shaped from what a live pull over this schema should return.

create table public.perf_orders (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  created_by uuid references auth.users (id),
  customer_email text not null,
  legacy_region text,
  created_at timestamptz not null default now()
);

-- M7-N-USED-INDEX: backs the seeded "look up an order by customer email" query. A live advisor
-- run (after that query is exercised so pg_stat_user_indexes shows idx_scan > 0) must NOT flag
-- this as unused_index.
create index idx_perf_orders_customer_email on public.perf_orders (customer_email);

-- M7-P-UNUSED-INDEX: no seeded/hot query ever filters on legacy_region. A live advisor run must
-- flag this as unused_index.
create index idx_perf_orders_legacy_region on public.perf_orders (legacy_region);

alter table public.perf_orders enable row level security;

-- M7-P-RLS-INITPLAN: bare auth.uid() in the USING clause — re-evaluated once PER ROW instead of
-- once per query. A live advisor run must flag this as auth_rls_initplan. Contrast
-- M7-N-WRAPPED-RLS below, which wraps the same call in (select …).
create policy perf_orders_select_own on public.perf_orders
  for select using (tenant_id = public.current_tenant_id() and created_by = auth.uid());

-- M7-P-UNINDEXED-FK: order_id references perf_orders(id) with NO covering index. A live advisor
-- run must flag this as unindexed_foreign_keys.
create table public.perf_line_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.perf_orders (id) on delete cascade,
  sku text not null,
  qty integer not null default 1
);
alter table public.perf_line_items enable row level security;
create policy perf_line_items_select_via_order on public.perf_line_items
  for select using (
    exists (select 1 from public.perf_orders o where o.id = order_id and o.tenant_id = public.current_tenant_id())
  );

-- M7-N-INDEXED-FK: order_id references perf_orders(id) WITH a covering index. Must NOT be
-- flagged unindexed_foreign_keys.
create table public.perf_shipments (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.perf_orders (id) on delete cascade,
  carrier text not null,
  shipped_at timestamptz
);
create index idx_perf_shipments_order_id on public.perf_shipments (order_id);
alter table public.perf_shipments enable row level security;
create policy perf_shipments_select_via_order on public.perf_shipments
  for select using (
    exists (select 1 from public.perf_orders o where o.id = order_id and o.tenant_id = public.current_tenant_id())
  );

-- M7-N-WRAPPED-RLS: auth.uid() correctly wrapped in (select …), hoisting it to a once-per-query
-- initplan instead of a per-row re-evaluation. Must NOT be flagged auth_rls_initplan.
create table public.perf_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  actor uuid references auth.users (id),
  event text not null,
  created_at timestamptz not null default now()
);
alter table public.perf_events enable row level security;
create policy perf_events_select_own on public.perf_events
  for select using (tenant_id = public.current_tenant_id() and actor = (select auth.uid()));
