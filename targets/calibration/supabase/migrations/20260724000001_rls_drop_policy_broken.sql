-- #937/#938 drop-policy lifecycle fixture — the BROKEN half.
--
-- An ORIGINAL re-expression (not a copy) of the supabase-security-labs paired-lab shape: a
-- tenant-scoped table given a `using (true)` SELECT policy that publishes every tenant's rows.
-- supabase-security-labs' own SQL is licence NONE and must never be vendored/distilled here
-- (src/scan/external-corpus.ts) — so this reproduces the SHAPE, authored from scratch.
--
-- The fix lands in a LATER migration (20260724000002) that DROPs and replaces this policy. Before
-- #937 the static reviewer read migrations cumulatively with no drop-policy tracking, so this
-- broken policy was still reported against the FIXED final schema — the byte-identical broken/fixed
-- output #937 closes. See N-RLS-DROP-POLICY-FIXED in rls-static-semantics.entries.ts.
create table public.audit_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  action text not null,
  created_at timestamptz not null default now()
);

alter table public.audit_events enable row level security;
create policy audit_events_select_all on public.audit_events
  for select using (true);
