-- #1183 (supatest F9) — the intersection of a SPARED `USING (true)` SELECT and M10's PII
-- classification of the same table.
--
-- The spare itself is correct and is pinned by N-RLS-PUBLIC-CATALOG-USING-TRUE
-- (20260715000001_rls_using_true_negatives.sql): public.plans declares no tenant column, so the
-- reviewer cannot tell a published price list from a leak and stays quiet. This file plants the
-- case where a SECOND module already answered the question the spare leaves open.

-- POSITIVE — the supatest F9 shape. No tenant column (so it reviews per-user and the USING(true)
-- rule spares it), no owner predicate, and an `email` column, which M10 classifies EMAIL at high
-- confidence. Every subscriber's email address is readable by anyone holding the anon key.
create table public.newsletter_subscribers (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  subscribed_at timestamptz not null default now()
);

alter table public.newsletter_subscribers enable row level security;
create policy newsletter_subscribers_select_all on public.newsletter_subscribers
  for select using (true);

-- NEGATIVE — the same clause on a table whose only classifiable column is an ambiguous name. M10
-- records `NAME?` at LOW confidence, which is exactly what a public catalog's product name looks
-- like, so the spare must hold. This is the boundary the upgrade rule is scoped against: "the
-- table appears in the data map" would flag this one, and public.plans and public.cities with it.
create table public.support_categories (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  sort_order integer not null default 0
);

alter table public.support_categories enable row level security;
create policy support_categories_select_all on public.support_categories
  for select using (true);
