-- #616 — always-true RLS policies disguised as logical TAUTOLOGIES. A migration built to defeat the
-- linter tier (SupatestVibeDemo/VulnBlog) never writes `USING (true)` literally; it writes
-- `(author_id IS NOT NULL OR author_id IS NULL)` — a column is always one or the other, so the
-- clause admits every row while reading like a real predicate. rls-policy-review.ts now collapses the
-- recognised tautologies to `true` before the always-true checks run.

create table public.tautology_articles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  author_id uuid,
  body text,
  created_at timestamptz not null default now()
);

alter table public.tautology_articles enable row level security;

-- PLANTED BUG (P-RLS-TAUTOLOGY-STATIC, #616): the disguised always-true clause. public.tautology_articles
-- declares tenant_id (per-tenant), so usingTrueReview fires — any caller can UPDATE any tenant's article.
create policy articles_update_tautology on public.tautology_articles
  for update using (author_id is not null or author_id is null);

-- TRUE NEGATIVE (N-RLS-TAUTOLOGY-SCOPED, #616): the correct shape a tenant-scoped read takes. The USING
-- constrains rows to the caller's tenant — it is not a tautology and must stay cleared.
create policy articles_select_scoped on public.tautology_articles
  for select using (tenant_id = public.current_tenant_id());

-- TRUE NEGATIVE (N-RLS-SINGLE-NOTNULL, #616 discriminator): a genuine single `IS NOT NULL` predicate.
-- It is NOT a tautology (a column can be null), so the collapse must leave it untouched and the policy
-- must stay dark. Proves the normalizer keys on the col-null PAIR, not on any `IS NOT NULL`.
create policy articles_select_notnull on public.tautology_articles
  for select using (author_id is not null);
