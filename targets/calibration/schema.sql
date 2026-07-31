-- #565 — a Supabase Table-Editor / no-code (Lovable/Bolt/v0) export commits its whole schema as a
-- single root schema.sql instead of supabase/migrations/*.sql. checkMigrationRlsStatic was
-- migrations-only (returned [] with no supabase/migrations), so every RLS-off table in such an export
-- was invisible. #565 broadened it to ALSO read this root schema.sql.

-- PLANTED BUG (P-RLS-MISSING-ROOT-SCHEMA, #565): a public-schema table created here that NEVER gets
-- `enable row level security` anywhere — auto-exposed by PostgREST, every row readable/writable with
-- the anon key. checkMigrationRlsStatic → high (Critical). The nocode-rescue #3 critical.
create table public.nocode_tickets (
  id uuid primary key default gen_random_uuid(),
  subject text not null,
  body text,
  requester_email text,
  created_at timestamptz default now()
);

-- TRUE NEGATIVE (N-RLS-ENABLED-ROOT-SCHEMA, #565): a table in the same root schema.sql that DOES get
-- RLS enabled — checkMigrationRlsStatic aggregates enables across every source it reads, so this is
-- cleared. Proves the root-schema pass distinguishes RLS-off from RLS-on, not just "any table in
-- schema.sql".
create table public.nocode_safe (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  note text
);
alter table public.nocode_safe enable row level security;

-- PLANTED BUG (P-RLS-BARE-CREATE-TABLE, #611 Gap B): a no-code Table-Editor export emits the table
-- UNQUALIFIED — `create table workspaces` — since public is the implicit default schema. Before #611
-- CREATE_TABLE required a literal `public.`, so this table was read but never enumerated → no RLS-off
-- finding. It gets no `enable row level security` anywhere → auto-exposed via PostgREST. → high.
create table workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid
);

-- TRUE NEGATIVE (N-RLS-BARE-ENABLED, #611 Gap B): a bare-unqualified table that DOES get RLS enabled
-- via an equally bare `alter table members enable row level security`. The symmetric ENABLE_RLS
-- broadening must clear it — proving the bare-name pass distinguishes RLS-off from RLS-on.
create table members (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  role text
);
alter table members enable row level security;

-- TRUE NEGATIVE (N-RLS-NONPUBLIC-SCHEMA, #611 Gap B): an EXPLICIT non-public schema table. It is not
-- PostgREST-exposed, so it must NOT be flagged RLS-off even though it never enables RLS. Proves the
-- optional-schema capture keeps a `private.`-qualified table out of the public enumeration.
create table private.internal_audit (
  id uuid primary key default gen_random_uuid(),
  event text
);

-- ---------------------------------------------------------------------------------------------
-- #1323 — six M1 static checks read SQL through readMigrations(), which was supabase/migrations-
-- only, so all six returned [] on a root schema.sql. Nothing above could expose that: this file
-- carried only `create table` and `alter table … enable row level security`, so the fixture proving
-- #565's fix was structurally unable to fail on the other six. Each pair below plants one shape a
-- reverted readMigrations() would go silent on, next to the near-miss that must stay silent.
-- ---------------------------------------------------------------------------------------------

create table public.nocode_invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  owner_id uuid not null,
  amount numeric
);
alter table public.nocode_invoices enable row level security;

-- PLANTED BUG (P-POLICY-PERMISSIVE-ROOT-SCHEMA, #1323): a SELECT policy with `using (true)` — RLS is
-- on, so the table reads as protected, and every authenticated caller sees every tenant's invoices.
-- checkMigrationPolicySemantics → review.
create policy nocode_invoices_read on public.nocode_invoices
  for select to authenticated using (true);

-- TRUE NEGATIVE (N-POLICY-TENANT-SCOPED-ROOT-SCHEMA, #1323): the same table's write policy, scoped to
-- the caller's tenant claim AND hoisted as `(select …)`. Must clear both the semantic reviewer and
-- the initplan perf check — proving the root-schema pass distinguishes a permissive policy from a
-- scoped one, not just "any policy in schema.sql".
create policy nocode_invoices_write on public.nocode_invoices
  for insert to authenticated
  with check (tenant_id = ((select auth.jwt()) ->> 'tenant_id')::uuid);

-- PLANTED BUG (P-RLS-INITPLAN-ROOT-SCHEMA, #1323): correctly tenant- AND owner-scoped, so the
-- semantic reviewer clears it — but the auth.uid() call is BARE, so Postgres re-evaluates it once
-- per row instead of hoisting it to an initplan. checkMigrationRlsInitplanStatic → review. The
-- scoping is what makes this a clean single-check probe rather than two findings on one policy.
create policy nocode_invoices_own on public.nocode_invoices
  for update to authenticated
  using (tenant_id = ((select auth.jwt()) ->> 'tenant_id')::uuid and owner_id = auth.uid());

-- PLANTED BUG (P-SECDEF-NOAUTH-ROOT-SCHEMA, #1323): a SECURITY DEFINER privileged write with no
-- caller check anywhere in the body — any caller who can reach it can promote anyone.
-- checkMigrationDefinerAuthz → review.
create or replace function public.nocode_set_role(target_user_id uuid, new_role text)
returns void
language plpgsql
security definer
as $$
begin
  update public.profiles set role = new_role where id = target_user_id;
end;
$$;

-- TRUE NEGATIVE (N-SECDEF-AUTHCHECK-ROOT-SCHEMA, #1323): the identical privileged write, gated on the
-- CALLER's own row before the target row is touched. Must stay silent.
create or replace function public.nocode_promote_guarded(target_user_id uuid, new_role text)
returns void
language plpgsql
security definer
as $$
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'not authorized';
  end if;
  update public.profiles set role = new_role where id = target_user_id;
end;
$$;

-- PLANTED BUG (P-PLPGSQL-SQLI-ROOT-SCHEMA, #1323): a parameter concatenated straight into an EXECUTE
-- query string — CWE-89, and DEFINER so the injected query runs as the owner.
-- checkMigrationDynamicSqlInjection → review.
create or replace function public.nocode_search_invoices(p_filter text)
returns setof public.nocode_invoices
language plpgsql
security definer
as $$
begin
  return query execute 'select * from public.nocode_invoices where amount::text like ''%' || p_filter || '%''';
end;
$$;

-- TRUE NEGATIVE (N-PLPGSQL-SQLI-SAFE-ROOT-SCHEMA, #1323): the same dynamic query with the parameter
-- bound through USING rather than spliced into the query text. Must stay silent.
create or replace function public.nocode_bound_invoice_query(p_filter text)
returns setof public.nocode_invoices
language plpgsql
security definer
as $$
begin
  return query execute 'select * from public.nocode_invoices where amount::text like $1' using p_filter;
end;
$$;

-- PLANTED BUG (P-SECDEF-ANON-GRANT-ROOT-SCHEMA, #1323): a DEFINER reader explicitly granted to anon
-- with no caller check — anyone holding the anon key dumps every tenant's invoices.
-- checkMigrationDefinerAnonGrant → review.
create or replace function public.nocode_all_invoices()
returns setof public.nocode_invoices
language plpgsql
security definer
as $$
begin
  return query select * from public.nocode_invoices;
end;
$$;
grant execute on function public.nocode_all_invoices() to anon;

-- PLANTED BUG (P-STORAGE-BUCKET-PUBLIC-ROOT-SCHEMA, #1323): a public storage bucket declared in the
-- root schema. Supabase serves every object in it unauthenticated, RLS policies do not apply.
-- checkMigrationStorageBuckets → review.
insert into storage.buckets (id, name, public) values ('nocode-attachments', 'nocode-attachments', true);

-- TRUE NEGATIVE (N-STORAGE-BUCKET-PRIVATE-ROOT-SCHEMA, #1323): the sibling bucket declared private.
-- Must stay silent — proving the root-schema pass reads the `public` column, not the insert.
insert into storage.buckets (id, name, public) values ('nocode-private', 'nocode-private', false);

-- PLANTED BUG (P-STORAGE-ANON-READ-ROOT-SCHEMA, #1323): the storage.objects half of the same check,
-- which reads through readMigrations rather than readRlsSqlSources — an anon SELECT policy whose
-- clause never names the caller, so every object in the bucket is readable with the anon key.
-- checkMigrationStorageBuckets → review. Without this pair the check's bucket-insert half (already
-- broadened by #565) made the whole check look guarded while half of it was dark.
create policy nocode_attachments_anon_read on storage.objects
  for select to anon using (bucket_id = 'nocode-attachments');

-- TRUE NEGATIVE (N-STORAGE-ANON-OWNER-SCOPED-ROOT-SCHEMA, #1323): the same shape scoped to the
-- caller's own folder. A clause that names the caller belongs to the semantic reviewer, not to this
-- rule, so it must stay silent. The auth.uid() is hoisted as `(select …)` deliberately: with it bare,
-- the #1344 review-tier ratchet correctly fired auth_rls_initplan on this fixture, which is the
-- ratchet doing its job — a negative must be clean in every rule's eyes, not just the one under test.
create policy nocode_private_owner_read on storage.objects
  for select to anon using (bucket_id = 'nocode-private' and owner = (select auth.uid()));
