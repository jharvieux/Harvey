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
