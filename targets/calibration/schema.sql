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
