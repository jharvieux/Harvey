-- D-091 item 13 (#1230) -- destructive migration ships before the read-switchover. The CONTRACT
-- step (dropping the old column) lands while app code still names that column inside its query
-- chain. Column names live in app code as STRINGS, so tsc is completely blind: nothing fails to
-- compile and nothing fails until those readers 500 in production.
--
-- Both tables carry the full RLS recipe (enable + policy + force) and an index on tenant_id, so
-- this fixture plants ONLY the column-drift class and nothing else fires on it.

create table public.d091_quotes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  legacy_grade text,
  sort_order integer not null default 0
);
create index d091_quotes_tenant_id_idx on public.d091_quotes (tenant_id);
alter table public.d091_quotes enable row level security;
alter table public.d091_quotes force row level security;
create policy d091_quotes_tenant_isolation on public.d091_quotes
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);

-- NEGATIVE: same column name, different table, never dropped. A rule that is not table-aware
-- reports the reader of this one too.
create table public.d091_bookings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  legacy_grade text,
  sort_order integer not null default 0
);
create index d091_bookings_tenant_id_idx on public.d091_bookings (tenant_id);
alter table public.d091_bookings enable row level security;
alter table public.d091_bookings force row level security;
create policy d091_bookings_tenant_isolation on public.d091_bookings
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);

-- The CONTRACT drop, shipped without step 2 (switch every reader off the column first).
alter table public.d091_quotes drop column legacy_grade;

-- D-091 item 25 (#1230), the schema half of src/d091/dedup-without-unique.ts: app code dedupes on
-- (tenant_id, external_ref) and there is no UNIQUE index behind that pair, so two concurrent
-- callers both read "absent" and both insert. Planted as a currently-uncaught class.
create table public.d091_contacts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  external_ref text not null
);
create index d091_contacts_tenant_id_idx on public.d091_contacts (tenant_id);
alter table public.d091_contacts enable row level security;
alter table public.d091_contacts force row level security;
create policy d091_contacts_tenant_isolation on public.d091_contacts
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);

-- #1257, the schema half of the item-25 NEGATIVES. Same shape as d091_contacts and the same RLS
-- recipe, differing only in the constraint the detector has to read: the composite pair the app
-- dedupes on is UNIQUE here, so the second concurrent insert fails and the dedup is correct.
create table public.d091_contacts_unique (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  external_ref text not null,
  unique (tenant_id, external_ref)
);
create index d091_contacts_unique_tenant_id_idx on public.d091_contacts_unique (tenant_id);
alter table public.d091_contacts_unique enable row level security;
alter table public.d091_contacts_unique force row level security;
create policy d091_contacts_unique_tenant_isolation on public.d091_contacts_unique
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);

-- #1257: the same table WITHOUT the constraint, for the read-only and upsert negatives — so those
-- two rows prove the app-side conjuncts rather than being satisfied by a constraint that would
-- clear them anyway.
create table public.d091_contacts_readonly (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  external_ref text not null
);
create index d091_contacts_readonly_tenant_id_idx on public.d091_contacts_readonly (tenant_id);
alter table public.d091_contacts_readonly enable row level security;
alter table public.d091_contacts_readonly force row level security;
create policy d091_contacts_readonly_tenant_isolation on public.d091_contacts_readonly
  for all
  using (tenant_id = current_setting('app.current_tenant')::uuid);
