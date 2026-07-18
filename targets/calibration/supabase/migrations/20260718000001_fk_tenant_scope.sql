-- #301 — FK-based bare-scope-column disclosure fixtures. A bare (non-_id, off-list) tenant column
-- that FOREIGN-KEYs to a tenant-shaped table must be NAMED by SB-RLS-TENANCY-MODEL's NOT RECOGNISED
-- list; an ordinary bare column whose FK targets a non-tenant lookup table must NOT be — that is
-- the false-positive flood the FK signal exists to avoid. Both tables review per-user (neither
-- declares a known tenant key), which is exactly the misclassification the disclosure surfaces.

-- A plain lookup table for the negative fixture's foreign key to point at (NOT tenant-shaped).
create table public.cities (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
alter table public.cities enable row level security;

-- POSITIVE (P-RLS-FK-TENANT-SCOPE): `site` has no _id suffix and is off the known tenant-key list,
-- but foreign-keys to public.tenants — structural evidence it is the tenant scope under an off-list
-- name. The static review infers per-user (no recognised tenant key) and must NAME `site`.
create table public.widgets (
  id uuid primary key default gen_random_uuid(),
  site uuid not null references public.tenants(id),
  label text
);
alter table public.widgets enable row level security;
create policy widgets_select_own on public.widgets for select using (site = (select public.current_tenant_id()));

-- NEGATIVE (N-RLS-FK-NON-TENANT): same shape (a bare uuid FK column), but `city` references
-- public.cities — an ordinary relation, not a tenancy root. Must stay unnamed; the row is correctly
-- own-row per-user (id = auth.uid()).
create table public.gadgets (
  id uuid primary key default gen_random_uuid(),
  city uuid not null references public.cities(id),
  status text
);
alter table public.gadgets enable row level security;
create policy gadgets_select_self on public.gadgets for select using (id = (select auth.uid()));
