-- vuln-seam-app schema. The seams under app/api are the fixture's point (they need only a booted
-- Next app), but the M2 live stand-up also provisions a local Supabase and seeds two tenants, so we
-- ship a minimal but real two-tenant, RLS-scoped schema for the introspection-driven seed to bind to
-- and for the Tier-1 PostgREST cross-tenant matrix to have a surface. No planted RLS bug here — the
-- planted vulnerabilities live in the seam routes, enumerated in the answer key.

create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  email text,
  role text not null default 'member',
  created_at timestamptz not null default now()
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  title text not null,
  body text,
  created_at timestamptz not null default now()
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.documents enable row level security;

-- Tenant-scoped policies keyed on the caller's profile row (the standard multi-tenant shape).
create policy tenants_self on public.tenants for select
  using (id in (select tenant_id from public.profiles where id = auth.uid()));

create policy profiles_same_tenant on public.profiles for select
  using (tenant_id in (select tenant_id from public.profiles where id = auth.uid()));

create policy documents_same_tenant on public.documents for all
  using (tenant_id in (select tenant_id from public.profiles where id = auth.uid()))
  with check (tenant_id in (select tenant_id from public.profiles where id = auth.uid()));
