-- Calibration target schema.
-- Two-tenant SaaS shape: tenants, per-user profiles, and tenant-scoped data tables.
-- RLS is applied in the next migration (20260708000002_rls.sql).

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

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  customer text not null,
  amount_cents integer not null,
  created_at timestamptz not null default now()
);

create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  action text not null,
  detail text,
  created_at timestamptz not null default now()
);

create table public.counters (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  name text not null,
  value bigint not null default 0,
  unique (tenant_id, name)
);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now()
);

-- Service-role-only internal table (never granted to anon/authenticated). RLS is enabled
-- with zero policies below (N-RLS-DENY-ALL) — deny-all by design, a benign true-negative.
create table public.service_state (
  id uuid primary key default gen_random_uuid(),
  key text not null unique,
  value jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- Resolves the calling user's tenant from their profile row. Correct RLS
-- policies below scope by this; the buggy ones ignore it.
create or replace function public.current_tenant_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select tenant_id from public.profiles where id = auth.uid();
$$;
