create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  role text not null default 'member' check (role in ('admin', 'member', 'guest'))
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  title text not null
);

alter table public.tenants enable row level security;
alter table public.profiles enable row level security;
alter table public.documents enable row level security;

create policy tenants_self on public.tenants for select
  using (id in (select tenant_id from public.profiles where id = auth.uid()));

create policy profiles_same_tenant on public.profiles for select
  using (tenant_id in (select tenant_id from public.profiles where id = auth.uid()));

create policy documents_same_tenant on public.documents for all
  using (tenant_id in (select tenant_id from public.profiles where id = auth.uid()))
  with check (tenant_id in (select tenant_id from public.profiles where id = auth.uid()));
