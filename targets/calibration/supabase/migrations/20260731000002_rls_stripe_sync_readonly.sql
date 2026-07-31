-- #1370 NEGATIVE for SB-RLS-CMDGAP-<table> — the shape the first version of the rule cried wolf on,
-- planted here so the corpus fails if it ever comes back.
--
-- Re-expressed (not copied) from devtodollars/mvp-boilerplate@2aac5c2f's own schema, the target
-- behind #227's "must not accuse a sound repo of a tenancy hole" control: a Stripe-synced billing
-- schema where the client's READ is policed and every WRITE is performed by the webhook handler
-- over the service-role key. Every table below leaves INSERT/UPDATE/DELETE uncovered, and that is
-- the design, not a hole — under RLS an uncovered command is DENIED, so the client cannot write
-- these tables at all. Nothing in migration text distinguishes this from a table the client simply
-- never writes, which is why the rule now reports only the read-side inversion.
--
-- The positive twin is 20260731000001_rls_write_without_read.sql.

-- Public catalogue, synced from Stripe. Read by logged-out visitors on the pricing page.
create table public.billing_products (
  id text primary key,
  active boolean,
  name text,
  description text
);
alter table public.billing_products enable row level security;
create policy billing_products_read_all on public.billing_products
  for select using (true);

create table public.billing_prices (
  id text primary key,
  product_id text references public.billing_products,
  active boolean,
  interval text
);
alter table public.billing_prices enable row level security;
create policy billing_prices_read_all on public.billing_prices
  for select using (true);

-- Own-row read, no client write: the webhook writes these rows.
create table public.billing_subscriptions (
  id text primary key,
  user_id uuid not null,
  status text
);
alter table public.billing_subscriptions enable row level security;
create policy billing_subscriptions_read_own on public.billing_subscriptions
  for select using (auth.uid() = user_id);

-- Read AND update own row, insert performed by a SECURITY DEFINER signup trigger, no delete.
-- The mixed case: a partially-covered write side is still not the inversion this rule reports.
create table public.billing_profiles (
  id uuid primary key,
  display_name text
);
alter table public.billing_profiles enable row level security;
create policy billing_profiles_read_own on public.billing_profiles
  for select using (auth.uid() = id);
create policy billing_profiles_update_own on public.billing_profiles
  for update using (auth.uid() = id);
