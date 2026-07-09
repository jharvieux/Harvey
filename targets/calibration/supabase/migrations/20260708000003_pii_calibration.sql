-- M10 calibration fixture (#72, spec §M10) — PII/PHI/PCI column-classification corpus for
-- tools/pii-classify.mjs. Column NAMES and TYPES only, never seeded with data (no INSERTs
-- anywhere in this repo) — privacy-safe by construction, exactly what classifyColumn expects.
-- RLS is enabled + tenant-scoped like the other app tables so this fixture doesn't also
-- register as an M1 RLS-disabled finding (out of scope here; see GROUND-TRUTH.md's M10 batch).

create table public.pii_calibration_fixture (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  -- M10-P-* planted positives (must be classified, all high confidence)
  email text,                     -- M10-P-EMAIL      -> EMAIL / PII / high
  date_of_birth date,             -- M10-P-DOB        -> DOB / PII / high
  customer_ssn text,              -- M10-P-SSN        -> US_SSN / SENSITIVE_PII / high
  passport_number text,           -- M10-P-PASSPORT   -> PASSPORT / SENSITIVE_PII / high
  cvv text,                       -- M10-P-CVV        -> CVV / PCI / high (severity-override -> Critical)
  card_last4 text,                -- M10-P-CARD       -> CARD / PCI / high
  -- M10-N-* benign lookalikes (the classifier's own exclusion pass must clear these)
  email_category text,            -- M10-N-EMAIL-CAT     -> descriptor suffix, not the value
  awaiting_dob_reprompt boolean,  -- M10-N-DOB-FLAG      -> boolean flag, not a DOB value
  vendor_health text,             -- M10-N-VENDOR-HEALTH -> infra health, not medical health
  product_name text,              -- M10-N-NAME-AMBIG    -> ambiguous NAME?, low confidence only
  created_at timestamptz not null default now()
);

alter table public.pii_calibration_fixture enable row level security;
create policy pii_calibration_fixture_rw_own_tenant on public.pii_calibration_fixture
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());
