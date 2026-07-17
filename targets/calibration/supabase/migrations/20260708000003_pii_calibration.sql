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
  -- M10-P-* planted positives (#376 PCI never-store: PIN block / track data)
  pin_block text,                 -- M10-P-PIN        -> PIN / PCI / high (severity-override -> Critical)
  track2 text,                    -- M10-P-TRACK      -> TRACK_DATA / PCI / high (same never-store category)
  -- M10-P-* planted positives (#378 HIPAA identifiers: device / vehicle / photo)
  mac_address text,               -- M10-P-MAC        -> DEVICE_ID / SENSITIVE_PII / medium (review tier)
  license_plate text,             -- M10-P-PLATE      -> VEHICLE_ID / PII / medium (review tier)
  avatar_url text,                -- M10-P-PHOTO      -> PHOTO / PII / medium (review tier)
  -- M10-P-* planted positive (#379 generic national/government ID)
  national_id text,               -- M10-P-NATIONAL-ID -> NATIONAL_ID / SENSITIVE_PII / medium (review tier)
  -- M10-P-* planted positive (#377 denormalized-PII JSON container review flag)
  profile jsonb,                  -- M10-P-JSON-BLOB  -> OPAQUE_JSON_BLOB / PII / low (review flag, not asserted)
  -- M10-N-* benign lookalikes (the classifier's own exclusion pass must clear these)
  email_category text,            -- M10-N-EMAIL-CAT     -> descriptor suffix, not the value
  awaiting_dob_reprompt boolean,  -- M10-N-DOB-FLAG      -> boolean flag, not a DOB value
  vendor_health text,             -- M10-N-VENDOR-HEALTH -> infra health, not medical health
  product_name text,              -- M10-N-NAME-AMBIG    -> ambiguous NAME?, low confidence only
  is_pinned boolean,              -- M10-N-PINNED-FLAG   -> UI pinned flag, not a payment-card PIN (#376)
  has_photo boolean,              -- M10-N-HAS-PHOTO     -> boolean photo flag, not an image column (#378)
  ui_state jsonb,                 -- M10-N-UI-STATE      -> jsonb outside the container vocabulary (#377)
  created_at timestamptz not null default now()
);

alter table public.pii_calibration_fixture enable row level security;
create policy pii_calibration_fixture_rw_own_tenant on public.pii_calibration_fixture
  for all
  using (tenant_id = public.current_tenant_id())
  with check (tenant_id = public.current_tenant_id());
