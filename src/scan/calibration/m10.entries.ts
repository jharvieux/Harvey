// M10 batch (#72, spec §M10) — PII/PHI/PCI data-classification corpus. Promotes
// tools/pii-classify.mjs's own selftest (already a precision measure — see its `cases` table
// and tools/pii-classify.test.ts) into the shared answer-key format, backed by a schema fixture:
// targets/calibration/supabase/migrations/20260708000003_pii_calibration.sql
// (`pii_calibration_fixture`, column names/types only — no seeded data, privacy-safe by
// construction). classifyColumn is pure name/type matching, no live DB needed.
//
// Tiering (locked preamble): a positive's tier mirrors its classify confidence — high-confidence
// classifications are `high` tier; medium/low-confidence ones (review-flag detections) are
// `review` tier. The `location` is the column name, matching the spec's "location = column"
// convention (§3b.3) for a future Finding-emitting adapter.
//
// Fixture parity: the original six positives + four negatives are planted in the fixture
// migration above. The #376/#378/#379/#377 entries below are validated by Layer 1
// (tools/pii-classify.test.ts + the selftest, both in `pnpm verify`) but NOT yet planted in the
// fixture SQL — migration files are operator-owned for automated sweeps; planting them there is
// a tracked follow-up, not a silent omission.
//
// NOT wired into runMechanicalScan (that's gitleaks/semgrep/OSV/leftover-auth — M1's tools; the
// PII classifier runs on parsed migration SQL via a separate static path, e.g. src/cli/dry-run.ts
// M10 phase). So these entries carry `module: "M10"` and are excluded from the CORPUS slice
// validate-calibration.ts scores against runMechanicalScan output (see its module filter). A
// Finding-emitting adapter + `pnpm validate:pii-calibration` (spec §M10(e) Layer 2, optional) is
// a documented follow-up — Layer 1 (this entry file + the extended pii-classify.test.ts, both run
// in `pnpm verify`) is the gate for this batch.

import type { CorpusEntry } from "./types.js";

const FIXTURE = "pii_calibration_fixture";

export const m10Entries: CorpusEntry[] = [
  // --- POSITIVES (must be classified) ---
  { id: "M10-P-EMAIL", kind: "positive", cls: "PII — email address", module: "M10", location: "email", expectedTier: "high", note: `${FIXTURE}.email → classifyColumn returns EMAIL/PII/high.` },
  { id: "M10-P-DOB", kind: "positive", cls: "PII — date of birth", module: "M10", location: "date_of_birth", expectedTier: "high", note: `${FIXTURE}.date_of_birth (date) → DOB/PII/high.` },
  { id: "M10-P-SSN", kind: "positive", cls: "SENSITIVE_PII — US Social Security Number", module: "M10", location: "customer_ssn", expectedTier: "high", note: `${FIXTURE}.customer_ssn → US_SSN/SENSITIVE_PII/high.` },
  { id: "M10-P-PASSPORT", kind: "positive", cls: "SENSITIVE_PII — passport number", module: "M10", location: "passport_number", expectedTier: "high", note: `${FIXTURE}.passport_number → PASSPORT/SENSITIVE_PII/high.` },
  { id: "M10-P-CVV", kind: "positive", cls: "PCI — CVV / sensitive authentication data", module: "M10", location: "cvv", expectedTier: "high", note: `${FIXTURE}.cvv → CVV/PCI/high; buildDataMap's INFOTYPE_POINT_OVERRIDES scores a lone CVV column Critical (PCI-DSS forbids storing it post-auth at all).` },
  { id: "M10-P-CARD", kind: "positive", cls: "PCI — cardholder data (PAN fragment)", module: "M10", location: "card_last4", expectedTier: "high", note: `${FIXTURE}.card_last4 → CARD/PCI/high.` },
  { id: "M10-P-PIN", kind: "positive", cls: "PCI — PIN block / sensitive authentication data", module: "M10", location: "pin_block", expectedTier: "high", note: `pin_block → PIN/PCI/high; INFOTYPE_POINT_OVERRIDES scores a lone PIN column Critical — same PCI-DSS never-store-post-auth category as CVV (#376).` },
  { id: "M10-P-TRACK", kind: "positive", cls: "PCI — track/magstripe data / sensitive authentication data", module: "M10", location: "track2", expectedTier: "high", note: `track2 → TRACK_DATA/PCI/high; scored Critical alone, same never-store category (#376).` },
  { id: "M10-P-MAC", kind: "positive", cls: "HIPAA #13 — device identifier (MAC address)", module: "M10", location: "mac_address", expectedTier: "review", note: `mac_address → DEVICE_ID/SENSITIVE_PII/medium (#378).` },
  { id: "M10-P-PLATE", kind: "positive", cls: "HIPAA #12 — vehicle identifier (license plate)", module: "M10", location: "license_plate", expectedTier: "review", note: `license_plate → VEHICLE_ID/PII/medium (#378).` },
  { id: "M10-P-PHOTO", kind: "positive", cls: "HIPAA #17 — full-face photograph / comparable image", module: "M10", location: "avatar_url", expectedTier: "review", note: `avatar_url → PHOTO/PII/medium — review-tier by design; many avatar columns are app furniture, but HIPAA/GDPR context makes silence the wrong default (#378).` },
  { id: "M10-P-NATIONAL-ID", kind: "positive", cls: "SENSITIVE_PII — generic national/government ID", module: "M10", location: "national_id", expectedTier: "review", note: `national_id → NATIONAL_ID/SENSITIVE_PII/medium — the catch-all for non-US government-ID schemes; compound names only, bare id/_id never matches (#379).` },
  { id: "M10-P-JSON-BLOB", kind: "positive", cls: "PII — denormalized-PII JSON container (review flag)", module: "M10", location: "profile", expectedTier: "review", note: `profile (jsonb) on an ordinary table → OPAQUE_JSON_BLOB/PII/low — "review this container's keys for nested PII", flagged not asserted; the report surfaces these as a distinct review list (#377).` },

  // --- NEGATIVES (must NOT be flagged in the free/high count) ---
  { id: "M10-N-EMAIL-CAT", kind: "negative", cls: "descriptor suffix, not the value", module: "M10", location: "email_category", note: `${FIXTURE}.email_category → excluded (DESCRIPTOR_SUFFIX_PATTERN, "categorizes the concept, isn't the value"); classifyColumn returns null.` },
  { id: "M10-N-DOB-FLAG", kind: "negative", cls: "boolean flag naming, not a data value", module: "M10", location: "awaiting_dob_reprompt", note: `${FIXTURE}.awaiting_dob_reprompt (boolean) → excluded (sql type boolean, and BOOLEAN_FLAG_NAME_PATTERN "awaiting_" prefix); classifyColumn returns null.` },
  { id: "M10-N-VENDOR-HEALTH", kind: "negative", cls: "infra/system health, not medical health", module: "M10", location: "vendor_health", note: `${FIXTURE}.vendor_health → excluded (INFRA_HEALTH_PATTERN); classifyColumn returns null despite the HEALTH rule otherwise matching.` },
  { id: "M10-N-NAME-AMBIG", kind: "negative", cls: "ambiguous NAME?, review-tier only", module: "M10", location: "product_name", note: `${FIXTURE}.product_name → NAME?/PII/low. Not excluded outright, but low confidence keeps it out of the free/high count — an assertion, not a review-tier flag.` },
  { id: "M10-N-PINNED-FLAG", kind: "negative", cls: "UI pinned-flag, not a payment-card PIN", module: "M10", location: "is_pinned", note: `is_pinned → null: no bare \`pin\` alternative exists by design (pinned flags, postal PIN codes), only compound card/ATM names match the PIN rule (#376).` },
  { id: "M10-N-HAS-PHOTO", kind: "negative", cls: "boolean photo flag, not an image column", module: "M10", location: "has_photo", note: `has_photo (boolean) → null: BOOLEAN_FLAG_NAME_PATTERN + the boolean-type exclusion keep concept-referencing flags out; only image-bearing compound names (photo_url, avatar_url, …) match PHOTO (#378).` },
  { id: "M10-N-UI-STATE", kind: "negative", cls: "jsonb outside the container vocabulary", module: "M10", location: "ui_state", note: `ui_state (jsonb) → null: the #377 review flag needs a denormalization-container NAME, not just a json type — "any jsonb column" would flood legitimately non-PII settings/state blobs with noise.` },
];
