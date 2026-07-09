// M10 batch (#72, spec §M10) — PII/PHI/PCI data-classification corpus. Promotes
// tools/pii-classify.mjs's own selftest (already a precision measure — see its `cases` table
// and tools/pii-classify.test.ts) into the shared answer-key format, backed by a schema fixture:
// targets/calibration/supabase/migrations/20260708000003_pii_calibration.sql
// (`pii_calibration_fixture`, column names/types only — no seeded data, privacy-safe by
// construction). classifyColumn is pure name/type matching, no live DB needed.
//
// Tiering (locked preamble): every M10 positive here classifies at HIGH confidence, so all six
// are `high` tier. The `location` is the column name, matching the spec's "location = column"
// convention (§3b.3) for a future Finding-emitting adapter.
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

  // --- NEGATIVES (must NOT be flagged in the free/high count) ---
  { id: "M10-N-EMAIL-CAT", kind: "negative", cls: "descriptor suffix, not the value", module: "M10", location: "email_category", note: `${FIXTURE}.email_category → excluded (DESCRIPTOR_SUFFIX_PATTERN, "categorizes the concept, isn't the value"); classifyColumn returns null.` },
  { id: "M10-N-DOB-FLAG", kind: "negative", cls: "boolean flag naming, not a data value", module: "M10", location: "awaiting_dob_reprompt", note: `${FIXTURE}.awaiting_dob_reprompt (boolean) → excluded (sql type boolean, and BOOLEAN_FLAG_NAME_PATTERN "awaiting_" prefix); classifyColumn returns null.` },
  { id: "M10-N-VENDOR-HEALTH", kind: "negative", cls: "infra/system health, not medical health", module: "M10", location: "vendor_health", note: `${FIXTURE}.vendor_health → excluded (INFRA_HEALTH_PATTERN); classifyColumn returns null despite the HEALTH rule otherwise matching.` },
  { id: "M10-N-NAME-AMBIG", kind: "negative", cls: "ambiguous NAME?, review-tier only", module: "M10", location: "product_name", note: `${FIXTURE}.product_name → NAME?/PII/low. Not excluded outright, but low confidence keeps it out of the free/high count — an assertion, not a review-tier flag.` },
];
