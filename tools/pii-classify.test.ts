import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { validateFindings } from "../src/findings.js";
import {
  buildDataMap,
  classifyColumn,
  classifyMigrationSql,
  classifyPrismaSchema,
  classifyWithFallback,
  createAnthropicSemanticClassifier,
  dataMapToFindings,
  DEFAULT_SEMANTIC_MODEL,
  gatherProtectionFacts,
  resolveSemanticClassifier,
} from "./pii-classify.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(REPO_ROOT, "tools", "pii-classify.mjs");
const PRISMA_FIXTURE_SCHEMA = join(REPO_ROOT, "src", "scan", "__fixtures__", "prisma-app", "prisma", "schema.prisma");

describe("classifyColumn — camelCase/PascalCase columns classify as their snake_case equivalents (#936)", () => {
  // carbon and half the Supabase corpus use camelCase/quoted-identifier column names; the
  // dictionary anchors on snake_case boundaries, so these all classified NONE before #936.
  it("classifies multi-word camelCase names the boundary-anchored rules used to miss", () => {
    expect(classifyColumn("firstName")).toEqual({ infotype: "NAME", category: "PII", confidence: "medium" });
    expect(classifyColumn("emailAddress")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(classifyColumn("mobilePhone")).toEqual({ infotype: "PHONE", category: "PII", confidence: "high" });
    expect(classifyColumn("dateOfBirth")).toEqual({ infotype: "DOB", category: "PII", confidence: "high" });
    expect(classifyColumn("addressLine1")).toEqual({ infotype: "ADDRESS", category: "PII", confidence: "medium" });
    expect(classifyColumn("taxId")).toEqual({ infotype: "TAX_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("nationalId")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("socialSecurityNumber")).toEqual({ infotype: "US_SSN", category: "SENSITIVE_PII", confidence: "high" });
  });

  it("handles PascalCase and acronym boundaries (APIKey → api_key)", () => {
    expect(classifyColumn("APIKey").category).toBe("SECRET");
    expect(classifyColumn("CustomerSSN").category).toBe("SENSITIVE_PII");
  });

  it("keeps the FP exclusions firing on camelCase, not just snake_case", () => {
    expect(classifyColumn("screenOrientation")).toBeNull();
    expect(classifyColumn("isPinned", "boolean")).toBeNull();
    expect(classifyColumn("raceId")).toBeNull();
    expect(classifyColumn("emailCategory")).toBeNull();
    // an entity display name on an org/tenant table is still not personal PII
    expect(classifyColumn("companyName", "text", "organizations")).toBeNull();
  });
});

describe("classifyColumn — true positives across the taxonomy", () => {
  it("matches HIPAA/GDPR contact & identity PII at high confidence", () => {
    expect(classifyColumn("email")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(classifyColumn("date_of_birth")).toEqual({ infotype: "DOB", category: "PII", confidence: "high" });
    expect(classifyColumn("phone_number")).toEqual({ infotype: "PHONE", category: "PII", confidence: "high" });
  });

  it("matches SENSITIVE_PII (SSN, passport, biometrics, genetic data)", () => {
    expect(classifyColumn("customer_ssn")).toEqual({
      infotype: "US_SSN",
      category: "SENSITIVE_PII",
      confidence: "high",
    });
    expect(classifyColumn("passport_number").category).toBe("SENSITIVE_PII");
    expect(classifyColumn("fingerprint_hash").category).toBe("SENSITIVE_PII");
    expect(classifyColumn("dna_sequence").category).toBe("SENSITIVE_PII");
  });

  it("matches PHI (HIPAA) — medical record numbers and health data", () => {
    expect(classifyColumn("medical_record_number")).toEqual({
      infotype: "MEDICAL_RECORD_NUMBER",
      category: "PHI",
      confidence: "high",
    });
    expect(classifyColumn("diagnosis_code").category).toBe("PHI");
  });

  it("matches PCI cardholder and sensitive authentication data", () => {
    expect(classifyColumn("card_last4")).toEqual({ infotype: "CARD", category: "PCI", confidence: "high" });
    expect(classifyColumn("cvv")).toEqual({ infotype: "CVV", category: "PCI", confidence: "high" });
    expect(classifyColumn("iban").category).toBe("PCI");
  });

  it("matches generic national/government-ID columns beyond the US-specific shapes (#379)", () => {
    expect(classifyColumn("national_id")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("government_id_number")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("citizen_id")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("resident_id")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("id_card_number")).toEqual({ infotype: "NATIONAL_ID", category: "SENSITIVE_PII", confidence: "medium" });
  });

  it("keeps bare id/PK/FK columns out of the national-ID catch-all (#379 FP guard)", () => {
    expect(classifyColumn("id")).toBeNull();
    expect(classifyColumn("user_id")).toBeNull();
    expect(classifyColumn("tenant_id")).toBeNull();
    expect(classifyColumn("order_id")).toBeNull();
  });

  it("matches PCI sensitive authentication data — PIN block and track/magstripe data (#376)", () => {
    expect(classifyColumn("pin_block")).toEqual({ infotype: "PIN", category: "PCI", confidence: "high" });
    expect(classifyColumn("atm_pin")).toEqual({ infotype: "PIN", category: "PCI", confidence: "high" });
    expect(classifyColumn("card_pin")).toEqual({ infotype: "PIN", category: "PCI", confidence: "high" });
    expect(classifyColumn("pin_verification_value")).toEqual({ infotype: "PIN", category: "PCI", confidence: "high" });
    expect(classifyColumn("track2")).toEqual({ infotype: "TRACK_DATA", category: "PCI", confidence: "high" });
    expect(classifyColumn("track_1_data")).toEqual({ infotype: "TRACK_DATA", category: "PCI", confidence: "high" });
    expect(classifyColumn("magstripe")).toEqual({ infotype: "TRACK_DATA", category: "PCI", confidence: "high" });
  });

  it("does not read pinned/PIN-code lookalikes as a payment-card PIN (#376 FP guard)", () => {
    // is_pinned is a UI feature flag; a bare `pin`/`pin_code` is deliberately not in the
    // dictionary (postal PIN code, app-level "pin this item" concepts) — only compound
    // card/ATM names assert the PCI infotype.
    expect(classifyColumn("is_pinned")).toBeNull();
    expect(classifyColumn("pinned_at")).toBeNull();
    expect(classifyColumn("pin")).toBeNull();
    expect(classifyColumn("pin_code")).toBeNull();
  });

  it("matches HIPAA device/vehicle/image identifiers — MAC address, license plate, photo columns (#378)", () => {
    // Safe Harbor #13 (device identifiers), #12 (vehicle identifiers incl. license plates),
    // #17 (full-face photographs and comparable images).
    expect(classifyColumn("mac_address")).toEqual({ infotype: "DEVICE_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("mac_addr")).toEqual({ infotype: "DEVICE_ID", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("license_plate")).toEqual({ infotype: "VEHICLE_ID", category: "PII", confidence: "medium" });
    expect(classifyColumn("plate_number")).toEqual({ infotype: "VEHICLE_ID", category: "PII", confidence: "medium" });
    expect(classifyColumn("photo_url")).toEqual({ infotype: "PHOTO", category: "PII", confidence: "medium" });
    expect(classifyColumn("avatar_url")).toEqual({ infotype: "PHOTO", category: "PII", confidence: "medium" });
    expect(classifyColumn("profile_picture")).toEqual({ infotype: "PHOTO", category: "PII", confidence: "medium" });
    expect(classifyColumn("signature_image")).toEqual({ infotype: "PHOTO", category: "PII", confidence: "medium" });
  });

  it("does not read photo/avatar boolean flags as image PII (#378 FP guard)", () => {
    expect(classifyColumn("has_photo", "boolean")).toBeNull();
    expect(classifyColumn("avatar_enabled")).toBeNull();
    // A bare `photo`/`avatar`/`signature` is deliberately not in the dictionary — webhook
    // signatures and loosely-named app concepts would flood the map; the compound image-bearing
    // names above are the guard.
    expect(classifyColumn("signature")).toBeNull();
  });

  it("flags ambiguous names as low confidence rather than asserting PII", () => {
    expect(classifyColumn("product_name")).toEqual({ infotype: "NAME?", category: "PII", confidence: "low" });
  });

  it("does not match non-PII columns", () => {
    expect(classifyColumn("created_at")).toBeNull();
    expect(classifyColumn("tenant_id")).toBeNull();
  });

  it("is case-insensitive", () => {
    expect(classifyColumn("EMAIL")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
  });
});

describe("classifyColumn — false-positive discipline (issue #17 acceptance cases)", () => {
  it("does not classify a category/type descriptor as the data itself", () => {
    // email_category classifies rows by email type (work/personal), it isn't an email value.
    expect(classifyColumn("email_category")).toBeNull();
    expect(classifyColumn("address_type")).toBeNull();
  });

  it("does not classify a boolean flag referencing a concept as the concept's value", () => {
    // awaiting_dob_reprompt is "do we need to ask for DOB again?", not a date of birth.
    expect(classifyColumn("awaiting_dob_reprompt")).toBeNull();
  });

  it("excludes boolean-typed columns even if the name alone would otherwise match", () => {
    expect(classifyColumn("date_of_birth", "boolean")).toBeNull();
    // but the same name with a real date-shaped type still matches
    expect(classifyColumn("date_of_birth", "date")).not.toBeNull();
  });

  it("does not classify infra/system health metadata as medical health data", () => {
    // vendor_health is uptime/status metadata for a vendor integration, not patient health data.
    expect(classifyColumn("vendor_health")).toBeNull();
    expect(classifyColumn("service_health_status")).toBeNull();
  });

  it("still classifies genuine health data unaffected by the infra-health exclusion", () => {
    expect(classifyColumn("patient_diagnosis")).not.toBeNull();
  });
});

describe("classifyColumn — stored credentials / secrets (#233)", () => {
  it("classifies API keys and stored passwords as SECRET at high confidence — the ATC dogfood must-not-miss case", () => {
    expect(classifyColumn("ai_api_key")).toEqual({ infotype: "API_KEY", category: "SECRET", confidence: "high" });
    expect(classifyColumn("smtp_pass")).toEqual({ infotype: "STORED_PASSWORD", category: "SECRET", confidence: "high" });
    expect(classifyColumn("account_password")).not.toBeNull();
  });

  it("classifies long-lived auth/session tokens as SECRET", () => {
    expect(classifyColumn("access_token")).toEqual({ infotype: "AUTH_TOKEN", category: "SECRET", confidence: "high" });
    expect(classifyColumn("session_token").category).toBe("SECRET");
  });

  it("does not classify a single-use capability token (invite/share/reset/verify) as a stored credential", () => {
    expect(classifyColumn("invite_token")).toBeNull();
    expect(classifyColumn("share_token")).toBeNull();
    // password_reset_token (and the reverse word order) would otherwise match STORED_PASSWORD
    // via its "password" substring — the capability-token exclusion is what keeps them out.
    expect(classifyColumn("password_reset_token")).toBeNull();
    expect(classifyColumn("reset_password_token")).toBeNull();
  });
});

describe("classifyColumn — org/tenant/company entity-name suppression (#233, table context)", () => {
  it("does not classify a bare `name`/`company_name` column as personal PII on an org/tenant/company table", () => {
    expect(classifyColumn("name", undefined, "organizations")).toBeNull();
    expect(classifyColumn("name", undefined, "tenants")).toBeNull();
    expect(classifyColumn("company_name", undefined, "companies")).toBeNull();
  });

  it("still flags the same ambiguous `name` column at low confidence when the table isn't an org/tenant/company entity", () => {
    expect(classifyColumn("name", undefined, "profiles")).toEqual({ infotype: "NAME?", category: "PII", confidence: "low" });
    // no table context at all — still the pre-existing ambiguous behavior
    expect(classifyColumn("name")).toEqual({ infotype: "NAME?", category: "PII", confidence: "low" });
  });
});

describe("classifyColumn — table-context-only detections (#233)", () => {
  it("classifies a bare `number` column as PHONE only with phone/contact/sms table context, at medium confidence", () => {
    expect(classifyColumn("number", undefined, "contact_numbers")).toEqual({ infotype: "PHONE", category: "PII", confidence: "medium" });
    expect(classifyColumn("number", undefined, "orders")).toBeNull();
    expect(classifyColumn("number")).toBeNull();
  });

  it("review-flags a jsonb denormalization container on ANY table at low confidence — never an assertion (#377)", () => {
    // profile jsonb holding {"email": ..., "phone": ...} on an ordinary users table is the
    // common denormalized-PII shape the name-only dictionary is blind to.
    expect(classifyColumn("profile", "jsonb", "users")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
    expect(classifyColumn("metadata", "jsonb", "customers")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
    expect(classifyColumn("custom_fields", "json")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
    expect(classifyColumn("preferences", "jsonb")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
  });

  it("does not flag every jsonb column — the vocabulary is the guard (#377)", () => {
    // A jsonb column named outside the denormalization-container vocabulary stays silent...
    expect(classifyColumn("ui_state", "jsonb")).toBeNull();
    expect(classifyColumn("feature_flags", "jsonb")).toBeNull();
    // ...and a vocabulary name on a non-json type is not a container at all.
    expect(classifyColumn("profile", "text")).toBeNull();
    expect(classifyColumn("details", "text")).toBeNull();
  });

  it("keeps the table-scoped SECRET store rule ahead of the jsonb review flag (#377 precedence)", () => {
    // payload on a *_store table is the higher-signal credential-store hit, not a PII review flag.
    expect(classifyColumn("payload", "jsonb", "jackson_store")).toEqual({
      infotype: "OPAQUE_ENCRYPTED_STORE",
      category: "SECRET",
      confidence: "medium",
    });
    expect(classifyColumn("payload", "jsonb", "events")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
  });

  it("classifies an opaquely-named value/data/payload column as an encrypted secret store only on a *_store/*_config table", () => {
    // BoxyHQ SAML/SSO's jackson_store.value — a name-based matcher skips a column called "value".
    expect(classifyColumn("value", undefined, "jackson_store")).toEqual({
      infotype: "OPAQUE_ENCRYPTED_STORE",
      category: "SECRET",
      confidence: "medium",
    });
    expect(classifyColumn("value", undefined, "widgets")).toBeNull();
  });

  it("adds tax_number to the existing tax-ID rule (vat_id was already covered)", () => {
    expect(classifyColumn("tax_number").category).toBe("SENSITIVE_PII");
    expect(classifyColumn("vat_id").category).toBe("SENSITIVE_PII");
  });
});

describe("classifyColumn — free-text review flag (#850)", () => {
  it("review-flags a narrative-shaped text column at low confidence — a flag, never an assertion", () => {
    expect(classifyColumn("case_notes", "text")).toEqual({ infotype: "FREE_TEXT_REVIEW", category: "PII", confidence: "low" });
    expect(classifyColumn("bio", "text")).toEqual({ infotype: "FREE_TEXT_REVIEW", category: "PII", confidence: "low" });
    expect(classifyColumn("description", "varchar")).toEqual({ infotype: "FREE_TEXT_REVIEW", category: "PII", confidence: "low" });
    expect(classifyColumn("comment", "character varying")).toEqual({ infotype: "FREE_TEXT_REVIEW", category: "PII", confidence: "low" });
  });

  it("is type-gated — a narrative name on a non-text type, or with no type, is not a free-text column", () => {
    expect(classifyColumn("notes")).toBeNull(); // no type → gate can't fire
    expect(classifyColumn("notes", "integer")).toBeNull();
    expect(classifyColumn("content", "jsonb")).toBeNull(); // jsonb 'content' isn't in the json-container vocab
  });

  it("stays out of the way of higher-signal hits — the dictionary and json-container rules win first", () => {
    // email_body matches EMAIL before the free-text flag; a jsonb 'profile' is the #377 flag, not free-text.
    expect(classifyColumn("email_body", "text")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(classifyColumn("profile", "jsonb", "users")).toEqual({ infotype: "OPAQUE_JSON_BLOB", category: "PII", confidence: "low" });
  });

  it("does not flag a text column outside the narrative vocabulary", () => {
    expect(classifyColumn("title", "text")).toBeNull();
    expect(classifyColumn("slug", "text")).toBeNull();
  });
});

describe("classifyColumn — #856 blood_type carve-out, new concepts, and over-broad-regex FP guards", () => {
  it("classifies blood_type as PHI — carved out of the _type descriptor-suffix exclusion", () => {
    expect(classifyColumn("blood_type")).toEqual({ infotype: "BLOOD_TYPE", category: "PHI", confidence: "high" });
    expect(classifyColumn("patient_blood_type")).toEqual({ infotype: "BLOOD_TYPE", category: "PHI", confidence: "high" });
    // the exclusion still kills genuine descriptor columns
    expect(classifyColumn("record_type")).toBeNull();
    expect(classifyColumn("email_category")).toBeNull();
  });

  it("adds salary/compensation, age, maiden name, security Q&A, and orientation concepts", () => {
    expect(classifyColumn("salary")).toEqual({ infotype: "COMPENSATION", category: "SENSITIVE_PII", confidence: "medium" });
    expect(classifyColumn("compensation").category).toBe("SENSITIVE_PII");
    expect(classifyColumn("age")).toEqual({ infotype: "AGE", category: "PII", confidence: "low" });
    expect(classifyColumn("maiden_name")).toEqual({ infotype: "MAIDEN_NAME", category: "SENSITIVE_PII", confidence: "high" });
    expect(classifyColumn("mothers_maiden_name").infotype).toBe("MAIDEN_NAME");
    expect(classifyColumn("security_question")).toEqual({ infotype: "SECURITY_QA", category: "SENSITIVE_PII", confidence: "high" });
    expect(classifyColumn("security_answer").infotype).toBe("SECURITY_QA");
    expect(classifyColumn("orientation")).toEqual({ infotype: "SPECIAL_CATEGORY", category: "SENSITIVE_PII", confidence: "medium" });
  });

  it("still classifies the GDPR special categories as tokens", () => {
    expect(classifyColumn("gender").infotype).toBe("SPECIAL_CATEGORY");
    expect(classifyColumn("race").infotype).toBe("SPECIAL_CATEGORY");
    expect(classifyColumn("sexual_orientation").infotype).toBe("SPECIAL_CATEGORY");
  });

  it("clears the over-broad-regex false positives the word-bounding + exclusions target", () => {
    // race_id (an FK), race_condition (concurrency), health_score (a metric) — technical suffixes.
    expect(classifyColumn("race_id")).toBeNull();
    expect(classifyColumn("race_condition")).toBeNull();
    expect(classifyColumn("health_score")).toBeNull();
    // screen/page/device orientation is UI furniture, not sexual orientation.
    expect(classifyColumn("screen_orientation")).toBeNull();
    expect(classifyColumn("page_orientation")).toBeNull();
    // age is token-bounded, so common substrings never fire.
    expect(classifyColumn("page_count")).toBeNull();
    expect(classifyColumn("usage")).toBeNull();
    expect(classifyColumn("language")).toBeNull();
  });

  it("keeps genuine health/passport data unaffected by the tightened patterns", () => {
    expect(classifyColumn("mental_health").category).toBe("PHI");
    expect(classifyColumn("health_conditions").category).toBe("PHI");
    expect(classifyColumn("passport_number").category).toBe("SENSITIVE_PII");
  });
});

describe("buildDataMap — severity weighting", () => {
  it("weights a table by what combination of data it exposes", () => {
    const columns = [
      { table_name: "users", column_name: "email", data_type: "text" },
      { table_name: "users", column_name: "date_of_birth", data_type: "date" },
      { table_name: "users", column_name: "passport_number", data_type: "text" },
      { table_name: "profiles", column_name: "display_name", data_type: "text" },
    ];
    const map = buildDataMap(columns);

    expect(map.users.categories.sort()).toEqual(["PII", "SENSITIVE_PII"]);
    expect(map.profiles.categories).toEqual(["PII"]);
    // email + dob + passport must outrank a lone ambiguous display name
    expect(map.users.severityScore).toBeGreaterThan(map.profiles.severityScore);
    expect(["High", "Critical"]).toContain(map.users.severity);
    expect(map.profiles.severity).toBe("Low");
  });

  it("marks tables holding PHI/PCI so compliance applicability (HIPAA/PCI-DSS) can be derived", () => {
    const columns = [
      { table_name: "billing", column_name: "card_number", data_type: "text" },
      { table_name: "medical", column_name: "diagnosis_code", data_type: "text" },
    ];
    const map = buildDataMap(columns);
    expect(map.billing.pci).toBe(true);
    expect(map.billing.phi).toBe(false);
    expect(map.medical.phi).toBe(true);
  });

  it("treats a stored CVV as critical by itself — PCI-DSS forbids storing it post-auth", () => {
    const map = buildDataMap([{ table_name: "payments", column_name: "cvv", data_type: "text" }]);
    expect(map.payments.severity).toBe("Critical");
  });

  it("treats a stored PIN block or track data as Critical alone — same PCI-DSS never-store category as CVV (#376)", () => {
    expect(buildDataMap([{ table_name: "cards", column_name: "pin_block", data_type: "text" }]).cards.severity).toBe("Critical");
    expect(buildDataMap([{ table_name: "cards", column_name: "track2", data_type: "text" }]).cards.severity).toBe("Critical");
  });

  it("flags a table storing a plaintext API key + password as Critical, above a lone contact-PII table — the ATC dogfood headline case", () => {
    // organisations.ai_api_key + organisations.smtp_pass, readable by any org member via RLS.
    const map = buildDataMap([
      { table_name: "organisations", column_name: "ai_api_key", data_type: "text" },
      { table_name: "organisations", column_name: "smtp_pass", data_type: "text" },
      { table_name: "organisations", column_name: "name", data_type: "text" }, // suppressed: entity name, not personal PII
      { table_name: "contacts", column_name: "email", data_type: "text" },
    ]);
    expect(map.organisations.secret).toBe(true);
    expect(map.organisations.severity).toBe("Critical");
    expect(map.organisations.columns.map((c) => c.column)).not.toContain("name");
    expect(map.organisations.severityScore).toBeGreaterThan(map.contacts.severityScore);
  });

  it("excludes false-positive columns from the data map entirely", () => {
    const columns = [
      { table_name: "accounts", column_name: "email_category", data_type: "text" },
      { table_name: "accounts", column_name: "awaiting_dob_reprompt", data_type: "boolean" },
      { table_name: "accounts", column_name: "vendor_health", data_type: "text" },
    ];
    const map = buildDataMap(columns);
    expect(map.accounts).toBeUndefined();
  });
});

describe("M10 calibration corpus (#72, spec §M10) — the planted answer key, run live", () => {
  // The exact columns planted in targets/calibration/supabase/migrations/
  // 20260708000003_pii_calibration.sql (table pii_calibration_fixture). Mirrors
  // src/scan/calibration/m10.entries.ts's answer key 1:1 — this is Layer 1 (pnpm verify);
  // src/cli/dry-run.ts's M10 phase is the live run over the parsed migration SQL.

  it("classifies every M10 planted positive at high confidence", () => {
    expect(classifyColumn("email", "text")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(classifyColumn("date_of_birth", "date")).toEqual({ infotype: "DOB", category: "PII", confidence: "high" });
    expect(classifyColumn("customer_ssn", "text")).toEqual({ infotype: "US_SSN", category: "SENSITIVE_PII", confidence: "high" });
    expect(classifyColumn("passport_number", "text")).toEqual({ infotype: "PASSPORT", category: "SENSITIVE_PII", confidence: "high" });
    expect(classifyColumn("cvv", "text")).toEqual({ infotype: "CVV", category: "PCI", confidence: "high" });
    expect(classifyColumn("card_last4", "text")).toEqual({ infotype: "CARD", category: "PCI", confidence: "high" });
  });

  it("clears every M10 named FP lookalike — none reach the free/high count", () => {
    expect(classifyColumn("email_category", "text")).toBeNull();
    expect(classifyColumn("awaiting_dob_reprompt", "boolean")).toBeNull();
    expect(classifyColumn("vendor_health", "text")).toBeNull();
    // Ambiguous NAME? is classified but only at low confidence — never asserted.
    expect(classifyColumn("product_name", "text")).toEqual({ infotype: "NAME?", category: "PII", confidence: "low" });
  });

  it("aggregates the fixture table to Critical severity, driven by the lone CVV column", () => {
    const columns = [
      { table_name: "pii_calibration_fixture", column_name: "email", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "date_of_birth", data_type: "date" },
      { table_name: "pii_calibration_fixture", column_name: "customer_ssn", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "passport_number", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "cvv", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "card_last4", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "email_category", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "awaiting_dob_reprompt", data_type: "boolean" },
      { table_name: "pii_calibration_fixture", column_name: "vendor_health", data_type: "text" },
      { table_name: "pii_calibration_fixture", column_name: "product_name", data_type: "text" },
    ];
    const map = buildDataMap(columns);
    // 6 positives classified + the 1 low-confidence NAME? hit; the 3 excluded FPs contribute nothing.
    expect(map.pii_calibration_fixture.columns).toHaveLength(7);
    expect(map.pii_calibration_fixture.categories.sort()).toEqual(["PCI", "PII", "SENSITIVE_PII"]);
    expect(map.pii_calibration_fixture.pci).toBe(true);
    expect(map.pii_calibration_fixture.severity).toBe("Critical");
  });
});

describe("classifyMigrationSql — static-schema entry point (#250)", () => {
  // No SUPABASE_DB_URL and no live DB — runs the same classifier over migration SQL text via
  // src/migration-sql-parse.ts's parseColumns, so M10 can join the source-only tier.
  it("parses CREATE TABLE columns out of migration SQL and classifies them", () => {
    const sql = `
      create table public.profiles (
        id uuid primary key,
        email text not null,
        date_of_birth date,
        display_name text
      );
    `;
    const { columns, dataMap } = classifyMigrationSql(sql);
    expect(columns.map((c) => c.column_name).sort()).toEqual(["date_of_birth", "display_name", "email", "id"]);
    expect(dataMap.profiles.infotypes.sort()).toEqual(["DOB", "EMAIL", "NAME?"]);
    expect(dataMap.profiles.columns.map((c) => c.column)).not.toContain("id");
  });

  it("returns no columns for SQL with no CREATE TABLE statements — surfaced by the CLI as a usage error, not a silent empty scan", () => {
    const { columns, dataMap } = classifyMigrationSql("-- just a comment, no schema here\n");
    expect(columns).toHaveLength(0);
    expect(dataMap).toEqual({});
  });

  it("classifies columns declared with inet/citext — types the parser used to drop silently (#375)", () => {
    // Before #375 widened migration-sql-parse's SQL_TYPES, an `ip_address inet` or `email citext`
    // column never reached classifyColumn at all in --schema mode — the dictionary rules for IP
    // and EMAIL existed but the parser extraction gate made the columns invisible.
    const sql = `
      create table public.sessions (
        id uuid primary key,
        ip_address inet,
        email citext not null
      );
    `;
    const { dataMap } = classifyMigrationSql(sql);
    expect(dataMap.sessions.columns).toContainEqual({ column: "email", infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(dataMap.sessions.columns).toContainEqual({ column: "ip_address", infotype: "IP", category: "PII", confidence: "medium" });
  });

  it("classifies a stored secret across multiple migration files concatenated together", () => {
    const sql = [
      "create table public.organisations (\n  id uuid primary key,\n  ai_api_key text\n);",
      "create table public.contacts (\n  id uuid primary key,\n  email text\n);",
    ].join("\n\n");
    const { dataMap } = classifyMigrationSql(sql);
    expect(dataMap.organisations.secret).toBe(true);
    expect(dataMap.contacts.categories).toEqual(["PII"]);
  });
});

describe("classifyMigrationSql — ALTER TABLE ADD COLUMN (#852) and unrecognized types (#851)", () => {
  it("classifies a PII column added by a later migration via ALTER TABLE ADD COLUMN", () => {
    const sql = `
      create table public.users (
        id uuid primary key,
        email text
      );
      alter table public.users add column ssn text;
      alter table users add column if not exists date_of_birth date;
    `;
    const { dataMap } = classifyMigrationSql(sql);
    expect(dataMap.users.infotypes.sort()).toEqual(["DOB", "EMAIL", "US_SSN"]);
  });

  it("excludes a column dropped by a later migration", () => {
    const sql = `
      create table public.users (
        id uuid primary key,
        customer_ssn text
      );
      alter table public.users drop column customer_ssn;
    `;
    const { dataMap } = classifyMigrationSql(sql);
    expect(dataMap.users).toBeUndefined(); // ssn dropped → nothing classified on the live table
  });

  it("fails loud on an unrecognized type — surfaces it in unknownType AND classifies it by name", () => {
    // `gender Gender` (a Postgres enum) and `ssn my_enc_type` (a custom type) are outside SQL_TYPES;
    // before #851 they vanished before classification. Now they're name-classified and disclosed.
    const sql = `
      create table public.people (
        id uuid primary key,
        gender gender_enum,
        ssn my_enc_type,
        status workflow_state
      );
    `;
    const { dataMap, unknownType } = classifyMigrationSql(sql);
    expect(unknownType.map((c) => `${c.column_name}:${c.data_type}`).sort()).toEqual([
      "gender:gender_enum",
      "ssn:my_enc_type",
      "status:workflow_state",
    ]);
    // gender + ssn classify by name; status matches nothing (correctly no false hit).
    expect(dataMap.people.infotypes.sort()).toEqual(["SPECIAL_CATEGORY", "US_SSN"]);
  });

  it("does not read a table-level constraint line as an unknown-type column", () => {
    const sql = `
      create table public.t (
        id uuid primary key,
        email text,
        constraint t_pkey primary key (id),
        foreign key (id) references other (id)
      );
    `;
    const { unknownType } = classifyMigrationSql(sql);
    expect(unknownType).toHaveLength(0);
  });

  it("discloses the tier scope in every finding's evidence (#853)", () => {
    const schema = dataMapToFindings(buildDataMap([{ table_name: "u", column_name: "email", data_type: "text" }]), { tier: "schema" });
    expect(schema[0]?.evidence).toMatch(/views, materialized views, and generated columns are not parsed/i);
    const live = dataMapToFindings(buildDataMap([{ table_name: "u", column_name: "email", data_type: "text" }]), { tier: "live" });
    expect(live[0]?.evidence).toMatch(/public schema only/i);
  });
});

// #758: a Prisma app declares its schema in schema.prisma, not migration SQL — before this,
// classifyMigrationSql (the --schema entry point) had nothing to parse a Prisma DSL file with, so
// a Prisma-only target's M10 tier classified nothing. classifyPrismaSchema is the CLI-independent
// entry point (bypasses any Prisma-CLI attempt) — the one CI can exercise with no target Prisma
// install anywhere, proving the fallback schema.prisma parser path directly.
describe("classifyPrismaSchema — schema.prisma classification, fallback-parser path (#758)", () => {
  it("classifies PII/PCI columns declared in schema.prisma model fields", () => {
    const schema = `
      model Customer {
        id      String  @id
        email   String  @unique
        phone   String?
        address String?
        cardNumber String? @map("card_number")
      }
    `;
    const { columns, dataMap } = classifyPrismaSchema(schema);
    expect(columns.map((c) => c.column_name).sort()).toEqual(["address", "card_number", "email", "id", "phone"]);
    expect(dataMap.Customer.infotypes.sort()).toEqual(["ADDRESS", "CARD", "EMAIL", "PHONE"]);
    expect(dataMap.Customer.categories.sort()).toEqual(["PCI", "PII"]);
  });

  it("classifies the real Prisma fixture's schema.prisma (not empty) — the #758 acceptance case", () => {
    // src/scan/__fixtures__/prisma-app/prisma/schema.prisma's Customer model: email/phone/address/
    // payment_method — the same PII/PCI columns a supabase/migrations-based app would classify.
    const schema = readFileSync(PRISMA_FIXTURE_SCHEMA, "utf8");
    const { columns, dataMap } = classifyPrismaSchema(schema);
    expect(columns.length).toBeGreaterThan(0);
    expect(dataMap.Customer).toBeDefined();
    expect(dataMap.Customer.infotypes.sort()).toEqual(["ADDRESS", "EMAIL", "PAYMENT_REF", "PHONE"]);
    expect(dataMap.Customer.categories.sort()).toEqual(["PCI", "PII"]);
  });

  it("returns no columns for schema text with no model blocks — surfaced as a usage error, not a silent empty scan", () => {
    const { columns, dataMap } = classifyPrismaSchema('datasource db {\n  provider = "postgresql"\n}\n');
    expect(columns).toHaveLength(0);
    expect(dataMap).toEqual({});
  });

  it("classifies an enum-typed field by name (#854) — `gender Gender` reaches the special-category rule", () => {
    const schema = `
      enum Gender { MALE FEMALE OTHER }
      model Patient {
        id     String @id
        gender Gender
        bloodType String @map("blood_type")
      }
    `;
    const { dataMap } = classifyPrismaSchema(schema);
    expect(dataMap.Patient.infotypes.sort()).toEqual(["BLOOD_TYPE", "SPECIAL_CATEGORY"]);
    // a relation field is still not misread as a column
  });

  it("parses composite `type` blocks so their embedded PII fields are classified (#854)", () => {
    const schema = `
      type Address {
        street String
        city   String
        zip    String
      }
      model User {
        id       String  @id
        homeAddr Address
      }
    `;
    const { dataMap } = classifyPrismaSchema(schema);
    expect(dataMap.Address).toBeDefined();
    expect(dataMap.Address.infotypes).toContain("ADDRESS");
    // the embedded-object FIELD itself (homeAddr) is not a stored scalar column
    expect(dataMap.User).toBeUndefined();
  });
});

describe("pii-classify --schema CLI — a schema.prisma target (#758)", () => {
  it("classifies the Prisma fixture end-to-end through the real CLI (no target prisma install — proves the fallback path is actually wired, not just unit-tested)", () => {
    const outPath = join(dirname(PRISMA_FIXTURE_SCHEMA), "out.json");
    try {
      execFileSync("node_modules/.bin/tsx", [CLI, "--schema", PRISMA_FIXTURE_SCHEMA, "--out", outPath], { cwd: REPO_ROOT, encoding: "utf8" });
      const findings = JSON.parse(readFileSync(outPath, "utf8"));
      const customer = findings.find((f: { location: string }) => f.location === "Customer");
      expect(customer).toBeDefined();
      expect(customer.evidence).toMatch(/email/);
    } finally {
      rmSync(outPath, { force: true });
    }
  });
});

// #1043/#1049 — the two outputs the orchestrator now depends on, driven through the real CLI so a
// wiring regression (a flag renamed, a writer dropped) fails here rather than silently producing a
// deliverable with un-escalated severities and no protection verdict.
describe("pii-classify --schema CLI — protection disclosure + data map (#1043/#1049)", () => {
  it("emits the M10-PROT-00 not-assessed row and the --data-map-out artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "pii-cli-"));
    const schemaPath = join(dir, "schema.sql");
    writeFileSync(schemaPath, "create table patients (\n  id uuid primary key,\n  email text,\n  medical_record_number text\n);\n");
    try {
      execFileSync("node_modules/.bin/tsx", [CLI, "--schema", schemaPath, "--out", join(dir, "out.json"), "--data-map-out", join(dir, "map.json")], { cwd: REPO_ROOT, encoding: "utf8" });
      const findings = JSON.parse(readFileSync(join(dir, "out.json"), "utf8"));
      // The claim sold on the connected tier is a protection VERDICT. On the schema tier there is
      // none — and the deliverable has to say so, because a longer sensitive-column list with no
      // stated limitation reads as "checked and protected".
      const scope = findings.find((f: { id: string }) => f.id === "M10-PROT-00");
      expect(scope.title).toContain("NOT verified");
      expect(validateFindings({ meta: FINDINGS_META, findings }).ok).toBe(true);

      const map = JSON.parse(readFileSync(join(dir, "map.json"), "utf8"));
      expect(map.patients.severity).toBe("High");
      expect(map.patients.categories).toContain("PHI");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// #1043 — the connected tier's protection inputs, against an injected `sql`. Without this the live
// path is exercised only in its failure mode, which is how "PII protection verified in production"
// became a claim nothing tested.
describe("gatherProtectionFacts — catalog rows → ExposureFacts (#1043)", () => {
  const rows: Record<string, Record<string, unknown>[]> = {
    relrowsecurity: [
      { table_name: "patients", rls_enabled: false }, // granted + RLS off → anon-reachable
      { table_name: "billing", rls_enabled: true }, // granted but RLS on → not auto-exposed
      { table_name: "internal_jobs", rls_enabled: false }, // RLS off but no client grant → unreachable
    ],
    role_table_grants: [{ table_name: "patients" }, { table_name: "billing" }],
  };
  const sqlWith = (masking: Record<string, unknown>[], maskedCols: Record<string, unknown>[]) =>
    ((strings: TemplateStringsArray) => {
      const q = strings.join("");
      if (q.includes("relrowsecurity")) return Promise.resolve(rows.relrowsecurity!);
      if (q.includes("role_table_grants")) return Promise.resolve(rows.role_table_grants!);
      if (q.includes("'masking_rule'")) return Promise.resolve(masking);
      if (q.includes("pgsodium.masking_rule")) return Promise.resolve(maskedCols);
      throw new Error(`unexpected query: ${q}`);
    }) as never;

  it("counts a table anon-reachable only when RLS is off AND a client role can SELECT it", async () => {
    const { facts } = await gatherProtectionFacts(sqlWith([], []));
    expect(facts.autoExposedTables).toEqual(["public.patients"]);
  });

  it("credits encryption at rest from pgsodium's masking rules when the view is readable", async () => {
    const masking = [{ column_name: "relname" }, { column_name: "attname" }];
    const { encrypted, detail } = await gatherProtectionFacts(sqlWith(masking, [{ table_name: "patients", column_name: "ssn" }]));
    expect(encrypted.has("patients.ssn")).toBe(true);
    expect(detail).toMatch(/listed 1 encrypted column/);
  });

  it("credits NOTHING as encrypted — and says so — when the masking view is absent or unreadable", async () => {
    const { encrypted, detail } = await gatherProtectionFacts(sqlWith([], []));
    expect(encrypted.size).toBe(0);
    expect(detail).toMatch(/no readable pgsodium.masking_rule view/);
  });
});

const FINDINGS_META = {
  client: "c", subtitle: "s", date: "d", commit: "abc", auditor: "a", confidential: true, overallHealth: 5,
  tenantIsolation: "t", authModel: "m", headline: "h", scope: "s", methodology: "m", outOfScope: "o",
};

describe("dataMapToFindings — report-schema Finding[] emitter (#436)", () => {
  const columns = [
    { table_name: "payments", column_name: "cvv", data_type: "text" },
    { table_name: "payments", column_name: "card_last4", data_type: "text" },
    { table_name: "users", column_name: "email", data_type: "text" },
    { table_name: "users", column_name: "profile", data_type: "jsonb" },
    { table_name: "prefs", column_name: "metadata", data_type: "jsonb" },
  ];
  const findings = dataMapToFindings(buildDataMap(columns), { tier: "schema" });

  it("emits one valid report-schema finding per PII-bearing table, severity from the data map, confidence Review", () => {
    expect(findings).toHaveLength(3);
    const meta = {
      client: "c", subtitle: "s", date: "d", commit: "x", auditor: "a", confidential: true,
      overallHealth: 5, tenantIsolation: "t", authModel: "m", headline: "h", scope: "sc",
      methodology: "me", outOfScope: "o",
    };
    expect(validateFindings({ meta, findings })).toEqual({ ok: true, errors: [] });
    const payments = findings.find((f) => f.location === "payments");
    expect(payments?.severity).toBe("Critical"); // lone CVV → Critical via the point override
    expect(findings.every((f) => f.confidence === "Review")).toBe(true);
    expect(findings.every((f) => f.mechanical === true && f.precisionTier === "review")).toBe(true);
  });

  it("orders findings by table severity, worst first, with deterministic ids", () => {
    expect(findings[0]?.location).toBe("payments");
    expect(findings.map((f) => f.id)).toEqual(["M10-01", "M10-02", "M10-03"]);
  });

  it("names the PCI never-store violation — a stored CVV is a violation independent of exposure", () => {
    const payments = findings.find((f) => f.location === "payments");
    expect(payments?.impact).toMatch(/forbids storing it post-authorization/);
    expect(payments?.fix).toMatch(/may not be stored post-authorization/);
  });

  it("keeps #377 review flags distinct from asserted columns — flagged in evidence, never claimed in the title", () => {
    const users = findings.find((f) => f.location === "users");
    expect(users?.title).toMatch(/holds PII data \(EMAIL\)/); // profile (jsonb) not asserted in the title
    expect(users?.evidence).toMatch(/Review for nested PII \(flagged, not asserted/);
    // A table with ONLY review flags never claims to hold PII — it asks for review.
    const prefs = findings.find((f) => f.location === "prefs");
    expect(prefs?.title).toMatch(/review for nested PII/i);
    expect(prefs?.title).not.toMatch(/holds/);
  });

  it("records which tier produced the evidence", () => {
    expect(findings[0]?.evidence).toMatch(/static migration-SQL schema parse/i);
    const live = dataMapToFindings(buildDataMap(columns), { tier: "live" });
    expect(live[0]?.evidence).toMatch(/live information_schema/i);
  });

  it("#459: marks a review-flag-only table so the renderer never shows it as an asserted PII holding", () => {
    const prefs = findings.find((f) => f.location === "prefs");
    expect(prefs?.reviewFlagOnly).toBe(true);
    expect(prefs?.reviewFlagColumns).toEqual(["metadata"]);
  });

  it("#459: a mixed table (asserted + review flag) stays asserted but still lists its flagged columns", () => {
    const users = findings.find((f) => f.location === "users");
    expect(users?.reviewFlagOnly).toBe(false);
    expect(users?.reviewFlagColumns).toEqual(["profile"]);
  });

  it("#459: a table with no review-flagged columns reports an empty reviewFlagColumns list", () => {
    const payments = findings.find((f) => f.location === "payments");
    expect(payments?.reviewFlagOnly).toBe(false);
    expect(payments?.reviewFlagColumns).toEqual([]);
  });
});

describe("dataMapToFindings — free-text review flags (#850)", () => {
  it("keeps a free-text flag distinct from asserted columns — a flag in evidence, never claimed as PII", () => {
    const map = buildDataMap([
      { table_name: "tickets", column_name: "email", data_type: "text" },
      { table_name: "tickets", column_name: "notes", data_type: "text" },
      { table_name: "articles", column_name: "body", data_type: "text" },
    ]);
    const findings = dataMapToFindings(map, { tier: "schema" });
    const tickets = findings.find((f) => f.location === "tickets");
    expect(tickets?.title).toMatch(/holds PII data \(EMAIL\)/); // notes (free-text) not asserted in the title
    expect(tickets?.evidence).toMatch(/Review for unstructured PII\/PHI \(flagged, not asserted/);
    expect(tickets?.reviewFlagColumns).toEqual(["notes"]);
    // a table with ONLY a free-text flag asks for review, never claims a holding
    const articles = findings.find((f) => f.location === "articles");
    expect(articles?.title).toMatch(/free-text column\(s\) to review/i);
    expect(articles?.title).not.toMatch(/holds/);
    expect(articles?.reviewFlagOnly).toBe(true);
  });
});

describe("classifyWithFallback — LLM semantic-pass hook", () => {
  it("returns the dictionary-only data map when no semantic classifier is supplied", async () => {
    const columns = [{ table_name: "users", column_name: "email", data_type: "text" }];
    const map = await classifyWithFallback(columns);
    expect(map.users.infotypes).toEqual(["EMAIL"]);
  });

  it("merges semantic hits for columns the dictionary can't resolve, tagged by source", async () => {
    // contact_handle is the obfuscated-field example named in issue #17 — the dictionary has no
    // rule for it by design, so it's exactly the case the semantic fallback exists to cover.
    expect(classifyColumn("contact_handle")).toBeNull();
    const columns = [
      { table_name: "users", column_name: "email", data_type: "text" },
      { table_name: "users", column_name: "contact_handle", data_type: "text" },
    ];
    const semanticClassifier = async (unresolved: { table_name: string; column_name: string; data_type?: string }[]) => {
      // the hook receives the declared type too (#855) — the LLM reasons over name+type+context
      expect(unresolved).toEqual([{ table_name: "users", column_name: "contact_handle", data_type: "text" }]);
      return new Map([["users.contact_handle", { infotype: "USERNAME_HANDLE", category: "PII", confidence: "low" }]]);
    };
    const map = await classifyWithFallback(columns, semanticClassifier);
    expect(map.users.infotypes.sort()).toEqual(["EMAIL", "USERNAME_HANDLE"]);
    const handleHit = map.users.columns.find((c) => c.column === "contact_handle");
    expect(handleHit?.source).toBe("semantic");
  });

  it("never overrides a dictionary hit with a semantic verdict — name-based results are the base layer", async () => {
    const columns = [
      { table_name: "users", column_name: "email", data_type: "text" },
      { table_name: "users", column_name: "contact_handle", data_type: "text" },
    ];
    // A hostile/wrong classifier that tries to reclassify the dictionary-resolved email column.
    const semanticClassifier = async () =>
      new Map([
        ["users.email", { infotype: "WRONG", category: "SECRET" as const, confidence: "medium" as const }],
        ["users.contact_handle", { infotype: "USERNAME_HANDLE", category: "PII" as const, confidence: "low" as const }],
      ]);
    const map = await classifyWithFallback(columns, semanticClassifier);
    const emailHit = map.users.columns.find((c) => c.column === "email");
    expect(emailHit).toEqual({ column: "email", infotype: "EMAIL", category: "PII", confidence: "high" }); // no source: "semantic"
    expect(map.users.infotypes.sort()).toEqual(["EMAIL", "USERNAME_HANDLE"]);
  });

  it("does not invoke the semantic classifier at all when the dictionary resolves everything", async () => {
    const semanticClassifier = vi.fn(async () => new Map());
    const map = await classifyWithFallback([{ table_name: "users", column_name: "email", data_type: "text" }], semanticClassifier);
    expect(semanticClassifier).not.toHaveBeenCalled();
    expect(map.users.infotypes).toEqual(["EMAIL"]);
  });

  it("produces the identical data map to buildDataMap when semantic is off — the default free tier is unchanged", async () => {
    const columns = [
      { table_name: "users", column_name: "email", data_type: "text" },
      { table_name: "users", column_name: "contact_handle", data_type: "text" },
      { table_name: "payments", column_name: "cvv", data_type: "text" },
    ];
    expect(await classifyWithFallback(columns)).toEqual(buildDataMap(columns));
  });
});

describe("resolveSemanticClassifier — the #855 double gate (opt-in flag AND API key)", () => {
  const env = { ANTHROPIC_API_KEY: "sk-ant-test" };

  it("returns null without the --semantic flag, even when a key is present — semantic is opt-in only", () => {
    expect(resolveSemanticClassifier({ argv: ["node", "pii-classify.mjs", "--schema", "x"], env })).toBeNull();
  });

  it("returns null (with a loud stderr disclosure) when --semantic is passed without ANTHROPIC_API_KEY", () => {
    const warn = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(resolveSemanticClassifier({ argv: ["node", "pii-classify.mjs", "--semantic"], env: {} })).toBeNull();
      expect(warn).toHaveBeenCalledWith(expect.stringContaining("ANTHROPIC_API_KEY is not set"));
    } finally {
      warn.mockRestore();
    }
  });

  it("returns a classifier defaulting to claude-sonnet-5 when both gates pass", () => {
    const classifier = resolveSemanticClassifier({ argv: ["node", "pii-classify.mjs", "--semantic"], env });
    expect(classifier).not.toBeNull();
    expect(classifier?.model).toBe("claude-sonnet-5");
    expect(DEFAULT_SEMANTIC_MODEL).toBe("claude-sonnet-5");
  });

  it("honors --semantic-model over the PII_SEMANTIC_MODEL env override", () => {
    const flagged = resolveSemanticClassifier({
      argv: ["node", "pii-classify.mjs", "--semantic", "--semantic-model", "claude-opus-4-8"],
      env: { ...env, PII_SEMANTIC_MODEL: "claude-haiku-4-5" },
    });
    expect(flagged?.model).toBe("claude-opus-4-8");
    const fromEnv = resolveSemanticClassifier({
      argv: ["node", "pii-classify.mjs", "--semantic"],
      env: { ...env, PII_SEMANTIC_MODEL: "claude-haiku-4-5" },
    });
    expect(fromEnv?.model).toBe("claude-haiku-4-5");
  });
});

describe("createAnthropicSemanticClassifier — fetch-based Messages API caller (#855, network fully mocked)", () => {
  const unresolved = [
    { table_name: "users", column_name: "contact_handle", data_type: "text" },
    { table_name: "users", column_name: "kv_blob", data_type: "jsonb" },
  ];
  const allColumns = [
    { table_name: "users", column_name: "email" },
    { table_name: "users", column_name: "contact_handle" },
    { table_name: "users", column_name: "kv_blob" },
  ];
  const apiResponse = (entries: unknown) => ({
    ok: true,
    status: 200,
    json: async () => ({ stop_reason: "end_turn", content: [{ type: "text", text: JSON.stringify(entries) }] }),
  });

  it("requires an apiKey — never constructible without one", () => {
    expect(() => createAnthropicSemanticClassifier({} as never)).toThrow(/apiKey/);
  });

  it("sends only names/types/table context (never values) to /v1/messages and maps the verdicts back", async () => {
    const fetchImpl = vi.fn(async () =>
      apiResponse([
        { table: "users", column: "contact_handle", infotype: "USERNAME_HANDLE", category: "PII", confidence: "low" },
      ]),
    );
    const classifier = createAnthropicSemanticClassifier({ apiKey: "sk-ant-test", allColumns, fetchImpl: fetchImpl as never });
    const hits = await classifier(unresolved);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, { headers: Record<string, string>; body: string }];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    expect(init.headers["x-api-key"]).toBe("sk-ant-test");
    expect(init.headers["anthropic-version"]).toBe("2023-06-01");
    const body = JSON.parse(init.body);
    expect(body.model).toBe("claude-sonnet-5");
    // the batch carries the unresolved names, declared types, and sibling-column context…
    expect(JSON.parse(body.messages[0].content)).toEqual([
      { table: "users", column: "contact_handle", sql_type: "text", sibling_columns: ["email", "kv_blob"] },
      { table: "users", column: "kv_blob", sql_type: "jsonb", sibling_columns: ["email", "contact_handle"] },
    ]);
    expect(hits.get("users.contact_handle")).toEqual({ infotype: "USERNAME_HANDLE", category: "PII", confidence: "low" });
    expect(hits.has("users.kv_blob")).toBe(false); // omitted by the model → no verdict, stays unclassified
  });

  it("clamps a semantic 'high' to medium and drops malformed verdicts — a guess never reaches the asserted tier", async () => {
    const fetchImpl = vi.fn(async () =>
      apiResponse([
        { table: "users", column: "contact_handle", infotype: "EMAIL", category: "PII", confidence: "high" },
        { table: "users", column: "kv_blob", infotype: "whatever", category: "NOT_A_CATEGORY", confidence: "low" },
        { table: "users", column: "kv_blob", infotype: "lower_case_bad", category: "PII", confidence: "low" },
      ]),
    );
    const classifier = createAnthropicSemanticClassifier({ apiKey: "sk-ant-test", fetchImpl: fetchImpl as never });
    const hits = await classifier(unresolved);
    expect(hits.get("users.contact_handle")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "medium" });
    expect(hits.has("users.kv_blob")).toBe(false);
  });

  it("fails loud on an API error or a non-JSON response — an opted-in pass never silently degrades", async () => {
    const errorFetch = vi.fn(async () => ({ ok: false, status: 401, text: async () => "authentication_error" }));
    const classifier = createAnthropicSemanticClassifier({ apiKey: "sk-ant-bad", fetchImpl: errorFetch as never });
    await expect(classifier(unresolved)).rejects.toThrow(/401/);

    const proseFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ stop_reason: "end_turn", content: [{ type: "text", text: "I could not classify these." }] }),
    }));
    const proseClassifier = createAnthropicSemanticClassifier({ apiKey: "sk-ant-test", fetchImpl: proseFetch as never });
    await expect(proseClassifier(unresolved)).rejects.toThrow(/no JSON array/);
  });

  it("plugs into classifyWithFallback end-to-end with the fetch mock — verdicts merge on top of the name-based base layer", async () => {
    const fetchImpl = vi.fn(async () =>
      apiResponse([{ table: "users", column: "contact_handle", infotype: "USERNAME_HANDLE", category: "PII", confidence: "low" }]),
    );
    const columns = [
      { table_name: "users", column_name: "email", data_type: "text" },
      { table_name: "users", column_name: "contact_handle", data_type: "text" },
    ];
    const classifier = createAnthropicSemanticClassifier({ apiKey: "sk-ant-test", allColumns: columns, fetchImpl: fetchImpl as never });
    const map = await classifyWithFallback(columns, classifier);
    expect(map.users.infotypes.sort()).toEqual(["EMAIL", "USERNAME_HANDLE"]);
    expect(map.users.columns.find((c) => c.column === "email")?.source).toBeUndefined();
    expect(map.users.columns.find((c) => c.column === "contact_handle")?.source).toBe("semantic");
  });
});

// #770: the M10 probe's discovery fallback (src/audit-runners.ts) may hand --schema more than one
// target when a project's schema DDL is scattered across unconventional locations — a root-level
// file (launch-mvp) plus a nested one (nocode-rescue) in the same run. This drives the real CLI
// (not classifyMigrationSql in-process) to prove the argv-parsing change actually reads and
// concatenates every target, not just the first.
describe("pii-classify --schema CLI — multiple targets (#770)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("classifies columns from a single unconventionally-named schema file", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-pii-schema-"));
    dirs.push(dir);
    const schema = join(dir, "initial_supabase_table_schema.sql");
    writeFileSync(schema, "create table customers (\n  id uuid primary key,\n  email text not null\n);\n");
    const outPath = join(dir, "out.json");

    execFileSync("node_modules/.bin/tsx", [CLI, "--schema", schema, "--out", outPath], { cwd: REPO_ROOT, encoding: "utf8" });

    const findings = JSON.parse(readFileSync(outPath, "utf8"));
    expect(findings.some((f: { location: string }) => f.location === "customers")).toBe(true);
  });

  it("concatenates two targets passed after a single --schema flag, classifying columns from both", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-pii-schema-multi-"));
    dirs.push(dir);
    const root = join(dir, "initial_supabase_table_schema.sql");
    writeFileSync(root, "create table customers (\n  id uuid primary key,\n  email text not null\n);\n");
    mkdirSync(join(dir, "before"));
    const nested = join(dir, "before", "schema.sql");
    writeFileSync(nested, "create table applicants (\n  id uuid primary key,\n  customer_ssn text\n);\n");
    const outPath = join(dir, "out.json");

    execFileSync("node_modules/.bin/tsx", [CLI, "--schema", root, nested, "--out", outPath], { cwd: REPO_ROOT, encoding: "utf8" });

    const findings = JSON.parse(readFileSync(outPath, "utf8"));
    const locations = findings.map((f: { location: string }) => f.location);
    expect(locations).toContain("customers");
    expect(locations).toContain("applicants");
  });

  it("errors out (rather than silently classifying nothing) when a --schema target does not exist", () => {
    expect(() =>
      execFileSync("node_modules/.bin/tsx", [CLI, "--schema", "/does/not/exist.sql"], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }),
    ).toThrow();
  });
});
