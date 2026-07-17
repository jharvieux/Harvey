import { describe, expect, it } from "vitest";
import { buildDataMap, classifyColumn, classifyMigrationSql, classifyWithFallback } from "./pii-classify.mjs";

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
    const semanticClassifier = async (unresolved: { table_name: string; column_name: string }[]) => {
      expect(unresolved).toEqual([{ table_name: "users", column_name: "contact_handle" }]);
      return new Map([["users.contact_handle", { infotype: "USERNAME_HANDLE", category: "PII", confidence: "low" }]]);
    };
    const map = await classifyWithFallback(columns, semanticClassifier);
    expect(map.users.infotypes.sort()).toEqual(["EMAIL", "USERNAME_HANDLE"]);
    const handleHit = map.users.columns.find((c) => c.column === "contact_handle");
    expect(handleHit?.source).toBe("semantic");
  });
});
