import { describe, expect, it } from "vitest";
import { buildDataMap, classifyColumn, classifyWithFallback } from "./pii-classify.mjs";

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
