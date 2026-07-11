import { describe, expect, it } from "vitest";
import { piiProtectionFindings, reviewPiiColumn, type ClassifiedColumn, type ExposureFacts } from "./pii-protection-review.js";

// POSITIVE — PII in an auto-exposed public table with no encryption.
const exposedEmail: ClassifiedColumn = {
  schema: "public",
  table: "customers",
  column: "email",
  category: "PII",
  infotype: "EMAIL",
  encrypted: false,
};

// NEGATIVE — sensitive column in an unexposed schema, encrypted at rest.
const protectedSsn: ClassifiedColumn = {
  schema: "private",
  table: "customers",
  column: "customer_ssn",
  category: "SENSITIVE_PII",
  infotype: "US_SSN",
  encrypted: true,
};

// NEGATIVE — reachable, but encrypted at rest, so the raw value isn't exposed.
const encryptedExposedPan: ClassifiedColumn = {
  schema: "public",
  table: "customers",
  column: "card_pan",
  category: "PCI",
  infotype: "CARD",
  encrypted: true,
};

const facts: ExposureFacts = { exposedSchemas: [], autoExposedTables: ["public.customers"] };

describe("reviewPiiColumn", () => {
  it("surfaces a PII column reachable by anon with no encryption", () => {
    expect(reviewPiiColumn(exposedEmail, facts)?.column).toBe("public.customers.email");
  });

  it("clears a sensitive column in an unexposed schema", () => {
    expect(reviewPiiColumn(protectedSsn, facts)).toBeNull();
  });

  it("clears an exposed column that is encrypted at rest", () => {
    expect(reviewPiiColumn(encryptedExposedPan, facts)).toBeNull();
  });
});

describe("piiProtectionFindings", () => {
  it("emits a review-tier finding only for the unprotected exposed column", () => {
    const findings = piiProtectionFindings([exposedEmail, protectedSsn, encryptedExposedPan], facts);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("public.customers.email");
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.severity).toBe("Medium");
  });
});
