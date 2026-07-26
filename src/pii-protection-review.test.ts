import { describe, expect, it } from "vitest";
import { validateFindings } from "./findings.js";
import { piiProtectionFindings, piiProtectionScope, reviewPiiColumn, type ClassifiedColumn, type ExposureFacts } from "./pii-protection-review.js";

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

// #1043 — the sold claim is "PII protection verified in production". These pin the two halves that
// make it true: a verdict when the connected tier gathered the facts, and an explicit not-assessed
// row when it did not. A run that produced NEITHER is the defect (M10 reported ran/partial and the
// deliverable implied a protection verdict it never made).
describe("piiProtectionScope", () => {
  it("states protection was NOT verified, with the reason, when no live facts were gathered", () => {
    const row = piiProtectionScope({ assessed: false, reason: "no live DB on this run" });
    expect(row.id).toBe("M10-PROT-00");
    expect(row.title).toContain("NOT verified");
    expect(row.evidence).toContain("no live DB on this run");
    // A not-assessed row that doesn't say how to falsify it is a permanent blocker.
    expect(row.impact).toContain("Falsifier");
  });

  it("records the verdict AND its limits when the connected tier did gather the facts", () => {
    const row = piiProtectionScope({ assessed: true, detail: "Read 4 public table(s).", columnsChecked: 7, unprotected: 2 });
    expect(row.title).toContain("7 classified column(s) checked, 2 unprotected");
    // The limits are the point: a verdict naming only what it found reads as a clean bill of health.
    expect(row.impact).toContain("application-layer encryption");
  });

  it("emits rows the report schema accepts", () => {
    const findings = [piiProtectionScope({ assessed: false, reason: "no live DB" }), ...piiProtectionFindings([exposedEmail], facts)];
    const doc = {
      meta: { client: "c", subtitle: "s", date: "d", commit: "abc", auditor: "a", confidential: true, overallHealth: 5, tenantIsolation: "t", authModel: "m", headline: "h", scope: "s", methodology: "m", outOfScope: "o" },
      findings,
    };
    expect(validateFindings(doc)).toEqual({ ok: true, errors: [] });
  });
});
