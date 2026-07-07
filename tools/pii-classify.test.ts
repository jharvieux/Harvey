import { describe, expect, it } from "vitest";
import { classifyColumn } from "./pii-classify.mjs";

describe("classifyColumn", () => {
  it("matches high-confidence PII columns", () => {
    expect(classifyColumn("email")).toEqual({ infotype: "EMAIL", category: "PII", confidence: "high" });
    expect(classifyColumn("customer_ssn")).toEqual({
      infotype: "US_SSN",
      category: "SENSITIVE_PII",
      confidence: "high",
    });
    expect(classifyColumn("date_of_birth")).toEqual({ infotype: "DOB", category: "PII", confidence: "high" });
    expect(classifyColumn("card_last4")).toEqual({ infotype: "CARD", category: "PCI", confidence: "high" });
  });

  it("flags ambiguous name columns as low confidence rather than asserting PII", () => {
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
