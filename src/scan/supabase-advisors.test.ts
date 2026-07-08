import { describe, expect, it } from "vitest";
import { parseAdvisorFindings, type AdvisorsResponse } from "./supabase-advisors.js";

// Fixture shape matches a live get_advisors(type: "security") response.
const FIXTURE: AdvisorsResponse = {
  lints: [
    {
      name: "rls_disabled_in_public",
      title: "RLS Disabled in Public",
      level: "ERROR",
      facing: "EXTERNAL",
      categories: ["SECURITY"],
      description: "Detects cases where RLS has not been enabled on a table in the public schema.",
      detail: "Table `public.orders` is public, but RLS has not been enabled.",
      remediation: "https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public",
      metadata: { name: "orders", type: "table", schema: "public" },
      cache_key: "rls_disabled_in_public_public_orders",
    },
    {
      name: "rls_enabled_no_policy",
      title: "RLS Enabled No Policy",
      level: "INFO",
      metadata: { name: "reports", type: "table", schema: "public" },
      cache_key: "rls_enabled_no_policy_public_reports",
    },
    {
      name: "some_future_lint_not_in_our_curated_map",
      title: "Some Future Lint",
      level: "WARN",
      metadata: { name: "widgets", type: "table", schema: "public" },
    },
  ],
};

describe("parseAdvisorFindings", () => {
  it("marks every advisor hit as mechanical + high precision — advisor-sourced is ground truth", () => {
    const findings = parseAdvisorFindings(FIXTURE);
    expect(findings.every((f) => f.mechanical && f.precisionTier === "high")).toBe(true);
  });

  it("escalates rls_disabled_in_public to Critical regardless of Supabase's own ERROR level", () => {
    const findings = parseAdvisorFindings(FIXTURE);
    expect(findings[0]?.severity).toBe("Critical");
    expect(findings[0]?.location).toBe("public.orders");
  });

  it("falls back to the level-based severity for lints outside the curated map", () => {
    const findings = parseAdvisorFindings(FIXTURE);
    expect(findings[2]?.severity).toBe("Medium"); // WARN → Medium
  });

  it("builds a stable id from cache_key when present, and from name+index otherwise", () => {
    const findings = parseAdvisorFindings(FIXTURE);
    expect(findings[0]?.id).toBe("SB-ADV-rls_disabled_in_public_public_orders");
    expect(findings[2]?.id).toBe("SB-ADV-some_future_lint_not_in_our_curated_map-3");
  });
});
