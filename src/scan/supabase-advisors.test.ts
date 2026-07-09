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

// Batch B8 (#71) — recorded advisor JSON for the 6 additional Supabase Advisor security lints
// named in the B8 spec (rls_disabled_in_public/rls_enabled_no_policy are already covered by
// FIXTURE above). Shape mirrors a live get_advisors(type: "security") response, fixtured against
// the fixtures planted in targets/calibration/supabase/migrations/20260709000004_b8_connected_
// advisors.sql — no live project was queried (offline batch, see GROUND-TRUTH.md §"Batch B8").
const B8_FIXTURE: AdvisorsResponse = {
  lints: [
    {
      name: "auth_users_exposed",
      title: "Auth Users Exposed",
      level: "ERROR",
      description: "Detects if auth.users is exposed to anon or authenticated roles via a view or materialized view in the public schema.",
      detail: "View `public.user_directory` exposes `auth.users` to anon/authenticated.",
      metadata: { name: "user_directory", type: "view", schema: "public" },
      cache_key: "auth_users_exposed_public_user_directory",
    },
    {
      name: "security_definer_view",
      title: "Security Definer View",
      level: "ERROR",
      detail: "View `public.tenant_totals` is a SECURITY DEFINER view.",
      metadata: { name: "tenant_totals", type: "view", schema: "public" },
      cache_key: "security_definer_view_public_tenant_totals",
    },
    {
      name: "function_search_path_mutable",
      title: "Function Search Path Mutable",
      level: "WARN",
      detail: "Function `public.get_invoice_total` has a mutable search_path.",
      metadata: { name: "get_invoice_total", type: "function", schema: "public" },
      cache_key: "function_search_path_mutable_public_get_invoice_total",
    },
    {
      name: "rls_references_user_metadata",
      title: "RLS References User Metadata",
      level: "WARN",
      detail: "Policy on `public.internal_notes` references `user_metadata`.",
      metadata: { name: "internal_notes", type: "table", schema: "public" },
      cache_key: "rls_references_user_metadata_public_internal_notes",
    },
    {
      name: "sensitive_columns_exposed",
      title: "Sensitive Columns Exposed",
      level: "WARN",
      detail: "Table `public.support_tickets` exposes column `customer_ssn`.",
      metadata: { name: "support_tickets", type: "table", schema: "public" },
      cache_key: "sensitive_columns_exposed_public_support_tickets",
    },
    {
      name: "rls_enabled_no_policy",
      title: "RLS Enabled No Policy",
      level: "INFO",
      detail: "Table `public.reports` has RLS enabled but no policies exist.",
      metadata: { name: "reports", type: "table", schema: "public" },
      cache_key: "rls_enabled_no_policy_public_reports",
    },
  ],
};

describe("parseAdvisorFindings — Batch B8 connected-tier lint set", () => {
  it("curates each B8 lint to the CURATED_SEVERITY the connected-tier calibration entries expect", () => {
    const findings = parseAdvisorFindings(B8_FIXTURE);
    const severityByName = Object.fromEntries(findings.map((f, i) => [B8_FIXTURE.lints[i]?.name, f.severity]));
    expect(severityByName).toEqual({
      auth_users_exposed: "Critical",
      security_definer_view: "High",
      function_search_path_mutable: "Medium",
      rls_references_user_metadata: "High",
      sensitive_columns_exposed: "High",
      rls_enabled_no_policy: "Medium",
    });
  });

  it("locates each finding at its schema-qualified entity name", () => {
    const findings = parseAdvisorFindings(B8_FIXTURE);
    expect(findings.map((f) => f.location)).toEqual([
      "public.user_directory",
      "public.tenant_totals",
      "public.get_invoice_total",
      "public.internal_notes",
      "public.support_tickets",
      "public.reports",
    ]);
  });

  it("marks every B8 lint mechanical + high precision, same as any other advisor hit", () => {
    const findings = parseAdvisorFindings(B8_FIXTURE);
    expect(findings.every((f) => f.mechanical && f.precisionTier === "high")).toBe(true);
  });
});
