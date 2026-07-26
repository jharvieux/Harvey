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

// #671 — the leaked-password / OTP advisor lints are gated on whether the auth method they protect
// is actually enabled (from the live GoTrue /config/auth external.* flags). ATC (OAuth-only) filed a
// Medium leaked-password protection finding here that was a not-applicable false positive.
const LEAKED_PW_FIXTURE: AdvisorsResponse = {
  lints: [
    {
      name: "auth_leaked_password_protection",
      title: "Leaked Password Protection Disabled",
      level: "WARN",
      description: "Leaked password protection is currently disabled.",
      cache_key: "auth_leaked_password_protection",
    },
    {
      name: "auth_otp_long_expiry",
      title: "OTP Long Expiry",
      level: "WARN",
      cache_key: "auth_otp_long_expiry",
    },
  ],
};

describe("parseAdvisorFindings — #671 auth-method gating", () => {
  it("keeps leaked-password protection a Medium when password (email) auth is enabled", () => {
    const findings = parseAdvisorFindings(LEAKED_PW_FIXTURE, { email: true, phone: false });
    const f = findings.find((x) => x.taxonomy === "auth_leaked_password_protection")!;
    expect(f.severity).toBe("Medium"); // WARN → Medium, un-gated
    expect(f.title).not.toContain("conditional");
  });

  it("reframes leaked-password protection to an Info conditional on an OAuth-only project (email off)", () => {
    const findings = parseAdvisorFindings(LEAKED_PW_FIXTURE, { email: false, phone: false });
    const f = findings.find((x) => x.taxonomy === "auth_leaked_password_protection")!;
    expect(f.severity).toBe("Info");
    expect(f.confidence).toBe("N/A");
    expect(f.title).toContain("conditional");
    // OTP advisor also downgrades when neither email nor phone OTP is in use.
    expect(findings.find((x) => x.taxonomy === "auth_otp_long_expiry")!.severity).toBe("Info");
  });

  it("leaves the advisor asserted when no authMethods signal is supplied (back-compat / local scans)", () => {
    const findings = parseAdvisorFindings(LEAKED_PW_FIXTURE);
    expect(findings.find((x) => x.taxonomy === "auth_leaked_password_protection")!.severity).toBe("Medium");
  });
});

// #1083 — Splinter (local/connected tier) returns SECURITY and PERFORMANCE lints in one pass;
// a PERFORMANCE lint must route through M7's curated profile (src/perf-scan.ts), not be filed as
// a generic "Supabase advisor" Low with a docs-link fix.
const MIXED_CATEGORY_FIXTURE: AdvisorsResponse = {
  lints: [
    {
      name: "unindexed_foreign_keys",
      title: "Unindexed foreign keys",
      level: "INFO",
      facing: "EXTERNAL",
      categories: ["PERFORMANCE"],
      description: "Identifies foreign key constraints without a covering index, which can impact database performance.",
      detail: "Table `public.audit_logs` has a foreign key `audit_logs_tenant_id_fkey` without a covering index.",
      remediation: "https://supabase.com/docs/guides/database/database-linter?lint=0001_unindexed_foreign_keys",
      metadata: { name: "audit_logs", type: "table", schema: "public" },
      cache_key: "unindexed_foreign_keys_public_audit_logs",
    },
    {
      name: "rls_disabled_in_public",
      title: "RLS Disabled in Public",
      level: "ERROR",
      facing: "EXTERNAL",
      categories: ["SECURITY"],
      detail: "Table `public.orders` is public, but RLS has not been enabled.",
      metadata: { name: "orders", type: "table", schema: "public" },
      cache_key: "rls_disabled_in_public_public_orders",
    },
  ],
};

describe("parseAdvisorFindings — #1083 PERFORMANCE lints route through M7's profile", () => {
  it("files a PERFORMANCE-category lint under category Performance with M7's curated impact/fix, not a generic docs-link", () => {
    const findings = parseAdvisorFindings(MIXED_CATEGORY_FIXTURE);
    const perf = findings.find((f) => f.taxonomy === "unindexed_foreign_keys")!;
    expect(perf.category).toBe("Performance");
    expect(perf.severity).toBe("Perf");
    expect(perf.impact).toContain("Sequential scans");
    expect(perf.fix).toContain("covering-index migration");
  });

  it("leaves a SECURITY-category lint filed as a Supabase advisor, unaffected", () => {
    const findings = parseAdvisorFindings(MIXED_CATEGORY_FIXTURE);
    const sec = findings.find((f) => f.taxonomy === "rls_disabled_in_public")!;
    expect(sec.category).toBe("Supabase advisor");
    expect(sec.severity).toBe("Critical");
  });

  it("folds facing (EXTERNAL/INTERNAL) into the evidence text since Finding has no dedicated field for it", () => {
    const findings = parseAdvisorFindings(MIXED_CATEGORY_FIXTURE);
    const perf = findings.find((f) => f.taxonomy === "unindexed_foreign_keys")!;
    expect(perf.evidence).toContain("external-facing");
  });
});
