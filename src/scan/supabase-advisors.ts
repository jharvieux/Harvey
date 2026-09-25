// Supabase Advisor catalog lints. Preserve the observed fact while separating
// configuration inventory from conclusions that require effective authorization.
//
// Response shape confirmed against a live `get_advisors(type: "security")` call (Supabase
// Management API `GET /v1/projects/{ref}/advisors/security` — verified against the published
// OpenAPI spec at https://api.supabase.com/api/v1-json). See src/scan/supabase.ts for the
// fetch wrapper.

import type { Finding, Severity } from "../findings.js";
import { profileFor } from "../perf-scan.js";
import { mechanicalFinding } from "./common.js";
import { eitherEnabled, gateOnAuthMethod, type AuthMethodState, type AuthMethods } from "./supabase-config.js";

export interface AdvisorLint {
  name: string;
  title: string;
  level: "ERROR" | "WARN" | "INFO";
  facing?: string;
  categories?: string[];
  description?: string;
  detail?: string;
  remediation?: string;
  metadata?: { name?: string; type?: string; schema?: string; [key: string]: unknown };
  cache_key?: string;
}

export interface AdvisorsResponse {
  lints: AdvisorLint[];
  // #1264 — local (Splinter/psql) mode only: lint rows the delimited-text parser could not split
  // into their 10 columns, so they are NOT in `lints`. Hosted mode reads JSON and never sets it.
  // Carried so scanLocal can disclose the loss (SB-SPLINTER-00) rather than return a short list.
  unparsedRows?: number;
  // #1755 — local (Splinter/psql) mode only: set when the psql run did NOT complete (a script
  // error under ON_ERROR_STOP, a lost connection, a missing binary). `lints` is always `[]` when
  // this is set — scanLocal must disclose it (SB-SPLINTER-FAIL-00), never read the empty list as
  // a clean result.
  failure?: string;
}

// Severity for the lints the issue calls out by name, curated from the product's blast-radius
// judgment rather than Supabase's own ERROR/WARN/INFO level. RLS and EXECUTE
// configuration inventory is handled separately from demonstrated exposure.
const CURATED_SEVERITY: Partial<Record<string, Severity>> = {
  function_search_path_mutable: "Medium",
};

const LEVEL_SEVERITY: Record<AdvisorLint["level"], Severity> = { ERROR: "High", WARN: "Medium", INFO: "Low" };

// These lints observe one part of authorization. Keep the upstream observation, but
// let the combined catalog assessment establish supported direct table-read paths.
const AUTHORIZATION_REVIEW: Partial<Record<string, string>> = {
  policy_exists_rls_disabled: "Inactive policies do not establish current schema/table/column grants or a reachable client path.",
  rls_policy_always_true: "An unconditional permissive policy can still be constrained by applicable restrictive policies, command applicability and effective grants. This lint alone does not prove unrestricted access.",
  rls_references_user_metadata: "A reference to editable metadata requires expression and caller review; its presence alone does not establish authorization dependence or a reachable row path.",
  sensitive_columns_exposed: "Column-name patterns do not establish sensitive contents. Effective schema usage, grants, RLS and API reachability are assessed separately.",
  security_definer_view: "View predicates, effective owner privileges and underlying RLS context remain unproved by the definer setting alone.",
  auth_users_exposed: "A view dependency and SELECT grant require schema, view predicate and effective owner review before asserting auth-user data exposure.",
  materialized_view_in_api: "A materialized-view grant and advertised schema require effective caller and contents review before asserting data exposure.",
  foreign_table_in_api: "Foreign-table access also depends on effective caller privileges, user mappings and remote authorization; this context remains unproved.",
  insecure_queue_exposed_in_api: "Queue table grants and API schema configuration do not establish the queue function's caller restrictions or effective execution context.",
  public_bucket_allows_listing: "A broad permissive storage policy remains subject to applicable restrictive policies, grants and the storage caller context; listing access is not proved by this lint alone.",
};

function entityLocation(lint: AdvisorLint): string {
  const { schema, name } = lint.metadata ?? {};
  if (schema && name) return `${schema}.${name}`;
  if (name) return name;
  return "project-level";
}

// #671 — advisor lints that only apply to a specific auth method, and how to read that method's
// enablement from AuthMethods. When the connected scan supplies authMethods (derived from the live
// GoTrue /config/auth), an inapplicable one of these (e.g. auth_leaked_password_protection on an
// OAuth-only project) is reframed to an Info conditional instead of an asserted Medium.
const AUTH_METHOD_GATED_LINTS: Record<string, { label: string; state: (m: AuthMethods) => AuthMethodState }> = {
  auth_leaked_password_protection: { label: "password authentication", state: (m) => m.email },
  auth_otp_long_expiry: { label: "email or SMS OTP", state: (m) => eitherEnabled(m.email, m.phone) },
  auth_otp_short: { label: "email or SMS OTP", state: (m) => eitherEnabled(m.email, m.phone) },
};

// #1083 — Splinter (the local/connected tier's source, src/scan/supabase-splinter.ts) returns
// SECURITY and PERFORMANCE lints together in one pass; a PERFORMANCE lint (unindexed_foreign_keys,
// auth_rls_initplan, unused_index, …) used to be filed here as a generic "Supabase advisor" Low
// with only a docs-link fix, instead of M7's curated impact/fix text. Route it through the SAME
// profile the hosted M7 advisor pull uses (src/perf-scan.ts#profileFor) — one source of truth for
// what these rules mean, not a second copy that drifts. `facing` (EXTERNAL vs INTERNAL) is folded
// into the evidence text since Finding carries no dedicated field for it.
export function parseAdvisorFindings(response: AdvisorsResponse, authMethods?: AuthMethods): Finding[] {
  return response.lints.map((lint, i) => {
    const id = `SB-ADV-${lint.cache_key ?? `${lint.name}-${i + 1}`}`;
    const location = entityLocation(lint);
    const detail = lint.detail ?? lint.description ?? lint.title;
    const evidence = lint.facing ? `${detail} (${lint.facing.toLowerCase()}-facing)` : detail;
    if (lint.name === "rls_enabled_no_policy" || lint.name === "rls_disabled_in_public") {
      const enabled = lint.name === "rls_enabled_no_policy";
      return mechanicalFinding({
        id, location, title: `${lint.title} — authorization inventory`, severity: "Info", category: "Supabase advisor", taxonomy: lint.name,
        evidence: `${evidence} ${enabled ? "Enabled RLS with no applicable permissive policy denies normal row access for non-owner, non-superuser, non-BYPASSRLS roles." : "Disabled RLS alone does not establish a current grant or reachable client path."}`,
        impact: "This is RLS configuration inventory. Current schema/table/column grants, effective roles, ownership and definer context determine access; the effective-authorization rows assess those facts separately.",
        fix: "Review the effective-authorization findings; preserve intentional deny-by-default tables and narrow any unintended current access.", precisionTier: "review",
      });
    }
    if (["anon_security_definer_function_executable", "authenticated_security_definer_function_executable"].includes(lint.name)) {
      return mechanicalFinding({
        id, location, title: `${lint.title} — caller authorization needs review`, severity: "Info", category: "Supabase advisor", taxonomy: lint.name,
        evidence: `${evidence} EXECUTE permission is catalog evidence, not proof that caller restrictions are absent or effective.`,
        impact: "Review the function's effective owner, grants and body. A definer can use a different RLS context from its caller; caller restrictions remain unproved by this lint.",
        fix: "Review and test allowed and disallowed callers against the definer body and owner context.", precisionTier: "review",
      });
    }
    const authorizationReview = AUTHORIZATION_REVIEW[lint.name];
    if (authorizationReview) {
      return mechanicalFinding({
        id, location, title: `Authorization review for ${location} (${lint.name})`, severity: "Info", category: "Supabase advisor", taxonomy: lint.name,
        evidence: `Advisor observation, not an effective-access verdict: ${evidence} Assessment boundary: ${authorizationReview}`,
        impact: "This catalog observation remains review evidence. The effective-authorization findings distinguish supported direct reads from denied or unproved access; this row provides no exposure or isolation clearance.",
        fix: "Review this observation with the combined role/grant/RLS assessment and test the relevant caller path.", precisionTier: "review",
      });
    }
    if (lint.categories?.includes("PERFORMANCE")) {
      const profile = profileFor({ name: lint.name, title: lint.title, level: lint.level, detail, description: lint.description, remediation: lint.remediation, metadata: lint.metadata, cache_key: lint.cache_key });
      // taxonomy stays lint.name (not profile.taxonomy) — same convention as the SECURITY branch
      // below, one Finding per lint keyed by its rule name; profile.taxonomy is M7's own GROUPED
      // label (perf-scan.ts rolls many lints of the same name into one Finding, this does not).
      return mechanicalFinding({
        id,
        title: lint.title,
        severity: profile.severity,
        category: "Performance",
        taxonomy: lint.name,
        location,
        evidence,
        impact: profile.impact,
        fix: profile.fix,
        precisionTier: "high",
      });
    }
    const input = {
      id,
      title: lint.title,
      severity: CURATED_SEVERITY[lint.name] ?? LEVEL_SEVERITY[lint.level],
      category: "Supabase advisor",
      taxonomy: lint.name,
      location,
      evidence,
      impact: lint.description ?? lint.title,
      fix: lint.remediation ?? "See the Supabase database linter docs for this lint.",
      precisionTier: "high" as const,
    };
    const gate = authMethods && AUTH_METHOD_GATED_LINTS[lint.name];
    return mechanicalFinding(gate ? gateOnAuthMethod(input, gate.label, gate.state(authMethods)) : input);
  });
}
