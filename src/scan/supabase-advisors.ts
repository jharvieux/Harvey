// Supabase Advisor security lints — the highest-trust mechanical source in the toolchain:
// Advisors run Splinter (Supabase's open-source Postgres linter) against the live schema, so
// results are ground-truth and near-zero-FP (docs/design/mechanical-toolchain.md §6).
//
// Response shape confirmed against a live `get_advisors(type: "security")` call (Supabase
// Management API `GET /v1/projects/{ref}/advisors/security` — verified against the published
// OpenAPI spec at https://api.supabase.com/api/v1-json). See src/scan/supabase.ts for the
// fetch wrapper.

import type { Finding, Severity } from "../findings.js";
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
}

// Severity for the lints the issue calls out by name, curated from the product's blast-radius
// judgment rather than Supabase's own ERROR/WARN/INFO level (e.g. Supabase reports
// rls_disabled_in_public as an error-level lint, but for a multi-tenant audit it's Critical).
const CURATED_SEVERITY: Partial<Record<string, Severity>> = {
  rls_disabled_in_public: "Critical",
  auth_users_exposed: "Critical",
  security_definer_view: "High",
  sensitive_columns_exposed: "High",
  rls_references_user_metadata: "High",
  anon_security_definer_function_executable: "High",
  authenticated_security_definer_function_executable: "Medium",
  function_search_path_mutable: "Medium",
  rls_enabled_no_policy: "Medium",
};

const LEVEL_SEVERITY: Record<AdvisorLint["level"], Severity> = { ERROR: "High", WARN: "Medium", INFO: "Low" };

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

export function parseAdvisorFindings(response: AdvisorsResponse, authMethods?: AuthMethods): Finding[] {
  return response.lints.map((lint, i) => {
    const input = {
      id: `SB-ADV-${lint.cache_key ?? `${lint.name}-${i + 1}`}`,
      title: lint.title,
      severity: CURATED_SEVERITY[lint.name] ?? LEVEL_SEVERITY[lint.level],
      category: "Supabase advisor",
      taxonomy: lint.name,
      location: entityLocation(lint),
      evidence: lint.detail ?? lint.description ?? lint.title,
      impact: lint.description ?? lint.title,
      fix: lint.remediation ?? "See the Supabase database linter docs for this lint.",
      precisionTier: "high" as const,
    };
    const gate = authMethods && AUTH_METHOD_GATED_LINTS[lint.name];
    return mechanicalFinding(gate ? gateOnAuthMethod(input, gate.label, gate.state(authMethods)) : input);
  });
}
