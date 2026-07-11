// M1 connected [LLM] — semantic review of LIVE RLS policy bodies (#199). The mechanical lints
// catch disabled / no-policy / USING(true) / user-metadata policies, but not a policy that is
// syntactically fine and SEMANTICALLY wrong: keys on the caller's identity where it should key on
// the tenant, or a WITH CHECK weaker than its USING. This pass reads the live pg_policies USING /
// WITH CHECK clauses against a declared tenancy model, clears the provably tenant-scoped ones, and
// surfaces the rest for review. Pure transform: src/cli/detect-deeper.ts does the live pull.

import type { Finding } from "./findings.js";
import { reviewFinding } from "./review-tier.js";

export interface LivePolicy {
  schema: string;
  table: string;
  name: string;
  cmd: string; // SELECT / INSERT / UPDATE / DELETE / ALL
  qual: string | null; // USING expression
  withCheck: string | null; // WITH CHECK expression
}

export interface TenancyModel {
  // The column that scopes a row to its tenant (from the threat model / M10 tenant key), e.g.
  // "tenant_id" or "org_id".
  tenantKey: string;
}

const CALLER_REF = /auth\.(uid|jwt|role)\s*\(\)|current_setting\s*\(/i;
const WRITE_CMDS = new Set(["INSERT", "UPDATE", "ALL"]);

function refsWord(clause: string | null, word: string): boolean {
  return clause != null && new RegExp(`\\b${word}\\b`, "i").test(clause);
}

interface PolicyReview {
  policy: string;
  reason: string;
}

export function reviewPolicy(policy: LivePolicy, model: TenancyModel): PolicyReview | null {
  const name = `${policy.schema}.${policy.table}.${policy.name}`;
  const key = model.tenantKey;
  const qualKey = refsWord(policy.qual, key);
  const checkKey = refsWord(policy.withCheck, key);
  const callerRef = (policy.qual != null && CALLER_REF.test(policy.qual)) || (policy.withCheck != null && CALLER_REF.test(policy.withCheck));
  const isWrite = WRITE_CMDS.has(policy.cmd.toUpperCase());

  if (callerRef && !qualKey && !checkKey) {
    return {
      policy: name,
      reason: `Policy scopes by a caller-identity function but never references the tenant key "${key}" — it may isolate on the wrong column (per-user where per-tenant is required, or vice-versa).`,
    };
  }

  if (isWrite && qualKey && policy.withCheck != null && !checkKey) {
    return {
      policy: name,
      reason: `USING constrains by the tenant key "${key}" but WITH CHECK does not — writes aren't tenant-constrained and may land rows in another tenant.`,
    };
  }

  return null;
}

export function policyReviewFindings(policies: LivePolicy[], model: TenancyModel): Finding[] {
  return policies
    .map((p) => reviewPolicy(p, model))
    .filter((r): r is PolicyReview => r !== null)
    .map((r, i) =>
      reviewFinding({
        id: `M1-RLS-${String(i + 1).padStart(2, "0")}`,
        title: `RLS policy ${r.policy} — semantic tenancy review`,
        severity: "High",
        category: "Multi-tenant security",
        taxonomy: "M1 — Multi-tenant security",
        location: r.policy,
        evidence: r.reason,
        question: `Does this policy restrict every row it exposes/accepts to the caller's own tenant under the declared tenancy model (tenant key "${model.tenantKey}")?`,
        impact: "A policy that keys on the wrong column or under-constrains writes lets one tenant read or write another tenant's rows even though RLS is enabled.",
        fix: `Compare the tenant key "${model.tenantKey}" against the caller's verified tenant (e.g. a JWT claim) in both USING and WITH CHECK, and make WITH CHECK at least as strict as USING.`,
        okWhen: "The policy already constrains every exposed/accepted row to the caller's own tenant, and the column it keys on is genuinely the tenant boundary.",
        notOkWhen: "The policy keys on a non-tenant column, or its WITH CHECK is weaker than its USING, so cross-tenant reads or writes slip through.",
      }),
    );
}
