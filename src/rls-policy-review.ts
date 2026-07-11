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
  // "tenant_id" or "org_id". Unused in per-user mode.
  tenantKey: string;
  // "per-tenant" (default): rows belong to a tenant identified by tenantKey. "per-user": rows are
  // owned by the individual caller (auth.uid()) and may key on a different column per table, so a
  // row bound to auth.uid() is the isolation boundary rather than a single tenant column (#206).
  mode?: "per-tenant" | "per-user";
}

const CALLER_REF = /auth\.(uid|jwt|role)\s*\(\)|current_setting\s*\(/i;
const WRITE_CMDS = new Set(["INSERT", "UPDATE", "ALL"]);

function refsWord(clause: string | null, word: string): boolean {
  return clause != null && new RegExp(`\\b${word}\\b`, "i").test(clause);
}

// A predicate binding a row column directly to the caller — `<col> = auth.uid()`, allowing a
// `(select auth.uid())` wrapper or the reverse order. Genuine owner-level isolation.
const OWNER_BINDING = /[\w.]+\s*=\s*\(?\s*(?:select\s+)?auth\.uid\s*\(\)|auth\.uid\s*\(\)\s*(?:as\s+\w+\s*)?\)?\s*=\s*[\w.]+/i;

function ownerBound(clause: string | null): boolean {
  return clause != null && OWNER_BINDING.test(clause);
}

interface PolicyReview {
  policy: string;
  reason: string;
  cmd: string;
  qual: string | null;
  withCheck: string | null;
}

export function reviewPolicy(policy: LivePolicy, model: TenancyModel): PolicyReview | null {
  const name = `${policy.schema}.${policy.table}.${policy.name}`;
  const callerRef = (policy.qual != null && CALLER_REF.test(policy.qual)) || (policy.withCheck != null && CALLER_REF.test(policy.withCheck));
  const isWrite = WRITE_CMDS.has(policy.cmd.toUpperCase());
  const raw = { cmd: policy.cmd, qual: policy.qual, withCheck: policy.withCheck };

  // Per-user apps isolate by the individual caller, keyed on different columns per table — there is
  // no single tenant column. A row bound to auth.uid() IS the boundary; only an indirect/unscoped
  // caller reference, or a write whose WITH CHECK drops the binding, is suspect (#206).
  if ((model.mode ?? "per-tenant") === "per-user") {
    const usingBound = ownerBound(policy.qual);
    const checkBound = ownerBound(policy.withCheck);
    if (callerRef && !usingBound && !checkBound) {
      return {
        policy: name,
        reason: `Policy references the caller (auth.uid()/current_setting) but never binds a row column to auth.uid() — ownership is indirect or unscoped; confirm it restricts rows to the calling user.`,
        ...raw,
      };
    }
    if (isWrite && usingBound && policy.withCheck != null && !checkBound) {
      return {
        policy: name,
        reason: `USING binds the row to auth.uid() but WITH CHECK does not — writes aren't owner-constrained and may create rows owned by another user.`,
        ...raw,
      };
    }
    return null;
  }

  const key = model.tenantKey;
  const qualKey = refsWord(policy.qual, key);
  const checkKey = refsWord(policy.withCheck, key);

  if (callerRef && !qualKey && !checkKey) {
    return {
      policy: name,
      reason: `Policy scopes by a caller-identity function but never references the tenant key "${key}" — it may isolate on the wrong column (per-user where per-tenant is required, or vice-versa).`,
      ...raw,
    };
  }

  if (isWrite && qualKey && policy.withCheck != null && !checkKey) {
    return {
      policy: name,
      reason: `USING constrains by the tenant key "${key}" but WITH CHECK does not — writes aren't tenant-constrained and may land rows in another tenant.`,
      ...raw,
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
        evidence: `${r.reason} Live clauses — ${r.cmd} USING: ${r.qual ?? "(none)"}; WITH CHECK: ${r.withCheck ?? "(none)"}.`,
        question: `Does this policy restrict every row it exposes/accepts to the caller's own tenant under the declared tenancy model (tenant key "${model.tenantKey}")?`,
        impact: "A policy that keys on the wrong column or under-constrains writes lets one tenant read or write another tenant's rows even though RLS is enabled.",
        fix: `Compare the tenant key "${model.tenantKey}" against the caller's verified tenant (e.g. a JWT claim) in both USING and WITH CHECK, and make WITH CHECK at least as strict as USING.`,
        okWhen: "The policy already constrains every exposed/accepted row to the caller's own tenant, and the column it keys on is genuinely the tenant boundary.",
        notOkWhen: "The policy keys on a non-tenant column, or its WITH CHECK is weaker than its USING, so cross-tenant reads or writes slip through.",
      }),
    );
}
