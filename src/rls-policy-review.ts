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

// A clause that admits every row — `(true)`, allowing parens/whitespace. Postgres normalises the
// live clause to "true", and migration text is nearly always as literal. Used for both WITH CHECK
// (writes accept anything) and USING (every existing row is in scope).
const CLAUSE_TRUE = /^\s*\(*\s*true\s*\)*\s*$/i;

// USING gates which EXISTING rows the caller reaches. INSERT is absent because it has no USING at
// all — Postgres rejects one ("only WITH CHECK expression allowed for INSERT").
const USING_GATED_CMDS = new Set(["SELECT", "UPDATE", "DELETE", "ALL"]);

function refsWord(clause: string | null, word: string): boolean {
  return clause != null && new RegExp(`\\b${word}\\b`, "i").test(clause);
}

// A predicate binding a row value directly to the caller — `<expr> = auth.uid()`, allowing a
// `(select auth.uid())` wrapper or the reverse order. Genuine owner-level isolation. The bound
// side may be a plain column OR an expression over one, e.g. Supabase's standard per-user storage
// pattern `(storage.foldername(name))[1] = auth.uid()::text` — hence the `)`/`]` terminators.
const OWNER_BINDING = /[\w.)\]]+\s*=\s*\(?\s*(?:select\s+)?auth\.uid\s*\(\)|auth\.uid\s*\(\)\s*(?:as\s+\w+\s*)?\)?(?:::\w+)?\s*=\s*[\w.)\]]+/i;

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

// `WITH CHECK (true)` on a write policy accepts ANY row the caller submits, whatever the tenancy
// model — so this runs in both modes (#256). It is the b16 P-STORAGE-UPLOAD-CHECK-TRUE shape, and
// crucially it needs no USING to be reachable: the mode rules above only fire when USING or the
// check references the tenant key / binds the owner, so a no-USING policy fell through clean.
//
// Deliberately last in each mode: a policy whose USING *is* scoped but whose check is `true` is
// already reported by the weaker-than-USING rules, whose wording names that specific defect.
function checkTrueReview(policy: LivePolicy, name: string, isWrite: boolean): PolicyReview | null {
  if (!isWrite || policy.withCheck === null || !CLAUSE_TRUE.test(policy.withCheck)) return null;
  return {
    policy: name,
    reason: `WITH CHECK is "true" — the policy accepts any row the caller submits, so writes are not constrained to the caller's own tenant or rows.`,
    cmd: policy.cmd,
    qual: policy.qual,
    withCheck: policy.withCheck,
  };
}

// `USING (true)` puts every existing row in scope for a command that gates row visibility, so a
// SELECT policy with it publishes the whole table to every role the policy applies to — anon
// included. It is the RLS-USING-TRUE calibration plant and the read-side mirror of checkTrueReview.
//
// Scoped DELIBERATELY to per-tenant tables, and that scoping is the rule, not a caveat. `USING
// (true)` is mechanically unambiguous about its EFFECT (all rows) but says nothing about INTENT: a
// published catalog or a lookup table is world-readable on purpose, and no amount of reading the
// clause distinguishes it from a leak. The one static fact that does is the table's own schema — a
// table declaring a tenant key asserts its rows belong to a tenant, so "every tenant reads every
// row" contradicts the table's own declaration. A per-user/undeclared table (the shape a reference
// table takes) has no such contradiction to point at, so we do not guess; that call needs the
// semantic tier. This costs recall on a genuinely leaky reference-shaped table — the deliberate
// trade, since a rule that flags every `USING (true)` trains users to ignore findings.
//
// Review tier like every rule here: the table may be intentionally public despite its tenant
// column (a shared catalog that merely records an owner), which only a human can settle.
//
// Ordered last with checkTrueReview and for the same reason: a policy whose USING is `true` AND
// whose WITH CHECK is weaker is better described by the rules above, which name that defect.
function usingTrueReview(policy: LivePolicy, name: string, model: TenancyModel): PolicyReview | null {
  if ((model.mode ?? "per-tenant") === "per-user") return null;
  if (!USING_GATED_CMDS.has(policy.cmd.toUpperCase())) return null;
  if (policy.qual === null || !CLAUSE_TRUE.test(policy.qual)) return null;
  const reads = policy.cmd.toUpperCase() === "SELECT" || policy.cmd.toUpperCase() === "ALL";
  return {
    policy: name,
    reason:
      `USING is "true" — the policy puts every row of a table that declares the tenant key "${model.tenantKey}" in scope, ` +
      (reads
        ? `so every caller the policy applies to (including anon, unless a role restriction narrows it) reads every tenant's rows.`
        : `so every caller the policy applies to can ${policy.cmd.toUpperCase()} any tenant's rows, not just their own.`),
    cmd: policy.cmd,
    qual: policy.qual,
    withCheck: policy.withCheck,
  };
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
    return checkTrueReview(policy, name, isWrite);
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

  return checkTrueReview(policy, name, isWrite) ?? usingTrueReview(policy, name, model);
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
