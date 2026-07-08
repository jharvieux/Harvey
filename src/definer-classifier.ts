// M1 DETECT DEEPER — SECURITY DEFINER body classifier (docs/scan-extras.txt).
// Turns "SECURITY DEFINER exposed to anon/authenticated, confirm intent" into a
// verdict per function by reading the actual body instead of stopping at the
// advisor's summary. Pure transform: src/cli/detect-deeper.ts does the live
// pg_get_functiondef query.

import type { Finding } from "./findings.js";

export type Verdict = "ok" | "flag" | "ambiguous";

export interface DefinerFunction {
  schema: string;
  name: string;
  /** Parameter names as declared, e.g. from pg_proc.proargnames. */
  argNames: string[];
  /** Roles with EXECUTE granted — only anon/authenticated make this reachable by a client. */
  exposedTo: string[];
  /** The function body text (from pg_get_functiondef), not the full CREATE statement. */
  body: string;
}

export interface DefinerVerdict {
  function: string;
  verdict: Verdict;
  reason: string;
  exposedTo: string[];
}

const CLIENT_ROLES = new Set(["anon", "authenticated"]);
const DYNAMIC_SQL = /\bexecute\b/i;
const AUTH_REF = /auth\.(uid|jwt)\s*\(\s*\)/i;
// auth.uid()/auth.jwt() on either side of a comparison operator — the shape a
// caller-scoping predicate actually takes (`user_id = auth.uid()`, `auth.jwt()->>'org' = org_id`).
const AUTH_COMPARISON = /(=|<>|!=|in\s*\()\s*auth\.(uid|jwt)\s*\(\)|auth\.(uid|jwt)\s*\(\)\s*(->>?\s*'[^']*'\s*)?(=|<>|!=|::)/i;
const ID_PARAM = /(^id$|_id$|tenant|conversation|account|^org$|org_id)/i;

function qualifiedName(fn: Pick<DefinerFunction, "schema" | "name">): string {
  return `${fn.schema}.${fn.name}`;
}

function paramUsedInBody(body: string, param: string): boolean {
  return new RegExp(`\\b${param}\\b`, "i").test(body);
}

export function classifyDefinerFunction(fn: DefinerFunction): DefinerVerdict {
  const exposedTo = fn.exposedTo.filter((r) => CLIENT_ROLES.has(r));
  const name = qualifiedName(fn);

  if (exposedTo.length === 0) {
    return { function: name, verdict: "ok", exposedTo, reason: "Not EXECUTE-granted to anon/authenticated — not client-callable." };
  }

  if (DYNAMIC_SQL.test(fn.body)) {
    return {
      function: name,
      verdict: "ambiguous",
      exposedTo,
      reason: "Body builds/executes dynamic SQL — static analysis can't confirm the constructed query is caller-scoped; needs manual review.",
    };
  }

  if (AUTH_COMPARISON.test(fn.body)) {
    return {
      function: name,
      verdict: "ok",
      exposedTo,
      reason: "auth.uid()/auth.jwt() appears in a comparison — the query is constrained by the calling user.",
    };
  }

  const idParams = fn.argNames.filter((p) => ID_PARAM.test(p));
  const usedIdParams = idParams.filter((p) => paramUsedInBody(fn.body, p));
  if (usedIdParams.length > 0) {
    return {
      function: name,
      verdict: "flag",
      exposedTo,
      reason: `Takes id parameter(s) ${usedIdParams.join(", ")} and uses them in the query with no caller (auth.uid()/auth.jwt()) constraint — returns data for arbitrary IDs.`,
    };
  }

  if (AUTH_REF.test(fn.body)) {
    return {
      function: name,
      verdict: "ambiguous",
      exposedTo,
      reason: "References auth.uid()/auth.jwt() but not in a recognizable comparison — can't confirm the query is actually constrained by it.",
    };
  }

  return {
    function: name,
    verdict: "ambiguous",
    exposedTo,
    reason: "No id parameter and no caller-auth reference detected in the body — can't determine caller-scoping statically.",
  };
}

export function classifyDefinerFunctions(fns: DefinerFunction[]): DefinerVerdict[] {
  return fns.map(classifyDefinerFunction);
}

export function definerFindings(verdicts: DefinerVerdict[]): Finding[] {
  return verdicts
    .filter((v) => v.verdict === "flag")
    .map((v, i): Finding => ({
      id: `M1-DEF-${String(i + 1).padStart(2, "0")}`,
      title: `SECURITY DEFINER ${v.function} exposes arbitrary-ID data`,
      severity: "High",
      confidence: "Likely",
      category: "Multi-tenant security",
      taxonomy: "M1 — Multi-tenant security",
      location: v.function,
      status: "Open",
      evidence: v.reason,
      impact: `Callable by ${v.exposedTo.join(", ")} — any authenticated caller can pass an arbitrary id and read another tenant/user's row.`,
      fix: "Add a caller-scoping predicate (auth.uid()/auth.jwt()) to the query, or REVOKE EXECUTE from anon/authenticated if the function isn't meant to be client-callable (check RLS policies don't depend on it first).",
      value: 5,
      ease: 3,
      safety: 3,
      notOkWhen: "The function returns or mutates rows for the passed id without also checking that id belongs to the calling user/tenant.",
      okWhen: "The query additionally constrains by auth.uid()/auth.jwt(), or the id parameter is only ever the caller's own (enforced elsewhere and provably unspoofable).",
    }));
}
