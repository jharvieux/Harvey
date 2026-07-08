// M1 DETECT DEEPER — RLS-no-policy grant classifier (docs/scan-extras.txt).
// Turns "RLS enabled, zero policies, confirm intent" into a verdict per table by
// cross-referencing role_table_grants against whether client code (vs. only
// service-role) reads the table. Pure transform: src/cli/detect-deeper.ts does
// the live information_schema/pg_policies query.

import type { Finding } from "./findings.js";

export type Verdict = "ok" | "flag" | "ambiguous";

export interface GrantRow {
  grantee: string;
  privilege: string;
}

export interface NoPolicyTable {
  schema: string;
  table: string;
  grants: GrantRow[];
  /** Does the client's own (non-service-role) code query this table? Caller-supplied
   *  from a static grep of the client repo — DB introspection alone can't tell. */
  queriedByClientCode: boolean;
}

export interface TableVerdict {
  table: string;
  verdict: Verdict;
  reason: string;
  clientSelectGrant: boolean;
  /** Over-broad TRUNCATE/REFERENCES grants to anon/authenticated — bonus check, independent of the main verdict. */
  overBroadGrants: string[];
}

const CLIENT_ROLES = new Set(["anon", "authenticated"]);
const OVERBROAD_PRIVILEGES = new Set(["TRUNCATE", "REFERENCES"]);

function qualifiedName(t: Pick<NoPolicyTable, "schema" | "table">): string {
  return `${t.schema}.${t.table}`;
}

function hasClientSelectGrant(grants: GrantRow[]): boolean {
  return grants.some((g) => CLIENT_ROLES.has(g.grantee) && g.privilege === "SELECT");
}

function findOverBroadGrants(grants: GrantRow[]): string[] {
  return grants
    .filter((g) => CLIENT_ROLES.has(g.grantee) && OVERBROAD_PRIVILEGES.has(g.privilege))
    .map((g) => `${g.grantee}: ${g.privilege}`);
}

export function classifyNoPolicyTable(t: NoPolicyTable): TableVerdict {
  const table = qualifiedName(t);
  const clientSelectGrant = hasClientSelectGrant(t.grants);
  const overBroadGrants = findOverBroadGrants(t.grants);

  if (!clientSelectGrant) {
    return {
      table,
      verdict: "ok",
      reason: "No anon/authenticated SELECT grant — deny-all by design; only service-role can read this table.",
      clientSelectGrant,
      overBroadGrants,
    };
  }

  if (t.queriedByClientCode) {
    return {
      table,
      verdict: "flag",
      reason: "anon/authenticated has a SELECT grant and client code queries this table, but no RLS policy exists — the read is silently returning zero rows (policy missing, not a working feature).",
      clientSelectGrant,
      overBroadGrants,
    };
  }

  return {
    table,
    verdict: "flag",
    reason: "anon/authenticated has a SELECT grant but no client code queries this table and no policy exists — vestigial grant; either revoke it or add the intended policy.",
    clientSelectGrant,
    overBroadGrants,
  };
}

export function classifyNoPolicyTables(tables: NoPolicyTable[]): TableVerdict[] {
  return tables.map(classifyNoPolicyTable);
}

export function grantFindings(verdicts: TableVerdict[]): Finding[] {
  const findings: Finding[] = [];
  let n = 0;

  for (const v of verdicts) {
    if (v.verdict === "flag") {
      n += 1;
      findings.push({
        id: `M1-GRANT-${String(n).padStart(2, "0")}`,
        title: `RLS-enabled, no policy: ${v.table} grant/policy mismatch`,
        severity: "Medium",
        confidence: "Review",
        category: "Multi-tenant security",
        taxonomy: "M1 — Multi-tenant security",
        location: v.table,
        status: "Open",
        evidence: v.reason,
        impact: "RLS with no policy denies all reads regardless of grants — this isn't a data leak, but it signals either a dead permission or a client feature that's silently broken.",
        fix: "If the table should be client-readable, add the missing SELECT policy. If not, REVOKE the anon/authenticated grant.",
        value: 3,
        ease: 4,
        safety: 4,
        okWhen: "The grant is a known leftover and no client feature depends on reading this table directly.",
        notOkWhen: "A client feature expects to read this table via PostgREST/supabase-js and is getting empty results because the policy is missing.",
      });
    }
  }

  for (const v of verdicts) {
    if (v.overBroadGrants.length === 0) continue;
    n += 1;
    findings.push({
      id: `M1-GRANT-${String(n).padStart(2, "0")}`,
      title: `Over-broad grant on ${v.table}`,
      severity: "Low",
      confidence: "Confirmed",
      category: "Multi-tenant security",
      taxonomy: "M1 — Multi-tenant security",
      location: v.table,
      status: "Open",
      evidence: `Granted to a client role: ${v.overBroadGrants.join(", ")}.`,
      impact: "TRUNCATE/REFERENCES to anon/authenticated is never needed for a client role and widens the blast radius if any other control (RLS, API layer) is misconfigured later.",
      fix: "REVOKE the TRUNCATE/REFERENCES grant from anon/authenticated.",
      value: 2,
      ease: 5,
      safety: 5,
    });
  }

  return findings;
}
