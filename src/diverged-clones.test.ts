import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  divergedCloneFindings,
  divergedScopeFinding,
  M4_DIVERGED_TAXONOMY,
  M4_DIVERGED_WIDE_TAXONOMY,
  type SecurityPathFile,
  wholeRepoDivergedCloneFindings,
} from "./diverged-clones.js";

const fixtureDir = join(import.meta.dirname, "..", "targets", "calibration", "dup", "auth");
const fixture = (name: string): SecurityPathFile => ({
  path: `dup/auth/${name}`,
  source: readFileSync(join(fixtureDir, name), "utf8"),
});

// A ~50-token guard body used to build synthetic variants below.
const guardSource = (fnName: string, column: string, extraLine = ""): string => `
export async function ${fnName}(db: Db, tenantId: string, id: string): Promise<Row> {
  const row = await db.query("select * from records where id = $1 and ${column} = $2", [id, tenantId]);
  ${extraLine}
  if (row === null || row === undefined) {
    throw new Error("record not visible in tenant scope");
  }
  if (row.deletedAt !== null) {
    throw new Error("record deleted");
  }
  return row;
}
`;

describe("divergedCloneFindings — the planted calibration pair (#360)", () => {
  it("flags the tenant_id/owner_id diverged guard pair and names the drifted literal", () => {
    const findings = divergedCloneFindings([fixture("require-tenant-api.ts"), fixture("require-tenant-admin.ts")]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.id).toBe("M4-DIV-01");
    expect(f.taxonomy).toBe(M4_DIVERGED_TAXONOMY);
    expect(f.severity).toBe("High");
    expect(f.precisionTier).toBe("review"); // an adjudication request, not a mechanical verdict
    expect(f.evidence).toContain('"tenant_id"');
    expect(f.evidence).toContain('"owner_id"');
    expect(f.impact).toContain("M1 authorization review");
  });

  it("does not pair either guard with the structurally-distinct api-key check in the same auth dir", () => {
    const findings = divergedCloneFindings([
      fixture("require-tenant-api.ts"),
      fixture("require-tenant-admin.ts"),
      fixture("api-key-check.ts"),
    ]);
    expect(findings).toHaveLength(1); // still only the planted pair
    expect(findings[0]!.location).not.toContain("api-key-check");
  });

  it("skips the session-check pair — a CONSISTENT rename (Type-2) is faithful duplication, not drift, and jscpd already reports it", () => {
    const findings = divergedCloneFindings([fixture("session-check-api.ts"), fixture("session-check-action.ts")]);
    expect(findings).toEqual([]);
  });
});

describe("divergedCloneFindings — divergence classes", () => {
  it("flags an inconsistent identifier mapping (one call site switched a variable, the rest still match)", () => {
    const a = { path: "auth/a.ts", source: guardSource("requireRecord", "tenant_id") };
    const b = { path: "auth/b.ts", source: guardSource("requireRecord", "tenant_id").replace("[id, tenantId]", "[id, userId]") };
    const findings = divergedCloneFindings([a, b]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("tenantId ↔ userId");
  });

  it("flags a structural edit (statement added to one copy) via the similarity branch", () => {
    const a = { path: "auth/a.ts", source: guardSource("requireRecord", "tenant_id") };
    const b = { path: "auth/b.ts", source: guardSource("requireRecord", "tenant_id", 'if (row.locked) { throw new Error("locked"); }') };
    const findings = divergedCloneFindings([a, b]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("% token-identical");
  });

  it("collapses a drifted family into ONE finding — three copies are one review decision, not three pairs", () => {
    const findings = divergedCloneFindings([
      { path: "auth/a.ts", source: guardSource("requireRecord", "tenant_id") },
      { path: "auth/b.ts", source: guardSource("requireRecord", "owner_id") },
      { path: "auth/c.ts", source: guardSource("requireRecord", "org_id") },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("clone family (3 functions)");
    for (const p of ["auth/a.ts", "auth/b.ts", "auth/c.ts"]) expect(findings[0]!.location).toContain(p);
  });

  it("skips raw-identical copies — Type-1 exact clones are jscpd's job", () => {
    const src = guardSource("requireRecord", "tenant_id");
    expect(divergedCloneFindings([{ path: "auth/a.ts", source: src }, { path: "auth/b.ts", source: src }])).toEqual([]);
  });

  // #1095 (operator ruling 2026-07-26) reverses the previous "never compares functions within the
  // same file" behaviour. It cited #232's "self-file clones are inert DATA" rationale, measured
  // false on 2026-07-25 — so two drifted copies of a guard in ONE file, the case with the WEAKEST
  // discovery cues, were invisible to the detector that exists to catch exactly that.
  it("compares functions within the same file — a drifted copy 12 lines down is the same bug (#1095)", () => {
    const source = guardSource("requireRecordA", "tenant_id") + guardSource("requireRecordB", "owner_id");
    const findings = divergedCloneFindings([{ path: "auth/a.ts", source }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("High");
    expect(findings[0]!.evidence).toContain("tenant_id");
    expect(findings[0]!.evidence).toContain("owner_id");
    // The path is stated once, not echoed on both sides of the arrow.
    expect(findings[0]!.title).toBe("Diverged security-path clones: auth/a.ts::requireRecordA ↔ ::requireRecordB");
  });

  // The one pair only same-file comparison can produce: a nested function is a token SUBSEQUENCE
  // of its parent, which LCS scores as near-identity. Containment is not divergence.
  it("does not flag a nested function against the parent that contains it (#1095)", () => {
    const source = `
export function requireRecordOuter(req: Req, id: string) {
  const load = async (recordId: string) => {
    const session = await getSession(req);
    if (!session) throw new Error("unauthenticated");
    const row = await db.query("select * from records where id = $1 and tenant_id = $2", [recordId, session.tenantId]);
    if (!row) throw new Error("not found");
    if (row.tenant_id !== session.tenantId) throw new Error("forbidden");
    if (row.deleted_at !== null) throw new Error("gone");
    await audit.write(session.tenantId, "read", recordId);
    return row;
  };
  return load(id);
}
`;
    expect(divergedCloneFindings([{ path: "auth/a.ts", source }])).toEqual([]);
  });

  it("ignores tiny guards — below the token floor, 'same shape' is meaningless", () => {
    const small = (name: string, col: string): SecurityPathFile => ({
      path: `auth/${name}.ts`,
      source: `export const ${name} = (r: Row) => r.${col} === current();`,
    });
    expect(divergedCloneFindings([small("a", "tenantId"), small("b", "ownerId")])).toEqual([]);
  });

  it("does not flag two structurally unrelated functions of similar size", () => {
    const other = `
export function assembleAuditRow(entries: Entry[], limit: number): string[] {
  const rows: string[] = [];
  for (const entry of entries) {
    if (rows.length >= limit) break;
    rows.push(entry.actor + ":" + entry.action + "@" + String(entry.at));
  }
  return rows.reverse();
}
`;
    const findings = divergedCloneFindings([
      { path: "auth/a.ts", source: guardSource("requireRecord", "tenant_id") },
      { path: "auth/b.ts", source: other },
    ]);
    expect(findings).toEqual([]);
  });
});

// #809: the opt-in whole-repo extension. Same divergence math as divergedCloneFindings, but the
// caller need not pre-screen for security relevance — so the finding shape, severity, and
// taxonomy are generic (never the "security check" framing), and a volume cap bounds the
// otherwise-unscoped O(n^2) comparison.
describe("wholeRepoDivergedCloneFindings (#809)", () => {
  // A config object builder — deliberately NOT under an auth/guard/security path and with no
  // tenant-key-scoped supabase query, so touchesSecurityPath/touchesTenantSupabasePath would both
  // gate it OUT of divergedCloneFindings' admission — proving this pass reaches beyond that scope.
  const configSource = (fnName: string, maxRows: number): string => `
export function ${fnName}(rows: string[], format: string): Record<string, unknown> {
  const config = {
    rows,
    format,
    delimiter: ",",
    maxRows: ${maxRows},
  };
  if (rows.length === 0) {
    throw new Error("no rows to export");
  }
  return config;
}
`;

  it("flags a diverged config builder duplicated between two non-security modules", () => {
    const findings = wholeRepoDivergedCloneFindings([
      { path: "lib/export/csv.ts", source: configSource("buildExportConfig", 500) },
      { path: "lib/reports/xlsx.ts", source: configSource("buildExportConfig", 2000) },
    ]);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.id).toBe("M4-DIVW-01");
    expect(f.taxonomy).toBe(M4_DIVERGED_WIDE_TAXONOMY);
    expect(f.taxonomy).not.toBe(M4_DIVERGED_TAXONOMY);
    expect(f.severity).toBe("Medium"); // not High — this scope carries no security guarantee
    expect(f.precisionTier).toBe("review");
    expect(f.evidence).toContain("500 ↔ 2000");
    expect(f.title).not.toContain("security"); // generic wording, unlike divergedCloneFindings
  });

  it("does not flag two structurally unrelated non-security functions of similar size", () => {
    const unrelated = `
export function summarizeOrders(orders: { total: number }[]): number {
  let sum = 0;
  for (const order of orders) {
    if (order.total > 0) sum += order.total;
  }
  return sum;
}
`;
    const findings = wholeRepoDivergedCloneFindings([
      { path: "lib/export/csv.ts", source: configSource("buildExportConfig", 500) },
      { path: "lib/orders/summary.ts", source: unrelated },
    ]);
    expect(findings).toEqual([]);
  });

  it("discloses a truncated volume cap rather than silently dropping the excess", () => {
    // Three files' worth of functions, capped at 2 — the third file's function never enters
    // comparison, and that gap must be disclosed (M4-98), not silently absorbed.
    const findings = wholeRepoDivergedCloneFindings(
      [
        { path: "a.ts", source: configSource("buildExportConfig", 500) },
        { path: "b.ts", source: configSource("buildExportConfig", 2000) },
        { path: "c.ts", source: configSource("buildExportConfig", 9000) },
      ],
      { maxFunctions: 2 },
    );
    const capNote = findings.find((f) => f.id === "M4-98");
    expect(capNote).toBeDefined();
    expect(capNote?.evidence).toContain("only the first 2");
  });

  it("does not disclose a volume cap when every function fit under it", () => {
    const findings = wholeRepoDivergedCloneFindings(
      [
        { path: "a.ts", source: configSource("buildExportConfig", 500) },
        { path: "b.ts", source: configSource("buildExportConfig", 2000) },
      ],
      { maxFunctions: 10 },
    );
    expect(findings.some((f) => f.id === "M4-98")).toBe(false);
  });
});

// #1080: the security-path pass runs ONLY over the caller's narrow (security/tenant-relevant)
// subset by default — before this, the only disclosure of that scoping was a CLI stderr line, never
// the deliverable. This is a plain scope-count disclosure, not a divergence finding.
describe("divergedScopeFinding (#1080)", () => {
  it("names the covered/eligible file counts and the remainder left unassessed", () => {
    const finding = divergedScopeFinding(12, 200);
    expect(finding.id).toBe("M4-97");
    expect(finding.taxonomy).toBe(M4_DIVERGED_WIDE_TAXONOMY);
    expect(finding.evidence).toContain("12 security/tenant-relevant file(s) of 200 eligible");
    expect(finding.evidence).toContain("188 file(s) were NOT compared");
  });
});
