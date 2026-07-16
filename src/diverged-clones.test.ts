import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { divergedCloneFindings, M4_DIVERGED_TAXONOMY, type SecurityPathFile } from "./diverged-clones.js";

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

  it("never compares functions within the same file", () => {
    const source = guardSource("requireRecordA", "tenant_id") + guardSource("requireRecordB", "owner_id");
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
