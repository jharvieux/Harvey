import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyBaseline, diffAgainstBaseline, findingIdentity, normalizeLocation } from "./audit-diff.js";
import { type Finding, type FindingsDocument, type ReportMeta, validateFindings } from "./findings.js";

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "F-01", title: "t", severity: "Low", confidence: "Confirmed", category: "Security",
  taxonomy: "auth_rls_initplan", location: "lib/rls.ts", status: "Open", evidence: "e", impact: "i",
  fix: "f", value: 2, ease: 3, safety: 4, ...over,
});

const statuses = (findings: Finding[]) => findings.map((f) => f.baselineStatus);

describe("finding identity (#457)", () => {
  it("is stable under line-number churn — a moved-but-same finding is persistent", () => {
    const prior = [finding({ id: "F-01", location: "lib/rls.ts:42" })];
    // Same rule + file, code shifted down 45 lines. The ONLY difference is the raw line.
    const current = [finding({ id: "F-07", location: "lib/rls.ts:87" })];
    const diff = diffAgainstBaseline(prior, current);
    expect(diff.counts).toEqual({ resolved: 0, persistent: 1, new: 0 });
    expect(diff.findings[0]?.baselineStatus).toBe("persistent");
  });

  it("does NOT key on volatile fields — same taxonomy+location, changed title/severity/BFTB stays persistent", () => {
    // If identity ever starts keying on title/severity/evidence/score, this flips to new+resolved.
    const prior = [finding({ id: "F-01", title: "50 policies re-evaluate auth", severity: "Perf", value: 4, ease: 4, safety: 4 })];
    const current = [finding({ id: "F-03", title: "48 policies re-evaluate auth", severity: "Low", value: 2, ease: 5, safety: 5, evidence: "reworded" })];
    const diff = diffAgainstBaseline(prior, current);
    expect(statuses(diff.findings)).toEqual(["persistent"]);
    expect(diff.resolved).toHaveLength(0);
  });

  it("distinguishes rule class — same location, different taxonomy is a different finding", () => {
    const prior = [finding({ id: "F-01", taxonomy: "Missing index", location: "main DB" })];
    const current = [finding({ id: "F-02", taxonomy: "auth_rls_initplan", location: "main DB" })];
    const diff = diffAgainstBaseline(prior, current);
    // Not the same finding: the old one is resolved, the new one is new.
    expect(diff.counts).toEqual({ resolved: 1, persistent: 0, new: 1 });
  });

  it("normalizeLocation strips lines, columns, and github anchors without folding file case", () => {
    expect(normalizeLocation("lib/Rls.ts:42:10")).toBe("lib/Rls.ts");
    expect(normalizeLocation("lib/rls.ts#L42-L48")).toBe("lib/rls.ts");
    expect(normalizeLocation("app/api/chat/route.ts (line 210)")).toBe("app/api/chat/route.ts");
  });

  it("findingIdentity ignores line but keeps taxonomy+path", () => {
    expect(findingIdentity(finding({ location: "lib/rls.ts:42" }))).toBe(findingIdentity(finding({ location: "lib/rls.ts:99" })));
    expect(findingIdentity(finding({ taxonomy: "a" }))).not.toBe(findingIdentity(finding({ taxonomy: "b" })));
  });

  it("canonicalizes equivalent rooted spellings and symlinks but preserves case-sensitive files", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-finding-identity-"));
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "a.ts"), "export {}\n");
      symlinkSync("src/a.ts", join(root, "alias.ts"));
      const options = { root, caseSensitive: true };
      const locations = [
        "src/a.ts:7",
        "./src//a.ts:19",
        "src\\.\\a.ts#L42",
        join(root, "src", "a.ts") + ":88",
        "alias.ts:3",
      ];
      expect(new Set(locations.map((location) => findingIdentity(finding({ location }), options))).size).toBe(1);

      const diff = diffAgainstBaseline(
        [finding({ id: "old", location: "./src//a.ts:7" })],
        [finding({ id: "new", location: "alias.ts:99" })],
        options,
      );
      expect(diff.counts).toEqual({ resolved: 0, persistent: 1, new: 0 });
      expect(findingIdentity(finding({ location: "src/Foo.ts" }), options)).not.toBe(
        findingIdentity(finding({ location: "src/foo.ts" }), options),
      );
      expect(findingIdentity(finding({ location: "src/Foo.ts" }), { ...options, caseSensitive: false })).toBe(
        findingIdentity(finding({ location: "src/foo.ts" }), { ...options, caseSensitive: false }),
      );
      expect(normalizeLocation("../outside.ts", options)).toMatch(/^external:/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("baseline diff buckets (#457)", () => {
  it("buckets an exact match as persistent", () => {
    const f = finding({ id: "F-01", location: "lib/a.ts" });
    const diff = diffAgainstBaseline([f], [{ ...f, id: "F-04" }]);
    expect(diff.counts).toEqual({ resolved: 0, persistent: 1, new: 0 });
  });

  it("buckets a baseline-only finding as resolved and a current-only finding as new", () => {
    const prior = [finding({ id: "F-01", taxonomy: "Dead code", location: "src/old.ts" })];
    const current = [finding({ id: "F-02", taxonomy: "Duplication", location: "src/new.ts" })];
    const diff = diffAgainstBaseline(prior, current);
    expect(diff.counts).toEqual({ resolved: 1, persistent: 0, new: 1 });
    expect(diff.resolved[0]?.baselineStatus).toBe("resolved");
    expect(diff.resolved[0]?.id).toBe("F-01");
    expect(diff.findings[0]?.baselineStatus).toBe("new");
  });

  it("mixes all three buckets correctly", () => {
    const prior = [
      finding({ id: "P-1", taxonomy: "Missing index", location: "db.ts" }), // persists
      finding({ id: "P-2", taxonomy: "Dead code", location: "old.ts" }), // resolved
    ];
    const current = [
      finding({ id: "C-1", taxonomy: "Missing index", location: "db.ts:88" }), // persists (moved)
      finding({ id: "C-2", taxonomy: "Hotspot", location: "route.ts" }), // new
    ];
    const diff = diffAgainstBaseline(prior, current);
    expect(diff.counts).toEqual({ resolved: 1, persistent: 1, new: 1 });
    expect(diff.resolved.map((f) => f.id)).toEqual(["P-2"]);
  });
});

describe("low-confidence match — fail loud, never silently merged (#457)", () => {
  it("a renamed file with the same taxonomy is new+flagged, and the prior stays resolved", () => {
    const prior = [finding({ id: "F-09", taxonomy: "Tests-verify-intent", location: "lib/commissions/state-machine.ts" })];
    // Same rule + same basename, but the descriptor drifted enough that the exact key differs
    // (a directory move). We must NOT merge it; we flag the possible match and keep both visible.
    const current = [finding({ id: "F-02", taxonomy: "Tests-verify-intent", location: "app/commissions/state-machine.ts" })];
    const diff = diffAgainstBaseline(prior, current);
    expect(diff.findings[0]?.baselineStatus).toBe("new");
    expect(diff.findings[0]?.lowConfidenceMatch).toBe("F-09");
    // The prior finding is still reported resolved — the uncertain pair points at each other.
    expect(diff.counts).toEqual({ resolved: 1, persistent: 0, new: 1 });
  });

  it("does not flag a low-confidence match when the taxonomy differs", () => {
    const prior = [finding({ id: "F-09", taxonomy: "Tests-verify-intent", location: "lib/x.ts" })];
    const current = [finding({ id: "F-02", taxonomy: "Missing index", location: "src/x.ts" })];
    const diff = diffAgainstBaseline(prior, current);
    expect(diff.findings[0]?.lowConfidenceMatch).toBeUndefined();
  });
});

describe("applyBaseline into the deliverable (#457)", () => {
  const meta: ReportMeta = {
    client: "C", subtitle: "s", date: "2026-07-17", commit: "x", auditor: "a", confidential: true,
    overallHealth: 7, tenantIsolation: "HOLDS", authModel: "oauth", headline: "h", scope: "sc",
    methodology: "m", outOfScope: "none",
  };
  const doc: FindingsDocument = { meta, findings: [finding({ id: "F-01", taxonomy: "Missing index", location: "db.ts" })] };

  it("tags findings and attaches the summary", () => {
    const prior = [finding({ id: "B-1", taxonomy: "Dead code", location: "old.ts" })];
    const out = applyBaseline(doc, prior, "2026-04-01 @ abc123");
    expect(out.baseline?.counts).toEqual({ resolved: 1, persistent: 0, new: 1 });
    expect(out.baseline?.priorLabel).toBe("2026-04-01 @ abc123");
    expect(out.findings[0]?.baselineStatus).toBe("new");
  });

  it("produces a document that still passes findings validation", () => {
    const out = applyBaseline(doc, [finding({ id: "B-1", taxonomy: "Dead code", location: "old.ts" })]);
    expect(validateFindings(out)).toEqual({ ok: true, errors: [] });
  });
});
