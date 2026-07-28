import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass, writePassArtifact } from "./audit-pass-artifact.js";
import type { RunContext } from "./audit-runner.js";
import {
  buildM6PassArtifact,
  compareReviewerPasses,
  parseReviewerPass,
  renderAgreementReport,
  toM6Findings,
  type ReviewerPass,
} from "./m6-agreement.js";

const passA: ReviewerPass = {
  reviewer: "reviewer-a",
  target: "targets/calibration/simplify",
  verdicts: [
    { file: "debounce.ts", verdict: "flag", replacement: "lodash-es debounce" },
    { file: "depdrop.ts", verdict: "spare", reason: "WHY comment records a deliberate dep-drop" },
    { file: "framework-adapter.ts", verdict: "spare", reason: "SupportedStorage contract" },
  ],
};

const passB: ReviewerPass = {
  reviewer: "reviewer-b",
  target: "targets/calibration/simplify",
  verdicts: [
    { file: "debounce.ts", verdict: "flag", replacement: "lodash-es debounce" },
    { file: "depdrop.ts", verdict: "spare" },
    { file: "framework-adapter.ts", verdict: "flag", confidence: "low", reason: "duplicates @supabase/ssr" },
    { file: "reconcile.ts", verdict: "spare" },
  ],
};

describe("parseReviewerPass", () => {
  it("round-trips a valid pass", () => {
    const parsed = parseReviewerPass(JSON.parse(JSON.stringify(passA)), "a.json");
    expect(parsed.reviewer).toBe("reviewer-a");
    expect(parsed.verdicts).toHaveLength(3);
    expect(parsed.verdicts[1]).toMatchObject({ file: "depdrop.ts", verdict: "spare" });
  });

  it("rejects an anonymous pass — independence is unprovable without a reviewer id", () => {
    expect(() => parseReviewerPass({ verdicts: passA.verdicts }, "a.json")).toThrow(/reviewer/);
  });

  it("rejects a verdict that is neither flag nor spare", () => {
    expect(() =>
      parseReviewerPass({ reviewer: "r", verdicts: [{ file: "x.ts", verdict: "maybe" }] }, "a.json"),
    ).toThrow(/"flag" or "spare"/);
  });

  it("rejects duplicate file rows — one verdict per file", () => {
    expect(() =>
      parseReviewerPass(
        { reviewer: "r", verdicts: [{ file: "x.ts", verdict: "flag" }, { file: "x.ts", verdict: "spare" }] },
        "a.json",
      ),
    ).toThrow(/more than once/);
  });

  it("rejects an empty verdict list rather than reporting vacuous agreement", () => {
    expect(() => parseReviewerPass({ reviewer: "r", verdicts: [] }, "a.json")).toThrow(/non-empty/);
  });
});

describe("compareReviewerPasses", () => {
  it("counts agreements and isolates the split for adjudication", () => {
    const report = compareReviewerPasses(passA, passB);
    expect(report.compared).toBe(3);
    expect(report.agreed).toBe(2);
    expect(report.bothFlag).toEqual(["debounce.ts"]);
    expect(report.bothSpare).toEqual(["depdrop.ts"]);
    expect(report.splits).toHaveLength(1);
    expect(report.splits[0]?.file).toBe("framework-adapter.ts");
    // The split carries BOTH reviewers' arguments — that is what the adjudicator triages.
    expect(report.splits[0]?.verdicts[0]?.reason).toMatch(/SupportedStorage/);
    expect(report.splits[0]?.verdicts[1]?.confidence).toBe("low");
  });

  it("lists a file reviewed by only one pass instead of silently dropping it", () => {
    const report = compareReviewerPasses(passA, passB);
    expect(report.onlyA).toEqual([]);
    expect(report.onlyB).toEqual(["reconcile.ts"]);
    // Uncompared files must never inflate the agreement rate.
    expect(report.compared + report.onlyB.length).toBe(passB.verdicts.length);
  });

  it("refuses a self-comparison — two passes with the same reviewer id are not independent", () => {
    expect(() => compareReviewerPasses(passA, { ...passB, reviewer: "reviewer-a" })).toThrow(/INDEPENDENT/);
  });

  it("refuses to compare passes over different targets", () => {
    expect(() => compareReviewerPasses(passA, { ...passB, target: "some/other/dir" })).toThrow(/different targets/);
  });
});

describe("renderAgreementReport", () => {
  it("states the measured rate, routes splits to a human, and forbids the precision framing", () => {
    const out = renderAgreementReport(compareReviewerPasses(passA, passB));
    expect(out).toContain("agreed 2/3");
    expect(out).toMatch(/human adjudicator/);
    expect(out).toContain("framework-adapter.ts");
    expect(out).toMatch(/never quote it as M6 precision/);
    expect(out).toMatch(/reconcile\.ts/); // the uncompared file is visible, not absent
  });

  it("says so explicitly when there are no splits", () => {
    const unanimous: ReviewerPass = { ...passB, verdicts: passB.verdicts.filter((v) => v.file !== "framework-adapter.ts") };
    const out = renderAgreementReport(compareReviewerPasses(passA, unanimous));
    expect(out).toMatch(/no splits/);
  });
});

// #1364: the M6 pass artifact src/cli/m6-agreement.ts writes with --target/--artifacts-dir.
describe("toM6Findings (#1364)", () => {
  const report = compareReviewerPasses(passA, passB);

  it("promotes only the unanimous-flag file (debounce.ts) — the split (framework-adapter.ts) never becomes a finding", () => {
    const findings = toM6Findings(passA, passB, report);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("debounce.ts");
    expect(findings.some((f) => f.location === "framework-adapter.ts")).toBe(false);
  });

  it("never grades M6 findings — Info severity, mirroring the free indicator layer's Info-only convention (#267)", () => {
    expect(toM6Findings(passA, passB, report)[0]?.severity).toBe("Info");
  });

  it("names the replacement both reviewers agreed on", () => {
    expect(toM6Findings(passA, passB, report)[0]?.fix).toContain("lodash-es debounce");
  });

  it("does not overclaim Confirmed when neither reviewer recorded high confidence", () => {
    expect(toM6Findings(passA, passB, report)[0]?.confidence).toBe("Review");
  });

  it("grades Confirmed only when BOTH reviewers stated high confidence", () => {
    const highA: ReviewerPass = { ...passA, verdicts: passA.verdicts.map((v) => (v.file === "debounce.ts" ? { ...v, confidence: "high" as const } : v)) };
    const highB: ReviewerPass = { ...passB, verdicts: passB.verdicts.map((v) => (v.file === "debounce.ts" ? { ...v, confidence: "high" as const } : v)) };
    expect(toM6Findings(highA, highB, compareReviewerPasses(highA, highB))[0]?.confidence).toBe("Confirmed");
  });

  it("one reviewer at high confidence and the other not stays Review — one confident reviewer cannot speak for both", () => {
    const highA: ReviewerPass = { ...passA, verdicts: passA.verdicts.map((v) => (v.file === "debounce.ts" ? { ...v, confidence: "high" as const } : v)) };
    expect(toM6Findings(highA, passB, compareReviewerPasses(highA, passB))[0]?.confidence).toBe("Review");
  });
});

describe("buildM6PassArtifact + write → derive round trip (#1364)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-m6-pass-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("a written M6 verdict pass artifact is read back fresh and derives ran, findings intact", () => {
    const report = compareReviewerPasses(passA, passB);
    const built = buildM6PassArtifact(passA, passB, report, "/engagement/target", "2026-07-27T00:00:00Z");
    expect(built.pass).toBe("verdict");
    const path = writePassArtifact(dir, built);
    expect(path).toBe(join(dir, "M6.pass.json"));

    const ctx: RunContext = {
      targetDir: "/engagement/target",
      env: { connected: false, dynamic: false, llm: true },
      exec: () => ({ ok: true, output: "" }),
      exists: (p) => existsSync(p),
      artifactsDir: dir,
      readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
      now: Date.parse("2026-07-27T12:00:00Z"),
    };
    const fresh = findFreshPass(ctx, "M6");
    expect(fresh.fresh).toBe(true);
    if (fresh.fresh) {
      const ran = ranFromPass(fresh.artifact, "mech");
      expect(ran.status).toBe("ran");
      expect(ran.findings).toEqual(toM6Findings(passA, passB, report));
    }
  });
});
