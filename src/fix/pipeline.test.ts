import { describe, expect, it } from "vitest";
import type { Finding, FindingsDocument, ReportMeta } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { batch, checkPlanRails, intake, type EngagementManifest } from "./pipeline.js";
import { renderPrBody, type FixResult } from "./result.js";

function makeFinding(o: Partial<Finding>): Finding {
  return {
    id: "F",
    title: "t",
    severity: "Medium",
    confidence: "Confirmed",
    category: "Data integrity",
    taxonomy: "D-091",
    location: "apps/main/src/x.ts",
    status: "Open",
    evidence: "e",
    impact: "i",
    fix: "f",
    value: 4,
    ease: 5,
    safety: 5,
    ...o,
  };
}

const meta = { client: "Acme", commit: "abc123" } as ReportMeta;

const manifest: EngagementManifest = {
  client: "Acme",
  baselineCommit: "abc123",
  approvedFindingIds: ["F-1", "F-2", "F-3", "F-missing"],
  enabledCategories: ["Data integrity"],
  allowlist: ["apps/main/src/**"],
  operator: "jane",
};

describe("intake", () => {
  const doc: FindingsDocument = {
    meta,
    findings: [
      makeFinding({ id: "F-1" }), // auto
      makeFinding({ id: "F-2", ease: 2 }), // manual (low ease)
      makeFinding({ id: "F-3", confidence: "Review" }), // recommend-only
      makeFinding({ id: "F-4" }), // present but not approved
    ],
  };

  it("buckets the client-approved subset by fix mode and never touches unapproved findings", () => {
    const r = intake(doc, manifest);
    expect(r.auto.map((e) => e.finding.id)).toEqual(["F-1"]);
    expect(r.manual.map((e) => e.finding.id)).toEqual(["F-2"]);
    expect(r.recommendOnly.map((e) => e.finding.id)).toEqual(["F-3"]);
    expect(r.notApproved).toEqual(["F-4"]);
  });

  it("reports approved ids that aren't in the findings doc", () => {
    expect(intake(doc, manifest).unknownApprovedIds).toEqual(["F-missing"]);
  });

  it("flags a baseline mismatch between the findings commit and the manifest", () => {
    expect(intake(doc, manifest).baselineMatches).toBe(true);
    expect(intake({ ...doc, meta: { ...meta, commit: "stale" } }, manifest).baselineMatches).toBe(false);
  });
});

describe("batch", () => {
  const node = (findingId: string, files: string[]): Pick<FixPlan, "findingId" | "blastRadius"> => ({
    findingId,
    blastRadius: { files, createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 5 },
  });

  it("groups findings that touch the same file and keeps independent ones apart", () => {
    const groups = batch([
      node("A", ["src/a.ts"]),
      node("B", ["src/a.ts", "src/b.ts"]), // overlaps A
      node("C", ["src/c.ts"]), // independent
    ]);
    const sorted = groups.map((g) => g.sort()).sort((x, y) => x[0]!.localeCompare(y[0]!));
    expect(sorted).toEqual([["A", "B"], ["C"]]);
  });

  it("treats a created file as an overlap too (two fixes can't both add the same helper)", () => {
    const a = node("A", ["src/a.ts"]);
    const b = node("B", ["src/b.ts"]);
    b.blastRadius.createdFiles = ["src/a.ts"];
    expect(batch([a, b])).toEqual([["A", "B"]]);
  });
});

describe("checkPlanRails", () => {
  const plan = (files: string[]): FixPlan => ({
    findingId: "F-1",
    severity: "Medium",
    category: "Data integrity",
    mode: "auto",
    detectorId: "d",
    approach: "a",
    blastRadius: { files, createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 5 },
    verifyCommands: [],
    testPlan: "",
    tier: "cheap",
    risks: [],
  });

  it("passes an allowlisted plan and rejects one that escapes the allowlist or hits the denylist", () => {
    expect(checkPlanRails(plan(["apps/main/src/a.ts"]), manifest).ok).toBe(true);
    expect(checkPlanRails(plan(["apps/main/src/.env"]), manifest).ok).toBe(false);
    expect(checkPlanRails(plan(["infra/deploy.ts"]), manifest).ok).toBe(false);
  });
});

// End-to-end decision flow against a synthetic (mocked) client-repo finding set:
// intake -> plan -> rails -> PR body, with no worktrees, git, or gh involved.
describe("pipeline end-to-end (synthetic fixture)", () => {
  it("carries an auto finding all the way to a citable PR body", () => {
    const doc: FindingsDocument = { meta, findings: [makeFinding({ id: "F-1", title: "Unchecked mutation" })] };
    const r = intake(doc, manifest);
    expect(r.auto).toHaveLength(1);

    const auto = r.auto[0]!;
    const plan: FixPlan = {
      findingId: auto.finding.id,
      severity: auto.finding.severity,
      category: auto.finding.category,
      mode: "auto",
      detectorId: "check:unchecked-mutation",
      approach: "Handle the ignored { error } and surface it.",
      blastRadius: {
        files: ["apps/main/src/x.ts"],
        createdFiles: [],
        symbols: ["save"],
        callers: [],
        behaviorPreserving: true,
        estimatedChangedLines: 8,
      },
      verifyCommands: ["pnpm run verify"],
      testPlan: "covered by existing save.test.ts",
      tier: auto.screen.tier,
      risks: [],
    };

    expect(checkPlanRails(plan, manifest).ok).toBe(true);

    const fixResult: FixResult = {
      findingId: plan.findingId,
      outcome: "pr-opened",
      plan,
      branch: `harvey/fix/${plan.findingId}`,
      tiersUsed: [plan.tier],
      railEvents: [],
    };
    expect(renderPrBody(fixResult, auto.finding, manifest.operator)).toContain("Fixes finding F-1");
  });
});
