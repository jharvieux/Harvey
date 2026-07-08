import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { fixBranch, prTitle, renderPrBody, type FixResult } from "./result.js";
import type { VerificationEvidence } from "./verify.js";

const finding: Finding = {
  id: "F-pay-01",
  title: "Zero-row update returns error: null",
  severity: "High",
  confidence: "Confirmed",
  category: "Data integrity",
  taxonomy: "D-091 #7",
  location: "apps/main/src/actions/payout.ts",
  status: "Open",
  evidence: "update() without .select() can affect zero rows yet return error: null",
  impact: "Silent no-op on payout status transitions",
  fix: "Chain .select('id') and assert the affected-row count",
  value: 5,
  ease: 5,
  safety: 5,
};

const plan: FixPlan = {
  findingId: "F-pay-01",
  severity: "High",
  category: "Data integrity",
  mode: "auto",
  detectorId: "check:zero-row-update",
  approach: "Chain .select('id') and throw when zero rows are affected.",
  blastRadius: {
    files: ["apps/main/src/actions/payout.ts"],
    createdFiles: ["apps/main/src/actions/payout.test.ts"],
    symbols: ["setPayoutStatus"],
    callers: [],
    behaviorPreserving: false,
    estimatedChangedLines: 24,
  },
  verifyCommands: ["pnpm run verify"],
  testPlan: "add payout.test.ts covering the zero-row case",
  tier: "standard",
  risks: [],
};

const evidence: VerificationEvidence = {
  findingId: "F-pay-01",
  worktreeCommit: "deadbeef",
  baselineCommit: "cafe1234",
  detectorBefore: { detectorId: "check:zero-row-update", fired: true, output: "1 hit" },
  detectorAfter: { detectorId: "check:zero-row-update", fired: false, output: "0 hits" },
  clientChecks: [
    { command: "pnpm run verify", cwd: ".", exitCode: 0, durationMs: 42000, outputTail: "ok" },
    { command: "pnpm run e2e", cwd: ".", exitCode: 0, durationMs: 0, outputTail: "", skipped: "needs-ci" },
    { command: "pnpm run flaky", cwd: ".", exitCode: 1, durationMs: 5, outputTail: "", skipped: "pre-existing-failure-on-baseline" },
  ],
  newTestAdded: "apps/main/src/actions/payout.test.ts",
  green: true,
  attempts: 1,
};

function result(overrides: Partial<FixResult> = {}): FixResult {
  return {
    findingId: "F-pay-01",
    outcome: "pr-opened",
    plan,
    branch: fixBranch("F-pay-01"),
    evidence,
    tiersUsed: ["cheap", "standard"],
    railEvents: [],
    ...overrides,
  };
}

describe("branch and title conventions", () => {
  it("names branches harvey/fix/<id> and titles PRs [<id>] <summary>", () => {
    expect(fixBranch("F-pay-01")).toBe("harvey/fix/F-pay-01");
    expect(prTitle(finding, "Assert affected-row count on payout transition")).toBe(
      "[F-pay-01] Assert affected-row count on payout transition",
    );
  });
});

describe("renderPrBody", () => {
  it("cites the finding, shows before/after detector state, and lists every client check", () => {
    const body = renderPrBody(result(), finding, "jane");
    expect(body).toContain("Fixes finding F-pay-01");
    expect(body).toContain("Severity: High");
    expect(body).toContain(plan.approach);
    expect(body).toContain("Detector `check:zero-row-update` before | FIRED");
    expect(body).toContain("after | clean");
    expect(body).toContain("`pnpm run verify` | exit 0, 42s");
    expect(body).toContain("skipped — needs-ci");
    expect(body).toContain("reviewed by jane");
  });

  it("lists pre-existing baseline failures separately so they aren't attributed to the fix", () => {
    expect(renderPrBody(result(), finding, "jane")).toContain("Pre-existing failures on baseline (not caused here): `pnpm run flaky`");
  });

  it("flags a detector that still fires rather than silently claiming clean", () => {
    const bad = result({
      evidence: { ...evidence, detectorAfter: { detectorId: "check:zero-row-update", fired: true, output: "1 hit" } },
    });
    expect(renderPrBody(bad, finding, "jane")).toContain("STILL FIRING");
  });

  it("always includes the mandatory, true rollback paragraph", () => {
    expect(renderPrBody(result(), finding, "jane")).toContain("Close this PR / revert this single commit");
  });
});
