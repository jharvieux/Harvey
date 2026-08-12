import { describe, expect, it } from "vitest";
import { EXTERNAL_CORPUS } from "./external-corpus.js";
import { M8_CORPUS_CONFIGS } from "./m8-corpus.js";
import {
  aggregateM8TargetResults,
  buildM8CorpusPlan,
  m8PhasesFromOutput,
  parseM8TargetResult,
  type M8TargetResult,
} from "./m8-corpus-artifacts.js";

const plan = buildM8CorpusPlan(EXTERNAL_CORPUS, M8_CORPUS_CONFIGS);

function result(target: string, status: "passed" | "failed" = "passed"): M8TargetResult {
  const row = { slug: target, check: "M8 mutation baseline", pass: status === "passed", detail: "unchanged" };
  return {
    schemaVersion: 1,
    target,
    status,
    exitCode: status === "passed" ? 0 : 1,
    durationMs: target === "inbox-zero" ? 598_000 : 45_000,
    phases: status === "passed"
      ? { clone: 1_000, "dependency preparation": 30_000, "test baseline": 27_000, mutation: 204_000, scoring: target === "inbox-zero" ? 336_000 : 0 }
      : null,
    scorecard: status === "passed" ? { rows: [row], findings: {} } : null,
    ...(status === "failed" ? { error: "mutation command exited 1" } : {}),
  };
}

describe("M8 corpus plan and aggregate (#1874)", () => {
  it("turns the real target banner and Stryker markers into a conserved per-target phase split", () => {
    const phases = m8PhasesFromOutput(
      "M8 PHASES: test baseline 27.0s, mutation 200.0s, line coverage 293.0s\n  inbox-zero: 598s — other 564.5s, install 30.4s, clone 2.7s",
      "inbox-zero",
      598_000,
      100_000,
    );
    expect(phases).toEqual({ clone: 2_700, "dependency preparation": 97_300, "test baseline": 27_000, mutation: 200_000, scoring: 271_000 });
    expect(Object.values(phases).reduce((sum, duration) => sum + duration, 0)).toBe(598_000);
    expect(() => m8PhasesFromOutput("inbox-zero: 1s — clone 0.1s", "inbox-zero", 1_000, 500)).toThrow(/timing markers/);
  });

  it("accounts for every external target exactly once, with a counted reason for each unconfigured target", () => {
    const all = [...plan.configured, ...plan.unconfigured.map((target) => target.target)];
    expect(all).toHaveLength(EXTERNAL_CORPUS.length);
    expect(new Set(all).size).toBe(EXTERNAL_CORPUS.length);
    expect(plan.unconfigured.every((target) => target.reason.length > 40)).toBe(true);
  });

  it("preserves every baseline row while reporting critical path and runner cost separately", () => {
    const inputs = plan.configured.map((target) => result(target));
    const report = aggregateM8TargetResults(plan, inputs);
    expect(report.ok).toBe(true);
    expect(report.criticalPath.target).toBe("inbox-zero");
    expect(report.aggregateRunnerCostMs).toBeGreaterThan(report.criticalPath.durationMs);
    expect(report.targets.map((target) => target.scorecard?.rows[0])).toEqual(
      [...inputs].sort((a, b) => a.target.localeCompare(b.target)).map((target) => target.scorecard?.rows[0]),
    );
  });

  it("preserves the hosted pre-shard mutation score byte-for-byte through parse and aggregate", () => {
    // Run 31549148351's accepted artifact is deliberately used verbatim. Inbox Zero's timeout
    // count can wobble without its killed/valid baseline moving, so 75.2% and 80/125 are distinct
    // measurements. Recomputing or rounding this row to the manifest's 76% would rewrite history.
    const hostedDetail = "MEASURED 75.2% (80/125 killed) over utils/similarity-score.ts — a scoped subset, NOT a whole-repo coverage claim — within the baseline's band; RECORDED baseline is 76% (80/125 killed)";
    const inputs = plan.configured.map((target) => {
      const entry = result(target);
      if (target === "inbox-zero") entry.scorecard!.rows[0] = {
        slug: target,
        check: "M8 mutation baseline",
        pass: true,
        detail: hostedDetail,
      };
      return parseM8TargetResult(JSON.stringify(entry), `${target}/result.json`);
    });

    const report = aggregateM8TargetResults(plan, inputs);
    const inboxZero = report.targets.find((target) => target.target === "inbox-zero");
    expect(inboxZero?.scorecard?.rows[0]).toMatchObject({ detail: hostedDetail });
    expect(JSON.stringify(inboxZero?.scorecard)).toContain("MEASURED 75.2%");
    expect(JSON.stringify(inboxZero?.scorecard)).not.toContain("matches baseline exactly: 76%");
  });

  it("waits for all results, then makes one failed target fail the aggregate", () => {
    const inputs = plan.configured.map((target) => result(target, target === "proposit" ? "failed" : "passed"));
    const report = aggregateM8TargetResults(plan, inputs);
    expect(report.targets).toHaveLength(plan.configured.length);
    expect(report.failed).toBe(1);
    expect(report.ok).toBe(false);
  });

  it("fails loud on missing, duplicate, unexpected, and internally wrong artifacts", () => {
    const inputs = plan.configured.map((target) => result(target));
    expect(() => aggregateM8TargetResults(plan, inputs.slice(1))).toThrow(/missing target artifact/);
    expect(() => aggregateM8TargetResults(plan, [...inputs, inputs[0]!])).toThrow(/duplicate target artifact/);
    expect(() => aggregateM8TargetResults(plan, [...inputs.slice(1), result("invented")])).toThrow(/not in the configured/);
    expect(() => aggregateM8TargetResults(plan, inputs.map((entry, index) => index === 0
      ? { ...entry, scorecard: { rows: [{ slug: "wrong", check: "M8 mutation baseline", pass: true }], findings: {} } }
      : entry))).toThrow(/exactly one M8 mutation baseline row/);
  });

  it("fails loud on corrupt schemas in both directions", () => {
    expect(() => parseM8TargetResult("{", "bad-json")).toThrow(/corrupt JSON/);
    expect(() => parseM8TargetResult(JSON.stringify({ ...result("proposit"), phases: { clone: -1 } }), "bad-phase")).toThrow(/clone must be finite/);
    expect(() => parseM8TargetResult(JSON.stringify({ ...result("proposit"), exitCode: 1 }), "false-pass")).toThrow(/passed target must/);
    expect(parseM8TargetResult(JSON.stringify(result("proposit", "failed")), "real-failure").status).toBe("failed");
  });
});
