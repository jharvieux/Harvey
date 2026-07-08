import { describe, expect, it } from "vitest";
import { mutationScore, summarizeMutationReport, toReportRows, type StrykerMutant, type StrykerReport } from "./mutation-scan.js";

// Shaped from the documented mutation-testing-elements JSON schema Stryker's json reporter
// emits (schemaVersion "1") — not captured from a live Stryker run (deferred, see
// docs/m8-test-quality.md "Deferred: live dry-run validation").
function mutant(overrides: Partial<StrykerMutant> & { status: StrykerMutant["status"] }): StrykerMutant {
  return {
    id: "1",
    mutatorName: "ConditionalExpression",
    location: { start: { line: 1, column: 1 }, end: { line: 1, column: 10 } },
    ...overrides,
  };
}

describe("mutationScore", () => {
  it("scores detected (killed + timeout) over valid mutants, excluding ignored/compileError/pending", () => {
    const mutants: StrykerMutant[] = [
      mutant({ status: "Killed" }),
      mutant({ status: "Timeout" }),
      mutant({ status: "Survived" }),
      mutant({ status: "NoCoverage" }),
      mutant({ status: "Ignored" }),
      mutant({ status: "CompileError" }),
    ];
    // valid = 4 (Killed, Timeout, Survived, NoCoverage); detected = 2 → 50%
    expect(mutationScore(mutants)).toBe(50);
  });

  it("returns 0 when every mutant is excluded from the denominator", () => {
    expect(mutationScore([mutant({ status: "Ignored" }), mutant({ status: "CompileError" })])).toBe(0);
  });

  it("rounds to one decimal place rather than truncating", () => {
    const mutants: StrykerMutant[] = [mutant({ status: "Killed" }), mutant({ status: "Killed" }), mutant({ status: "Survived" })];
    expect(mutationScore(mutants)).toBeCloseTo(66.7, 1);
  });
});

const report: StrykerReport = {
  schemaVersion: "1",
  files: {
    "src/scan/secrets.ts": {
      mutants: [
        mutant({ id: "1", status: "Killed", mutatorName: "EqualityOperator" }),
        mutant({ id: "2", status: "Survived", mutatorName: "BooleanLiteral", location: { start: { line: 42, column: 3 }, end: { line: 42, column: 20 } }, replacement: "true" }),
      ],
    },
    "src/scan/supabase.ts": {
      mutants: [
        mutant({ id: "3", status: "NoCoverage", mutatorName: "ConditionalExpression", location: { start: { line: 7, column: 1 }, end: { line: 7, column: 30 } } }),
        mutant({ id: "4", status: "Killed" }),
      ],
    },
    "src/findings.ts": {
      mutants: [mutant({ id: "5", status: "Killed" }), mutant({ id: "6", status: "Killed" })],
    },
  },
};

describe("summarizeMutationReport", () => {
  it("computes an overall score across every file", () => {
    const summary = summarizeMutationReport(report);
    // 4 killed / 6 valid (all 6 are valid — no Ignored/CompileError in the fixture) → 66.7%
    expect(summary.overall.totalMutants).toBe(6);
    expect(summary.overall.killed).toBe(4);
    expect(summary.overall.mutationScore).toBeCloseTo(66.7, 1);
  });

  it("groups mutants by directory into per-module summaries, worst score first", () => {
    const summary = summarizeMutationReport(report);
    const modules = summary.byModule.map((m) => m.module);
    expect(modules).toEqual(["src/scan", "src"]); // "src/findings.ts" buckets under its dirname, "src"
    expect(summary.byModule[0]?.mutationScore).toBe(50); // src/scan: 2 killed / 4 valid
    expect(summary.byModule[1]?.mutationScore).toBe(100); // src: 2/2 (src/findings.ts)
  });

  it("collects only Survived/NoCoverage mutants as surviving, with file+line+mutator", () => {
    const summary = summarizeMutationReport(report);
    expect(summary.survivingMutants).toHaveLength(2);
    const bySrc = summary.survivingMutants.find((m) => m.file === "src/scan/secrets.ts");
    expect(bySrc).toMatchObject({ line: 42, mutatorName: "BooleanLiteral", status: "Survived", replacement: "true" });
  });

  it("flags surviving mutants on a supplied hotspot file and ranks them first", () => {
    const summary = summarizeMutationReport(report, ["src/scan/supabase.ts"]);
    expect(summary.survivingMutants[0]).toMatchObject({ file: "src/scan/supabase.ts", hotspot: true });
    expect(summary.survivingMutants[1]).toMatchObject({ file: "src/scan/secrets.ts", hotspot: false });
  });
});

describe("toReportRows", () => {
  it("shapes one row per module with mutation score and surviving-mutant counts for the §3b table", () => {
    const summary = summarizeMutationReport(report, ["src/scan/supabase.ts"]);
    const rows = toReportRows(summary);
    const scanRow = rows.find((r) => r.module === "src/scan");
    expect(scanRow).toEqual({ module: "src/scan", mutationScore: 50, survivingCount: 2, hotspotSurvivingCount: 1 });
    const findingsRow = rows.find((r) => r.module === "src");
    expect(findingsRow).toEqual({ module: "src", mutationScore: 100, survivingCount: 0, hotspotSurvivingCount: 0 });
  });
});
