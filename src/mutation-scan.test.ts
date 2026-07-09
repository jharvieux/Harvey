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

// M8 calibration corpus (#72 §M8) — a REAL Stryker 9.6.1 JSON capture (trimmed to the
// StrykerReport shape; dropped fields unused by this module: testFiles, config, framework,
// projectRoot) from `npx stryker run` against targets/calibration/test-quality/
// (stryker.config.json, coverageAnalysis: "perTest", vitest test runner). Closes the
// docs/m8-test-quality.md "Deferred: live timed run" gap — unlike `report` above, this is not
// shaped from the documented schema, it's an actual run's output. See
// src/scan/calibration/m8.entries.ts (M8-P-TAUTOLOGICAL / M8-N-STRONG) and
// targets/calibration/GROUND-TRUTH.md "M8 (#72)" for the full answer key + live result.
const m8Report: StrykerReport = {
  schemaVersion: "1.0",
  thresholds: { high: 80, low: 60 },
  files: {
    "discount.ts": {
      language: "typescript",
      mutants: [
        mutant({ id: "15", mutatorName: "StringLiteral", status: "NoCoverage", replacement: '""', location: { start: { line: 4, column: 34 }, end: { line: 4, column: 62 } } }),
        mutant({ id: "24", mutatorName: "ArithmeticOperator", status: "NoCoverage", replacement: "total / 0.9", location: { start: { line: 7, column: 10 }, end: { line: 7, column: 21 } } }),
        mutant({ id: "10", mutatorName: "BlockStatement", status: "Killed", replacement: "{}", location: { start: { line: 3, column: 73 }, end: { line: 8, column: 2 } } }),
        mutant({ id: "11", mutatorName: "ConditionalExpression", status: "Killed", replacement: "true", location: { start: { line: 4, column: 7 }, end: { line: 4, column: 16 } } }),
        mutant({ id: "12", mutatorName: "ConditionalExpression", status: "Survived", replacement: "false", location: { start: { line: 4, column: 7 }, end: { line: 4, column: 16 } } }),
        mutant({ id: "13", mutatorName: "EqualityOperator", status: "Survived", replacement: "total <= 0", location: { start: { line: 4, column: 7 }, end: { line: 4, column: 16 } } }),
        mutant({ id: "14", mutatorName: "EqualityOperator", status: "Killed", replacement: "total >= 0", location: { start: { line: 4, column: 7 }, end: { line: 4, column: 16 } } }),
        mutant({ id: "16", mutatorName: "BooleanLiteral", status: "Killed", replacement: "isMember", location: { start: { line: 5, column: 7 }, end: { line: 5, column: 16 } } }),
        mutant({ id: "17", mutatorName: "ConditionalExpression", status: "Killed", replacement: "true", location: { start: { line: 5, column: 7 }, end: { line: 5, column: 16 } } }),
        mutant({ id: "18", mutatorName: "ConditionalExpression", status: "Survived", replacement: "false", location: { start: { line: 5, column: 7 }, end: { line: 5, column: 16 } } }),
        mutant({ id: "19", mutatorName: "ConditionalExpression", status: "Survived", replacement: "true", location: { start: { line: 6, column: 7 }, end: { line: 6, column: 19 } } }),
        mutant({ id: "20", mutatorName: "ConditionalExpression", status: "Killed", replacement: "false", location: { start: { line: 6, column: 7 }, end: { line: 6, column: 19 } } }),
        mutant({ id: "21", mutatorName: "EqualityOperator", status: "Killed", replacement: "total > 100", location: { start: { line: 6, column: 7 }, end: { line: 6, column: 19 } } }),
        mutant({ id: "22", mutatorName: "EqualityOperator", status: "Killed", replacement: "total < 100", location: { start: { line: 6, column: 7 }, end: { line: 6, column: 19 } } }),
        mutant({ id: "23", mutatorName: "ArithmeticOperator", status: "Killed", replacement: "total / 0.8", location: { start: { line: 6, column: 28 }, end: { line: 6, column: 39 } } }),
      ],
    },
    "authz.ts": {
      language: "typescript",
      mutants: [
        mutant({ id: "1", mutatorName: "ConditionalExpression", status: "Killed", replacement: "true", location: { start: { line: 7, column: 7 }, end: { line: 7, column: 23 } } }),
        mutant({ id: "0", mutatorName: "BlockStatement", status: "Killed", replacement: "{}", location: { start: { line: 6, column: 64 }, end: { line: 9, column: 2 } } }),
        mutant({ id: "2", mutatorName: "ConditionalExpression", status: "Killed", replacement: "false", location: { start: { line: 7, column: 7 }, end: { line: 7, column: 23 } } }),
        mutant({ id: "3", mutatorName: "EqualityOperator", status: "Killed", replacement: 'role !== "admin"', location: { start: { line: 7, column: 7 }, end: { line: 7, column: 23 } } }),
        mutant({ id: "4", mutatorName: "StringLiteral", status: "Killed", replacement: '""', location: { start: { line: 7, column: 16 }, end: { line: 7, column: 23 } } }),
        mutant({ id: "5", mutatorName: "BooleanLiteral", status: "Killed", replacement: "false", location: { start: { line: 7, column: 32 }, end: { line: 7, column: 36 } } }),
        mutant({ id: "6", mutatorName: "ConditionalExpression", status: "Killed", replacement: "true", location: { start: { line: 8, column: 10 }, end: { line: 8, column: 27 } } }),
        mutant({ id: "7", mutatorName: "ConditionalExpression", status: "Killed", replacement: "false", location: { start: { line: 8, column: 10 }, end: { line: 8, column: 27 } } }),
        mutant({ id: "8", mutatorName: "EqualityOperator", status: "Killed", replacement: 'action !== "read"', location: { start: { line: 8, column: 10 }, end: { line: 8, column: 27 } } }),
        mutant({ id: "9", mutatorName: "StringLiteral", status: "Killed", replacement: '""', location: { start: { line: 8, column: 21 }, end: { line: 8, column: 27 } } }),
      ],
    },
  },
};

describe("M8 calibration corpus — live Stryker capture (#72 §M8)", () => {
  it("leaves surviving mutants on discount.ts (M8-P-TAUTOLOGICAL: the weak test's false confidence)", () => {
    const summary = summarizeMutationReport(m8Report);
    const discountModule = summary.byModule.find((m) => m.module === "discount.ts");
    // Real Stryker run: 9 killed / 15 valid mutants = 60.0% — matches Stryker's own reported score.
    expect(discountModule).toMatchObject({ totalMutants: 15, killed: 9, survived: 4, noCoverage: 2, mutationScore: 60 });
    const discountSurvivors = summary.survivingMutants.filter((m) => m.file === "discount.ts");
    expect(discountSurvivors).toHaveLength(6); // 4 Survived + 2 NoCoverage
  });

  it("leaves zero surviving mutants on authz.ts (M8-N-STRONG: must not land on the false-confidence list)", () => {
    const summary = summarizeMutationReport(m8Report);
    const authzModule = summary.byModule.find((m) => m.module === "authz.ts");
    // Real Stryker run: 10/10 killed = 100.0% — the strong test's exhaustive truth table.
    expect(authzModule).toMatchObject({ totalMutants: 10, killed: 10, survived: 0, noCoverage: 0, mutationScore: 100 });
    expect(summary.survivingMutants.some((m) => m.file === "authz.ts")).toBe(false);
  });

  it("computes the overall mutation score across both fixtures", () => {
    const summary = summarizeMutationReport(m8Report);
    // 19 killed / 25 valid = 76.0% — matches Stryker's own "All files" score-table row.
    expect(summary.overall).toMatchObject({ totalMutants: 25, killed: 19, survived: 4, noCoverage: 2, mutationScore: 76 });
  });
});
