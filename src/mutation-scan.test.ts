import { describe, expect, it } from "vitest";
import {
  coveredScopeLine,
  detectNoTestSuite,
  mutationScore,
  noTestSuiteFinding,
  noTestSuiteModuleRecord,
  summarizeMutationReport,
  toReportRows,
  type StrykerMutant,
  type StrykerReport,
} from "./mutation-scan.js";

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

// #386 layer 2: the mutator-type breakdown that separates "the denial/boundary branch is
// untested" (survivors concentrated in ConditionalExpression/EqualityOperator/BooleanLiteral)
// from "scattered coverage gaps".
describe("mutatorBreakdown", () => {
  it("counts each file's Survived+NoCoverage mutants per mutator type", () => {
    const summary = summarizeMutationReport(report);
    const secrets = summary.mutatorBreakdown.find((b) => b.file === "src/scan/secrets.ts");
    expect(secrets).toMatchObject({ survivorsByMutator: { BooleanLiteral: 1 }, boundarySurvivors: 1, otherSurvivors: 0 });
    const supabase = summary.mutatorBreakdown.find((b) => b.file === "src/scan/supabase.ts");
    expect(supabase).toMatchObject({ survivorsByMutator: { ConditionalExpression: 1 }, boundarySurvivors: 1, otherSurvivors: 0 });
  });

  it("does NOT call a single boundary survivor concentrated — the >=2 floor is load-bearing", () => {
    const summary = summarizeMutationReport(report);
    expect(summary.mutatorBreakdown.every((b) => !b.denialBoundaryConcentrated)).toBe(true);
  });

  it("omits files with zero survivors entirely", () => {
    const summary = summarizeMutationReport(report);
    expect(summary.mutatorBreakdown.some((b) => b.file === "src/findings.ts")).toBe(false);
  });
});

// #319: the overall score is a percentage of the mutated file set, never a repo-level claim. The
// covered scope must travel with it so "100% over one file" can't read as "the repo is tested".
describe("coveredScope (#319)", () => {
  it("reports the mutated file set straight from the Stryker report", () => {
    const summary = summarizeMutationReport(report);
    expect(summary.coveredScope).toEqual(["src/findings.ts", "src/scan/secrets.ts", "src/scan/supabase.ts"]);
  });

  it("renders a scope line that names the files and disclaims a whole-repo claim", () => {
    const line = coveredScopeLine(summarizeMutationReport(report));
    expect(line).toContain("3 mutated file(s)");
    expect(line).toContain("NOT a whole-repo coverage claim");
  });

  it("keeps a single-file scope legible — the proposit '100% over one file' case", () => {
    const oneFile: StrykerReport = { schemaVersion: "1", files: { "lib/pdf/launch.ts": { mutants: [mutant({ status: "Killed" })] } } };
    const summary = summarizeMutationReport(oneFile);
    expect(summary.overall.mutationScore).toBe(100);
    expect(coveredScopeLine(summary)).toContain("lib/pdf/launch.ts");
    expect(coveredScopeLine(summary)).toContain("1 mutated file(s)");
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

  // #386's acceptance ground truth: M8-P-TAUTOLOGICAL's documented survivors land on the
  // non-member branch, the negative-total guard, and the <100 boundary — so the breakdown must
  // identify discount.ts as denial/boundary-concentrated without any new fixture being planted.
  it("flags discount.ts as denial/boundary-concentrated (4 boundary-family vs 2 other survivors) and leaves authz.ts out", () => {
    const summary = summarizeMutationReport(m8Report);
    const discount = summary.mutatorBreakdown.find((b) => b.file === "discount.ts");
    expect(discount).toMatchObject({
      survivorsByMutator: { ConditionalExpression: 3, EqualityOperator: 1, StringLiteral: 1, ArithmeticOperator: 1 },
      boundarySurvivors: 4,
      otherSurvivors: 2,
      denialBoundaryConcentrated: true,
    });
    expect(summary.mutatorBreakdown.some((b) => b.file === "authz.ts")).toBe(false);
  });
});

// #224: supabase-multi-tenant-starter had no test script, no test-runner dep, and no Stryker
// config, so StrykerJS simply couldn't run — the CLI needs to detect that and report it as a
// finding instead of erroring out un-runnable.
describe("detectNoTestSuite", () => {
  it("reports missing when there's no package.json, no runner dep, and no Stryker config", () => {
    const result = detectNoTestSuite(undefined, false);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("no package.json found");
  });

  it("reports missing when scripts.test is only the npm-init placeholder and no runner dep/Stryker config exists", () => {
    const result = detectNoTestSuite({ scripts: { test: 'echo "Error: no test specified" && exit 1' } }, false);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("npm-init placeholder");
  });

  it("is not missing once a real test script is present", () => {
    const result = detectNoTestSuite({ scripts: { test: "vitest run" }, devDependencies: { vitest: "^3.0.0" } }, false);
    expect(result.missing).toBe(false);
  });

  it("is not missing when a known test-runner dependency is present even without a wired test script", () => {
    const result = detectNoTestSuite({ devDependencies: { jest: "^29.0.0" } }, false);
    expect(result.missing).toBe(false);
  });

  it("is not missing when a Stryker config already exists, even with no test script/dep detected", () => {
    const result = detectNoTestSuite(undefined, true);
    expect(result.missing).toBe(false);
  });
});

describe("noTestSuiteFinding / noTestSuiteModuleRecord", () => {
  it("emits a High-severity M8 finding carrying the detection reason", () => {
    const finding = noTestSuiteFinding("no package.json found; no known test-runner dependency; no stryker.conf.* found");
    expect(finding).toMatchObject({ severity: "High", confidence: "Confirmed", taxonomy: "M8 — No automated test suite" });
    expect(finding.evidence).toContain("no package.json found");
  });

  it("marks the M8 coverage record partial rather than a silent gap", () => {
    const record = noTestSuiteModuleRecord("no package.json found");
    expect(record).toMatchObject({ status: "partial" });
    expect(record.note).toContain("no package.json found");
  });
});
