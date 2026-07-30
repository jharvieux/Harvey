import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  coveredScopeLine,
  detectDryRunFailure,
  detectNoTestSuite,
  detectRootWorkspaceTestSuite,
  detectTestEnv,
  detectTestRunner,
  detectTs7TsconfigCrash,
  detectWorkspaceTestSuites,
  dryRunFailureFinding,
  dryRunFailureModuleRecord,
  isIncompatibleTypeScript7,
  isPlaceholderSpec,
  mutationNotRunModuleRecord,
  mutationScore,
  mutationScoreBasedOnCoveredCode,
  noCoverageFindings,
  noTestSuiteFinding,
  noTestSuiteModuleRecord,
  planTsconfigRewrites,
  reRootReportToApp,
  resolveJsonReporterPath,
  rootScopedMutateGlobs,
  rootWorkspaceTestFinding,
  rootWorkspaceTestModuleRecord,
  scaffoldStrykerConfig,
  scopedRunModuleRecord,
  summarizeLineCoverage,
  summarizeMutationReport,
  survivingMutantFindings,
  testQualityFromArtifact,
  toReportRows,
  TS7_TSCONFIG_BYPASS_FILENAME,
  unverifiableScopeModuleRecord,
  vacuousTestFiles,
  vacuousTestFindings,
  verifyMutationScope,
  withOffTreeScratch,
  withTs7TsconfigBypass,
  workspaceTestSuiteFinding,
  workspaceTestSuiteModuleRecord,
  type AncestorTestSignals,
  type IstanbulCoverageSummary,
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

// Real committed Stryker 9.6.1 report captures (see __fixtures__/stryker/PROVENANCE.md).
function loadStrykerCapture(name: string): StrykerReport {
  return JSON.parse(
    readFileSync(fileURLToPath(new URL(`./scan/__fixtures__/stryker/${name}`, import.meta.url)), "utf8"),
  ) as StrykerReport;
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

  // #1076: MEASURED against upstream's calculateMetrics.ts — RuntimeError sits in totalInvalid
  // alongside CompileError, excluded from the denominator entirely. Harvey previously counted it as
  // valid-but-undetected, silently pulling the score down; a comment claimed the mirror while the
  // code diverged.
  it("excludes RuntimeError from the denominator, same as CompileError (upstream calculateMetrics.ts)", () => {
    const mutants: StrykerMutant[] = [mutant({ status: "Killed" }), mutant({ status: "RuntimeError" })];
    expect(mutationScore(mutants)).toBe(100);
  });
});

// #1076: recomputed from the committed ATC capture, this diverges sharply from mutationScore
// (58.1% vs 27.8%) because half that repo's mutants were never executed at all — the two numbers
// tell different stories and Stryker's own report shows both.
describe("mutationScoreBasedOnCoveredCode (#1076)", () => {
  it("scores detected over covered (detected + survived), excluding NoCoverage from the denominator", () => {
    const mutants: StrykerMutant[] = [
      mutant({ status: "Killed" }),
      mutant({ status: "Survived" }),
      mutant({ status: "NoCoverage" }),
      mutant({ status: "NoCoverage" }),
    ];
    // covered = Killed + Survived = 2; detected = 1 → 50%, vs. mutationScore's 25% over all 4 valid.
    expect(mutationScoreBasedOnCoveredCode(mutants)).toBe(50);
    expect(mutationScore(mutants)).toBe(25);
  });

  it("returns 0 when every valid mutant has no coverage (nothing was ever executed)", () => {
    expect(mutationScoreBasedOnCoveredCode([mutant({ status: "NoCoverage" }), mutant({ status: "NoCoverage" })])).toBe(0);
  });

  it("returns 0 when there are no valid mutants at all", () => {
    expect(mutationScoreBasedOnCoveredCode([mutant({ status: "Ignored" })])).toBe(0);
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

  it("#819: merges per-module line coverage onto the same row when supplied", () => {
    const summary = summarizeMutationReport(report, ["src/scan/supabase.ts"]);
    const rows = toReportRows(summary, { "src/scan": 42.5, src: 100 });
    expect(rows.find((r) => r.module === "src/scan")).toMatchObject({ lineCoverage: 42.5 });
    expect(rows.find((r) => r.module === "src")).toMatchObject({ lineCoverage: 100 });
  });

  it("#819: a module absent from the coverage map gets no lineCoverage key — never a silent 0", () => {
    const summary = summarizeMutationReport(report, ["src/scan/supabase.ts"]);
    const rows = toReportRows(summary, { "src/scan": 42.5 });
    const srcRow = rows.find((r) => r.module === "src")!;
    expect("lineCoverage" in srcRow).toBe(false);
  });
});

describe("summarizeLineCoverage (#819)", () => {
  it("aggregates file-level Istanbul line coverage into the same per-directory module buckets as mutation scoring", () => {
    const coverage: IstanbulCoverageSummary = {
      total: { lines: { total: 999, covered: 999, skipped: 0, pct: 100 } },
      "src/scan/supabase.ts": { lines: { total: 10, covered: 5, skipped: 0, pct: 50 } },
      "src/scan/secrets.ts": { lines: { total: 10, covered: 10, skipped: 0, pct: 100 } },
      "src/findings.ts": { lines: { total: 4, covered: 4, skipped: 0, pct: 100 } },
    };
    const byModule = summarizeLineCoverage(coverage, "/repo");
    expect(byModule["src/scan"]).toBe(75); // (5+10)/(10+10)
    expect(byModule.src).toBe(100);
    expect(byModule.total).toBeUndefined(); // the Istanbul "total" key is not a module
  });

  it("un-absolutes file keys relative to targetDir before bucketing", () => {
    const coverage: IstanbulCoverageSummary = {
      "/repo/src/findings.ts": { lines: { total: 8, covered: 4, skipped: 0, pct: 50 } },
    };
    expect(summarizeLineCoverage(coverage, "/repo")).toEqual({ src: 50 });
  });
});

describe("resolveJsonReporterPath (#820)", () => {
  it("reads a custom jsonReporter.fileName off the resolved config", () => {
    expect(resolveJsonReporterPath({ jsonReporter: { fileName: "out/custom-report.json" } })).toBe("out/custom-report.json");
  });

  it("falls back to Stryker's documented default when the config has no jsonReporter entry", () => {
    expect(resolveJsonReporterPath(undefined)).toBe("reports/mutation/mutation.json");
    expect(resolveJsonReporterPath({})).toBe("reports/mutation/mutation.json");
  });
});

// M8 calibration corpus (#72 §M8) — a REAL Stryker 9.6.1 JSON capture, committed byte-faithful
// (config/framework/projectRoot dropped — machine-specific, unread) with a sibling PROVENANCE.md,
// from `npx stryker run` against targets/calibration/test-quality/ (stryker.config.json,
// coverageAnalysis: "perTest", vitest test runner). Was TRANSCRIBED-FROM-RUN (rebuilt through the
// mutant() helper); #1150 points the test at the raw report so it can be re-captured and diffed.
// See src/scan/calibration/m8.entries.ts (M8-P-TAUTOLOGICAL / M8-N-STRONG) and
// targets/calibration/GROUND-TRUTH.md "M8 (#72)" for the full answer key + live result.
const m8Report = loadStrykerCapture("stryker-9.6.1-m8-calibration.json");

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

// #435: a real Stryker run's { summary, reportRows } carried no report-schema Finding[] — only
// the no-test-suite branch's M8-00 contributed to the deliverable. This maps the ONE signal §3b's
// console warning already calls out (denial/boundary concentration), one finding per file, not one
// per surviving mutant (a repo can have hundreds of the latter).
describe("survivingMutantFindings (#435)", () => {
  it("emits one finding for discount.ts (denial/boundary-concentrated) and none for authz.ts (strong suite)", () => {
    const summary = summarizeMutationReport(m8Report);
    const findings = survivingMutantFindings(summary);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "M8-02-01",
      category: "Test quality",
      taxonomy: "M8 — Denial/boundary path untested",
      location: "discount.ts",
      severity: "Medium",
    });
  });

  it("raises severity to High when the concentrated file is a flagged M1/M3 hotspot", () => {
    const summary = summarizeMutationReport(m8Report, ["discount.ts"]);
    const findings = survivingMutantFindings(summary);
    expect(findings[0]?.severity).toBe("High");
    expect(findings[0]?.evidence).toMatch(/flagged M1\/M3 hotspot/);
  });

  it("emits nothing when no file's survivors concentrate in the boundary/negation families", () => {
    expect(survivingMutantFindings(summarizeMutationReport(report))).toEqual([]);
  });
});

// #1100: MEASURED against a live `npx stryker run` capture (a scratch fixture with a module-level
// `const LIMIT = 10 * 2`) — a static mutant reads coveredBy: [] even when it IS killed, because
// perTest coverage analysis cannot attribute a once-per-suite mutant to any one test. It is weaker
// evidence than an ordinary per-test survivor, so a boundary-concentrated file whose survivors are
// MOSTLY static downgrades confidence to "Review" instead of "Confirmed".
describe("survivingMutantFindings — STATIC confidence downgrade (#1100)", () => {
  // Same shape as discount.ts's concentration (3 ConditionalExpression + 1 EqualityOperator
  // boundary survivors, 2 other) but every boundary survivor is static.
  const mostlyStaticReport: StrykerReport = {
    schemaVersion: "1",
    files: {
      "static-heavy.ts": {
        mutants: [
          mutant({ id: "s1", mutatorName: "ConditionalExpression", status: "Survived", static: true }),
          mutant({ id: "s2", mutatorName: "ConditionalExpression", status: "Survived", static: true }),
          mutant({ id: "s3", mutatorName: "ConditionalExpression", status: "Survived", static: true }),
          mutant({ id: "s4", mutatorName: "EqualityOperator", status: "Survived", static: false }),
          mutant({ id: "s5", mutatorName: "StringLiteral", status: "Survived", static: false }),
          mutant({ id: "s6", mutatorName: "ArithmeticOperator", status: "Survived", static: false }),
        ],
      },
    },
  };

  it("downgrades confidence to Review when a majority of boundary survivors are static", () => {
    const findings = survivingMutantFindings(summarizeMutationReport(mostlyStaticReport));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ confidence: "Review", location: "static-heavy.ts" });
    expect(findings[0]?.evidence).toContain("3/4 of the boundary survivors are STATIC");
  });

  it("keeps confidence Confirmed when static survivors are a minority (discount.ts's real shape has none)", () => {
    // discount.ts's captured survivors are all per-test (static: false) — the real corpus shape.
    const findings = survivingMutantFindings(summarizeMutationReport(m8Report));
    expect(findings[0]).toMatchObject({ confidence: "Confirmed", location: "discount.ts" });
  });
});

// #1076: ModuleMutationSummary already counted noCoverage per module; nothing turned it into a
// Finding. A module the suite never even EXECUTED is a stronger signal than a surviving mutant
// (survivingMutantFindings above) — this is the gap MEASURED at 50.8% on the committed ATC capture.
describe("noCoverageFindings (#1076)", () => {
  // Each fixture file lives in its OWN top-level directory: moduleOf() groups by dirname, so
  // files sharing a directory would sum into one module's counts — these three are deliberately
  // separate modules so each threshold case (majority/minority/too-small) is isolated.
  const untested: StrykerReport = {
    schemaVersion: "1",
    files: {
      "never-tested/file.ts": {
        mutants: Array.from({ length: 8 }, (_, i) => mutant({ id: `nt${i}`, status: i === 0 ? "Killed" : "NoCoverage" })),
      },
      "well-tested/file.ts": {
        mutants: [mutant({ id: "wt1", status: "Killed" }), mutant({ id: "wt2", status: "Killed" }), mutant({ id: "wt3", status: "NoCoverage" })],
      },
      "tiny/file.ts": {
        mutants: [mutant({ id: "t1", status: "NoCoverage" }), mutant({ id: "t2", status: "NoCoverage" })],
      },
    },
  };

  it("emits an M8-05 finding for a module whose mutants are majority NoCoverage", () => {
    const findings = noCoverageFindings(summarizeMutationReport(untested));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "M8-05-01",
      category: "Test quality",
      taxonomy: "M8 — Module has no mutation test coverage",
      location: "never-tested",
      severity: "Medium", // 7/8 = 87.5%, below the 90% High threshold
    });
  });

  it("stays silent on a module below the no-coverage ratio threshold (2/3 killed)", () => {
    const findings = noCoverageFindings(summarizeMutationReport(untested));
    expect(findings.some((f) => f.location === "well-tested")).toBe(false);
  });

  it("stays silent on a module too small to be a signal, even at 100% no-coverage", () => {
    const findings = noCoverageFindings(summarizeMutationReport(untested));
    expect(findings.some((f) => f.location === "tiny")).toBe(false);
  });

  it("states the exact never-executed count and ratio in the evidence", () => {
    const [finding] = noCoverageFindings(summarizeMutationReport(untested));
    expect(finding?.evidence).toContain("7/8 mutant(s)");
    expect(finding?.evidence).toContain("NEVER EXECUTED");
  });

  it("raises severity to High at or above a 90% no-coverage ratio", () => {
    const whollyUntested: StrykerReport = {
      schemaVersion: "1",
      files: { "dead-code/file.ts": { mutants: Array.from({ length: 6 }, (_, i) => mutant({ id: `d${i}`, status: "NoCoverage" })) } },
    };
    const [finding] = noCoverageFindings(summarizeMutationReport(whollyUntested));
    expect(finding?.severity).toBe("High");
  });
});

// #1100: a REAL Stryker 9.6.1 JSON capture (`npx stryker run stryker.vacuous.config.json` from
// targets/calibration/test-quality/, coverageAnalysis: "perTest"), committed byte-faithful with a
// sibling PROVENANCE.md, of the planted M8-P-VACUOUS-STRYKER fixture — vacuous.ts's gradeScore(),
// covered ONLY by vacuous.smoke.test.ts's single test, which calls gradeScore(85) and then asserts
// expect(true).toBe(true): the call executes real branches (coveredBy is non-empty) but the
// assertion never depends on the return value, so the live run scored 0% (10 Survived + 2
// NoCoverage of 12, 0 Killed) — the answer key for the testFiles/coveredBy/killedBy join. See
// targets/calibration/GROUND-TRUTH.md "M8 (#1100)" and src/scan/calibration/m8.entries.ts.
const vacuousReport = loadStrykerCapture("stryker-9.6.1-m8-vacuous.json");

describe("vacuousTestFiles / vacuousTestFindings (#1100) — live Stryker capture", () => {
  it("flags vacuous.smoke.test.ts: it covers 10 mutants but kills none of them", () => {
    const files = vacuousTestFiles(vacuousReport);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatchObject({
      path: "vacuous.smoke.test.ts",
      vacuousTests: [{ id: "0", name: "gradeScore (vacuous smoke test) runs without throwing" }],
      executedMutantCount: 10,
    });
  });

  it("emits an M8-06 finding naming the test(s) and the executed-but-unkilled count", () => {
    const findings = vacuousTestFindings(vacuousReport);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "M8-06-01",
      category: "Test quality",
      taxonomy: "M8 — Vacuous test (executes code, kills zero mutants)",
      location: "vacuous.smoke.test.ts",
      severity: "Medium",
      confidence: "Confirmed",
    });
    expect(findings[0]?.evidence).toContain("10 mutant(s)");
    expect(findings[0]?.evidence).toContain("gradeScore (vacuous smoke test) runs without throwing");
  });

  it("returns nothing when the report carries no testFiles (an older Stryker run, or a hand-assembled report)", () => {
    expect(vacuousTestFiles(m8Report)).toEqual([]);
  });

  it("clears a test file where at least one covering test kills something (discount.tautological.test.ts's real shape)", () => {
    // m8Report predates #1100 and has no testFiles — build a minimal one reusing its real
    // coveredBy/killedBy shape (test "4" DOES kill several discount.ts mutants).
    const withKills: StrykerReport = {
      ...m8Report,
      testFiles: { "discount.tautological.test.ts": { tests: [{ id: "4", name: "gives members a discount on a big order" }] } },
      files: { "discount.ts": { mutants: [mutant({ id: "d1", status: "Survived", coveredBy: ["4"] }), mutant({ id: "d2", status: "Killed", coveredBy: ["4"], killedBy: ["4"] })] } },
    };
    expect(vacuousTestFiles(withKills)).toEqual([]);
  });

  it("clears a test file that never ran against mutated code at all — that gap is NoCoverage's, not this one", () => {
    const neverRan: StrykerReport = {
      schemaVersion: "1",
      testFiles: { "unrelated.test.ts": { tests: [{ id: "9", name: "some other test" }] } },
      files: { "file.ts": { mutants: [mutant({ id: "f1", status: "NoCoverage" })] } },
    };
    expect(vacuousTestFiles(neverRan)).toEqual([]);
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

// #252: harness present but suite absent — the agreed threshold is "zero test files, or a single
// placeholder/smoke spec". A single MEANINGFUL spec still counts as a suite (proposit's one real
// vitest spec must keep its mutation baseline; multi-tenant-starter's one real RLS test must keep
// its Docker not-run reason rather than being reclassified as no-suite).
describe("detectNoTestSuite — #252 harness-but-no-suite threshold", () => {
  const harness = { scripts: { test: "vitest run" }, devDependencies: { vitest: "^3.0.0" } };
  const realSpec = {
    path: "src/thing.test.ts",
    text: `import { it, expect } from "vitest";\nimport { add } from "./thing";\nit("adds", () => { expect(add(1, 2)).toBe(3); });\nit("rejects negatives", () => { expect(() => add(-1, 2)).toThrow(); });\n`,
  };

  it("reports missing when a harness is configured but the tree has zero test files", () => {
    const result = detectNoTestSuite(harness, false, []);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("ZERO test files");
  });

  it("reports missing when the only test file is a placeholder (no test cases)", () => {
    const result = detectNoTestSuite(harness, false, [{ path: "smoke.test.ts", text: "// TODO write tests\n" }]);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("smoke.test.ts");
    expect(result.reason).toContain("placeholder");
  });

  it("reports missing when the only test file asserts nothing", () => {
    const result = detectNoTestSuite(harness, false, [
      { path: "app.spec.ts", text: `it("boots", async () => { await import("./app"); });\n` },
    ]);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("zero assertions");
  });

  it("reports missing when the only test file's assertions are constant tautologies", () => {
    const result = detectNoTestSuite(harness, false, [
      { path: "sanity.test.ts", text: `it("works", () => { expect(true).toBe(true); });\ntest("still works", () => { expect(1).toBe(1); });\n` },
    ]);
    expect(result.missing).toBe(true);
    expect(result.reason).toContain("tautological");
  });

  it("does NOT report missing for a single meaningful spec — the threshold is ≤1 placeholder, not ≤1 file", () => {
    expect(detectNoTestSuite(harness, false, [realSpec]).missing).toBe(false);
  });

  it("does NOT report missing for two files even if one is a placeholder", () => {
    const placeholder = { path: "smoke.test.ts", text: `it("is alive", () => {});\n` };
    expect(detectNoTestSuite(harness, false, [realSpec, placeholder]).missing).toBe(false);
  });

  it("keeps the pre-#252 behavior when no census is supplied", () => {
    expect(detectNoTestSuite(harness, false).missing).toBe(false);
  });
});

describe("isPlaceholderSpec (#252)", () => {
  it("calls a real assertion over computed values meaningful", () => {
    expect(isPlaceholderSpec(`it("x", () => { expect(compute(4)).toEqual({ total: 8 }); });`).placeholder).toBe(false);
  });
  it("handles node:test style assert calls as real assertions", () => {
    expect(isPlaceholderSpec(`test("rls", async () => { assert.ok(rows.length > 0); });`).placeholder).toBe(false);
  });
  it("treats a nested constant-only expectation as tautological", () => {
    expect(isPlaceholderSpec(`it("x", () => { expect(true).toBe(true); });`)).toMatchObject({ placeholder: true });
  });
});

describe("noTestSuiteFinding / noTestSuiteModuleRecord", () => {
  it("emits a High-severity M8 finding carrying the detection reason", () => {
    const finding = noTestSuiteFinding("no package.json found; no known test-runner dependency; no stryker.conf.* found");
    expect(finding).toMatchObject({ severity: "High", confidence: "Confirmed", taxonomy: "M8 — No automated test suite" });
    expect(finding.evidence).toContain("no package.json found");
  });

  it("flags the record noSuite:true so the M8 probe can read it as a complete verdict, not a gap (#754)", () => {
    const record = noTestSuiteModuleRecord("no package.json found");
    expect(record).toMatchObject({ status: "partial", noSuite: true });
    expect(record.note).toContain("no package.json found");
  });
});

describe("detectTestRunner / scaffoldStrykerConfig (#513)", () => {
  it("detects vitest/jest/mocha from either dependency block, mapping to the Stryker runner plugin", () => {
    expect(detectTestRunner({ devDependencies: { vitest: "^3.0.0" } })).toEqual({ runner: "vitest", plugin: "@stryker-mutator/vitest-runner" });
    expect(detectTestRunner({ dependencies: { mocha: "^10.0.0" } })).toEqual({ runner: "mocha", plugin: "@stryker-mutator/mocha-runner" });
  });

  it("prefers vitest over jest when both are present, and detects nothing for unsupported runners", () => {
    expect(detectTestRunner({ devDependencies: { jest: "^29.0.0", vitest: "^3.0.0" } })?.runner).toBe("vitest");
    expect(detectTestRunner({ devDependencies: { ava: "^6.0.0" } })).toBeUndefined();
    expect(detectTestRunner(undefined)).toBeUndefined();
  });

  it("scaffolds the minimal config the M8 wrapper needs: perTest coverage, json reporter, detected runner", () => {
    const cfg = scaffoldStrykerConfig("jest", ["src"]);
    expect(cfg).toMatchObject({ testRunner: "jest", coverageAnalysis: "perTest" });
    expect(cfg.reporters).toContain("json");
    expect(cfg.jsonReporter).toEqual({ fileName: "reports/mutation/mutation.json" });
  });

  // #1284: Stryker's default plugin discovery (`plugins: ["@stryker-mutator/*"]`) globs relative to
  // wherever @stryker-mutator/core itself resolved from — MEASURED against the installed 9.6.1
  // source, that does not reliably reach a sibling runner package under pnpm's content-addressable
  // node_modules layout, even though the plugin is genuinely installed and resolves fine as a bare
  // import. Naming it explicitly skips the glob (and the layout it depends on) entirely.
  it("names the runner plugin explicitly rather than relying on Stryker's default glob discovery", () => {
    expect(scaffoldStrykerConfig("jest", ["src"]).plugins).toEqual(["@stryker-mutator/jest-runner"]);
    expect(scaffoldStrykerConfig("vitest", []).plugins).toEqual(["@stryker-mutator/vitest-runner"]);
    expect(scaffoldStrykerConfig("mocha", ["src"]).plugins).toEqual(["@stryker-mutator/mocha-runner"]);
  });

  it("builds mutate globs only from source dirs that exist, excluding tests/types/node_modules", () => {
    const cfg = scaffoldStrykerConfig("vitest", ["src", "app"]);
    expect(cfg.mutate).toEqual([
      "src/**/*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}",
      "app/**/*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}",
      "!**/*.test.*",
      "!**/*.spec.*",
      "!**/__tests__/**",
      "!**/*.d.ts",
      "!**/node_modules/**",
    ]);
  });

  it("omits mutate entirely when no known source dir exists — Stryker defaults, honestly unverifiable scope", () => {
    const cfg = scaffoldStrykerConfig("vitest", []);
    expect("mutate" in cfg).toBe(false);
    expect(verifyMutationScope(["a.ts"], undefined, ["a.ts"]).verified).toBe(false);
  });

  it("scaffolded globs are evaluable by the #504 scope check — a scaffolded run's scope is always verifiable", () => {
    const cfg = scaffoldStrykerConfig("vitest", ["src"]);
    const scope = verifyMutationScope(["src/a.ts"], cfg.mutate as string[], ["src/a.ts", "src/b.ts", "src/a.test.ts", "src/types.d.ts"]);
    expect(scope.verified).toBe(true);
    expect(scope.scoped).toBe(true);
    expect(scope.missing).toEqual(["src/b.ts"]);
  });

  it("mutationNotRunModuleRecord states the full degradation ladder and the reason — never a silent drop", () => {
    const record = mutationNotRunModuleRecord("no recognized test runner");
    expect(record.status).toBe("partial");
    expect(record.note).toContain("no recognized test runner");
    expect(record.note).toMatch(/full mutation.*--stub-check.*test-intent.*M8-00/s);
  });
});

describe("TS7 tsconfig-preprocessor bypass (#773)", () => {
  it("flags TypeScript 7 and newer as incompatible, and pre-7 versions as fine", () => {
    expect(isIncompatibleTypeScript7("7.0.2")).toBe(true);
    expect(isIncompatibleTypeScript7("8.1.0")).toBe(true);
    expect(isIncompatibleTypeScript7("5.9.3")).toBe(false);
    expect(isIncompatibleTypeScript7("6.9.9")).toBe(false);
    expect(isIncompatibleTypeScript7(undefined)).toBe(false);
  });

  it("withTs7TsconfigBypass adds tsconfigFile without mutating or dropping the original config", () => {
    const original = { testRunner: "vitest", coverageAnalysis: "perTest", mutate: ["src/**/*.ts"] };
    const patched = withTs7TsconfigBypass(original);
    expect(patched).toMatchObject({ testRunner: "vitest", coverageAnalysis: "perTest", mutate: ["src/**/*.ts"] });
    expect(patched.tsconfigFile).toBe(TS7_TSCONFIG_BYPASS_FILENAME);
    expect(original).not.toHaveProperty("tsconfigFile"); // never mutates the input
  });

  it("withOffTreeScratch redirects all three Stryker write locations without mutating or dropping the original", () => {
    const original = { testRunner: "vitest", coverageAnalysis: "perTest", tempDirName: "stryker-tmp", jsonReporter: { fileName: "reports/mutation/mutation.json" } };
    const paths = { tempDir: "/scratch/stryker-tmp", reportFile: "/scratch/reports/mutation/mutation.json", incrementalFile: "/scratch/incremental.json" };
    const patched = withOffTreeScratch(original, paths);
    expect(patched.tempDirName).toBe("/scratch/stryker-tmp");
    expect(patched.jsonReporter).toEqual({ fileName: "/scratch/reports/mutation/mutation.json" });
    expect(patched.incrementalFile).toBe("/scratch/incremental.json");
    expect(patched.testRunner).toBe("vitest"); // everything else survives
    expect(original.tempDirName).toBe("stryker-tmp"); // never mutates the input
    expect(original.jsonReporter.fileName).toBe("reports/mutation/mutation.json");
  });

  it("withOffTreeScratch keeps the target's other jsonReporter keys while overriding fileName", () => {
    const patched = withOffTreeScratch({ jsonReporter: { fileName: "reports/x.json", someFutureOption: true } }, { tempDir: "/s/t", reportFile: "/s/r.json", incrementalFile: "/s/i.json" });
    expect(patched.jsonReporter).toEqual({ fileName: "/s/r.json", someFutureOption: true });
  });

  it("withOffTreeScratch redirects a config that declared none of the three (Stryker's cwd-relative defaults would apply)", () => {
    const patched = withOffTreeScratch({ testRunner: "jest" }, { tempDir: "/s/t", reportFile: "/s/r.json", incrementalFile: "/s/i.json" });
    expect(patched.tempDirName).toBe("/s/t");
    expect(patched.jsonReporter).toEqual({ fileName: "/s/r.json" });
  });

  it("detectTs7TsconfigCrash recognizes the exact upstream crash signature, with or without the `ts.` receiver", () => {
    expect(detectTs7TsconfigCrash("TypeError: ts.parseConfigFileTextToJson is not a function")).toBe(true);
    expect(detectTs7TsconfigCrash("    at TSConfigPreprocessor.rewriteTSConfigFile (parseConfigFileTextToJson is not a function)")).toBe(true);
  });

  it("detectTs7TsconfigCrash does not fire on unrelated Stryker output (no false positives)", () => {
    expect(detectTs7TsconfigCrash("Final mutation score of 42.00 is lower than break threshold")).toBe(false);
    expect(detectTs7TsconfigCrash("")).toBe(false);
  });
});

describe("planTsconfigRewrites — Harvey's own preprocessor replacement (#773 reopened)", () => {
  // The exact shape MEASURED 2026-07-27 against a real TS7 target (apps/web extending a
  // repo-root tsconfig.base.json two levels up) — the standard monorepo pattern the bypass alone
  // left broken.
  const files = new Map<string, string>([
    ["/repo/apps/web/tsconfig.json", JSON.stringify({ extends: "../../tsconfig.base.json", include: ["src"] })],
    ["/repo/tsconfig.base.json", JSON.stringify({ compilerOptions: { strict: true } })],
  ]);
  const readFile = (p: string) => files.get(p);

  it("rewrites an extends chain reaching outside the boundary dir to an absolute path", () => {
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", readFile);
    expect(rewrites).toHaveLength(1);
    expect(rewrites[0]!.path).toBe("/repo/apps/web/tsconfig.json");
    const rewritten = JSON.parse(rewrites[0]!.text);
    expect(rewritten.extends).toBe("/repo/tsconfig.base.json");
    expect(rewritten.include).toEqual(["src"]); // everything else survives
  });

  it("leaves an extends chain that stays inside the boundary dir untouched — no rewrite needed", () => {
    const inside = new Map([
      ["/repo/apps/web/tsconfig.json", JSON.stringify({ extends: "./tsconfig.local.json" })],
      ["/repo/apps/web/tsconfig.local.json", JSON.stringify({ compilerOptions: {} })],
    ]);
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", (p) => inside.get(p));
    expect(rewrites).toEqual([]);
  });

  it("recurses through an inside hop to rewrite a further outside hop (a 2-level chain)", () => {
    const chain = new Map([
      ["/repo/apps/web/tsconfig.json", JSON.stringify({ extends: "./tsconfig.local.json" })],
      ["/repo/apps/web/tsconfig.local.json", JSON.stringify({ extends: "../../tsconfig.base.json" })],
      ["/repo/tsconfig.base.json", JSON.stringify({ compilerOptions: {} })],
    ]);
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", (p) => chain.get(p));
    expect(rewrites).toHaveLength(1);
    expect(rewrites[0]!.path).toBe("/repo/apps/web/tsconfig.local.json");
    expect(JSON.parse(rewrites[0]!.text).extends).toBe("/repo/tsconfig.base.json");
  });

  it("rewrites references[].path the same way as extends", () => {
    const refs = new Map([
      ["/repo/apps/web/tsconfig.json", JSON.stringify({ references: [{ path: "../../packages/shared" }] })],
    ]);
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", (p) => refs.get(p));
    expect(rewrites).toHaveLength(1);
    expect(JSON.parse(rewrites[0]!.text).references).toEqual([{ path: "/repo/packages/shared" }]);
  });

  it("leaves an already-absolute extends alone — Stryker's own preprocessor only rewrites relative refs", () => {
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", (p) =>
      new Map([["/repo/apps/web/tsconfig.json", JSON.stringify({ extends: "/opt/shared/tsconfig.json" })]]).get(p),
    );
    expect(rewrites).toEqual([]);
  });

  it("returns no rewrites when the entry tsconfig doesn't exist", () => {
    expect(planTsconfigRewrites("/repo/apps/web", "tsconfig.json", () => undefined)).toEqual([]);
  });

  it("returns no rewrites for a non-JSON-parseable tsconfig (comments/trailing commas) rather than throwing", () => {
    const rewrites = planTsconfigRewrites("/repo/apps/web", "tsconfig.json", (p) =>
      p.endsWith("tsconfig.json") ? "// a comment\n{ \"extends\": \"../../tsconfig.base.json\", }" : undefined,
    );
    expect(rewrites).toEqual([]);
  });

  it("does not infinite-loop on a cyclic extends chain", () => {
    const cyclic = new Map([
      ["/repo/a/tsconfig.json", JSON.stringify({ extends: "../b/tsconfig.json" })],
      ["/repo/b/tsconfig.json", JSON.stringify({ extends: "../a/tsconfig.json" })],
    ]);
    expect(() => planTsconfigRewrites("/repo/a", "tsconfig.json", (p) => cyclic.get(p))).not.toThrow();
  });
});

describe("verifyMutationScope (#504)", () => {
  const SOURCES = ["src/auth.ts", "src/billing.ts", "src/util/dates.ts", "src/types.d.ts", "scripts/build.ts", "src/auth.test.ts"];
  const GLOBS = ["src/**/*.ts", "!**/*.test.ts"];

  it("verifies a run that covered every file the configured mutate globs match", () => {
    const scope = verifyMutationScope(["src/auth.ts", "src/billing.ts", "src/util/dates.ts"], GLOBS, SOURCES);
    expect(scope).toMatchObject({ verified: true, scoped: false, expectedFileCount: 3 });
  });

  it("flags a subset run as scoped, naming the count and the missing files — the ATC 263-file case in miniature", () => {
    const scope = verifyMutationScope(["src/auth.ts"], GLOBS, SOURCES);
    expect(scope.scoped).toBe(true);
    expect(scope.missingCount).toBe(2);
    expect(scope.missing).toEqual(["src/billing.ts", "src/util/dates.ts"]);
    expect(scope.note).toContain("src/billing.ts");
  });

  it("excludes .d.ts files from the expected set — no executable code, no mutants, no false scoping", () => {
    const scope = verifyMutationScope(["src/auth.ts", "src/billing.ts", "src/util/dates.ts"], ["src/**/*.ts", "!**/*.test.ts"], SOURCES);
    expect(scope.scoped).toBe(false);
  });

  it("respects negation globs — test files the config excludes are not expected", () => {
    const scope = verifyMutationScope(["src/auth.ts", "src/billing.ts", "src/util/dates.ts"], GLOBS, SOURCES);
    expect(scope.scoped).toBe(false);
  });

  it("expands brace alternations like real Stryker configs use", () => {
    const scope = verifyMutationScope(["src/auth.ts"], ["{src,lib}/**/*.{ts,tsx}", "!**/*.test.ts", "!**/*.d.ts"], ["src/auth.ts", "lib/x.tsx"]);
    expect(scope.scoped).toBe(true);
    expect(scope.missing).toEqual(["lib/x.tsx"]);
  });

  it("reports unverifiable (never guessing) when there are no statically readable mutate globs", () => {
    const scope = verifyMutationScope(["src/auth.ts"], undefined, SOURCES);
    expect(scope).toMatchObject({ verified: false, scoped: false });
    expect(scope.note).toMatch(/not statically readable/);
  });

  it("reports unverifiable on glob syntax it cannot evaluate, naming the glob", () => {
    const scope = verifyMutationScope(["src/auth.ts"], ["src/**/!(*.spec).ts"], SOURCES);
    expect(scope).toMatchObject({ verified: false, scoped: false });
    expect(scope.note).toContain("!(*.spec)");
  });

  // #1309: the branch #504's own tests skipped — verified: false is neither a proven full run nor
  // a proven subset, so it needs its OWN moduleRecord (the caller in src/cli/mutation-scan.ts wires
  // this in whenever scope.verified is false), never silence that lets a full `ran` stand.
  it("unverifiableScopeModuleRecord is partial and carries the scope's own unverifiable note", () => {
    const noGlobs = verifyMutationScope(["src/a.ts"], undefined, ["src/a.ts", "src/b.ts"]);
    expect(noGlobs).toMatchObject({ verified: false, scoped: false });
    const record = unverifiableScopeModuleRecord(noGlobs);
    expect(record.status).toBe("partial");
    expect(record.note).toMatch(/#1309/);
    expect(record.note).toMatch(/not statically readable/);

    const badGlob = verifyMutationScope(["src/auth.ts"], ["src/**/!(*.spec).ts"], SOURCES);
    const record2 = unverifiableScopeModuleRecord(badGlob);
    expect(record2.note).toContain("!(*.spec)");
  });

  it("scopedRunModuleRecord is partial and says a subset is never the module's measurement", () => {
    const scope = verifyMutationScope(["src/auth.ts"], GLOBS, SOURCES);
    const record = scopedRunModuleRecord(scope);
    expect(record.status).toBe("partial");
    expect(record.note).toMatch(/never ran \(#504\)/);
    expect(record.note).toContain("src/billing.ts");
  });
});

describe("detectTestEnv (#503)", () => {
  it("reads a YAML env mapping from a CI workflow — the ATC TZ case", () => {
    const env = detectTestEnv([{ path: ".github/workflows/ci.yml", text: "jobs:\n  test:\n    env:\n      TZ: Pacific/Honolulu\n" }]);
    expect(env).toEqual([{ key: "TZ", value: "Pacific/Honolulu", source: ".github/workflows/ci.yml" }]);
  });

  it("reads an inline env prefix from a package.json test script", () => {
    const env = detectTestEnv([{ path: "package.json (scripts)", text: JSON.stringify({ test: "TZ=UTC vitest run" }) }]);
    expect(env).toEqual([{ key: "TZ", value: "UTC", source: "package.json (scripts)" }]);
  });

  it("reads a quoted env object entry from a vitest config", () => {
    const env = detectTestEnv([{ path: "vitest.config.ts", text: `export default { test: { env: { TZ: "America/New_York", LANG: "en_US.UTF-8" } } };` }]);
    expect(env).toContainEqual({ key: "TZ", value: "America/New_York", source: "vitest.config.ts" });
    expect(env).toContainEqual({ key: "LANG", value: "en_US.UTF-8", source: "vitest.config.ts" });
  });

  it("reads a process.env assignment from a setup file — the runtime-reassignment pattern that needs process-start replication", () => {
    const env = detectTestEnv([{ path: "vitest.setup.ts", text: `process.env.TZ = "Pacific/Honolulu";\n` }]);
    expect(env).toEqual([{ key: "TZ", value: "Pacific/Honolulu", source: "vitest.setup.ts" }]);
  });

  it("first declaration per key wins across the caller-ordered file list (runner config beats workflow)", () => {
    const env = detectTestEnv([
      { path: "vitest.config.ts", text: `env: { TZ: "UTC" }` },
      { path: ".github/workflows/ci.yml", text: "env:\n  TZ: Pacific/Honolulu\n" },
    ]);
    expect(env).toEqual([{ key: "TZ", value: "UTC", source: "vitest.config.ts" }]);
  });

  it("ignores env keys outside the locale/timezone allowlist — CI secrets must never be scraped", () => {
    const env = detectTestEnv([{ path: ".github/workflows/ci.yml", text: "env:\n  DATABASE_URL: postgres://x\n  API_TOKEN: abc\n" }]);
    expect(env).toEqual([]);
  });
});

describe("detectDryRunFailure / dry-run-failure verdict (#503)", () => {
  const STRYKER_FAIL = [
    "12:01:02 (1234) ERROR Stryker Something went wrong",
    "× src/format-date.test.ts > formats a negative-UTC-offset timezone",
    "ConfigError: There were failed tests in the initial test run.",
  ].join("\n");

  it("recognizes Stryker's failed-initial-test-run abort and extracts the first failing test line", () => {
    const verdict = detectDryRunFailure(STRYKER_FAIL);
    expect(verdict.failed).toBe(true);
    expect(verdict.detail).toContain("format-date.test.ts");
  });

  it("recognizes an initial-test-run timeout", () => {
    expect(detectDryRunFailure("Initial test run timed out!").failed).toBe(true);
  });

  it("does not fire on ordinary Stryker output (break-threshold exit, score table)", () => {
    expect(detectDryRunFailure("Final mutation score of 42.00 is lower than break threshold").failed).toBe(false);
  });

  // #1284: MEASURED against the installed Stryker 9.6.1 source
  // (@stryker-mutator/core/dist/src/process/3-dry-run-executor.js's validateResultCompleted) — a
  // dry run that ERRORS or TIMES OUT (DryRunStatus.Error/Timeout, as opposed to running tests that
  // then fail) throws the plain "Something went wrong in the initial test run", not either phrase
  // the regex previously recognized. Before this fix that phrase went unmatched, and the CLI's
  // "report not found" fallback wrote NO artifact at all — a real Stryker 9.6.1 run against a
  // TypeScript-7 target hit exactly this in #773's own verification.
  it("recognizes Stryker 9.6.1's actual 'something went wrong' phrasing for an errored/timed-out dry run", () => {
    const STRYKER_961_ERROR = ["12:03:44 (5678) ERROR StrykerJS One or more tests resulted in an error:", "\tTypeError: Cannot read properties of undefined", "12:03:44 (5678) ERROR StrykerJS Something went wrong in the initial test run"].join("\n");
    const verdict = detectDryRunFailure(STRYKER_961_ERROR);
    expect(verdict.failed).toBe(true);
    expect(verdict.detail).toContain("Something went wrong in the initial test run");
  });

  it("emits an M8-03 finding naming the applied env and the failing test", () => {
    const finding = dryRunFailureFinding("× format-date.test.ts > negative-UTC-offset", [{ key: "TZ", value: "UTC", source: "ci.yml" }]);
    expect(finding.id).toBe("M8-03");
    expect(finding.evidence).toContain("TZ=UTC");
    expect(finding.evidence).toContain("format-date.test.ts");
  });

  it("marks the coverage record partial with a distinct, actionable note — never a generic void", () => {
    const record = dryRunFailureModuleRecord("× format-date.test.ts", []);
    expect(record.status).toBe("partial");
    expect(record.note).toMatch(/dry run FAILED/);
    expect(record.note).toContain("format-date.test.ts");
  });
});

// #623: a per-app invocation on a workspace monorepo whose test config lives at the ROOT must be
// told apart from a genuinely untested package — a false "no test suite" reads as zero coverage on
// an app the root suite in fact covers.
describe("detectRootWorkspaceTestSuite (#623)", () => {
  const noSignals = { hasPnpmWorkspaceYaml: false, hasVitestWorkspaceConfig: false, hasGit: false };

  it("detects a monorepo root that declares workspaces AND a test suite (root test:* script)", () => {
    const ancestors: AncestorTestSignals[] = [
      { dir: "/repo", pkg: { workspaces: ["apps/*"], scripts: { "test:cross-tenant": "vitest run" }, devDependencies: { vitest: "^3" } }, ...noSignals, hasGit: true },
    ];
    const found = detectRootWorkspaceTestSuite(ancestors);
    expect(found?.root).toBe("/repo");
    expect(found?.reason).toMatch(/test:cross-tenant/);
    expect(found?.reason).toMatch(/monorepo root/);
  });

  it("detects a vitest workspace/projects config as both the root marker and the suite", () => {
    const ancestors: AncestorTestSignals[] = [
      { dir: "/repo", pkg: { name: "root" } as never, ...noSignals, hasVitestWorkspaceConfig: true, hasGit: true },
    ];
    expect(detectRootWorkspaceTestSuite(ancestors)?.root).toBe("/repo");
  });

  it("does NOT fire on a workspace root that has NO test suite — that is a real gap, not this one", () => {
    const ancestors: AncestorTestSignals[] = [
      { dir: "/repo", pkg: { workspaces: ["apps/*"] }, ...noSignals, hasGit: true },
    ];
    expect(detectRootWorkspaceTestSuite(ancestors)).toBeUndefined();
  });

  it("does NOT fire on a plain ancestor with a test suite but no workspace marker", () => {
    const ancestors: AncestorTestSignals[] = [
      { dir: "/somedir", pkg: { scripts: { test: "vitest run" }, devDependencies: { vitest: "^3" } }, ...noSignals, hasGit: true },
    ];
    expect(detectRootWorkspaceTestSuite(ancestors)).toBeUndefined();
  });

  it("emits an M8-04 measurement-gap finding and partial record — NOT the M8-00 zero-coverage shape", () => {
    const info = { root: "/repo", reason: 'a root "test:cross-tenant" script; package.json workspaces marks it a monorepo root' };
    const finding = rootWorkspaceTestFinding(info);
    expect(finding.id).toBe("M8-04");
    expect(finding.evidence).toContain("/repo");
    expect(finding.evidence).toMatch(/measurement gap/i);
    const record = rootWorkspaceTestModuleRecord(info);
    expect(record.status).toBe("partial");
    expect(record.note).toMatch(/#623/);
    expect(record.note).toMatch(/not suite-absent/);
  });
});

// #932: the inverse of #623 — a monorepo ROOT invoked directly whose own package.json carries no
// test script/runner dep, while its WORKSPACES carry the actual suites (documenso, measured
// 2026-07-24: root has neither, packages/lib declares `"test": "vitest run"`, 128 tracked spec
// files — the false M8-00 zero-coverage High this regression guards against).
describe("detectWorkspaceTestSuites (#932)", () => {
  it("finds a workspace child with its own test script", () => {
    const found = detectWorkspaceTestSuites([
      { path: "packages/lib", pkg: { scripts: { test: "vitest run" } } },
      { path: "apps/web", pkg: { scripts: {} } },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0]).toEqual({ path: "packages/lib", reason: 'a "test" script' });
  });

  it("finds a workspace child via a known runner dependency, with no script named test", () => {
    const found = detectWorkspaceTestSuites([{ path: "packages/signing", pkg: { devDependencies: { vitest: "^3" } } }]);
    expect(found).toEqual([{ path: "packages/signing", reason: "a vitest dependency" }]);
  });

  it("does NOT fire when no workspace child has a test script or runner dependency", () => {
    const found = detectWorkspaceTestSuites([
      { path: "apps/web", pkg: { scripts: {} } },
      { path: "packages/ui", pkg: undefined },
    ]);
    expect(found).toEqual([]);
  });

  it("ignores an npm-init placeholder test script on a workspace child, same as detectNoTestSuite's root check", () => {
    const found = detectWorkspaceTestSuites([{ path: "packages/x", pkg: { scripts: { test: 'echo "Error: no test specified" && exit 1' } } }]);
    expect(found).toEqual([]);
  });

  it("emits an M8-04 measurement-gap finding and partial record naming the workspaces — NOT the M8-00 zero-coverage shape", () => {
    const suites = [
      { path: "packages/lib", reason: 'a "test" script' },
      { path: "packages/signing", reason: "a vitest dependency" },
    ];
    const finding = workspaceTestSuiteFinding(suites);
    expect(finding.id).toBe("M8-04");
    expect(finding.evidence).toContain("packages/lib");
    expect(finding.evidence).toContain("packages/signing");
    expect(finding.evidence).toMatch(/measurement gap/i);
    const record = workspaceTestSuiteModuleRecord(suites);
    expect(record.status).toBe("partial");
    expect(record.note).toMatch(/#932/);
    expect(record.note).toMatch(/not suite-absent/);
  });
});

// #655: closes the #623 measurement gap — a root-scoped run's mutate globs and report file keys
// live in a different coordinate space (relative to the workspace ROOT) than an ordinary per-app
// run's (relative to the app). These two pure transforms are the seam between them; the CLI wires
// them around an actual Stryker invocation, which these fixture-based tests deliberately do not
// attempt (see #655's task note — no live Stryker run needed to prove the scoping logic).
describe("rootScopedMutateGlobs (#655)", () => {
  it("re-roots positive globs under the app's path from the workspace root", () => {
    expect(rootScopedMutateGlobs("apps/foo", ["src/**/*.{js,ts}", "lib/**/*.ts"])).toEqual([
      "apps/foo/src/**/*.{js,ts}",
      "apps/foo/lib/**/*.ts",
    ]);
  });

  it("leaves negated exclusion globs untouched — they are not app-specific", () => {
    expect(rootScopedMutateGlobs("apps/foo", ["src/**/*.ts", "!**/*.test.*", "!**/node_modules/**"])).toEqual([
      "apps/foo/src/**/*.ts",
      "!**/*.test.*",
      "!**/node_modules/**",
    ]);
  });

  it("is the inverse re-rooting scaffoldStrykerConfig's per-app globs need for a root cwd", () => {
    const appGlobs = scaffoldStrykerConfig("vitest", ["src"]).mutate as string[];
    const rootGlobs = rootScopedMutateGlobs("apps/foo", appGlobs);
    expect(rootGlobs[0]).toBe("apps/foo/src/**/*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}");
    // the four negated excludes are unchanged, just re-rooted-globs-adjacent
    expect(rootGlobs.slice(1)).toEqual(appGlobs.slice(1));
  });
});

describe("reRootReportToApp (#655)", () => {
  const rawReport: StrykerReport = {
    files: {
      "apps/foo/src/a.ts": { mutants: [mutant({ status: "Killed" })] },
      "apps/foo/src/b.ts": { mutants: [mutant({ status: "Survived" })] },
    },
  };

  it("strips the app's root-relative prefix so downstream code sees ordinary app-relative keys", () => {
    const { report, dropped } = reRootReportToApp(rawReport, "apps/foo");
    expect(Object.keys(report.files).sort()).toEqual(["src/a.ts", "src/b.ts"]);
    expect(dropped).toEqual([]);
  });

  it("drops (and reports) any file outside the app's prefix instead of mis-attributing it", () => {
    const mixed: StrykerReport = {
      files: { ...rawReport.files, "packages/shared/src/c.ts": { mutants: [mutant({ status: "Killed" })] } },
    };
    const { report, dropped } = reRootReportToApp(mixed, "apps/foo");
    expect(Object.keys(report.files).sort()).toEqual(["src/a.ts", "src/b.ts"]);
    expect(dropped).toEqual(["packages/shared/src/c.ts"]);
  });

  it("round-trips with rootScopedMutateGlobs: a report produced under root-rooted globs re-roots back to the app-rooted view", () => {
    const appGlobs = scaffoldStrykerConfig("vitest", ["src"]).mutate as string[];
    const rootGlobs = rootScopedMutateGlobs("apps/foo", appGlobs);
    // Every file the root-rooted globs would mutate carries the "apps/foo/" prefix Stryker's report
    // would use as its key when run with cwd = the workspace root.
    expect(rootGlobs.every((g) => g.startsWith("!") || g.startsWith("apps/foo/"))).toBe(true);
    const { report } = reRootReportToApp(rawReport, "apps/foo");
    expect(report.files["src/a.ts"]).toBeDefined();
  });
});

// #1045: the seam that was missing entirely — the CLI's --out artifact carried a real measurement
// and nothing turned it into the deliverable's §3b payload. The honesty rules travel with it: an
// unverifiable mutate scope is NOT a whole-repo claim, and a non-run must not fabricate a score.
describe("testQualityFromArtifact (#1045)", () => {
  const artifact = {
    summary: {
      overall: { mutationScore: 62.5 },
      coveredScope: ["src/auth.ts"],
      survivingMutants: [
        { file: "src/auth.ts", line: 42, mutatorName: "ConditionalExpression", hotspot: true },
        { file: "src/util.ts", line: 7, mutatorName: "BooleanLiteral", hotspot: false },
      ],
    },
    reportRows: [{ module: "src/auth", lineCoverage: 94, mutationScore: 41, survivingCount: 12, hotspotSurvivingCount: 3 }],
    scope: { verified: true, scoped: false, note: "run covered all 1 file(s) matched by the configured mutate globs" },
    lineCoverage: { status: "ran" as const },
  };

  it("carries the overall score, the per-module rows, the scope verdict and the survivors", () => {
    const tq = testQualityFromArtifact(artifact)!;
    expect(tq.mutationScore).toBe(62.5);
    expect(tq.rows).toEqual(artifact.reportRows);
    expect(tq.wholeRepo).toBe(true);
    expect(tq.survivorTotal).toBe(2);
    expect(tq.survivors[0]).toEqual({ file: "src/auth.ts", line: 42, mutator: "ConditionalExpression", hotspot: true });
  });

  it("treats an UNVERIFIABLE scope as not-whole-repo — unproven is not full coverage (#504)", () => {
    const unverified = { ...artifact, scope: { verified: false, scoped: false, note: "configured mutate scope not statically readable" } };
    expect(testQualityFromArtifact(unverified)!.wholeRepo).toBe(false);
    expect(testQualityFromArtifact({ ...artifact, scope: undefined })!.wholeRepo).toBe(false);
  });

  it("discloses a missing line-coverage verdict as partial rather than assuming it ran (#819)", () => {
    const tq = testQualityFromArtifact({ ...artifact, lineCoverage: undefined })!;
    expect(tq.lineCoverage.status).toBe("partial");
    expect(tq.lineCoverage.reason).toMatch(/no line-coverage verdict/);
  });

  it("returns nothing for an artifact that is not a mutation measurement", () => {
    // The no-test-suite branch: a finding and a moduleRecord, no summary. Inventing a table here
    // would put a fabricated score in front of a client.
    expect(testQualityFromArtifact({ finding: { id: "M8-00" }, moduleRecord: { status: "partial" } })).toBeUndefined();
    expect(testQualityFromArtifact(undefined)).toBeUndefined();
  });

  // #1076: the covered-code score threads through when the artifact carries it, and is simply
  // absent (never fabricated as 0 or copied from mutationScore) for an older artifact that predates it.
  it("carries mutationScoreBasedOnCoveredCode through when present, and omits it (not fabricates) when absent", () => {
    const withCovered = { ...artifact, summary: { ...artifact.summary, overall: { ...artifact.summary.overall, mutationScoreBasedOnCoveredCode: 58.1 } } };
    expect(testQualityFromArtifact(withCovered)!.mutationScoreBasedOnCoveredCode).toBe(58.1);
    expect(testQualityFromArtifact(artifact)!.mutationScoreBasedOnCoveredCode).toBeUndefined();
  });
});
