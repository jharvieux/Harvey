// The free tier's CODEBASE-HEALTH SCORECARD (#1305), implementing the operator's 2026-07-12
// correction to #227.
//
// The correction, verbatim: "the free grade is a **codebase-health scorecard across all modules**,
// and security is one (indicator-heavy) dimension, not the subject … So the decided shape — hygiene
// grade + risk disclosure + non-grading indicators + scope annotation — applies **per dimension**,
// composed into a health grade."
//
// What shipped instead (PR #244) was the security-hygiene grade ALONE: one composite penalty over
// one module's findings, annotated "hygiene only". Nine dimensions never entered, and the fact that
// they never entered was stated only inside the `--sarif-out` file — never in the terminal output a
// prospect actually reads. An unstated scope limitation reads as a clean bill of health.
//
// So this module owns three things:
//   1. PER-DIMENSION decomposition. Every module M1–M10 gets its own row with its own status, its
//      own number where one is honestly derivable, and its own scope sentence.
//   2. COMPOSITION. The overall health grade is the equal-weight mean of the GRADED dimensions only
//      — equal weight because CLAUDE.md's scope rule is that all ten modules carry equal weight, and
//      graded-only because averaging in a dimension that was never run would launder a gap into a
//      score.
//   3. FAIL-LOUD EXHAUSTIVENESS. DIMENSIONS is asserted exhaustive over M1–M10 at module load: a
//      module with nothing to say renders a row that says so and names the tier that would answer
//      it. There is no code path that drops a module. This is the same posture as the #1314 census
//      (a module with zero entries renders a `0` row rather than emitting no row at all) and the
//      M1-LANG-00 / INFRA-SCOPE-00 not-assessed family — a gap is a ROW, never silence.
//
// Two measurement kinds, because the operator's correction distinguishes them. M1 keeps the
// SEVERITY-weighted curve #244/#996 pinned (a single verified Critical is an F) — that curve is a
// security judgment and is deliberately untouched here. The quality dimensions the correction names
// as "factual measurements, FP-safe after triage" grade on DENSITY instead: findings per 1,000 lines
// of application code, or for M4 a duplication percentage. A density is a fact about the codebase
// that needs no exploitability judgment, which is exactly why the correction put them in the free
// tier's "real strength" bucket.

import type { Finding } from "./findings.js";
import type { SourceInput } from "./detectors/common.js";
import type { TargetFramework, WorkspaceFramework } from "./scan/framework-detect.js";
import type { TargetOrm } from "./scan/framework-detect.js";
import { detectAppRouterFindings } from "./detectors/app-router.js";
import { detectPerfCodeFindings } from "./detectors/perf-code.js";
import { detectSlopFindings } from "./detectors/slop.js";
import { NON_PRODUCT } from "./detectors/load-sources.js";
import { gradeOf, type Grade } from "./quick-scan.js";

type DimensionStatus =
  | "graded" // a number this tier stands behind, composed into the health grade
  | "indicator-only" // measured, surfaced, deliberately NOT composed (needs confirmation elsewhere)
  | "not-assessed"; // this tier did not run it — the row states why and what would

export interface HealthDimension {
  module: string; // "M1".."M10"
  label: string; // the plain-English dimension name a prospect reads
  status: DimensionStatus;
  grade?: Grade; // graded rows only
  score?: number; // graded rows only, 0–100, on the same curve as the overall grade
  measure?: string; // the raw fact behind the grade ("3.2 findings per 1k lines"), always shown
  count?: number; // findings/indicators this dimension actually produced
  scope: string; // what this row does and does not cover — travels WITH the number, never separately
  reason?: string; // not-assessed rows only: why this tier could not answer it
  needs?: string; // not-assessed rows only: the tier that would
  notAssessedRows?: number; // in-dimension disclosure rows (confidence "N/A") the detector emitted
}

export interface HealthScorecard {
  dimensions: HealthDimension[]; // EXHAUSTIVE over M1–M10, in module order
  grade: Grade;
  score: number;
  gradedModules: string[];
  unassessedModules: string[];
  composition: string; // how the overall grade was arrived at, in one sentence
  scopeSentence: string; // the #1305 disclosure: how many modules this run did not attempt
}

// Every module M1–M10, with the label a prospect reads. The list is the exhaustiveness contract:
// buildHealthScorecard emits exactly these ten rows, in this order, always.
const DIMENSIONS: { module: string; label: string }[] = [
  { module: "M1", label: "Security & multi-tenant isolation" },
  { module: "M2", label: "Live authorization pen test" },
  { module: "M3", label: "Hotspots & web vitals" },
  { module: "M4", label: "Duplication" },
  { module: "M5", label: "Dead code & slop" },
  { module: "M6", label: "Maintainability / reinvention" },
  { module: "M7", label: "Performance (source)" },
  { module: "M8", label: "Test quality" },
  { module: "M9", label: "Framework-boundary correctness" },
  { module: "M10", label: "Data classification (PII/PHI/PCI)" },
];

// Fail loud at module load, not at render time: a scorecard that silently lost a module is exactly
// the defect #1305 records, so the list is re-checked at module load rather than trusted.
const EXPECTED_MODULES = Array.from({ length: 10 }, (_, i) => `M${i + 1}`);
{
  const listed = DIMENSIONS.map((d) => d.module);
  const missing = EXPECTED_MODULES.filter((m) => !listed.includes(m));
  const unexpected = listed.filter((m) => !EXPECTED_MODULES.includes(m));
  if (missing.length || unexpected.length || listed.length !== EXPECTED_MODULES.length) {
    throw new Error(
      `health-scorecard DIMENSIONS must be exhaustive over M1–M10 exactly.` +
        `${missing.length ? ` Missing: ${missing.join(", ")}.` : ""}${unexpected.length ? ` Unexpected: ${unexpected.join(", ")}.` : ""}`,
    );
  }
}

// A detector's own not-assessed disclosure row (the M1-LANG-00 / "M9 — … — not assessed" family)
// carries confidence "N/A". It is a statement about COVERAGE, not a defect found, so it must never
// be counted as one — grading a coverage row would penalise a target for what Harvey could not see.
// It is counted separately and printed, because dropping it silently is the other failure.
const isDisclosureRow = (f: Finding): boolean => f.confidence === "N/A";

// Density → score on the SAME curve the overall grade and M1's hygiene grade use (A ≥ 90 … F < 60),
// by piecewise-linear interpolation between published band edges. One curve in the codebase: a
// second grading scale would make two rows labelled "B" mean different things.
//
// The edges are stated in every scope line this module writes, so the number always ships with the
// rule that produced it. They are a PRESENTATION choice over a factual measurement — the density
// itself is the fact, and it is printed alongside the letter for exactly that reason.
interface Band {
  max: number; // upper edge of this band, in the measure's own units
  scoreAt: number; // score at that edge
}

function interpolate(value: number, bands: Band[], floorSlope: number): number {
  let lowValue = 0;
  let lowScore = 100;
  for (const b of bands) {
    if (value <= b.max) {
      const span = b.max - lowValue;
      const t = span === 0 ? 1 : (value - lowValue) / span;
      return Math.round(lowScore - t * (lowScore - b.scoreAt));
    }
    lowValue = b.max;
    lowScore = b.scoreAt;
  }
  return Math.max(0, Math.round(lowScore - floorSlope * (value - lowValue)));
}

// Findings per 1,000 lines of application code.
const DENSITY_BANDS: Band[] = [
  { max: 1, scoreAt: 90 },
  { max: 2.5, scoreAt: 80 },
  { max: 5, scoreAt: 70 },
  { max: 10, scoreAt: 60 },
];
const DENSITY_BAND_TEXT = "A ≤ 1.0, B ≤ 2.5, C ≤ 5.0, D ≤ 10.0, F above — findings per 1,000 lines";

export function densityScore(findingCount: number, kloc: number): number {
  if (kloc <= 0) return 100;
  return interpolate(findingCount / kloc, DENSITY_BANDS, 6);
}

// Duplicated lines as a percentage of comparable lines (jscpd's own headline number).
const DUPLICATION_BANDS: Band[] = [
  { max: 2, scoreAt: 90 },
  { max: 5, scoreAt: 80 },
  { max: 10, scoreAt: 70 },
  { max: 20, scoreAt: 60 },
];
const DUPLICATION_BAND_TEXT = "A ≤ 2%, B ≤ 5%, C ≤ 10%, D ≤ 20%, F above — duplicated lines";

export function duplicationScore(percentage: number): number {
  return interpolate(percentage, DUPLICATION_BANDS, 3);
}

const round1 = (n: number): string => (Math.round(n * 10) / 10).toFixed(1);

// A graded quality dimension: run its detector's output through the density curve, keeping its
// coverage-disclosure rows out of the numerator and visible in the row.
function gradedDensityRow(
  spec: { module: string; label: string },
  findings: Finding[],
  kloc: number,
  scopeTail: string,
): HealthDimension {
  const disclosures = findings.filter(isDisclosureRow);
  const defects = findings.filter((f) => !isDisclosureRow(f));
  const score = densityScore(defects.length, kloc);
  return {
    module: spec.module,
    label: spec.label,
    status: "graded",
    grade: gradeOf(score),
    score,
    count: defects.length,
    measure: kloc > 0 ? `${round1(defects.length / kloc)} per 1,000 lines (${defects.length} in ${round1(kloc)}k lines)` : `${defects.length} finding(s)`,
    scope: `${scopeTail} Banding: ${DENSITY_BAND_TEXT}.`,
    ...(disclosures.length ? { notAssessedRows: disclosures.length } : {}),
  };
}

// A dimension this tier did not run. The row is the product: it names the reason and the tier that
// would answer it, so a reader can tell "we looked and found nothing" from "we never looked".
function notAssessedRow(spec: { module: string; label: string }, reason: string, needs: string): HealthDimension {
  return {
    module: spec.module,
    label: spec.label,
    status: "not-assessed",
    scope: "Not attempted by the free scan. Absence of a result here is not evidence of absence of a problem.",
    reason,
    needs,
  };
}

export interface DuplicationMeasure {
  percentage: number;
  duplicatedLines: number;
  totalLines: number;
}

export interface ScorecardInput {
  // M1's hygiene grade, computed by src/quick-scan.ts on its own severity-weighted curve and passed
  // in verbatim — this module never re-grades M1, so the #244/#996 pinned promises stay pinned.
  m1: { grade: Grade; score: number; gradedCount: number; indicatorCount: number };
  // The target's FULL source set, exactly as loadSources returns it — test files included. This
  // module splits it itself rather than taking a pre-filtered list: M5/M7/M9 must see PRODUCT code
  // only (a perf finding in a test file is not an audit finding — the rule every other consumer of
  // these detectors applies), while M8's census is about the test files specifically. A caller that
  // pre-filtered would silently zero M8; a caller that did not would grade the target on its tests.
  sources: SourceInput[];
  kloc: number; // application lines of code / 1000, from measureCodebaseSize
  framework?: TargetFramework;
  nonNextWorkspaces?: WorkspaceFramework[];
  orm?: TargetOrm;
  // M4: jscpd's summary when the run succeeded, or the reason it did not. Exactly one is expected;
  // supplying neither is what a caller does when it deliberately skipped M4, and produces a row
  // saying so rather than a silent omission.
  duplication?: DuplicationMeasure;
  duplicationGap?: string;
  // M6: the hand-rolled indicator rollup the free report already carries (#267).
  handrolledClasses: number;
  handrolledTotal: number;
  // M8: whether package.json declares a test script. A runner declared with no test files behind it
  // is a louder finding than no runner at all, so the row distinguishes them.
  testRunnerDeclared?: boolean;
  // M10: tables carrying at least one classified PII/PHI/PCI column, and whether any schema was
  // readable at all — the difference between "no sensitive data" and "no schema to read".
  pii?: { tables: number; columns: number };
  piiGap?: string;
}

export function buildHealthScorecard(input: ScorecardInput): HealthScorecard {
  const spec = (m: string) => DIMENSIONS.find((d) => d.module === m)!;
  const { kloc } = input;
  const sources = input.sources.filter((f) => !NON_PRODUCT.test(f.path));
  const testFiles = input.sources.filter((f) => NON_PRODUCT.test(f.path));
  const dimensions: HealthDimension[] = [];

  // M1 — graded on the severity curve, not the density curve. Security is the one dimension where a
  // single instance is decisive, which is the whole point of the correction's "security is the
  // OUTLIER" sentence: it stays graded, it just stops being the headline.
  dimensions.push({
    ...spec("M1"),
    status: "graded",
    grade: input.m1.grade,
    score: input.m1.score,
    count: input.m1.gradedCount,
    measure: `${input.m1.gradedCount} mechanically-verified hygiene issue(s)`,
    scope:
      "Mechanically-verifiable hygiene only — dependency, secret and dangerous-config classes. " +
      "Tenant isolation and authorization are NOT graded from source; they ride as indicators below " +
      `(${input.m1.indicatorCount}) and are confirmed or cleared only by the deep scan. Severity-weighted, not density: one verified Critical is an F.`,
  });

  dimensions.push(
    notAssessedRow(
      spec("M2"),
      "The live authorization pen test needs a running database and two seeded tenants; the free scan is source-only and starts no stack.",
      "connected / dynamic tier",
    ),
  );

  dimensions.push(
    notAssessedRow(
      spec("M3"),
      "Hotspot ranking needs the target's git history, and web vitals need a built, served app; the free scan reads a source tree only.",
      "connected tier (git history) + dynamic tier (vitals)",
    ),
  );

  // M4 — the operator's first-named source-gradable dimension.
  if (input.duplication) {
    const score = duplicationScore(input.duplication.percentage);
    dimensions.push({
      ...spec("M4"),
      status: "graded",
      grade: gradeOf(score),
      score,
      count: input.duplication.duplicatedLines,
      measure: `${input.duplication.percentage}% duplicated (${input.duplication.duplicatedLines.toLocaleString("en-US")} of ${input.duplication.totalLines.toLocaleString("en-US")} comparable lines)`,
      scope: `Copy-paste clones across your source, excluding generated/vendored paths. A factual measurement — no exploitability judgment is involved. Banding: ${DUPLICATION_BAND_TEXT}.`,
    });
  } else {
    dimensions.push(
      notAssessedRow(
        spec("M4"),
        input.duplicationGap ?? "The duplication pass was not run for this scan.",
        "re-run once the duplication engine is available",
      ),
    );
  }

  dimensions.push(
    gradedDensityRow(
      spec("M5"),
      detectSlopFindings(sources),
      kloc,
      "Unused/unreachable code and machine-authored slop, from your source. A count, not a judgment call — no verification needed.",
    ),
  );

  // M6 — indicator-only by the correction's own framing: a hand-rolled shape may be a deliberate
  // choice, so it is surfaced and never composed into the grade.
  dimensions.push({
    ...spec("M6"),
    status: "indicator-only",
    count: input.handrolledTotal,
    measure: `${input.handrolledTotal} occurrence(s) across ${input.handrolledClasses} recognised shape(s)`,
    scope:
      "Recognisable hand-rolled shapes in your source. NOT composed into the health grade and no " +
      "defect is asserted — each may be a deliberate choice. The deep scan triages every one.",
  });

  dimensions.push(
    gradedDensityRow(
      spec("M7"),
      detectPerfCodeFindings(sources, input.framework),
      kloc,
      "Performance anti-patterns visible in source (N+1 awaits, blocking sync I/O, render-loop allocations). Bundle weight and live vitals are separate tiers and are not in this number.",
    ),
  );

  // M8 — the correction's own third bullet: "needs the target's tests to run — BUT 'NO TESTS' IS
  // ITSELF A GRADABLE FINDING". So the absence of tests is graded (it is a fact about the source,
  // decidable with no execution), while their PRESENCE is only an indicator: that files exist says
  // nothing about whether they pass or assert anything, and claiming otherwise from source is the
  // over-reach this tier exists to avoid. Mutation-scored quality stays a connected-tier claim.
  if (testFiles.length === 0) {
    dimensions.push({
      ...spec("M8"),
      status: "graded",
      grade: gradeOf(0),
      score: 0,
      count: 0,
      measure: `no test or spec files found across ${sources.length} source file(s)${input.testRunnerDeclared ? " — despite a test script being declared in package.json" : ""}`,
      scope:
        "Whether your codebase has automated tests at all. This is graded because it needs no " +
        "execution to establish" +
        (input.testRunnerDeclared
          ? " — and a declared test script with no test files behind it is the loudest form of it. "
          : ". ") +
        "How GOOD the tests are (do they assert anything, do they kill mutants) is measured by the deep scan, which runs your suite.",
    });
  } else {
    dimensions.push({
      ...spec("M8"),
      status: "indicator-only",
      count: testFiles.length,
      measure: `${testFiles.length} test/spec file(s) alongside ${sources.length} source file(s)`,
      scope:
        "Your codebase HAS automated tests — that is all this tier establishes, and it is why no " +
        "letter is assigned. It is not a statement that they pass, that they cover anything, or " +
        "that they assert anything: the deep scan runs your suite and mutation-scores it.",
    });
  }

  dimensions.push(
    gradedDensityRow(
      spec("M9"),
      detectAppRouterFindings(sources, input.framework, input.nonNextWorkspaces ?? [], input.orm),
      kloc,
      "Framework-boundary correctness — server/client boundary, caching and route-segment configuration read straight from your source.",
    ),
  );

  // M10 — source-measurable but NOT source-gradable: a schema declares WHICH columns hold sensitive
  // data, which is a fact; whether each is adequately protected is a live-database question
  // (src/pii-protection-review.ts, connected tier). Reporting a letter here would assert a
  // protection verdict that is measured on the connected tier, so it is surfaced as an indicator with
  // the count stated. Deviation from the correction's "source-gradable" bucket, stated on the row.
  if (input.pii) {
    dimensions.push({
      ...spec("M10"),
      status: "indicator-only",
      count: input.pii.tables,
      measure: `${input.pii.tables} table(s) holding ${input.pii.columns} classified PII/PHI/PCI column(s)`,
      scope:
        "Which of your tables hold sensitive data, classified from your migrations. This is an " +
        "inventory, not a grade: whether each column is adequately protected is a live-database " +
        "question the deep scan answers, so no letter is assigned here.",
    });
  } else {
    dimensions.push(
      notAssessedRow(
        spec("M10"),
        input.piiGap ?? "No schema (SQL migrations or a Prisma schema) was found to classify, so no data inventory could be built.",
        "connected tier (reads the live schema directly)",
      ),
    );
  }

  const graded = dimensions.filter((d) => d.status === "graded");
  // Equal weight, graded dimensions only. CLAUDE.md: all ten modules carry equal weight — none is
  // the lead. Averaging in a dimension nobody ran would turn a coverage gap into a score, which is
  // the exact inversion #1305 exists to stop.
  const score = graded.length === 0 ? 0 : Math.round(graded.reduce((sum, d) => sum + (d.score ?? 0), 0) / graded.length);
  const unassessed = dimensions.filter((d) => d.status === "not-assessed").map((d) => d.module);
  const indicatorOnly = dimensions.filter((d) => d.status === "indicator-only").map((d) => d.module);

  const scopeSentence =
    unassessed.length === 0
      ? `All ten modules were assessed by this scan (${indicatorOnly.length} as indicators only).`
      : `${unassessed.length} of the 10 audit modules were NOT run by this free scan (${unassessed.join(", ")}), ` +
        `and ${indicatorOnly.length} more (${indicatorOnly.join(", ")}) produced indicators that are deliberately not graded. ` +
        `Absence of a result for those is NOT evidence that they are clean — each row below says what it would take to answer it.`;

  return {
    dimensions,
    grade: gradeOf(score),
    score,
    gradedModules: graded.map((d) => d.module),
    unassessedModules: unassessed,
    composition:
      graded.length === 0
        ? "No dimension could be graded by this scan, so there is no health grade — see the rows below."
        : `Equal-weight mean of the ${graded.length} graded dimension(s): ${graded.map((d) => `${d.module} ${d.score}`).join(", ")}. ` +
          `Indicator-only and not-assessed dimensions are deliberately excluded rather than scored as clean.`,
    scopeSentence,
  };
}
