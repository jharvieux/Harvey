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
  | "risk-band" // an exposure-surface band (M10), deliberately NOT a letter and NOT composed
  | "indicator-only" // measured, surfaced, deliberately NOT composed (needs confirmation elsewhere)
  | "not-assessed"; // this tier did not run it — the row states why and what would

// M10's band (operator ruling 2026-07-28 on #1305). Deliberately NOT the A–F letter scale: a letter
// on M10 reads as a protection verdict ("your PII is safe"), which only the connected tier can
// support. A band states how much sensitive data exists and how sensitive it is — exposure surface,
// which source genuinely measures — and says in the output what it does not mean.
export type RiskBand = "Low" | "Medium" | "High" | "Critical";

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
  band?: RiskBand; // risk-band rows only
  bandDerivation?: string; // risk-band rows only: the inputs and the rule that produced the band
  bandCaveat?: string; // risk-band rows only: what the band does NOT mean, in the client's words
  // The DISCLOSED ROLLUP of this dimension's evidence (operator ruling 2026-07-28 on #1305).
  // Absent ⇒ this dimension surfaces no per-finding evidence, not "it had none".
  evidence?: ExampleRollup;
}

// At most five examples per dimension, duplicates collapsed to one row plus a count — the operator's
// ruling verbatim: "only show 5 examples of each and if there's dupes just give one example and
// state how many times it appears".
export const EXAMPLES_SHOWN = 5;

interface DimensionExample {
  shape: string; // the finding's taxonomy — the "shape" that repeats
  title: string;
  location: string; // ONE representative location; the rest are in the paid report
  occurrences: number; // how many times this shape appears IN THE FULL SET
}

// The rollup carries the TRUE totals next to the shown rows, because a capped list that says
// "5 findings" when 47 exist is a fabricated number, and a collapsed duplicate printed as one row
// reads as singular. CLAUDE.md: when volume is the objection the answer is a threshold or a
// DISCLOSED rollup (#935's shape) — never quietly showing fewer rows.
export interface ExampleRollup {
  examples: DimensionExample[];
  totalFindings: number; // every finding in the dimension, not just the shown ones
  totalShapes: number; // every distinct shape, not just the shown ones
  hiddenShapes: number; // shapes not shown
  hiddenFindings: number; // findings behind those shapes
  capped: boolean; // true ⇒ the list was cut; false ⇒ every shape is shown
}

// Group by shape, most-frequent first (deterministic tiebreak), keep the first `limit`. The totals
// are always computed over the WHOLE input, never over the kept slice — that arithmetic is the
// difference between a disclosed rollup and a silent truncation, and it is what the tests pin.
export function rollupExamples(findings: Finding[], limit = EXAMPLES_SHOWN): ExampleRollup {
  const byShape = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byShape.get(f.taxonomy) ?? [];
    list.push(f);
    byShape.set(f.taxonomy, list);
  }
  const ordered = [...byShape.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const shown = ordered.slice(0, limit);
  const hidden = ordered.slice(limit);
  return {
    examples: shown.map(([shape, hits]) => ({
      shape,
      title: hits[0]!.title,
      location: [...hits].sort((a, b) => a.location.localeCompare(b.location))[0]!.location,
      occurrences: hits.length,
    })),
    totalFindings: findings.length,
    totalShapes: ordered.length,
    hiddenShapes: hidden.length,
    hiddenFindings: hidden.reduce((sum, [, hits]) => sum + hits.length, 0),
    capped: hidden.length > 0,
  };
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
  // The score is computed on `defects` — the FULL set — and the rollup is derived from the same
  // array AFTERWARDS. A dimension graded on the five shown rows when forty-seven exist would be a
  // fabricated number; keeping the score off the rollup's output is what prevents that, and
  // `grades on the full set, not the shown examples` is the test that pins it.
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
    evidence: rollupExamples(defects),
    ...(disclosures.length ? { notAssessedRows: disclosures.length } : {}),
  };
}


// One table's classification, exactly as tools/pii-classify.mjs already derives it from source. The
// per-table Low/Medium/High/Critical scale is that module's own shipped `scoreToSeverity` (category
// points x confidence weight, stacked across infotypes) — this module reuses it rather than
// inventing a parallel sensitivity scale that could disagree with the M10 findings themselves.
export interface PiiTableBand {
  table: string;
  severity: string; // "Low" | "Medium" | "High" | "Critical" | "Info", from the classifier
  categories: string[];
  columns: number;
}

const BAND_ORDER: RiskBand[] = ["Low", "Medium", "High", "Critical"];

// Volume is the operator's third named input ("volume of PII-bearing entities"). Forty tables of
// personal data is a materially larger exposure surface than one, at the same sensitivity, so the
// peak sensitivity is raised ONE step at this many PII-bearing tables. One step, capped at Critical:
// volume widens a breach, it does not make ordinary contact data regulated.
const VOLUME_ESCALATION_TABLES = 10;

// Derived ONLY from what the source declares: which columns are classified, what sensitivity class
// they fall in, and how many tables carry them. No protection signal (RLS, grants, policies) is an
// input, by ruling — mixing one in is what would turn this back into a protection verdict.
export function riskBandOf(pii: { tables: number; columns: number; tableBands?: PiiTableBand[] }): { band: RiskBand; derivation: string } {
  const bands = pii.tableBands ?? [];
  const rated = bands.filter((b) => BAND_ORDER.includes(b.severity as RiskBand));
  if (pii.tables === 0 || rated.length === 0) {
    return {
      band: "Low",
      derivation: `No table in your schema carries a column this tier classifies as personal, health, payment or secret data (${pii.columns} column(s) were read and classified).`,
    };
  }
  const peakIndex = Math.max(...rated.map((b) => BAND_ORDER.indexOf(b.severity as RiskBand)));
  const peak = BAND_ORDER[peakIndex]!;
  const top = rated.find((b) => b.severity === peak)!;
  const atPeak = rated.filter((b) => b.severity === peak).length;
  const escalated = pii.tables >= VOLUME_ESCALATION_TABLES && peakIndex < BAND_ORDER.length - 1;
  const band = escalated ? BAND_ORDER[peakIndex + 1]! : peak;

  const sensitivity =
    `Most sensitive table: \`${top.table}\` — ${peak} (${top.categories.join(", ")}, ${top.columns} classified column(s))` +
    (atPeak > 1 ? `, one of ${atPeak} table(s) at that level.` : ".");
  // Three distinct cases, and conflating the last two prints a falsehood: a schema at 18 tables is
  // NOT "below the 10-table threshold" just because the band was already at the ceiling.
  const atVolume = pii.tables >= VOLUME_ESCALATION_TABLES;
  const volume = escalated
    ? ` ${pii.tables} tables hold classified data, at or above the ${VOLUME_ESCALATION_TABLES}-table volume threshold, which raises the band one step to ${band}.`
    : atVolume
      ? ` ${pii.tables} tables hold classified data, at or above the ${VOLUME_ESCALATION_TABLES}-table volume threshold — the band is already at ${band}, the highest, so volume cannot raise it further.`
      : ` ${pii.tables} table(s) hold classified data — below the ${VOLUME_ESCALATION_TABLES}-table volume threshold that would raise the band, so it stays at ${band}.`;
  return { band, derivation: sensitivity + volume };
}

// M10's evidence rollup obeys the same cap as every other dimension: the most sensitive tables
// first, the true total stated beside them.
function piiEvidence(bands: PiiTableBand[]): ExampleRollup {
  const ordered = [...bands].sort(
    (a, b) => BAND_ORDER.indexOf(b.severity as RiskBand) - BAND_ORDER.indexOf(a.severity as RiskBand) || b.columns - a.columns || a.table.localeCompare(b.table),
  );
  const shown = ordered.slice(0, EXAMPLES_SHOWN);
  const hidden = ordered.slice(EXAMPLES_SHOWN);
  return {
    examples: shown.map((b) => ({
      shape: `${b.severity} — ${b.categories.join(", ")}`,
      title: `Table \`${b.table}\``,
      location: b.table,
      occurrences: b.columns,
    })),
    totalFindings: bands.reduce((sum, b) => sum + b.columns, 0),
    totalShapes: bands.length,
    hiddenShapes: hidden.length,
    hiddenFindings: hidden.reduce((sum, b) => sum + b.columns, 0),
    capped: hidden.length > 0,
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
  m1: { grade: Grade; score: number; gradedCount: number; indicatorCount: number; findings?: Finding[] };
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
  duplicationFindings?: Finding[]; // jscpdToFindings' output, for M4's capped example rollup
  // M6: the hand-rolled indicator rollup the free report already carries (#267).
  handrolledClasses: number;
  handrolledTotal: number;
  // M8: whether package.json declares a test script. A runner declared with no test files behind it
  // is a louder finding than no runner at all, so the row distinguishes them.
  testRunnerDeclared?: boolean;
  // M10: tables carrying at least one classified PII/PHI/PCI column, and whether any schema was
  // readable at all — the difference between "no sensitive data" and "no schema to read".
  pii?: { tables: number; columns: number; tableBands?: PiiTableBand[] };
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
    ...(input.m1.findings ? { evidence: rollupExamples(input.m1.findings) } : {}),
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
      ...(input.duplicationFindings ? { evidence: rollupExamples(input.duplicationFindings) } : {}),
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

  // M10 — a RISK BAND, not a letter and not a bare indicator (operator ruling 2026-07-28 on #1305).
  // A letter would read as a protection verdict only the connected tier can support; a bare
  // indicator conveys no magnitude and under-delivers against the 2026-07-12 correction. The band
  // states how much sensitive data exists and how sensitive it is — exposure surface — and every
  // input to it is something the SOURCE can see. It is never composed into the letter grade.
  if (input.pii) {
    const { band, derivation } = riskBandOf(input.pii);
    dimensions.push({
      ...spec("M10"),
      status: "risk-band",
      band,
      count: input.pii.tables,
      measure: `${input.pii.tables} table(s) holding ${input.pii.columns} classified PII/PHI/PCI column(s)`,
      bandDerivation: derivation,
      bandCaveat:
        "What this band does NOT mean: it is NOT a statement that your data has been exposed, " +
        "breached, or accessed. It is NOT a verdict on your access controls — a `Critical` band on a " +
        "properly-locked-down database is normal and expected, and a `Low` band does NOT mean your " +
        "data is protected. It measures ONE thing: how much sensitive data your schema holds and how " +
        "sensitive it is. Whether each column is actually protected is a live-database question the " +
        "deep scan answers.",
      scope:
        "Which of your tables hold sensitive data, and how sensitive, classified from your " +
        "migrations. Rated Low/Medium/High/Critical for EXPOSURE SURFACE, deliberately not A–F: a " +
        "letter would imply a protection verdict this tier does not measure, so this band is reported " +
        "beside the graded dimensions and never averaged into them.",
      ...(input.pii.tableBands ? { evidence: piiEvidence(input.pii.tableBands) } : {}),
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

  const banded = dimensions.filter((d) => d.status === "risk-band");
  // The risk band is named on its own: folding it into "indicators" would hide that M10 carries a
  // real Low/Medium/High/Critical rating, which is the whole point of the 2026-07-28 ruling.
  const bandClause = banded.length
    ? ` ${banded.map((d) => `${d.module} carries a ${d.band} data-exposure rating, reported beside the letter grades rather than averaged into them`).join("; ")}.`
    : "";
  const notGraded = dimensions.filter((d) => d.status === "indicator-only").map((d) => d.module);
  const scopeSentence =
    unassessed.length === 0
      ? `All ten modules were assessed by this scan${notGraded.length ? ` (${notGraded.join(", ")} as indicators only)` : ""}.${bandClause}`
      : `${unassessed.length} of the 10 audit modules were NOT run by this free scan (${unassessed.join(", ")})` +
        (notGraded.length ? `, and ${notGraded.length} more (${notGraded.join(", ")}) produced indicators that are deliberately not graded` : "") +
        `. Absence of a result for those is NOT evidence that they are clean — each row below says what it would take to answer it.${bandClause}`;

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
