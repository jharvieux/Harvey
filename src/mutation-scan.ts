// M8 (mutation testing / test intent) — shapes StrykerJS's JSON reporter output
// (mutation-testing-elements schema: https://github.com/stryker-mutator/mutation-testing-elements)
// into the summary shape §3b of the audit report needs: mutation score overall + per module,
// and a ranked surviving-mutant list. Pure transforms only; src/cli/mutation-scan.ts does the
// process invocation and file I/O.
//
// Score formula mirrors Stryker's own published metric (mutation-testing-elements/packages/
// metrics/src/calculateMetrics.ts — MEASURED 2026-07-25; this comment previously claimed the
// mirror while diverging on RuntimeError, corrected by #1076): a mutant is "valid" unless its
// status is Ignored or Pending (never actually run), or CompileError or RuntimeError (ran, but its
// outcome reflects a build/runtime failure rather than test quality — upstream excludes both from
// scoring the same way). score = detected / valid, where detected = Killed + Timeout. NoCoverage
// and Survived count against the score — each is a mutant the suite had the opportunity to kill
// and did not.

import { dirname, isAbsolute, relative, sep } from "node:path";
import type { Finding, TestQuality, TestQualityRow } from "./findings.js";

export type MutantStatus =
  | "Killed"
  | "Survived"
  | "NoCoverage"
  | "Timeout"
  | "CompileError"
  | "RuntimeError"
  | "Ignored"
  | "Pending";

export interface StrykerMutant {
  id: string;
  mutatorName: string;
  status: MutantStatus;
  replacement?: string;
  statusReason?: string;
  location: { start: { line: number; column: number }; end: { line: number; column: number } };
  coveredBy?: string[];
  killedBy?: string[];
}

export interface StrykerFileReport {
  language?: string;
  mutants: StrykerMutant[];
}

export interface StrykerReport {
  schemaVersion?: string;
  thresholds?: { high: number; low: number };
  files: Record<string, StrykerFileReport>;
  // #1076: "Free-format object that represents the configuration used to run mutation testing"
  // (mutation-testing-report-schema.json, MEASURED 2026-07-25) — the EFFECTIVE config, including
  // its resolved `mutate` globs, sits in the JSON report already loaded. verifyMutationScope's
  // caller (src/cli/mutation-scan.ts) reads config.mutate as the primary scope source, so a target
  // using a non-JSON stryker.conf.mjs/.js (previously "not statically readable") is no longer
  // scope-blind.
  config?: Record<string, unknown>;
}

// Not exported: nothing outside this file needs to name these shapes — callers get them as
// the (fully-typed) inferred return of summarizeMutationReport/toReportRows.
interface ModuleMutationSummary {
  module: string;
  totalMutants: number;
  killed: number;
  survived: number;
  noCoverage: number;
  timeout: number;
  runtimeErrors: number;
  ignored: number;
  compileErrors: number;
  mutationScore: number;
  // #1076: Stryker's OTHER published headline metric — detected / (detected + survived), i.e. the
  // score over only the mutants a test actually reached (excludes NoCoverage from the denominator,
  // unlike mutationScore above). Recomputed from the committed ATC capture: 58.1% here vs. 27.8%
  // for mutationScore — "your tests are bad" and "your tests are decent but reach half the code"
  // are different findings, and Stryker's own report shows both.
  mutationScoreBasedOnCoveredCode: number;
}

interface SurvivingMutant {
  file: string;
  line: number;
  column: number;
  mutatorName: string;
  status: "Survived" | "NoCoverage";
  replacement?: string;
  hotspot: boolean;
}

// #386 layer 2: the mutator families that encode negation/boundary logic. Survivors
// concentrated here mean "the suite never tested the denial branch" — a distinct, higher-
// priority signal than scattered coverage gaps, and the sentence the report needs.
const BOUNDARY_MUTATORS: ReadonlySet<string> = new Set(["ConditionalExpression", "EqualityOperator", "BooleanLiteral"]);

interface FileMutatorBreakdown {
  file: string;
  // Survived + NoCoverage counts per mutator type — both are mutants the suite never disproved.
  survivorsByMutator: Record<string, number>;
  boundarySurvivors: number;
  otherSurvivors: number;
  // Concentration needs a majority AND at least two boundary-family survivors — a single
  // surviving ConditionalExpression is an ordinary gap, not a denial-branch pattern.
  denialBoundaryConcentrated: boolean;
}

interface MutationSummary {
  overall: ModuleMutationSummary;
  byModule: ModuleMutationSummary[];
  survivingMutants: SurvivingMutant[];
  mutatorBreakdown: FileMutatorBreakdown[];
  // #319: the files Stryker actually mutated — its `mutate` scope, read straight from the report.
  // The overall score is a percentage OF THIS SET, not of the repo. When the set is a handful of
  // files a scoped config named (the corpus's launch.ts/server-common.ts case), a high score is
  // "the covered files are tested well", not "the repo is tested" — and that distinction is only
  // legible if the covered scope travels with the score. Callers that surface the score MUST
  // surface this alongside it (see coveredScopeLine); the deliverable renderer requires it.
  coveredScope: string[];
}

// #1076: RuntimeError added — MEASURED 2026-07-25 against upstream's calculateMetrics.ts, which
// puts RuntimeError in totalInvalid alongside CompileError (both excluded from the valid/scored
// set); Harvey previously counted a RuntimeError mutant as valid-but-undetected, silently pulling
// the score down whenever one occurred (runtimeErrors was 0 in the one real capture measured, so
// this has never actually bitten a real report — but the header comment claimed the mirror while
// the code diverged).
const NOT_VALID: ReadonlySet<MutantStatus> = new Set(["Ignored", "CompileError", "Pending", "RuntimeError"]);
const DETECTED: ReadonlySet<MutantStatus> = new Set(["Killed", "Timeout"]);
const SURVIVING: ReadonlySet<MutantStatus> = new Set(["Survived", "NoCoverage"]);

export function mutationScore(mutants: StrykerMutant[]): number {
  const valid = mutants.filter((m) => !NOT_VALID.has(m.status));
  if (valid.length === 0) return 0;
  const detected = valid.filter((m) => DETECTED.has(m.status)).length;
  return Math.round((detected / valid.length) * 1000) / 10;
}

// #1076: upstream's mutationScoreBasedOnCoveredCode (MEASURED 2026-07-25): detected / (detected +
// survived) — i.e. valid mutants MINUS the ones with no coverage at all. Harvey computed only the
// first score; this is the second one Stryker's own report always shows alongside it.
export function mutationScoreBasedOnCoveredCode(mutants: StrykerMutant[]): number {
  const valid = mutants.filter((m) => !NOT_VALID.has(m.status));
  if (valid.length === 0) return 0;
  const detected = valid.filter((m) => DETECTED.has(m.status)).length;
  const covered = valid.filter((m) => m.status !== "NoCoverage").length;
  if (covered === 0) return 0;
  return Math.round((detected / covered) * 1000) / 10;
}

function summarize(module: string, mutants: StrykerMutant[]): ModuleMutationSummary {
  const count = (s: MutantStatus) => mutants.filter((m) => m.status === s).length;
  return {
    module,
    totalMutants: mutants.length,
    killed: count("Killed"),
    survived: count("Survived"),
    noCoverage: count("NoCoverage"),
    timeout: count("Timeout"),
    runtimeErrors: count("RuntimeError"),
    ignored: count("Ignored"),
    compileErrors: count("CompileError"),
    mutationScore: mutationScore(mutants),
    mutationScoreBasedOnCoveredCode: mutationScoreBasedOnCoveredCode(mutants),
  };
}

// Groups files by directory — the closest generic proxy for "module" a whole-repo scan can use
// without client-specific config. A client that wants a finer/coarser grouping can post-process
// this array (it's already keyed by directory string).
function moduleOf(file: string): string {
  const dir = dirname(file);
  return dir === "." ? file : dir;
}

export function summarizeMutationReport(report: StrykerReport, hotspotFiles: readonly string[] = []): MutationSummary {
  const hotspots = new Set(hotspotFiles);
  const allMutants: StrykerMutant[] = [];
  const byModuleMutants = new Map<string, StrykerMutant[]>();
  const survivingMutants: SurvivingMutant[] = [];

  for (const [file, fileReport] of Object.entries(report.files)) {
    allMutants.push(...fileReport.mutants);
    const mod = moduleOf(file);
    const bucket = byModuleMutants.get(mod) ?? [];
    bucket.push(...fileReport.mutants);
    byModuleMutants.set(mod, bucket);

    for (const m of fileReport.mutants) {
      if (!SURVIVING.has(m.status)) continue;
      survivingMutants.push({
        file,
        line: m.location.start.line,
        column: m.location.start.column,
        mutatorName: m.mutatorName,
        status: m.status as "Survived" | "NoCoverage",
        replacement: m.replacement,
        hotspot: hotspots.has(file),
      });
    }
  }

  const byModule = [...byModuleMutants.entries()]
    .map(([mod, mutants]) => summarize(mod, mutants))
    .sort((a, b) => a.mutationScore - b.mutationScore);

  const byFileSurvivors = new Map<string, SurvivingMutant[]>();
  for (const s of survivingMutants) {
    const bucket = byFileSurvivors.get(s.file) ?? [];
    bucket.push(s);
    byFileSurvivors.set(s.file, bucket);
  }
  const mutatorBreakdown: FileMutatorBreakdown[] = [...byFileSurvivors.entries()]
    .map(([file, survivors]) => {
      const survivorsByMutator: Record<string, number> = {};
      for (const s of survivors) survivorsByMutator[s.mutatorName] = (survivorsByMutator[s.mutatorName] ?? 0) + 1;
      const boundarySurvivors = survivors.filter((s) => BOUNDARY_MUTATORS.has(s.mutatorName)).length;
      const otherSurvivors = survivors.length - boundarySurvivors;
      return {
        file,
        survivorsByMutator,
        boundarySurvivors,
        otherSurvivors,
        denialBoundaryConcentrated: boundarySurvivors >= 2 && boundarySurvivors > otherSurvivors,
      };
    })
    .sort((a, b) => b.boundarySurvivors - a.boundarySurvivors || (a.file < b.file ? -1 : 1));

  // Hotspot-flagged survivors first (the cross-reference against M1/M3 that makes them top
  // remediation priority), then by file/line for a stable, reviewable order.
  survivingMutants.sort((a, b) => {
    if (a.hotspot !== b.hotspot) return a.hotspot ? -1 : 1;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });

  return {
    overall: summarize("(overall)", allMutants),
    byModule,
    survivingMutants,
    mutatorBreakdown,
    coveredScope: Object.keys(report.files).sort(),
  };
}

// #319: the sentence that keeps the overall score honest wherever it is printed — the score is a
// percentage of the mutated file set, never a repo-level coverage claim, and that is only obvious
// once the reader sees how few files it covers. A one-file scope reading 100% is exactly the
// misrepresentation this guards against (proposit in the corpus).
export function coveredScopeLine(summary: MutationSummary): string {
  const n = summary.coveredScope.length;
  const files = n <= 3 ? summary.coveredScope.join(", ") : `${summary.coveredScope.slice(0, 3).join(", ")} +${n - 3} more`;
  return `score is over ${n} mutated file(s) (${files}) — a scoped subset, NOT a whole-repo coverage claim`;
}

interface ReportRow {
  module: string;
  // #819: undefined only when line coverage genuinely could not be auto-pulled for this module
  // (see src/cli/mutation-scan.ts's runLineCoverage) — the CLI always discloses WHY at the
  // top-level `lineCoverage` verdict rather than letting an undefined column read as "0%".
  lineCoverage?: number;
  mutationScore: number;
  survivingCount: number;
  hotspotSurvivingCount: number;
}

// Formats the per-module rows for the §3b Test-quality table (docs/audit-report-skeleton.md):
// | Module / file | Line cov | Mutation score | Surviving mutants (critical) | Action |
// #819: `lineCoverageByModule` (from summarizeLineCoverage, keyed the same way as byModule) is
// merged in here so the two numbers land on one row; omit it (or a missing module key) when the
// target's own coverage tool couldn't be run — the CLI's top-level `lineCoverage` verdict carries
// the reason so the gap is disclosed, never silently read as 0%.
export function toReportRows(summary: MutationSummary, lineCoverageByModule?: Record<string, number>): ReportRow[] {
  return summary.byModule.map((m) => {
    const forModule = summary.survivingMutants.filter((s) => moduleOf(s.file) === m.module);
    return {
      module: m.module,
      ...(lineCoverageByModule?.[m.module] !== undefined ? { lineCoverage: lineCoverageByModule[m.module] } : {}),
      mutationScore: m.mutationScore,
      survivingCount: forModule.length,
      hotspotSurvivingCount: forModule.filter((s) => s.hotspot).length,
    };
  });
}

// How many surviving mutants the deliverable lists individually. The rest are disclosed by count
// (survivorTotal) — the no-silent-cap rule the rollup already applies to findings (#935).
const SURVIVOR_LIST_MAX = 10;

// #1045: the §3b Test-quality payload the deliverable renders, assembled from src/cli/mutation-scan.ts's
// --out artifact (the only place the summary, the per-module rows, the #504 scope verdict and the
// #819 line-coverage verdict exist together). Undefined when the artifact is not a real mutation
// run — the no-test-suite and blocked branches write no `summary`, and M8's coverage row carries
// the reason, so the report states why rather than rendering an empty table.
export function testQualityFromArtifact(artifact: unknown): TestQuality | undefined {
  if (typeof artifact !== "object" || artifact === null) return undefined;
  const a = artifact as {
    summary?: MutationSummary;
    reportRows?: TestQualityRow[];
    scope?: MutationScope;
    lineCoverage?: TestQuality["lineCoverage"];
  };
  if (!a.summary?.overall || !Array.isArray(a.reportRows)) return undefined;
  const survivors = a.summary.survivingMutants ?? [];
  return {
    mutationScore: a.summary.overall.mutationScore,
    // #1076: absent ⇒ this artifact predates the metric (an older run's JSON) rather than a value
    // invented here — same optional-when-not-computed convention as cwe/owasp/references elsewhere.
    ...(a.summary.overall.mutationScoreBasedOnCoveredCode !== undefined
      ? { mutationScoreBasedOnCoveredCode: a.summary.overall.mutationScoreBasedOnCoveredCode }
      : {}),
    coveredScope: a.summary.coveredScope ?? [],
    // An UNVERIFIABLE scope is not a whole-repo claim: only a verified, unscoped run earns `true`.
    wholeRepo: Boolean(a.scope?.verified && !a.scope.scoped),
    scopeNote: a.scope?.note ?? "the scan reported no mutate-scope verdict — treat the score as covering only the listed files",
    rows: a.reportRows,
    lineCoverage: a.lineCoverage ?? { status: "partial", reason: "the scan reported no line-coverage verdict (#819)" },
    survivors: survivors.slice(0, SURVIVOR_LIST_MAX).map((s) => ({ file: s.file, line: s.line, mutator: s.mutatorName, hotspot: s.hotspot })),
    survivorTotal: survivors.length,
  };
}

// #819: the Istanbul `coverage-summary.json` shape (the json-summary reporter, produced by both
// @vitest/coverage-v8 and Jest's built-in istanbul coverage) — the one machine-readable coverage
// format both of Harvey's scaffoldable runners can be made to emit, so this reads one schema
// regardless of which runner produced it.
export interface IstanbulCoverageSummary {
  [file: string]: { lines: { total: number; covered: number; skipped: number; pct: number } };
}

// Aggregates the file-level Istanbul summary into the SAME per-directory "module" buckets
// toReportRows/byModule already use for mutation score, so line coverage lands on the identical
// row without a separate join key. `targetDir` un-absolutes any absolute paths the coverage tool
// wrote (Jest/vitest report keys are usually absolute; report keyed already-relative if the tool
// ran with a relative rootDir).
export function summarizeLineCoverage(coverage: IstanbulCoverageSummary, targetDir: string): Record<string, number> {
  const byModule = new Map<string, { covered: number; total: number }>();
  for (const [file, data] of Object.entries(coverage)) {
    if (file === "total") continue;
    const rel = (isAbsolute(file) ? relative(targetDir, file) : file).split(sep).join("/");
    const bucket = byModule.get(moduleOf(rel)) ?? { covered: 0, total: 0 };
    bucket.covered += data.lines.covered;
    bucket.total += data.lines.total;
    byModule.set(moduleOf(rel), bucket);
  }
  const result: Record<string, number> = {};
  for (const [mod, { covered, total }] of byModule) {
    result[mod] = total === 0 ? 0 : Math.round((covered / total) * 1000) / 10;
  }
  return result;
}

// #820: Stryker's json reporter path is configurable (`jsonReporter.fileName`); #262 only
// confirmed this wrapper's assumed default against one pinned version (9.6.1), not that every
// major writes there. Reading the path back out of whichever config actually ran (falling back to
// that assumed default) means a differing major doesn't need a version pin, just a readable config.
export function resolveJsonReporterPath(cfg: { jsonReporter?: { fileName?: string } } | undefined): string {
  return cfg?.jsonReporter?.fileName ?? "reports/mutation/mutation.json";
}

// #224: a target with no test script, no known test-runner dependency, and no Stryker config
// can't run Stryker at all — src/cli/mutation-scan.ts used to have nothing to do but error out.
// That absence is itself a finding (a security-critical codebase with zero automated regression
// coverage), so the CLI checks this before invoking Stryker and reports it instead of failing.
export interface PackageJsonForTestDetection {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  // #623: a `workspaces` field (npm/yarn) marks a monorepo root — used to tell "this app has no
  // tests" from "this app's tests live at the workspace root".
  workspaces?: string[] | { packages?: string[] };
}

const KNOWN_TEST_RUNNER_DEPS = ["vitest", "jest", "mocha", "ava", "tape", "jasmine", "karma", "cypress", "@japa/runner", "uvu", "tap"];
// npm/pnpm init's default placeholder — present but not a real test suite.
const PLACEHOLDER_TEST_SCRIPT = /Error: no test specified/;

// #252: the boundary between "has a test suite" and "has a harness but no suite". A configured
// runner with zero test files, or with a single spec that is itself a placeholder (no test cases,
// no assertions, or only constant-literal assertions like `expect(true).toBe(true)`) is NOT a
// suite — it must draw #224's zero-coverage finding, not pass as covered. A single MEANINGFUL
// spec (proposit's one real vitest spec, multi-tenant-starter's one real RLS test) still counts
// as a suite: the ruling's threshold is "≤1 placeholder", not "≤1 file".
const TEST_CASE_RE = /\b(?:it|test)(?:\.\w+)*\s*\(/g;
const ASSERTION_HEAD_RE = /\b(?:expect|assert(?:\.\w+)*)\s*\(/g;
const CONSTANT_ASSERTION_ARG = /^(?:|true|false|null|undefined|-?\d+(?:\.\d+)?|'[^']*'|"[^"]*"|`[^`]*`)$/;

// First (balanced-paren) argument of every expect(...)/assert.*(...) call in the file.
function assertionArgs(text: string): string[] {
  const args: string[] = [];
  for (const m of text.matchAll(ASSERTION_HEAD_RE)) {
    let depth = 1;
    let arg = "";
    for (let i = m.index + m[0].length; i < text.length && depth > 0 && arg.length < 200; i++) {
      const c = text[i]!;
      if (c === "(") depth++;
      else if (c === ")") depth--;
      if (depth > 0 && !(depth === 1 && c === ",")) arg += c;
      if (depth === 1 && c === ",") break;
    }
    args.push(arg.trim());
  }
  return args;
}

export function isPlaceholderSpec(text: string): { placeholder: boolean; why?: string } {
  const cases = text.match(TEST_CASE_RE)?.length ?? 0;
  if (cases === 0) return { placeholder: true, why: "it declares no test cases (no it()/test() calls)" };
  const args = assertionArgs(text);
  if (args.length === 0) return { placeholder: true, why: `its ${cases} test case(s) contain zero assertions` };
  if (args.every((a) => CONSTANT_ASSERTION_ARG.test(a))) {
    return { placeholder: true, why: "every assertion is over a constant literal (e.g. expect(true)) — tautological" };
  }
  return { placeholder: false };
}

// `testFiles` is the census of the target's actual test files (paths matching *.test.*/*.spec.*
// or living under __tests__/). Omit it to get the pre-#252 harness-only detection (used by unit
// tests that only exercise the package.json rules); the CLI always passes it.
export function detectNoTestSuite(
  pkg: PackageJsonForTestDetection | undefined,
  hasStrykerConfig: boolean,
  testFiles?: readonly { path: string; text: string }[],
): { missing: boolean; reason?: string } {
  const testScript = pkg?.scripts?.test;
  const hasRealTestScript = !!testScript && !PLACEHOLDER_TEST_SCRIPT.test(testScript);
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const hasRunnerDep = KNOWN_TEST_RUNNER_DEPS.some((d) => d in deps) || (testScript?.includes("--test") ?? false);
  if (!hasRealTestScript && !hasRunnerDep && !hasStrykerConfig) {
    const reason = [
      pkg ? (testScript ? `"scripts.test" is the npm-init placeholder ("${testScript}")` : `no "scripts.test" in package.json`) : "no package.json found",
      "no known test-runner dependency (vitest/jest/mocha/ava/...)",
      "no stryker.conf.* found",
    ].join("; ");
    return { missing: true, reason };
  }

  // #252: harness present — now check it has a meaningful suite behind it.
  if (testFiles) {
    if (testFiles.length === 0) {
      return { missing: true, reason: "a test harness is configured (test script / runner dependency / stryker config) but the tree contains ZERO test files — a runner with nothing to run counts as suite absent (#252)" };
    }
    if (testFiles.length === 1) {
      const only = testFiles[0]!;
      const verdict = isPlaceholderSpec(only.text);
      if (verdict.placeholder) {
        return { missing: true, reason: `the harness's ONLY test file (${only.path}) is a placeholder/smoke spec: ${verdict.why} — a single placeholder counts as suite absent (#252)` };
      }
    }
  }
  return { missing: false };
}

export function noTestSuiteFinding(reason: string): Finding {
  return {
    id: "M8-00",
    status: "Open",
    category: "Test quality",
    title: "No automated test suite — mutation coverage undefined",
    severity: "High",
    confidence: "Confirmed",
    taxonomy: "M8 — No automated test suite",
    location: "package.json",
    evidence: `${reason}.`,
    impact: "Zero automated regression coverage on a codebase in scope for a security/quality audit — mutation testing (or any other coverage metric) has nothing to measure.",
    fix: "Add a test suite (start with the auth, tenant-isolation, and money-critical paths), then wire Stryker so mutation testing can measure it.",
    value: 5,
    ease: 2,
    safety: 5,
  };
}

// #754: `noSuite: true` distinguishes this verdict from the genuine measurement-gap records below
// (root-workspace-unreachable #623, dry-run failure #503, degraded ladder #513, scoped subset
// #504) — a suite that never existed has nothing left to measure, so the M8-00 finding above IS
// the complete verdict, not a partial one. The M8 probe reads this flag to record `status: "ran"`
// while every other moduleRecord shape here still reads `partial`.
export function noTestSuiteModuleRecord(reason: string): { status: "partial"; note: string; noSuite: true } {
  return { status: "partial", note: `No automated test suite found (${reason}) — mutation scan could not run.`, noSuite: true };
}

// #623: a per-app invocation on a workspace monorepo whose test config lives at the ROOT (a vitest
// `workspace`/`projects` config, root `test:*` scripts) finds no test script/runner in the APP's
// own package.json and would falsely report "no automated test suite" — the ATC engagement's app
// (apps/main) has no scripts.test but the monorepo root runs a substantial vitest workspace. A root
// suite that covers the app is NOT suite-absence; it is a suite this per-app path cannot invoke.
// Detect it from the target's ancestors so the CLI emits a distinct "measurement gap" verdict
// (M8-04) rather than the M8-00 zero-coverage finding.
export interface AncestorTestSignals {
  dir: string;
  pkg?: PackageJsonForTestDetection;
  hasPnpmWorkspaceYaml: boolean;
  // A vitest.workspace.* file, or a vitest config declaring `projects`/`workspace` — the shape of a
  // multi-project root whose suite is invoked from the root, not per-package.
  hasVitestWorkspaceConfig: boolean;
  // The repo root marker — the ancestor walk stops here so it never climbs past the repository.
  hasGit: boolean;
}

// Callers receive this as the inferred return of detectRootWorkspaceTestSuite / the param of the
// finding+record builders — no name needs exporting.
interface RootWorkspaceTestSuite {
  root: string;
  reason: string;
}

const TEST_SCRIPT_KEY = /^test(:|$)/;

function ancestorTestSuite(a: AncestorTestSignals): string | undefined {
  if (a.hasVitestWorkspaceConfig) return "a vitest workspace/projects config";
  const scripts = a.pkg?.scripts ?? {};
  const testScript = Object.entries(scripts).find(([k, v]) => TEST_SCRIPT_KEY.test(k) && !PLACEHOLDER_TEST_SCRIPT.test(v));
  if (testScript) return `a root "${testScript[0]}" script`;
  const deps = { ...a.pkg?.dependencies, ...a.pkg?.devDependencies };
  const dep = KNOWN_TEST_RUNNER_DEPS.find((d) => d in deps);
  if (dep) return `a root ${dep} dependency`;
  return undefined;
}

function isWorkspaceRoot(a: AncestorTestSignals): string | undefined {
  if (a.pkg?.workspaces) return "package.json workspaces";
  if (a.hasPnpmWorkspaceYaml) return "pnpm-workspace.yaml";
  if (a.hasVitestWorkspaceConfig) return "a vitest workspace config";
  return undefined;
}

// `ancestors` are the target's ancestors nearest-first (excluding the target itself); the caller
// bounds the walk at the repo root (a `.git`-bearing dir).
export function detectRootWorkspaceTestSuite(ancestors: readonly AncestorTestSignals[]): RootWorkspaceTestSuite | undefined {
  for (const a of ancestors) {
    const rootMarker = isWorkspaceRoot(a);
    const suite = ancestorTestSuite(a);
    if (rootMarker && suite) return { root: a.dir, reason: `${suite}; ${rootMarker} marks it a monorepo root` };
    if (a.hasGit) break;
  }
  return undefined;
}

export function rootWorkspaceTestFinding(info: RootWorkspaceTestSuite): Finding {
  return {
    id: "M8-04",
    status: "Open",
    category: "Test quality",
    title: "Test suite lives at the monorepo root — per-app mutation scan could not reach it",
    severity: "Medium",
    confidence: "Confirmed",
    taxonomy: "M8 — Root-workspace test suite not reachable per-app",
    location: "package.json",
    evidence: `This package declares no test script/runner of its own, but a workspace-root test suite was detected at ${info.root} (${info.reason}). A per-app mutation scan runs only this package, so it cannot execute the root suite — this is a measurement gap, NOT an absent suite.`,
    impact: "M8 could not measure this app from a per-app invocation, and the app may in fact be covered by the root workspace suite — reported as a coverage gap rather than a false 'no automated test suite' (which would read as zero coverage on a tested app).",
    fix: "Run M8 from the monorepo root with the root test command, scoping the mutate globs to this app (e.g. select this app's project in the root vitest workspace), so the root suite's coverage of the app is measured.",
    value: 3,
    ease: 3,
    safety: 5,
  };
}

export function rootWorkspaceTestModuleRecord(info: RootWorkspaceTestSuite): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `A workspace-root test suite was detected at ${info.root} (${info.reason}) but this per-app invocation cannot run it — M8 here is a measurement GAP, not suite-absent (#623). Re-run M8 from the monorepo root (scoping mutate globs to this app) to measure it.`,
  };
}

// #932: the inverse of #623 — a monorepo ROOT invoked directly whose own package.json carries no
// test script/runner dep (all detectNoTestSuite looks at), while its WORKSPACES carry the actual
// suites (documenso: root has neither, packages/lib declares `"test": "vitest run"`, 128 tracked
// spec/test files). Reuses the same script/dep check ancestorTestSuite already applies climbing
// UP from an app to its root, applied instead to each of the root's own workspace children.
// Callers receive this as the inferred return of detectWorkspaceTestSuites / the param of the
// finding+record builders — no name needs exporting (mirrors RootWorkspaceTestSuite above).
interface WorkspaceTestSuite {
  path: string;
  reason: string;
}

function workspaceOwnTestSuite(pkg: PackageJsonForTestDetection | undefined): string | undefined {
  const scripts = pkg?.scripts ?? {};
  const testScript = Object.entries(scripts).find(([k, v]) => TEST_SCRIPT_KEY.test(k) && !PLACEHOLDER_TEST_SCRIPT.test(v));
  if (testScript) return `a "${testScript[0]}" script`;
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const dep = KNOWN_TEST_RUNNER_DEPS.find((d) => d in deps);
  if (dep) return `a ${dep} dependency`;
  return undefined;
}

// `workspaces` are the target's OWN workspace children (e.g. from discoverTargets), each paired
// with its own package.json (or undefined if unreadable) — a pure filesystem-facts-in transform,
// same split as detectRootWorkspaceTestSuite above.
export function detectWorkspaceTestSuites(workspaces: readonly { path: string; pkg?: PackageJsonForTestDetection }[]): WorkspaceTestSuite[] {
  const found: WorkspaceTestSuite[] = [];
  for (const w of workspaces) {
    const reason = workspaceOwnTestSuite(w.pkg);
    if (reason) found.push({ path: w.path, reason });
  }
  return found;
}

export function workspaceTestSuiteFinding(suites: readonly WorkspaceTestSuite[]): Finding {
  const examples = suites.slice(0, 5).map((s) => `${s.path} (${s.reason})`).join(", ");
  const more = suites.length > 5 ? `, +${suites.length - 5} more` : "";
  return {
    id: "M8-04",
    status: "Open",
    category: "Test quality",
    title: "Test suites live in workspaces — root-level mutation scan could not reach them",
    severity: "Medium",
    confidence: "Confirmed",
    taxonomy: "M8 — Root-workspace test suite not reachable per-app",
    location: "package.json",
    evidence: `This monorepo root declares no test script/runner of its own, but ${suites.length} workspace(s) carry their own test suite: ${examples}${more}. A root-level mutation scan runs only the root, so it cannot execute any workspace's suite — this is a measurement gap, NOT an absent suite.`,
    impact: "M8 could not measure this monorepo from a root-level invocation, and the workspaces above may in fact be well covered — reported as a coverage gap rather than a false 'no automated test suite' (which would read as zero coverage on a tested monorepo).",
    fix: "Re-run M8 per workspace (pnpm mutation-scan <workspace-path>) so each workspace's own suite is measured.",
    value: 3,
    ease: 3,
    safety: 5,
  };
}

export function workspaceTestSuiteModuleRecord(suites: readonly WorkspaceTestSuite[]): { status: "partial"; note: string } {
  const names = suites.map((s) => s.path).join(", ");
  return {
    status: "partial",
    note: `${suites.length} workspace(s) carry their own test suite (${names}) but this root-level invocation cannot run them — M8 here is a measurement GAP, not suite-absent (#932). Re-run M8 per workspace to measure it.`,
  };
}

// #655: closes the #623 measurement gap — rather than only DISCLOSING that the app's suite lives
// at the workspace root, the CLI now invokes Stryker there. scaffoldStrykerConfig's mutate globs
// are relative to wherever Stryker's cwd is; a per-app scaffold (cwd = the app) produces app-
// relative globs like "src/**/*.{...}", but a root-scoped run's cwd is the WORKSPACE ROOT, so those
// same globs must be re-rooted under the app's path from the root or Stryker would mutate the
// entire monorepo instead of just this app. The negated exclusion globs (test/spec/d.ts/
// node_modules) stay as-is — they are not app-specific, and re-rooting them would only narrow what
// they exclude, not what they scope to.
export function rootScopedMutateGlobs(appRelFromRoot: string, appGlobs: readonly string[]): string[] {
  return appGlobs.map((g) => (g.startsWith("!") ? g : `${appRelFromRoot}/${g}`));
}

// #655: the flip side of rootScopedMutateGlobs — a root-scoped run's report keys files relative to
// the root cwd it executed from (e.g. "apps/foo/src/x.ts"). Stripping the app's root-relative
// prefix lets the rest of the pipeline (summarizeMutationReport, verifyMutationScope, the CLI's
// output shaping) treat the result exactly like an ordinary per-app run's target-relative report,
// with no separate code path. A key that does NOT carry the prefix is outside the app's scoped
// mutate globs — Stryker should never produce one since it only mutates matched files, so it is
// dropped rather than silently mis-attributed to this app, and the caller is told how many/which.
export function reRootReportToApp(report: StrykerReport, appRelFromRoot: string): { report: StrykerReport; dropped: string[] } {
  const prefix = `${appRelFromRoot}/`;
  const files: Record<string, StrykerFileReport> = {};
  const dropped: string[] = [];
  for (const [key, val] of Object.entries(report.files)) {
    if (key.startsWith(prefix)) files[key.slice(prefix.length)] = val;
    else dropped.push(key);
  }
  return { report: { ...report, files }, dropped };
}

// #503: a target's suite can pass ONLY under a specific process env (ATC: a timezone-sensitive
// test that needs the process to START with TZ=Pacific/Honolulu — a runtime process.env.TZ
// reassignment does not re-init Node's timezone). Stryker's initial dry run then fails under the
// audit machine's ambient env and M8 voids with no actionable reason. These functions detect the
// env the target itself declares (CI workflow, test-runner config/setup, package.json test
// script) so the CLI can replicate it when invoking Stryker/stub-check.
//
// Only locale/timezone keys: they are the env-fragility class that breaks a dry run without being
// a secret or machine-specific path. Anything wider (DATABASE_URL, tokens) must come from the
// operator, not be scraped out of the target's CI.
const TEST_ENV_KEYS = "TZ|LANG|LC_ALL";
const ENV_PATTERNS: RegExp[] = [
  new RegExp(`\\b(${TEST_ENV_KEYS})=([A-Za-z0-9_./:+-]+)`, "g"), // inline prefix: TZ=UTC vitest run
  new RegExp(`\\b(${TEST_ENV_KEYS})["']?\\s*:\\s*["']?([A-Za-z0-9_./:+-]+)`, "g"), // YAML env: / JS env object
  new RegExp(`process\\.env\\.(${TEST_ENV_KEYS})\\s*=\\s*["']([^"']+)["']`, "g"), // setup-file assignment
];

export interface DetectedEnvVar {
  key: string;
  value: string;
  source: string;
}

// First declaration per key wins, in the file order the caller supplies — the CLI passes
// test-runner configs/setup files first (closest to the runner), then package.json scripts, then
// CI workflows, so a runner-level TZ beats a workflow-level one.
export function detectTestEnv(files: readonly { path: string; text: string }[]): DetectedEnvVar[] {
  const found = new Map<string, DetectedEnvVar>();
  for (const { path, text } of files) {
    for (const pattern of ENV_PATTERNS) {
      for (const m of text.matchAll(pattern)) {
        const key = m[1]!;
        if (!found.has(key)) found.set(key, { key, value: m[2]!, source: path });
      }
    }
  }
  return [...found.values()];
}

// #503: Stryker aborts with a ConfigError when any test fails in its initial (unmutated) dry run —
// the report is never written, so before this the CLI fell through to "mutation report not found"
// and the probe recorded a generic requires-live-run. The failure is distinct and actionable:
// the SUITE does not pass under the invoked env, which is the target's defect (or an env we
// failed to replicate), not an environment gap.
const DRY_RUN_FAILURE = /failed tests in the initial test run|initial test run (?:failed|timed out)/i;
// Best-effort first failing test out of the runner output Stryker echoes (vitest ×/✗, jest ●/FAIL).
const FAILING_TEST_LINE = /^.*(?:✗|✖|×|✘|●|\bFAIL\b).*$/m;

export function detectDryRunFailure(output: string): { failed: boolean; detail?: string } {
  if (!DRY_RUN_FAILURE.test(output)) return { failed: false };
  const failing = output.match(FAILING_TEST_LINE)?.[0].trim();
  const configError = output.match(/^.*initial test run.*$/im)?.[0].trim();
  return { failed: true, detail: failing ?? configError ?? "Stryker reported a failed initial test run" };
}

const describeEnv = (env: readonly DetectedEnvVar[]): string =>
  env.length ? env.map((e) => `${e.key}=${e.value} (from ${e.source})`).join(", ") : "no target-declared test env detected; ambient process env only";

export function dryRunFailureFinding(detail: string, env: readonly DetectedEnvVar[]): Finding {
  return {
    id: "M8-03",
    status: "Open",
    category: "Test quality",
    title: "Test suite fails its own unmutated dry run — mutation testing blocked",
    severity: "Medium",
    confidence: "Confirmed",
    taxonomy: "M8 — Suite fails unmutated dry run (env-fragile tests)",
    location: "package.json (test suite)",
    evidence: `Stryker's initial dry run — the target's own suite, unmutated — failed under the invoked environment (${describeEnv(env)}). First failure: ${detail}.`,
    impact: "The suite only passes under an environment it does not declare (or not at all) — CI green is unreproducible elsewhere, and mutation testing (M8's headline metric) cannot run until the suite passes a clean dry run.",
    fix: "Make the suite pass in a declared environment: pin required env (TZ, locale) in the test-runner config rather than relying on ambient machine state or runtime process.env reassignment (which does not re-init Node's timezone), then re-run the mutation scan.",
    value: 3,
    ease: 3,
    safety: 5,
  };
}

export function dryRunFailureModuleRecord(detail: string, env: readonly DetectedEnvVar[]): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `Stryker's initial dry run FAILED — the target suite does not pass under the invoked environment (${describeEnv(env)}): ${detail}. M8 mutation scoring could not run (#503); the suite must pass an unmutated run first.`,
  };
}

// #1067: the stub-check tier's equivalent of the rung above. A stub run counts as "the test caught
// the deletion" on ANY non-zero exit, so a suite that cannot run at all scored as a flawless one —
// and this branch, alone among the CLI's degraded rungs, wrote no moduleRecord to contradict it.
export function stubCheckBaselineModuleRecord(testCmd: string, detail: string): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `M8 stub-check did not run: the target suite FAILED its own UNMUTATED baseline under \`${testCmd}\` — ${detail}. No deletion-survival result is reported, because a suite that cannot pass unmutated fails every stubbed run for the same reason and would score as perfect deletion coverage.`,
  };
}

// #504: nothing prevented a mutation run over PART of the configured mutate scope (a --mutate
// subset, an alternate scoped config, or a replayed scoped report) from being treated as the
// module's measurement — a subset score looks exactly like a whole-suite number. The ATC run
// scoped Stryker to 263 files and reported the result as M8; that silently invalidated the
// module, the same class as the exit-0-as-evidence bugs (#350). verifyMutationScope compares the
// file set the report actually covers against the files matched by the CONFIGURED mutate globs
// (the target's own config), so a scoped run is recorded partial with its scope — never `ran`.
//
// The matcher supports the glob subset real Stryker configs use (`**`, `*`, `?`, `{a,b}` braces,
// leading-`!` negation). Anything wider (extglobs, character classes) makes the scope
// unverifiable — recorded as such, never guessed at.
const UNSUPPORTED_GLOB = /[[\]]|[!+@*?]\(/;

function expandBraces(glob: string): string[] {
  const m = glob.match(/\{([^{}]*)\}/);
  if (!m) return [glob];
  return m[1]!.split(",").flatMap((alt) => expandBraces(glob.replace(m[0], alt)));
}

function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // "**/" spans zero or more whole segments; a bare "**" spans anything.
        source += glob[i + 2] === "/" ? "(?:[^/]+/)*" : ".*";
        i += glob[i + 2] === "/" ? 2 : 1;
      } else {
        source += "[^/]*";
      }
    } else if (c === "?") {
      source += "[^/]";
    } else if (/[.+^$()|\\]/.test(c)) {
      source += `\\${c}`;
    } else {
      source += c;
    }
  }
  return new RegExp(`^${source}$`);
}

function matchesMutateGlobs(path: string, globs: readonly string[]): boolean {
  let included = false;
  for (const g of globs) {
    const negated = g.startsWith("!");
    const raw = negated ? g.slice(1) : g;
    if (expandBraces(raw).some((e) => globToRegExp(e).test(path))) included = !negated;
  }
  return included;
}

// Not exported (same rule as the summary shapes above): callers receive it as verifyMutationScope's
// inferred return type.
interface MutationScope {
  mutatedFileCount: number;
  configuredGlobs?: string[];
  expectedFileCount?: number;
  missingCount?: number;
  // Sample (max 5) of files the configured globs match but the report never covered.
  missing?: string[];
  // False when the configured scope could not be statically read (non-JSON config, no mutate
  // array, unsupported glob syntax) — the run is not KNOWN scoped, but full coverage is unproven.
  verified: boolean;
  scoped: boolean;
  note: string;
}

export function verifyMutationScope(
  reportFiles: readonly string[],
  mutateGlobs: readonly string[] | undefined,
  sourceFiles: readonly string[],
): MutationScope {
  const base = { mutatedFileCount: reportFiles.length };
  if (!mutateGlobs || mutateGlobs.length === 0) {
    return { ...base, verified: false, scoped: false, note: "configured mutate scope not statically readable (no JSON Stryker config with a mutate array) — full-scope coverage is unverified, treat the score as covering only the listed files" };
  }
  const unsupported = mutateGlobs.find((g) => UNSUPPORTED_GLOB.test(g));
  if (unsupported) {
    return { ...base, configuredGlobs: [...mutateGlobs], verified: false, scoped: false, note: `configured mutate glob "${unsupported}" uses syntax this scope check cannot evaluate — full-scope coverage is unverified` };
  }
  // .d.ts files carry no executable code, so Stryker configs rarely bother excluding them; leaving
  // them in `expected` would flag honest full runs as scoped.
  const expected = sourceFiles.filter((f) => !f.endsWith(".d.ts") && matchesMutateGlobs(f, mutateGlobs));
  const covered = new Set(reportFiles);
  const missing = expected.filter((f) => !covered.has(f));
  if (missing.length > 0) {
    return {
      ...base,
      configuredGlobs: [...mutateGlobs],
      expectedFileCount: expected.length,
      missingCount: missing.length,
      missing: missing.slice(0, 5),
      verified: true,
      scoped: true,
      note: `run covered ${reportFiles.length} file(s) but the configured mutate globs match ${expected.length} — ${missing.length} file(s) were never mutated (e.g. ${missing.slice(0, 3).join(", ")})`,
    };
  }
  return { ...base, configuredGlobs: [...mutateGlobs], expectedFileCount: expected.length, verified: true, scoped: false, note: `run covered all ${expected.length} file(s) matched by the configured mutate globs` };
}

export function scopedRunModuleRecord(scope: MutationScope): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `Scoped mutation run — ${scope.note}. A subset measurement is not M8's result: recorded partial, never ran (#504). Re-run over the full configured mutate scope for the module's measurement.`,
  };
}

// #513: most third-party clients have a test suite but no Stryker setup — before this, M8's
// headline metric (mutation score) was simply unavailable to them ("this wrapper does not
// generate a config" was the old stance; ATC masked it by shipping its own config). Now the CLI
// detects the target's test runner and scaffolds a minimal, off-tree Stryker config for it.
// Test-runner choice IS still client-specific — which is why this detects rather than assumes,
// and degrades loudly (mutationNotRunModuleRecord) when it cannot detect one.
type ScaffoldRunner = "vitest" | "jest" | "mocha";
const SCAFFOLD_RUNNERS: readonly ScaffoldRunner[] = ["vitest", "jest", "mocha"];

export function detectTestRunner(pkg: PackageJsonForTestDetection | undefined): { runner: ScaffoldRunner; plugin: string } | undefined {
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const runner = SCAFFOLD_RUNNERS.find((r) => r in deps);
  return runner ? { runner, plugin: `@stryker-mutator/${runner}-runner` } : undefined;
}

// Where a target's product code usually lives. Only dirs that actually exist go into the
// scaffolded mutate globs; a target matching none gets no mutate key (Stryker's own defaults),
// which verifyMutationScope then honestly reports as an unverifiable scope.
export const SCAFFOLD_SOURCE_DIRS: readonly string[] = ["src", "app", "apps", "pages", "lib", "components", "server", "packages", "utils", "api"];

// Deliberately the glob subset verifyMutationScope can evaluate (braces + ** + !-negation, no
// extglobs) so a scaffolded run's scope is always verifiable.
export function scaffoldStrykerConfig(runner: ScaffoldRunner, presentDirs: readonly string[]): Record<string, unknown> {
  const mutate = presentDirs.length
    ? [
        ...presentDirs.map((d) => `${d}/**/*.{js,jsx,ts,tsx,cjs,mjs,cts,mts}`),
        "!**/*.test.*",
        "!**/*.spec.*",
        "!**/__tests__/**",
        "!**/*.d.ts",
        "!**/node_modules/**",
      ]
    : undefined;
  return {
    testRunner: runner,
    coverageAnalysis: "perTest",
    reporters: ["json", "progress"],
    jsonReporter: { fileName: "reports/mutation/mutation.json" },
    tempDirName: "stryker-tmp",
    ...(mutate ? { mutate } : {}),
  };
}

// #773: TypeScript 7 (the native/Go-rewritten compiler) restructured the "typescript" package's
// exports — its default entry (`import("typescript")`) now resolves to a version-only module
// (typescript@7's package.json maps "." to "./lib/version.cjs"), not the classic compiler API
// namespace. Stryker's OWN sandbox step (@stryker-mutator/core/dist/src/sandbox/ts-config-
// preprocessor.js) dynamically imports "typescript" and unconditionally calls
// `ts.parseConfigFileTextToJson(...)` on the target's tsconfig.json whenever Stryker isn't running
// `inPlace` (Harvey never sets `inPlace` — it would mutate the live checkout, defeating #600's
// disposable-copy crash-safety guarantee) — regardless of whether that tsconfig's `extends`/
// `references` even need rewriting for the sandbox copy. `parseConfigFileTextToJson` is undefined
// on TS7's restructured package, so the call throws before Stryker runs a single mutant.
//
// The preprocessor no-ops (skips the call entirely) when Stryker's `tsconfigFile` option resolves
// to a path it never tracked as a project file — pointing it at a name that provably doesn't exist
// avoids the crash. The only real cost is an out-of-sandbox tsconfig `extends`/`references` chain
// not getting rewritten (rare, and irrelevant here: Harvey never enables the optional
// `@stryker-mutator/typescript-checker` plugin, `tsconfigFile`'s only other consumer).
export const TS7_TSCONFIG_BYPASS_FILENAME = ".__harvey-ts7-tsconfig-preprocessor-bypass__.json";

export function isIncompatibleTypeScript7(installedVersion: string | undefined): boolean {
  if (!installedVersion) return false;
  const major = Number.parseInt(installedVersion, 10);
  return Number.isFinite(major) && major >= 7;
}

// Never mutates `config` — callers always write the result to a fresh path (the scaffolded config
// dir, or a derived copy of a target-owned config), matching the #655 derived-config pattern:
// a target's own committed Stryker config is never rewritten in place.
export function withTs7TsconfigBypass(config: Record<string, unknown>): Record<string, unknown> {
  return { ...config, tsconfigFile: TS7_TSCONFIG_BYPASS_FILENAME };
}

// Reactive safety net for when the proactive bypass above wasn't applied (a non-JSON target
// config Harvey can't safely rewrite) or missed the incompatibility (TypeScript resolved from
// somewhere this tool didn't check, e.g. a differently-hoisted monorepo layout) — Stryker's crash
// still carries this exact signature, so the CLI can degrade to a precise, named partial verdict
// instead of falling through to the opaque "mutation report not found" this used to produce.
const TS7_TSCONFIG_CRASH = /(?:ts\.)?parseConfigFileTextToJson is not a function/;

export function detectTs7TsconfigCrash(output: string): boolean {
  return TS7_TSCONFIG_CRASH.test(output);
}

// The explicit degradation ladder (#513): when the full-mutation rung cannot run, the ledger says
// which rung this was, why it stopped, and what the next rung is — never a silent drop.
export function mutationNotRunModuleRecord(reason: string): { status: "partial"; note: string } {
  return {
    status: "partial",
    note: `Mutation scoring did not run: ${reason}. M8 degradation ladder (#513): full mutation (target or scaffolded Stryker config) → deletion-survival (pnpm mutation-scan <target> --stub-check) → source-only test-intent detectors (pnpm detect-static <target>) → M8-00 zero-coverage finding. The full-mutation rung stopped here; the drop to a lower rung is recorded, never silent.`,
  };
}

// #435: a real Stryker run's { summary, reportRows } carries no report-schema Finding[], so it
// contributed nothing to the engagement deliverable — only the no-test-suite branch's M8-00 did
// (#224/#420). Surviving mutants are noisy at the individual-mutant level (a repo can have hundreds),
// so this maps the signal §3b's console warning already calls out: files where survivors CONCENTRATE
// in the denial/boundary mutator families (mutatorBreakdown.denialBoundaryConcentrated) — "the denial
// branch was never tested", one finding per file, not one per mutant. Distinct id family from M8-00
// (no suite) and M8-01-* (stub-check, src/stub-check.ts): M8-02-*.
export function survivingMutantFindings(summary: MutationSummary): Finding[] {
  let n = 0;
  return summary.mutatorBreakdown
    .filter((b) => b.denialBoundaryConcentrated)
    .map((b) => {
      const hotspot = summary.survivingMutants.some((s) => s.file === b.file && s.hotspot);
      const total = b.boundarySurvivors + b.otherSurvivors;
      const mutators = Object.entries(b.survivorsByMutator).map(([k, v]) => `${k}: ${v}`).join(", ");
      return {
        id: `M8-02-${String(++n).padStart(2, "0")}`,
        status: "Open",
        category: "Test quality",
        title: `Denial/boundary path untested: ${b.file}`,
        severity: hotspot ? "High" : "Medium",
        confidence: "Confirmed",
        taxonomy: "M8 — Denial/boundary path untested",
        location: b.file,
        evidence: `${b.boundarySurvivors}/${total} surviving mutant(s) are boundary/negation mutants (${mutators})${hotspot ? " — this file is a flagged M1/M3 hotspot" : ""}.`,
        impact: "The suite never proved itself against the negation/boundary condition here (e.g. an inverted comparison or off-by-one) — a real defect on that path would pass every existing test.",
        fix: "Add test cases that exercise the boundary/negation condition directly (e.g. equal-to, just-over, just-under, and the inverted branch) for the mutators listed above.",
        value: 4,
        ease: 3,
        safety: 5,
      } satisfies Finding;
    });
}

// #1076: NoCoverage was parsed and counted per module (ModuleMutationSummary.noCoverage, computed
// above by summarize()) but nothing downstream turned it into a Finding — MEASURED against the
// committed real ATC capture (reports/atc/captures/m8-mutation-broad.json): 26,488/52,152 mutants
// (50.8%) have NO coverage at all, and the deliverable's 32 findings were all "Denial/boundary path
// untested" (survivingMutantFindings above), never stating that half the mutated code never ran. A
// module the suite never even EXECUTED is a stronger, more urgent gap than a surviving mutant: that
// code ran and wasn't killed; this code never ran at all. One finding per module whose mutants are
// MAJORITY no-coverage (a module below NO_COVERAGE_MIN_MUTANTS is too small a sample to be a
// signal, not filtered out of noise-aversion alone). No manual cap here: #935's presentation-layer
// rollup (report-template/rollup.mjs) already groups repeats of the same (taxonomy, severity) shape
// past ROLLUP_THRESHOLD, the same as every other finding family — a second cap here would just be
// two caps disagreeing. Distinct id family from M8-00 (no suite at all) and M8-02-* (survived-but-
// covered): M8-05-*.
const NO_COVERAGE_MIN_MUTANTS = 5;
const NO_COVERAGE_RATIO_THRESHOLD = 0.5;

export function noCoverageFindings(summary: MutationSummary): Finding[] {
  let n = 0;
  return summary.byModule
    .filter((m) => m.totalMutants >= NO_COVERAGE_MIN_MUTANTS && m.noCoverage / m.totalMutants >= NO_COVERAGE_RATIO_THRESHOLD)
    .map((m) => {
      const ratio = Math.round((m.noCoverage / m.totalMutants) * 1000) / 10;
      return {
        id: `M8-05-${String(++n).padStart(2, "0")}`,
        status: "Open",
        category: "Test quality",
        title: `No test coverage at all: ${m.module}`,
        severity: ratio >= 90 ? "High" : "Medium",
        confidence: "Confirmed",
        taxonomy: "M8 — Module has no mutation test coverage",
        location: m.module,
        evidence: `${m.noCoverage}/${m.totalMutants} mutant(s) in this module (${ratio}%) were NEVER EXECUTED by the test suite — not surviving a kill attempt, simply never run.`,
        impact: "A defect anywhere in this module's mutated lines would pass every existing test, because no test exercises the code at all — a stronger, more urgent gap than a surviving mutant (which at least means the code ran and the suite failed to kill it).",
        fix: "Add tests that execute this module's code at all (even a smoke test moves these mutants from NoCoverage toward Killed/Survived) before investing in kill-quality improvements here.",
        value: 5,
        ease: 3,
        safety: 5,
      } satisfies Finding;
    });
}
