// M8 (mutation testing / test intent) — shapes StrykerJS's JSON reporter output
// (mutation-testing-elements schema: https://github.com/stryker-mutator/mutation-testing-elements)
// into the summary shape §3b of the audit report needs: mutation score overall + per module,
// and a ranked surviving-mutant list. Pure transforms only; src/cli/mutation-scan.ts does the
// process invocation and file I/O.
//
// Score formula mirrors Stryker's own published metric: a mutant is "valid" unless its status
// is Ignored, CompileError, or Pending (never actually run); score = detected / valid, where
// detected = Killed + Timeout. NoCoverage, Survived, and RuntimeError all count against the
// score — each is a mutant the suite did not prove itself against.

import { dirname } from "node:path";
import type { Finding } from "./findings.js";

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

const NOT_VALID: ReadonlySet<MutantStatus> = new Set(["Ignored", "CompileError", "Pending"]);
const DETECTED: ReadonlySet<MutantStatus> = new Set(["Killed", "Timeout"]);
const SURVIVING: ReadonlySet<MutantStatus> = new Set(["Survived", "NoCoverage"]);

export function mutationScore(mutants: StrykerMutant[]): number {
  const valid = mutants.filter((m) => !NOT_VALID.has(m.status));
  if (valid.length === 0) return 0;
  const detected = valid.filter((m) => DETECTED.has(m.status)).length;
  return Math.round((detected / valid.length) * 1000) / 10;
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
  mutationScore: number;
  survivingCount: number;
  hotspotSurvivingCount: number;
}

// Formats the per-module rows for the §3b Test-quality table (docs/audit-report-skeleton.md):
// | Module / file | Line cov | Mutation score | Surviving mutants (critical) | Action |
// Line coverage isn't in Stryker's mutant-level report, so it's left for the operator to fill in
// from the client's existing coverage tool — this only emits the mutation-derived columns.
export function toReportRows(summary: MutationSummary): ReportRow[] {
  return summary.byModule.map((m) => {
    const forModule = summary.survivingMutants.filter((s) => moduleOf(s.file) === m.module);
    return {
      module: m.module,
      mutationScore: m.mutationScore,
      survivingCount: forModule.length,
      hotspotSurvivingCount: forModule.filter((s) => s.hotspot).length,
    };
  });
}

// #224: a target with no test script, no known test-runner dependency, and no Stryker config
// can't run Stryker at all — src/cli/mutation-scan.ts used to have nothing to do but error out.
// That absence is itself a finding (a security-critical codebase with zero automated regression
// coverage), so the CLI checks this before invoking Stryker and reports it instead of failing.
export interface PackageJsonForTestDetection {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
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

export function noTestSuiteModuleRecord(reason: string): { status: "partial"; note: string } {
  return { status: "partial", note: `No automated test suite found (${reason}) — mutation scan could not run.` };
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
