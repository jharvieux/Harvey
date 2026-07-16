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
  };
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

export function detectNoTestSuite(pkg: PackageJsonForTestDetection | undefined, hasStrykerConfig: boolean): { missing: boolean; reason?: string } {
  const testScript = pkg?.scripts?.test;
  const hasRealTestScript = !!testScript && !PLACEHOLDER_TEST_SCRIPT.test(testScript);
  const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
  const hasRunnerDep = KNOWN_TEST_RUNNER_DEPS.some((d) => d in deps) || (testScript?.includes("--test") ?? false);
  if (hasRealTestScript || hasRunnerDep || hasStrykerConfig) return { missing: false };

  const reason = [
    pkg ? (testScript ? `"scripts.test" is the npm-init placeholder ("${testScript}")` : `no "scripts.test" in package.json`) : "no package.json found",
    "no known test-runner dependency (vitest/jest/mocha/ava/...)",
    "no stryker.conf.* found",
  ].join("; ");
  return { missing: true, reason };
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
