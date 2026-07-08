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

interface MutationSummary {
  overall: ModuleMutationSummary;
  byModule: ModuleMutationSummary[];
  survivingMutants: SurvivingMutant[];
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
