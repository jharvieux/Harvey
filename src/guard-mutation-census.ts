// #1890 promotes the measured guard census to a versioned blocking baseline.
// The comparator owns the verdict; this formatter keeps the measured populations visible.

import { vacuousTestFiles } from "./mutation-scan.js";
import type { StrykerReport } from "./mutation-scan.js";

/**
 * The guard set #1738 names, as a declared list rather than as whatever `stryker.guards.config.json`
 * happens to say. `guardSetIsFullyAccounted` requires every member to be either mutated or recorded
 * in the baseline with a fresh exclusion probe and reviewed reason, so a file quietly dropped from `mutate` fails `pnpm verify` instead of
 * disappearing from a census that keeps reading green.
 */
export const GUARD_SET = [
  "src/acceptance-conservation.ts",
  "src/alert-paths.ts",
  "src/calibration-verdict.ts",
  "src/ci-liveness.ts",
  "src/recorded-reasons.ts",
  "src/scan/calibration.ts",
  "src/scored-gates.ts",
] as const;

/** Every declared guard is either mutated or disclosed — and never both. */
export function guardSetIsFullyAccounted(mutated: readonly string[], excluded: readonly string[] = []): { missing: string[]; doubleBooked: string[]; unexpected: string[] } {
  const declared = new Set<string>(GUARD_SET);
  const covered = new Set([...mutated, ...excluded]);
  return {
    missing: [...declared].filter((f) => !covered.has(f)).sort(),
    doubleBooked: mutated.filter((f) => excluded.includes(f)).sort(),
    unexpected: [...covered].filter((f) => !declared.has(f)).concat(mutated.filter((f, i) => mutated.indexOf(f) !== i), excluded.filter((f, i) => excluded.indexOf(f) !== i)).sort(),
  };
}

interface GuardRow {
  file: string;
  mutants: number;
  killed: number;
  survived: number;
  noCoverage: number;
  /** Mutants Stryker never scored (CompileError / Ignored / RuntimeError / Pending). */
  notScored: number;
  /** killed / (killed + survived + noCoverage). Undefined when nothing scorable was produced. */
  score?: number;
}

interface GuardCensus {
  rows: GuardRow[];
  /** The population #1738 asks for: guards with scorable mutants and ZERO kills. */
  zeroKill: GuardRow[];
  /** Guards Stryker produced no scorable mutant for at all — a different gap, and not evidence. */
  unscored: GuardRow[];
  totalMutants: number;
  totalKilled: number;
  /**
   * Mutants nothing disproved. The file-level `zeroKill` signal #1738 names is the extreme case and
   * is currently empty; this is the number underneath it that actually moves, and reporting only
   * the extreme would let a guard go from 80% to 5% with the headline unchanged.
   */
  totalUnnoticed: number;
  /**
   * The per-TEST-FILE mirror (#1100): a test file that covered mutated code and killed none of it.
   * It disagrees with `zeroKill` in both directions — a guard can be killed by an unrelated test
   * while its own test file is vacuous — which is why both are printed.
   */
  vacuousGuardTests: { path: string; tests: number; executedMutants: number }[];
}

const DETECTED = new Set(["Killed", "Timeout"]);

export function guardMutationCensus(report: StrykerReport): GuardCensus {
  const rows: GuardRow[] = [];
  for (const [file, fileReport] of Object.entries(report.files)) {
    const killed = fileReport.mutants.filter((m) => DETECTED.has(m.status)).length;
    const survived = fileReport.mutants.filter((m) => m.status === "Survived").length;
    const noCoverage = fileReport.mutants.filter((m) => m.status === "NoCoverage").length;
    const scorable = killed + survived + noCoverage;
    rows.push({
      file,
      mutants: fileReport.mutants.length,
      killed,
      survived,
      noCoverage,
      notScored: fileReport.mutants.length - scorable,
      ...(scorable > 0 ? { score: (killed / scorable) * 100 } : {}),
    });
  }
  rows.sort((a, b) => (a.score ?? -1) - (b.score ?? -1) || (a.file < b.file ? -1 : 1));
  return {
    rows,
    // `scorable > 0` is the whole discrimination. A guard Stryker could not mutate reports zero
    // kills exactly like a guard nothing can kill, and reading the first as the second would
    // manufacture the finding this tool exists to make honest — the #1065 zero-file-scan shape.
    zeroKill: rows.filter((r) => r.score !== undefined && r.killed === 0),
    unscored: rows.filter((r) => r.score === undefined),
    totalMutants: rows.reduce((n, r) => n + r.mutants, 0),
    totalKilled: rows.reduce((n, r) => n + r.killed, 0),
    totalUnnoticed: rows.reduce((n, r) => n + r.survived + r.noCoverage, 0),
    vacuousGuardTests: vacuousTestFiles(report).map((f) => ({ path: f.path, tests: f.vacuousTests.length, executedMutants: f.executedMutantCount })),
  };
}

export function formatGuardCensus(census: GuardCensus): string {
  const out: string[] = [];
  out.push(`GUARD MUTATION CENSUS (#1738) — ${census.rows.length} guard file(s), ${census.totalMutants} mutants, ${census.totalKilled} killed`);
  out.push("");
  out.push(`  ${"score".padStart(7)}  ${"mut".padStart(5)}  ${"kill".padStart(5)}  ${"surv".padStart(5)}  ${"no-cov".padStart(6)}  file`);
  for (const r of census.rows) {
    const score = r.score === undefined ? "  n/a  " : `${r.score.toFixed(1)}%`.padStart(7);
    out.push(`  ${score}  ${String(r.mutants).padStart(5)}  ${String(r.killed).padStart(5)}  ${String(r.survived).padStart(5)}  ${String(r.noCoverage).padStart(6)}  ${r.file}`);
  }
  out.push("");
  out.push(`GUARDS WITH ZERO KILLED MUTANTS — the population this exists to shrink: ${census.zeroKill.length} of ${census.rows.length - census.unscored.length} scored`);
  for (const r of census.zeroKill) {
    out.push(`  ${r.file}: ${r.survived + r.noCoverage} scorable mutant(s), 0 killed — nothing in the suite can tell this file's logic from a rewrite of it.`);
  }
  if (census.zeroKill.length === 0) out.push("  (none — every scored guard has at least one mutation something noticed)");
  out.push("");
  out.push(`MUTANTS NOTHING DISPROVED: ${census.totalUnnoticed} of ${census.totalMutants}. The line above is the extreme case; this is the number underneath it,`);
  out.push("and the one that moves. A guard can fall from 80% to 5% with the zero-kill count unchanged.");
  out.push("");
  out.push(`TEST FILES THAT EXECUTED GUARD CODE AND KILLED NOTHING (#1100's join): ${census.vacuousGuardTests.length}`);
  out.push("  Read as a LEAD, not a finding. Against a scoped `mutate` set most of these are incidental — a test");
  out.push("  file that imports a guard for its constants and exercises its logic only as a module-load side");
  out.push("  effect. It is the file's OWN subject that decides, and this join does not know it.");
  for (const t of census.vacuousGuardTests) out.push(`  ${t.path}: ${t.tests} test(s), ${t.executedMutants} executed mutant(s), 0 killed`);
  if (census.vacuousGuardTests.length === 0) out.push("  (none — every test file that reached a guard killed at least one mutation of it)");
  if (census.unscored.length > 0) {
    out.push("");
    out.push(`NOT EVIDENCE — ${census.unscored.length} guard file(s) produced no scorable mutant (compile error, ignored, or nothing to mutate).`);
    out.push("A zero here is a measurement that did not happen, not a clean bill of health:");
    for (const r of census.unscored) out.push(`  ${r.file}: ${r.mutants} mutant(s), none scorable`);
  }
  out.push("");
  out.push("BLOCKING — the CLI compares every declared guard and retained row with guard-mutation-baseline.json (#1890).");
  return out.join("\n");
}
