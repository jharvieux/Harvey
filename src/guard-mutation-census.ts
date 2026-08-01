// #1738 — mutation-test the GUARDS, so "this check has no failing direction" is a measurement instead of a
// discovery.
//
// Harvey's gates are the least-guarded code in the repo. One sweep on 2026-07-31 found roughly
// fourteen distinct guards that report and never fail, and #1628 then quantified the same shape in
// the corpus: 223 of 384 mechanical positives (58%) had no failing direction, and giving them one
// cost nothing. Every one of those was found by a human reading code. This is the mechanical form
// of the same question: mutate a guard's own logic and ask whether anything goes red.
//
// THE SIGNAL IS `all mutants survived` FOR A GIVEN GUARD. A file whose every mutant survives is a
// file no test in the suite distinguishes from a rewrite of it — stated mechanically rather than found
// by inspection. `vacuousTestFiles` (#1100) answers the mirror question from the TEST side; this
// answers it from the GUARD side, and the two disagree in useful ways: a guard can be killed by an
// unrelated test while its own test file is vacuous, and vice versa.
//
// REPORT ONLY. Operator ruling 2026-07-31 on #1738: build it as report-only, promote it to blocking
// once we are comfortable with it. Promotion is a SEPARATE, LATER DECISION — nothing here returns a
// non-zero exit, and the CLI has no verdict branch to flip. Do not add one
// without that ruling; the point of writing this down is that nobody flips it quietly.

import { vacuousTestFiles } from "./mutation-scan.js";
import type { StrykerReport } from "./mutation-scan.js";

/**
 * The guard set #1738 names, as a declared list rather than as whatever `stryker.guards.config.json`
 * happens to say. `guardSetIsFullyAccounted` requires every member to be either mutated or recorded
 * below with a reason, so a file quietly dropped from `mutate` fails `pnpm verify` instead of
 * disappearing from a census that keeps reading green.
 */
const GUARD_SET = [
  "src/acceptance-conservation.ts",
  "src/alert-paths.ts",
  "src/calibration-verdict.ts",
  "src/ci-liveness.ts",
  "src/recorded-reasons.ts",
  "src/scan/calibration.ts",
  "src/scored-gates.ts",
] as const;

/** Guards this run did not mutate, and what was tried. Disclosed in the census output, never silent. */
export const NOT_MUTATED: Record<string, string> = {
  "src/recorded-reasons.ts":
    "MEASURED 2026-08-01: instrumenting it alone fails Stryker's dry run before any mutant is scored — `the repo's own recorded reasons (the gate pnpm verify enforces) are all well-formed` returns 2 errors. That gate reads REASON blocks out of SOURCE COMMENTS and this file carries 7 of them, so the instrumenter perturbs the very input the guard reads. This bounds the MEASUREMENT, not the guard. " +
    "Falsifier: `test -x node_modules/.bin/stryker || exit 127; node -e 'const c=require(\"./stryker.guards.config.json\");c.mutate=[\"src/recorded-reasons.ts\"];c.jsonReporter.fileName=\"reports/guard-mutation/reasons-falsifier.json\";require(\"fs\").writeFileSync(\"/tmp/stryker.reasons.json\",JSON.stringify(c))' && node_modules/.bin/stryker run /tmp/stryker.reasons.json` — exits 0 once the dry run completes.",
};

/** Every declared guard is either mutated or disclosed — and never both. */
export function guardSetIsFullyAccounted(mutated: readonly string[]): { missing: string[]; doubleBooked: string[] } {
  const declared = new Set<string>(GUARD_SET);
  const covered = new Set([...mutated, ...Object.keys(NOT_MUTATED)]);
  return {
    missing: [...declared].filter((f) => !covered.has(f)).sort(),
    doubleBooked: mutated.filter((f) => f in NOT_MUTATED).sort(),
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
  if (Object.keys(NOT_MUTATED).length > 0) {
    out.push("");
    out.push(`NOT MUTATED — ${Object.keys(NOT_MUTATED).length} declared guard(s) this run did not measure. Stated, because an absent row cannot be argued with:`);
    for (const [file, why] of Object.entries(NOT_MUTATED)) out.push(`  ${file}: ${why}`);
  }
  if (census.unscored.length > 0) {
    out.push("");
    out.push(`NOT EVIDENCE — ${census.unscored.length} guard file(s) produced no scorable mutant (compile error, ignored, or nothing to mutate).`);
    out.push("A zero here is a measurement that did not happen, not a clean bill of health:");
    for (const r of census.unscored) out.push(`  ${r.file}: ${r.mutants} mutant(s), none scorable`);
  }
  out.push("");
  out.push("REPORT ONLY — this never fails the build (operator ruling 2026-07-31 on #1738). Promoting it to");
  out.push("blocking is a separate, later decision; the number above is the argument for it, and the thing");
  out.push("that should shrink.");
  return out.join("\n");
}
