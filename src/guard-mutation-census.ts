// #1738 — mutation-test the GUARDS, so "this check cannot fail" is a measurement instead of a
// discovery.
//
// Harvey's gates are the least-guarded code in the repo. One sweep on 2026-07-31 found roughly
// fourteen distinct guards that report and cannot fail, and #1628 then quantified the same shape in
// the corpus: 223 of 384 mechanical positives (58%) had no failing direction, and giving them one
// cost nothing. Every one of those was found by a human reading code. This is the mechanical form
// of the same question: mutate a guard's own logic and ask whether anything goes red.
//
// THE SIGNAL IS `all mutants survived` FOR A GIVEN GUARD. A file whose every mutant survives is a
// file the suite cannot distinguish from any rewrite of it — stated mechanically rather than found
// by inspection. `vacuousTestFiles` (#1100) answers the mirror question from the TEST side; this
// answers it from the GUARD side, and the two disagree in useful ways: a guard can be killed by an
// unrelated test while its own test file is vacuous, and vice versa.
//
// REPORT ONLY. Operator ruling 2026-07-31 on #1738: build it as report-only, promote it to blocking
// once we are comfortable with it. Promotion is a SEPARATE, LATER DECISION — nothing here returns a
// non-zero exit, and `censusVerdict` deliberately has no failing branch to switch on. Do not add one
// without that ruling; the point of writing this down is that nobody flips it quietly.

import type { StrykerReport } from "./mutation-scan.js";

export interface GuardRow {
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

export interface GuardCensus {
  rows: GuardRow[];
  /** The population #1738 asks for: guards with scorable mutants and ZERO kills. */
  zeroKill: GuardRow[];
  /** Guards Stryker produced no scorable mutant for at all — a different gap, and not evidence. */
  unscored: GuardRow[];
  totalMutants: number;
  totalKilled: number;
}

const DETECTED = new Set(["Killed", "Timeout"]);
const SURVIVING = new Set(["Survived", "NoCoverage"]);

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
