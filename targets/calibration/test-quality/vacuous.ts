// M8-P-VACUOUS-STRYKER (#1100) — planted VACUOUS test fixture: the covering test below calls this
// function and executes its branches, but its assertion never depends on the return value, so no
// mutation of this logic can ever fail it. Distinct from the M8-P-DELETION-SURVIVING pair
// (audit-log.ts): that one is scored by stub-check's deletion-survival execution; this one is
// scored by real Stryker mutation testing — the coveredBy/killedBy join #1100 adds.
export function gradeScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  return "F";
}
