// Negative control for the #1307 gate. This file carries one PLANT and two CONTROLS; the gate must
// separate them, and a run that reports all three (or none) is broken, not strict.

// PLANT — reachable only from lib.test.ts. This is the shape #1307 exists to surface.
export function testOnlyExport(): number {
  return 3;
}

// PLANT — the same shape for a type. This one is TRIAGED: the block below is the #1547 control, so
// the gate has to report it as carrying a recorded reason while `testOnlyExport` above — the same
// shape in the same file, with no block naming it — stays untriaged. One reason absolving a whole
// file is the failure this pair rules out.
//
// REASON: TestOnlyType is the planted control for the recorded-reason half of the #1547 backlog split, so nothing in this fixture's production entry point imports it.
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-31 — planted for src/cli/validate-test-only-exports.test.ts.
// FALSIFIER: test -f targets/test-only-export-control/src/entry.ts || exit 127; git grep -q TestOnlyType -- targets/test-only-export-control/src/entry.ts
export interface TestOnlyType {
  a: number;
}

// CONTROL — entry.ts calls it. Must never be reported, or the gate is just listing every export.
export function usedInProduction(): number {
  return internallyUsed() + 1;
}

// CONTROL — used inside this file AND asserted by the test. Every detector in src/scan/ is exported
// in exactly this shape for its own test, so a gate that reports it fires on ~every new detector.
export function internallyUsed(): number {
  return 1;
}
