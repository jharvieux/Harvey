// Negative control for the #1307 gate. This file carries one PLANT and two CONTROLS; the gate must
// separate them, and a run that reports all three (or none) is broken, not strict.

// PLANT — reachable only from lib.test.ts. This is the shape #1307 exists to surface.
export function testOnlyExport(): number {
  return 3;
}

// PLANT — the same shape for a type.
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
