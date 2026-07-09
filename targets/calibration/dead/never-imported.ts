// dead/never-imported.ts — PLANTED (M5-P-DEAD-FILE): no entry point ever
// imports this file; knip's top-level files[] must report it whole.
export function neverCalled(): string {
  return "never imported";
}
