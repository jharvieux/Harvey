// dead/orphan.ts — one live export, one dead export.
export function computeTotal(a: number, b: number): number {
  return a + b;
}

// PLANTED (M5-P-DEAD-EXPORT): never imported anywhere in the target.
export function unusedHelper(value: number): number {
  return value * 2;
}
