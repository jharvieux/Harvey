// M8 calibration fixture (#72 §M8) — the WEAK-test-covered source. See
// discount.tautological.test.ts for the planted weak test (M8-P-TAUTOLOGICAL).
export function applyDiscount(total: number, isMember: boolean): number {
  if (total < 0) throw new Error("total must be non-negative");
  if (!isMember) return total;
  if (total >= 100) return total * 0.8; // members get 20% off orders >= 100
  return total * 0.9; // members get 10% off smaller orders
}
