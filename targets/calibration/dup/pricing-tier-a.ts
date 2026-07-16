// dup/pricing-tier-a.ts — checkout path: volume-discount tier ladder.
// PLANTED SMALL CLONE (#365, M4-P-SMALL-DISCLOSED / M4-N-SMALL-FLOOR): the tier ladder
// below is genuine business logic copy-pasted into pricing-tier-b.ts. It is 5-9 duplicated
// lines — under MIN_SIGNIFICANT_LINES — so it must NOT become an individual M4 finding,
// but it MUST be counted by the M4-00 sub-threshold disclosure.
export function checkoutDiscountedTotal(units: number, unitPrice: number): number {
  const gross = units * unitPrice;
  if (units >= 500) return gross * 0.8;
  if (units >= 250) return gross * 0.85;
  if (units >= 100) return gross * 0.9;
  if (units >= 50) return gross * 0.93;
  if (units >= 25) return gross * 0.95;
  if (units >= 10) return gross * 0.97;
  return gross;
}

export function checkoutLabel(units: number): string {
  return units >= 10 ? "volume pricing applied" : "standard pricing";
}
