// dup/pricing-tier-b.ts — quote-builder path: the same volume-discount tier ladder,
// regenerated per call site instead of shared (the small-block AI-duplication shape #365
// measured on the external corpus). See pricing-tier-a.ts for the planted-clone contract.
export interface QuoteLine {
  units: number;
  unitPrice: number;
}

export function quoteExpiryDays(units: number): number {
  return units >= 100 ? 14 : 30;
}

export function quoteDiscountedTotal(line: QuoteLine): number {
  const units = line.units;
  const gross = units * line.unitPrice;
  if (units >= 500) return gross * 0.8;
  if (units >= 250) return gross * 0.85;
  if (units >= 100) return gross * 0.9;
  if (units >= 50) return gross * 0.93;
  if (units >= 25) return gross * 0.95;
  if (units >= 10) return gross * 0.97;
  return gross;
}
