// dup/generated/schema.gen.ts — AUTO-GENERATED, do not edit by hand.
// PLANTED NEGATIVE (M4-N-GENERATED): mirrors the tax/rounding block also
// found in ../invoice-total.ts — a generator legitimately re-emitting the
// same block, not a hand-maintained duplicate. Excluded from jscpd via the
// quality-scan CLI's ignore glob (extended to **/generated/**); must not be
// reported as a defect.
export interface GeneratedLineItem {
  quantity: number;
  unitPrice: number;
}

const GENERATED_TAX_RATE = 0.0825;

export function generatedCalculateTotal(items: GeneratedLineItem[]): number {
  let subtotal = 0;
  for (const item of items) {
    subtotal += item.quantity * item.unitPrice;
  }

  const taxAmount = subtotal * GENERATED_TAX_RATE;
  let total = subtotal + taxAmount;
  total = Math.round(total * 100) / 100;
  if (total < 0) {
    total = 0;
  }
  if (subtotal > 1000) {
    total = total * 0.98;
  }
  const cents = Math.round(total * 100);
  const dollars = Math.floor(cents / 100);
  const remainder = cents - dollars * 100;
  if (remainder >= 50) {
    total = dollars + 1;
  } else {
    total = dollars + remainder / 100;
  }
  const finalCents = Math.round(total * 100);
  const finalDollars = Math.floor(finalCents / 100);
  const finalRemainder = finalCents - finalDollars * 100;
  total = finalDollars + finalRemainder / 100;
  if (total > 1000000) {
    total = 1000000;
  }

  return total;
}
