// dup/order-total.ts — order total: subtotal, tax, rounding.
export interface OrderLine {
  qty: number;
  price: number;
}

const SALES_TAX_RATE = 0.0825;

export function calculateOrderTotal(lines: OrderLine[]): number {
  let subtotal = 0;
  for (const line of lines) {
    subtotal += line.qty * line.price;
  }

  // PLANTED CLONE (M4-P-CLONE-A): identical tax + rounding block, copy-pasted
  // from invoice-total.ts instead of being extracted into a shared helper.
  const taxAmount = subtotal * SALES_TAX_RATE;
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
