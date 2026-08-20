import type Stripe from "stripe";

export function chargeWithLaterUnsafeOverride(stripe: Stripe, tenantId: string, bookingId: string) {
  const unsafeOverride = { idempotencyKey: crypto.randomUUID() };
  return stripe.paymentIntents.create(
    { amount: 100 },
    { idempotencyKey: `charge:${tenantId}:${bookingId}:v1`, ...unsafeOverride },
  );
}
