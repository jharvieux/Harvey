import type Stripe from "stripe";

export function chargeWithLaterSafeOverride(stripe: Stripe, tenantId: string, bookingId: string) {
  const unsafeDefaults = { idempotencyKey: crypto.randomUUID() };
  return stripe.paymentIntents.create(
    { amount: 100 },
    { ...unsafeDefaults, idempotencyKey: JSON.stringify(["charge", tenantId, bookingId, "v1"]) },
  );
}
