import type Stripe from "stripe";

declare function makeProviderKey(tenantId: string, bookingId: string, operation: string): string;

export function chargeWithRandomKey(stripe: Stripe) {
  return stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: crypto.randomUUID() });
}

export function chargeWithClockKey(stripe: Stripe, bookingId: string) {
  return stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: `charge:${bookingId}:${Date.now()}` });
}

export function chargeWithGlobalKey(stripe: Stripe) {
  return stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: "all-charges" });
}

export function chargeWithoutTenantScope(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create({ amount: 100 }, { idempotencyKey: `charge:${bookingId}:v1` });
}

export function chargeThroughOpaqueHelper(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100 },
    { idempotencyKey: makeProviderKey(tenantId, bookingId, "charge") },
  );
}

export function chargeWithUnrelatedAssurance(stripe: Stripe, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100 },
    { metadata: { idempotencyNote: bookingId } },
  );
}

export function chargeWithTenantMisusedAsEntity(stripe: Stripe, tenantId: string) {
  return stripe.paymentIntents.create(
    { amount: 100 },
    { idempotencyKey: JSON.stringify(["charge", tenantId, "v1"]) },
  );
}

export function chargeWithRawTupleFraming(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100 },
    { idempotencyKey: `charge:${tenantId}:${bookingId}:v1` },
  );
}

export function chargeWithSharedProviderContract(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["shared-effect", tenantId, bookingId, "v1"]) },
  );
}

export function refundWithSharedProviderContract(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.refunds.create(
    { payment_intent: bookingId },
    { idempotencyKey: JSON.stringify(["shared-effect", tenantId, bookingId, "v1"]) },
  );
}
