import type Stripe from "stripe";

// The correct form of D-091 item 24 (#1230): a key derived from immutable identifiers, so a retry
// of the same logical operation is a no-op at the provider and two DIFFERENT operations never
// collide.

export async function chargeBookingIdempotent(stripe: Stripe, tenantId: string, bookingId: string, amountCents: number) {
  return stripe.paymentIntents.create(
    { amount: amountCents, currency: "usd", metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["charge", tenantId, bookingId, "v1"]) },
  );
}

export async function notifyPartnerIdempotent(payload: unknown, tenantId: string, messageId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": JSON.stringify(["partner", tenantId, messageId, "v1"]) },
    body: JSON.stringify(payload),
  });
}
