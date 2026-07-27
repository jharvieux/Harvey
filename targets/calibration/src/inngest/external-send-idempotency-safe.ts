import type Stripe from "stripe";

// The correct form of D-091 item 24 (#1230): a key derived from immutable identifiers, so a retry
// of the same logical operation is a no-op at the provider and two DIFFERENT operations never
// collide.

export async function chargeBookingIdempotent(stripe: Stripe, bookingId: string, amountCents: number) {
  return stripe.paymentIntents.create(
    { amount: amountCents, currency: "usd", metadata: { bookingId } },
    { idempotencyKey: `charge:${bookingId}:v1` },
  );
}

export async function notifyPartnerIdempotent(payload: unknown, messageId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": `partner:${messageId}:v1` },
    body: JSON.stringify(payload),
  });
}
