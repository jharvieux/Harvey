import type Stripe from "stripe";

// D-091 item 24 (#1230) -- a retryable context (this file is an Inngest step) calls an external
// API that supports idempotency keys, without passing one. Inngest retries the step on any
// failure after the call was already accepted, so the charge lands twice. The provider's dedup
// window is minutes to hours; single-run tests never retry.

export async function chargeBooking(stripe: Stripe, bookingId: string, amountCents: number) {
  return stripe.paymentIntents.create({
    amount: amountCents,
    currency: "usd",
    metadata: { bookingId },
  });
}

export async function notifyPartner(payload: unknown) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
