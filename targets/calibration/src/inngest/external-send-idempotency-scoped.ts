import type Stripe from "stripe";

export async function chargeBooking(stripe: Stripe, tenantId: string, bookingId: string) {
  const operationKey = `charge:${tenantId}:${bookingId}:v1`;
  return stripe.paymentIntents.create(
    { amount: 100, currency: "usd", metadata: { bookingId } },
    { idempotencyKey: operationKey },
  );
}

export function sendBookingReceipt(tenantId: string, bookingId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: new Headers({ "Content-Type": "application/json", "Idempotency-Key": `receipt:${tenantId}:${bookingId}:v1` }),
  });
}
