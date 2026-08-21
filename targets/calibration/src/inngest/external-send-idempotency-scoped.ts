import type Stripe from "stripe";

export async function chargeBooking(stripe: Stripe, tenantId: string, bookingId: string) {
  const operationKey = JSON.stringify(["charge", tenantId, bookingId, "v1"]);
  return stripe.paymentIntents.create(
    { amount: 100, currency: "usd", metadata: { bookingId } },
    { idempotencyKey: operationKey },
  );
}

export function sendBookingReceipt(tenantId: string, bookingId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: new Headers({
      "Content-Type": "application/json",
      "Idempotency-Key": JSON.stringify(["receipt", tenantId, bookingId, "v1"]),
    }),
  });
}

export function sendChargeNotice(tenantId: string, bookingId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Idempotency-Key": JSON.stringify(["charge", tenantId, bookingId, "v1"]),
    },
  });
}

export function sendEncodedReceipt(tenantId: string, bookingId: string) {
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Idempotency-Key": `encoded-receipt:${encodeURIComponent(tenantId)}:${encodeURIComponent(bookingId)}:v1`,
    },
  });
}

export function createTwoIndependentPayments(stripe: Stripe, tenantId: string, bookingId: string) {
  stripe.paymentIntents.create(
    { amount: 100, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["authorize-dual-charge", tenantId, bookingId, "v1"]) },
  );
  return stripe.paymentIntents.create(
    { amount: 200, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["capture-dual-charge", tenantId, bookingId, "v1"]) },
  );
}

export function reserveInvoice(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["reserve-invoice", tenantId, bookingId, "v1"]) },
  );
}

export function settleInvoice(stripe: Stripe, tenantId: string, bookingId: string) {
  return stripe.paymentIntents.create(
    { amount: 100, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["settle-invoice", tenantId, bookingId, "v1"]) },
  );
}

type FiniteBookingId = 1001 | 1002;

export function chargeKnownNumericBooking(stripe: Stripe, tenantId: string, bookingId: FiniteBookingId) {
  return stripe.paymentIntents.create(
    { amount: 100, metadata: { bookingId } },
    { idempotencyKey: JSON.stringify(["known-numeric-charge", tenantId, bookingId, "v1"]) },
  );
}
