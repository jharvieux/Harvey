export function sendReceiptWithLaterSafeHeaders(tenantId: string, bookingId: string) {
  const unsafeDefaults = { "Idempotency-Key": Date.now().toString() };
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: new Headers({
      ...unsafeDefaults,
      "Idempotency-Key": `receipt:${tenantId}:${bookingId}:v1`,
    }),
  });
}
