export function sendReceiptWithLaterUnsafeHeaders(tenantId: string, bookingId: string) {
  const unsafeOverride = { "Idempotency-Key": Date.now().toString() };
  return fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: new Headers({
      "Idempotency-Key": `receipt:${tenantId}:${bookingId}:v1`,
      ...unsafeOverride,
    }),
  });
}
