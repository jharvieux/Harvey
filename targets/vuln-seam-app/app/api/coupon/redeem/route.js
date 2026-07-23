// PLANTED BUG (NO-RATE-LIMIT): a high-value coupon-redemption flow that accepts the same request
// endlessly with no anti-automation cap or single-use enforcement. The probe replays the same POST
// 5x; every call returns 2xx -> proven.
export const dynamic = "force-dynamic";

export async function POST(request) {
  const body = await request.json().catch(() => ({}));
  // No throttle, no idempotency/one-time-use check — the code can be redeemed unbounded times.
  return Response.json({ redeemed: true, code: body.code ?? null, credit: 500 });
}
