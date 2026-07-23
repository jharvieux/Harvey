// NEGATIVE CONTROL (NO-RATE-LIMIT must stay not-vulnerable): a high-value checkout flow with a
// per-process token-bucket. The probe's 5 rapid replays exhaust the bucket after the first, so calls
// 2..5 return 429 -> the probe never sees 5/5 accepted -> unproven.
export const dynamic = "force-dynamic";

let allowance = 1;
let windowStart = Date.now();
const WINDOW_MS = 60_000;

export async function POST() {
  const now = Date.now();
  if (now - windowStart > WINDOW_MS) {
    windowStart = now;
    allowance = 1;
  }
  if (allowance <= 0) {
    return new Response(JSON.stringify({ error: "rate_limited" }), {
      status: 429,
      headers: { "Content-Type": "application/json", "Retry-After": "60" },
    });
  }
  allowance -= 1;
  return Response.json({ ok: true });
}
