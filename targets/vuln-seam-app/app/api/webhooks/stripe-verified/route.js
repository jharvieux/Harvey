// NEGATIVE CONTROL (CROSS-SERVICE-WEBHOOK must stay not-vulnerable): a receiver that HMAC-verifies
// the inbound signature over the raw body and, on failure, returns an empty 200 without processing
// (the boxyhq dsync shape #713/#716 — a bare/empty 2xx is NOT acceptance evidence). The seam probe's
// forged `x-signature` fails verification, so the response carries no processing evidence -> unproven.
import { createHmac, timingSafeEqual } from "node:crypto";

export const dynamic = "force-dynamic";

export async function POST(request) {
  const signature = request.headers.get("stripe-signature") ?? "";
  const raw = await request.text();
  const secret = process.env.WEBHOOK_SIGNING_SECRET ?? "";
  const expected = createHmac("sha256", secret).update(raw).digest("hex");

  const ok =
    signature.length === expected.length &&
    timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  if (!ok) {
    // Reject: end with an empty 200 (no processing). Deliberately the hardest not-vulnerable shape
    // for the probe — it must NOT read a 2xx as acceptance when the body carries no evidence.
    return new Response(null, { status: 200 });
  }

  const event = JSON.parse(raw || "{}");
  return Response.json({ received: true, processed: event.event ?? "unknown" });
}
