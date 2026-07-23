// PLANTED BUG (CROSS-SERVICE-WEBHOOK): an inbound webhook receiver that READS the signature header
// but never verifies it, then processes the event and returns a body carrying processing evidence.
// Any caller who finds the URL can forge cross-service events. The seam probe posts an unsigned event
// with a bogus `x-signature`; this handler processes it and returns a non-trivial body -> proven.
export const dynamic = "force-dynamic";

export async function POST(request) {
  // Reading the signature header is what makes this a webhook RECEIVER to seam-discovery — but the
  // value is never checked against a computed HMAC, so a forged event sails through.
  const signature = request.headers.get("stripe-signature");
  const event = await request.json().catch(() => ({}));

  // "Process" the event unconditionally and echo processing evidence (the acceptance signal #716 keys on).
  return Response.json({
    received: true,
    processed: event.event ?? event.type ?? "unknown",
    sawSignatureHeader: Boolean(signature),
    ledgerId: "evt_" + Math.random().toString(36).slice(2),
  });
}
