import crypto from "crypto";
import { admin } from "../../lib/supabaseAdmin";

// Inbound signed webhook (e.g. a billing provider). The HMAC check itself is fine.
export default async function handler(req, res) {
  const signature = req.headers["x-signature"] || "";
  const payload = JSON.stringify(req.body);

  const expected = crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(payload)
    .digest("hex");

  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return res.status(401).json({ error: "bad signature" });
  }

  // PLANTED BUG (no replay protection): the signature is valid but nothing checks a
  // timestamp or nonce, so a captured request can be replayed indefinitely — every
  // replay re-applies the side effect below.
  await admin.from("audit_logs").insert({
    tenant_id: req.body.tenant_id,
    action: "webhook",
    detail: req.body.event,
  });

  res.status(200).json({ ok: true });
}
