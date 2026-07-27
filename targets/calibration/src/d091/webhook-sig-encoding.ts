import { createHmac, timingSafeEqual } from "node:crypto";

// D-091 item 12 (#1230) -- webhook signature decoded with the wrong encoding. Svix (Resend,
// Clerk, and anything else fronted by Svix) sends the signature base64-encoded; decoding it as
// hex makes EVERY valid delivery fail verification, so the handler and every enforcement behind
// it are silently inoperative. Nothing errors and the tests pass, because a mock signature is
// produced by the same wrong decode.

export function verifyResendWebhook(req: Request, body: string): boolean {
  const signature = req.headers.get("svix-signature") ?? "";
  const secret = process.env.RESEND_WEBHOOK_SECRET ?? "";
  const expected = createHmac("sha256", secret).update(body).digest();
  return timingSafeEqual(Buffer.from(signature, "hex"), expected);
}
