import { createHmac, timingSafeEqual } from "node:crypto";

// The correct forms of D-091 item 12 (#1230), one per provider whose documented encoding differs,
// plus the shape the rule must not guess about.

// GitHub signs `sha256=<hex>` -- hex is right here.
export function verifyGithubWebhook(req: Request, body: string): boolean {
  const signature = (req.headers.get("x-hub-signature-256") ?? "").replace("sha256=", "");
  const expected = createHmac("sha256", process.env.GITHUB_WEBHOOK_SECRET ?? "").update(body).digest();
  return timingSafeEqual(Buffer.from(signature, "hex"), expected);
}

// Shopify sends the HMAC base64-encoded.
export function verifyShopifyWebhook(req: Request, body: string): boolean {
  const signature = req.headers.get("x-shopify-hmac-sha256") ?? "";
  const expected = createHmac("sha256", process.env.SHOPIFY_WEBHOOK_SECRET ?? "").update(body).digest();
  return timingSafeEqual(Buffer.from(signature, "base64"), expected);
}

// Svix, decoded correctly.
export function verifySvixWebhook(req: Request, body: string): boolean {
  const signature = (req.headers.get("svix-signature") ?? "").split(",")[1] ?? "";
  const expected = createHmac("sha256", process.env.SVIX_WEBHOOK_SECRET ?? "").update(body).digest();
  return timingSafeEqual(Buffer.from(signature, "base64"), expected);
}

// Stripe's SDK owns the encoding internally -- there is no encoding literal here to compare
// against the provider table, so the rule has nothing to say and must stay silent.
export function verifyStripeWebhook(req: Request, body: string, stripe: { webhooks: { constructEvent: (b: string, s: string, k: string) => unknown } }) {
  const signature = req.headers.get("stripe-signature") ?? "";
  return stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");
}
