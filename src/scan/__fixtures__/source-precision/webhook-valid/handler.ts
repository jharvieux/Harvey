import { processWebhook } from "./shared.js";

declare const database: { entitlements: { upsert(payload: { userId: string }): Promise<void> } };

export async function handle(req: Request) {
  const rawBody = await req.text();
  const signatureHeader = req.headers.get("Stripe-Signature");
  const secret = "fixture-secret-from-env";
  return processWebhook({
    rawBody,
    signatureHeader,
    secret,
    grantEntitlement: async (userId: string) => database.entitlements.upsert({ userId }),
  });
}
