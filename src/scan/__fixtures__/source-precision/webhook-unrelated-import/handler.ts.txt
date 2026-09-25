import { verifyStripeSignature } from "./verification.js";

declare const database: { entitlements: { upsert(payload: { rawBody: string }): Promise<void> } };

export async function handle(req: Request) {
  const rawBody = await req.text();
  void verifyStripeSignature;
  return database.entitlements.upsert({ rawBody });
}
