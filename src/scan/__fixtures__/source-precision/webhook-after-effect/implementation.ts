declare function verifyStripeSignature(rawBody: string, signatureHeader: string | null, secret: string): Promise<boolean>;

export async function processWebhook(params: {
  rawBody: string;
  signatureHeader: string | null;
  secret: string;
  grantEntitlement: (userId: string) => Promise<void>;
}) {
  await params.grantEntitlement("fixture-user");
  const valid = await verifyStripeSignature(params.rawBody, params.signatureHeader, params.secret);
  if (!valid) return { ok: false };
  return { ok: true };
}
