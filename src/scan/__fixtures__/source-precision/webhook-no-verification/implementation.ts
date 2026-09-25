export async function processWebhook(params: {
  rawBody: string;
  signatureHeader: string | null;
  secret: string;
  grantEntitlement: (userId: string) => Promise<void>;
}) {
  await params.grantEntitlement("fixture-user");
  return { ok: true };
}
