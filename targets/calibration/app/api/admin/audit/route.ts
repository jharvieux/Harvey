import { admin } from "../../../../lib/supabaseAdmin";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-ADMIN-AUDIT, #171): an App Router admin route wrapped by
// withPlatformAdminAudit(...) (ATC's @/lib/db/platform-admin-client, ~70-route FP shape). "with"
// joined harvey-route-noauth's weak-verb bucket (paired with an auth-ish token in the same
// identifier, e.g. "Admin"), so withPlatformAdminAudit now clears the same way jwtVerify/
// verifyWebhookSignature already did.
export async function POST(req: Request) {
  return withPlatformAdminAudit(req, async () => {
    const body = await req.json();
    const { data } = await admin.from("audit_log").insert({ actor: body.actor, action: body.action });
    return Response.json(data);
  });
}
