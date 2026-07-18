import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// PLANTED BUG (P-AUTHED-NO-ROLE-CHECK, #561): an admin route that AUTHENTICATES (reads the session
// via getUser) and 401s an anonymous caller, but performs NO role/permission check before returning
// privileged, org-wide revenue data. Any authenticated lower-privilege member reaches the CFO view —
// broken function-level authorization (OWASP API5 / BFLA). This is the real shape behind vandyand #5
// (app/api/admin/revenue/route.ts), previously only flagged by the filename+missing-auth-hint
// heuristic with a FALSE rationale ("unauthenticated"). harvey-authed-no-role-check → review (High).
export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await admin.from("invoices").select("amount_cents, org_id");
  return Response.json({ revenue: data });
}
