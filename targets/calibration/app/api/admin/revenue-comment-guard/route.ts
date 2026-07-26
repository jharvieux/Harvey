import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// PLANTED BUG (P-ROLE-COMMENT-GUARD, #1066): the SAME authenticated-but-unauthorized admin route as
// revenue/route.ts, plus one FIXME naming the gate that is missing. harvey-authed-no-role-check
// clears any handler whose source text mentions a role/permission/403 concept, and before #1066
// that text match saw comments — so admitting the gap in a comment removed the finding. This
// positive must STILL fire.
export async function GET(req: Request) {
  // FIXME: no permission gate here yet
  const user = await getUser(req);
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await admin.from("invoices").select("amount_cents, org_id");
  return Response.json({ revenue: data });
}
