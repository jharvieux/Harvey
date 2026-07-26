import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// PLANTED BUG (P-ROLE-BLOCK-COMMENT-GUARD, #1093): the SAME authenticated-but-unauthorized admin
// route as revenue/route.ts, but the "role gate" is named inside a MULTI-LINE block comment whose
// interior line does not start with `*`. Same block-comment hole as
// P-NOAUTH-BLOCK-COMMENT-GUARD, on harvey-authed-no-role-check's role/permission-gate clause
// instead of harvey-route-noauth's guard clause. This positive must fire.
export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response("Unauthorized", { status: 401 });
  /*
  requireAdmin role check
  */
  const { data } = await admin.from("invoices").select("amount_cents, org_id");
  return Response.json({ revenue: data });
}
