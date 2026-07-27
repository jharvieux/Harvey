import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-IDOR-SEARCHPARAMS, #1221): the record id arrives as `?id=` and is the only
// predicate on the query — no owner/tenant scoping. harvey-idor-param modelled req.query and the
// route-params argument but not searchParams, so the commonest App Router id-passing shape was
// dark. #1221 named this rule a confirmed blind spot and then left it out of both its own scope
// list and #1224's split.
export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const { data } = await admin.from("invoices").select("*").eq("id", id).single();
  return Response.json({ invoice: data });
}
