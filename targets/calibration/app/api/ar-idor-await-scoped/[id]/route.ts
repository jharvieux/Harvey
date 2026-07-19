import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// TRUE NEGATIVE (N-IDOR-AWAIT-PARAMS-SCOPED, #601): the same awaited-params read, but scoped to the
// caller with an extra .eq("company_id", user.sub) before .single(). The scoping .eq() lengthens the
// sink RHS expression tree, so harvey-idor-param's exact-shape sink no longer matches — cleared.
// Regression guard for the new await-params source.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = getUser(req);
  const { id } = await params;
  const { data } = await admin.from("invoices").select("*").eq("id", id).eq("company_id", user.sub).single();
  return Response.json({ invoice: data });
}
