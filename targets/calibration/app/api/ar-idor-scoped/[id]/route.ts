import { admin } from "../../../../lib/supabaseAdmin";
import { getUser } from "../../../../lib/auth";

// TRUE NEGATIVE (N-IDOR-APPROUTER-SCOPED, #570): the same App Router by-id read, but scoped to the
// caller with an extra .eq("owner_id", user.sub). The scoping .eq() sits between .eq("id", params.id)
// and .single(), lengthening the RHS expression tree, so harvey-idor-param's exact-shape sink no
// longer matches — cleared. Regression guard for the new App Router sink variants.
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = getUser(req);
  const { data } = await admin
    .from("notes")
    .select("*")
    .eq("id", params.id)
    .eq("owner_id", user.sub)
    .single();
  return Response.json({ note: data });
}
