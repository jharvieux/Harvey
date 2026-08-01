import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// SAFE TWIN (N-AR-BENIGN-BODY-FIELD, #1682): the App Router body spelling reading an ORDINARY
// field. The new arm is gated on the same privilege-flag vocabulary as the Express arms, so
// widening the rule to `await req.json()` must not make every App Router body read a finding.
export async function PATCH(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  const { data } = await admin.from("posts").update({ title: body.title }).eq("id", user.id).select().single();
  return Response.json({ post: data });
}
