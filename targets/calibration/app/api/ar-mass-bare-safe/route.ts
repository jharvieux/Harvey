import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// TRUE NEGATIVE (N-MASS-ASSIGN-BARE-RECONSTRUCTED, #601): the request body is parsed, but only two
// named fields are copied into a NEW object which is then passed to update(). harvey-mass-assignment-
// bare unifies $BODY to the identifier declared from await req.json(); `upd` has a different RHS
// (an object literal), so it never binds $BODY — cleared. Proves the bare sink keys on the raw body
// variable, not on any variable-argument update().
export async function PATCH(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  const upd = { display_name: body.display_name, bio: body.bio };
  const { data } = await admin.from("profiles").update(upd).eq("id", user.id).select().single();
  return Response.json({ profile: data });
}
