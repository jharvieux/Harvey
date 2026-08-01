import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// PLANTED BUG (P-CLIENT-TRUSTED-ROLE-AR, #1682): the App Router spelling of P-CLIENT-TRUSTED-ROLE.
// The body is awaited into a local first, so there is no literal `req.body` anywhere and the rule's
// Express-only arms were blind to it — while its price sibling, added by #1373, already carried the
// App Router arm. harvey-client-trusted-role → review.
export async function PATCH(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  const { data } = await admin.from("profiles").update({ role: body.role }).eq("id", user.id).select().single();
  return Response.json({ profile: data });
}
