import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// TRUE NEGATIVE (N-ROUTE-NOAUTH-GETUSER-WRAPPER, #562): an App Router PATCH handler that reads the
// session through a plain top-level wrapper helper -- `getUser(req)` -- before mutating. This is the
// vandyand/saas-security-teardown app/api/profile/route.ts shape: harvey-route-noauth previously
// asserted "no auth-check call anywhere" here (false premise), because it only recognized the
// supabase.auth.getUser() METHOD call, not a bare getUser() wrapper. #562 added the bare
// session-accessor names to the guard-name regex, so this must now CLEAR harvey-route-noauth.
// (The route still has a real, different defect -- mass assignment -- caught by harvey-mass-assignment
// / M2, not by route-noauth.)
export async function PATCH(req: Request) {
  const user = await getUser(req);
  const body = await req.json();
  await admin.from("profiles").update({ display_name: body.displayName }).eq("id", user.id);
  return Response.json({ updated: true });
}
