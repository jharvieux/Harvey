import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-ROUTE-NOAUTH-GETUSER-ABSENT, #562): the paired positive for the getUser-wrapper
// negative next door -- the SAME PATCH-mutation shape, but with the getUser(req) session read
// removed. Confirms the #562 guard-name broadening did not over-suppress: a genuinely unguarded
// route (no session read of any name) still fires harvey-route-noauth. harvey-route-noauth → review.
export async function PATCH(req: Request) {
  const body = await req.json();
  await admin.from("profiles").update({ display_name: body.displayName }).eq("id", body.id);
  return Response.json({ updated: true });
}
