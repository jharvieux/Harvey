import { getUser } from "../../../../lib/auth";

// TRUE NEGATIVE (N-SENSITIVE-ROUTE-GETUSER, #568): an admin route that reads the session through a
// bare top-level wrapper — `getUser(req)` — before responding. leftover-auth's sensitive-route
// heuristic previously labelled this "Unauthenticated debug/admin route" because AUTH_HINT only knew
// the dotted supabase.auth.getUser() METHOD call, not a bare getUser() wrapper (the vandyand
// app/api/admin/revenue shape). #568 broadened AUTH_HINT to the bare session-accessor names — this
// must now CLEAR the AUTH-sensitive-route heuristic.
export async function GET(req: Request) {
  const user = await getUser(req);
  if (!user) return new Response("Unauthorized", { status: 401 });
  return Response.json({ ok: true });
}
