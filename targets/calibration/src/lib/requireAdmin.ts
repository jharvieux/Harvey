import { admin } from "../../lib/supabaseAdmin";
import { getUser } from "../../lib/auth";

// TRUE NEGATIVE (N-CLIENT-AUTHZ-SERVER-CHECK, #576): the same `role !== "admin"` comparison, but on
// the SERVER — it reads the role from the database keyed on the verified session user and 403s before
// returning. This is a legitimate authorization check, NOT a client-side bypass. leftover-auth's
// client-side-authz heuristic requires a browser navigation/render gate to co-occur with the role
// comparison; a server handler has none, so this must clear. (This comment avoids naming those
// browser-gate helpers, since the heuristic greps the whole file text.)
export async function requireAdmin(req: Request) {
  const user = await getUser(req);
  const { data: profile } = await admin.from("profiles").select("role").eq("id", user.id).single();
  if (profile.role !== "admin") return new Response("Forbidden", { status: 403 });
  return user;
}
