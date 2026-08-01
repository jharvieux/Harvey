import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// PLANTED BUG (P-CLIENT-TRUSTED-ROLE-AR-LET, #1682): the `let` binding of the same App Router
// spelling. Registered separately because the arm matches the DECLARATION keyword, so `const` and
// `let` are two patterns and only one of them being present would be a silent half-fix.
export async function PATCH(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  let body = await req.json();
  const { data } = await admin.from("profiles").update({ is_admin: body.isAdmin }).eq("id", user.id).select().single();
  return Response.json({ profile: data });
}
