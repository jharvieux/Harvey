import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// PLANTED BUG (P-MASS-ASSIGN-BARE, #601 CX-14): the whole parsed request body is passed DIRECTLY as
// the update payload — `update(body)`, no spread, no field allowlist. A caller can set any column
// (role/is_admin) by adding it to the JSON. Even stronger over-posting than a spread, but the
// spread-only sink `update({ ...body })` never matched a bare variable. harvey-mass-assignment-bare
// → review.
export async function PATCH(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  const { data } = await admin.from("profiles").update(body).eq("id", user.id).select().single();
  return Response.json({ profile: data });
}
