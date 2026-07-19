import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// PLANTED BUG (P-MASS-ASSIGN-APPROUTER, #570): the App Router request body (await req.json()) is
// spread whole into an insert payload with no field allowlist — a caller can set any column the
// table exposes (role/is_admin/owner_id) by adding it to the JSON. The route authenticates (so it is
// not a route-noauth case); the defect is over-posting. The Express-only req.body source never
// connected to this await-req.json() body. harvey-mass-assignment → review.
export async function POST(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  const { data } = await admin.from("notes").insert({ ...body }).select().single();
  return Response.json({ note: data });
}
