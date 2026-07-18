import { admin } from "../../../lib/supabaseAdmin";
import { getUser } from "../../../lib/auth";

// TRUE NEGATIVE (N-MASS-ASSIGN-APPROUTER-PICK, #570): only an explicit destructured allowlist of
// fields from the JSON body is inserted — no { ...body } spread. harvey-mass-assignment's sink
// requires a spread of the request body; a named object literal is a different, safe shape —
// cleared. Regression guard for the new await-req.json() source.
export async function POST(req: Request) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401 });
  const { title, body: content } = await req.json();
  const { data } = await admin.from("notes").insert({ title, body: content }).select().single();
  return Response.json({ note: data });
}
