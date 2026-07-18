import { admin } from "../../../../lib/supabaseAdmin";

// PLANTED BUG (P-IDOR-APPROUTER, #570): an App Router route handler reads a note by the id from the
// { params } second-arg (params.id) as the SOLE predicate — no owner/tenant scoping. This is the
// App Router IDOR shape the Express-only sources (req.query/req.params) missed; the id enters via
// the handler's params argument, not req.query. The .single() single-row idiom is the reason the
// sink also spells out the trailing-.single() variant. harvey-idor-param → review.
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await admin.from("notes").select("*").eq("id", params.id).single();
  return Response.json({ note: data });
}
