import { admin } from "../../../../lib/supabaseAdmin";

// PLANTED BUG (P-IDOR-AWAIT-PARAMS, #601 CX-13): Next 15/16 makes the route-handler params a Promise,
// read as `const { id } = await params`. The id is the SOLE predicate on the query — no owner/tenant
// scope. Before #601 harvey-idor-param's App Router source was `params.id` (property access); the
// awaited-promise destructure went unrecognized, so this pure-App-Router IDOR stayed dark.
// harvey-idor-param → review.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { data } = await admin.from("invoices").select("*").eq("id", id).single();
  return Response.json({ invoice: data });
}
