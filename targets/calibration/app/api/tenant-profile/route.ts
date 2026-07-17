import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-ROUTE-NOAUTH-PUT-VERB, #382): an App Router PUT route handler that updates a row
// with no auth guard anywhere in the function. Same mutation-with-no-guard shape as the POST
// positive; before #382 the PUT verb (the idiomatic REST verb for an update) sat outside
// harvey-route-noauth's App Router pattern set and was never flagged. harvey-route-noauth → review.
export async function PUT(req: Request) {
  const body = await req.json();
  await admin.from("profiles").update({ display_name: body.displayName }).eq("id", body.id);
  return Response.json({ updated: true });
}
