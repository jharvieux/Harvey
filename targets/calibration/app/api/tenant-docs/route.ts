import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-ROUTE-NOAUTH-DELETE-VERB, #382): an App Router DELETE route handler that deletes
// a row with no auth guard anywhere in the function — no session read, no supabase.auth.getUser(),
// no guard-named call. Before #382 harvey-route-noauth's App Router half only recognized the POST
// verb, so a DELETE handler in exactly this shape (the idiomatic REST verb for a delete) was
// silently never flagged. harvey-route-noauth → review.
export async function DELETE(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  await admin.from("documents").delete().eq("id", id);
  return Response.json({ deleted: true });
}
