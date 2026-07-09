import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-ROUTE-NOAUTH): a Pages Router route handler that deletes data with no auth
// guard anywhere in the function — no session read, no supabase.auth.getUser() call, nothing.
// Distinct from P-DEBUG-ENDPOINT (leftover-auth's sensitive-route heuristic, gated on the
// /debug|seed|admin|api\/dev path segment): this route's path has no sensitive segment, so only
// a mutation-shaped heuristic catches it.
export default async function handler(req, res) {
  await admin.from("settings").delete().eq("key", req.body.key);
  res.status(200).json({ deleted: true });
}
