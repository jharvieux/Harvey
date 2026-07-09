import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-IDOR-PARAM): the order is looked up by its own id only — no predicate scoping
// it to the caller. Any authenticated (or anonymous) caller who guesses/enumerates another
// tenant's order id can read it via this route (BOLA/IDOR, OWASP API1).
export default async function handler(req, res) {
  const { data } = await admin.from("orders").select("*").eq("id", req.query.id);
  res.status(200).json({ order: data });
}
