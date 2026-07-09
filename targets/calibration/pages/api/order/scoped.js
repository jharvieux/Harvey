import { admin } from "../../../lib/supabaseAdmin";
import { getServerSession } from "next-auth";

// TRUE NEGATIVE (N-IDOR-SCOPED): the same by-id lookup, but scoped to the authenticated caller
// via an additional user_id predicate. harvey-idor-param's sink pattern requires the query to be
// EXACTLY .eq('id', $ID) with nothing else chained; the extra .eq('user_id', ...) here makes the
// destructured RHS a different (longer) expression tree, so it does not match.
export default async function handler(req, res) {
  const session = await getServerSession(req);
  const { data } = await admin
    .from("orders")
    .select("*")
    .eq("id", req.query.id)
    .eq("user_id", session.user.id);
  res.status(200).json({ order: data });
}
