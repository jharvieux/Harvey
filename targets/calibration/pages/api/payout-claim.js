import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-ZERO-ROW-UPDATE, D-091 #7): the compare-and-swap that claims the payout has no
// .select() on the chain, so a lost race reads exactly like a won one — Supabase returns
// { error: null } for "matched 0 rows" too. Two workers can both report the transfer as claimed.
export default async function handler(req, res) {
  await admin
    .from("payouts")
    .update({ status: "sending" })
    .eq("id", req.body.payoutId)
    .eq("status", "pending");

  return res.status(200).json({ claimed: true });
}
