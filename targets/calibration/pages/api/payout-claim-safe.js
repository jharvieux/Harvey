import { admin } from "../../lib/supabaseAdmin";

// The same compare-and-swap, chained with .select("id") so the affected rows come back and the
// handler can tell "I took the lock" from "someone else already did".
export default async function handler(req, res) {
  const { data, error } = await admin
    .from("payouts")
    .update({ status: "sending" })
    .eq("id", req.body.payoutId)
    .eq("status", "pending")
    .select("id");

  if (error) return res.status(500).json({ error: "claim failed" });
  if (data.length !== 1) return res.status(409).json({ error: "already claimed" });

  return res.status(200).json({ claimed: true });
}
