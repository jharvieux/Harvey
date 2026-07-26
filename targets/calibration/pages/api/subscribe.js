import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-UNCHECKED-MUTATION, D-091 #3): the insert is awaited but its { error } tuple is
// discarded. Supabase JS v2 does not throw on a database error, so a failed write still returns
// 200 to the caller and the subscription is silently lost.
export default async function handler(req, res) {
  await admin.from("subscribers").insert({ email: req.body.email, plan: req.body.plan });

  return res.status(200).json({ subscribed: true });
}
