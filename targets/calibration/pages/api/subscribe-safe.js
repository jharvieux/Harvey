import { admin } from "../../lib/supabaseAdmin";

// The same insert with its { error } destructured and acted on — a failed write becomes a 500,
// never a silent 200.
export default async function handler(req, res) {
  const { error } = await admin.from("subscribers").insert({ email: req.body.email, plan: req.body.plan });

  if (error) return res.status(500).json({ error: "subscribe failed" });

  return res.status(200).json({ subscribed: true });
}
