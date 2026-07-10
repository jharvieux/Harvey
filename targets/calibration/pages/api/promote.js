import { admin } from "../../lib/supabaseAdmin";

// PLANTED BUG (P-CLIENT-PRIV-HEADER): the authorization decision trusts a client-controlled
// request header — anyone can send `x-role: admin` and elevate an arbitrary user.
export default async function handler(req, res) {
  if (req.headers["x-role"] === "admin") {
    await admin.from("users").update({ role: "admin" }).eq("id", req.body.userId);
    return res.status(200).json({ ok: true });
  }
  return res.status(403).json({ error: "forbidden" });
}
