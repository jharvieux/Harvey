import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (CACHE-CROSS-USER): a per-user response served with a shared, public cache header
// and no Vary on the auth token. A CDN/proxy caches the first user's personalized summary under
// the path and replays it to every later visitor. See me/private.js for the fix.
export default async function handler(req, res) {
  const userId = req.headers["x-user-id"] || "anon";
  const { data } = await admin.from("profiles").select("tenant_id, email").eq("id", userId).single();
  res.setHeader("Cache-Control", "public, s-maxage=60");
  res.status(200).json({ tenant_id: data?.tenant_id ?? "anon", email: data?.email });
}
