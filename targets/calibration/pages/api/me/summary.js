import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (CACHE-CROSS-USER): a per-user response served with a shared, public cache header
// and no Vary on the auth token. A CDN/proxy caches the first user's personalized summary under
// the path and replays it to every later visitor. See me/private.js for the fix.
//
// #1669 — the identity comes from the Authorization bearer, not from an `x-user-id` header. The
// old shape keyed on `req.headers["x-user-id"]`, which no probe (and no realistic client) ever
// sends: MEASURED 2026-07-31 against a stood-up stack, every request therefore fell through to the
// "anon" branch and the response was IDENTICAL for every caller, so the route was not personalized
// and the planted bug was unprovable on its own fixture. Reading the session token is also what a
// real per-user endpoint does, so the fixture now models the shape it claims to.
export default async function handler(req, res) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const { data: auth } = token ? await admin.auth.getUser(token) : { data: null };
  const userId = auth?.user?.id;
  const { data } = userId ? await admin.from("profiles").select("tenant_id, email").eq("id", userId).single() : { data: null };
  res.setHeader("Cache-Control", "public, s-maxage=60");
  res.status(200).json({ tenant_id: data?.tenant_id ?? "anon", email: data?.email });
}
