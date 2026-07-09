import { admin } from "../../../lib/supabaseAdmin";

// PLANTED BUG (P-NO-RATE-LIMIT): a login endpoint with no rate limiter — an attacker can brute
// force credentials with unlimited attempts. Caught by the leftover-auth sensitive-auth-route
// heuristic (route segment + no rate-limiter hint).
export default async function handler(req, res) {
  const { data, error } = await admin.auth.signInWithPassword({
    email: req.body.email,
    password: req.body.password,
  });
  if (error) return res.status(401).json({ error: "invalid credentials" });
  res.status(200).json({ session: data.session });
}
