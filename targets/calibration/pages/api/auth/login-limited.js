import { admin } from "../../../lib/supabaseAdmin";
import { rateLimit } from "../../../lib/rate-limiter";

// TRUE NEGATIVE (N-NO-RATE-LIMIT): same login shape, but a rate limiter guards it first. The
// leftover-auth rate-limit heuristic's hint regex matches the rateLimit() call in this file.
export default async function handler(req, res) {
  const ok = await rateLimit(req);
  if (!ok) return res.status(429).json({ error: "too many requests" });
  const { data, error } = await admin.auth.signInWithPassword({
    email: req.body.email,
    password: req.body.password,
  });
  if (error) return res.status(401).json({ error: "invalid credentials" });
  res.status(200).json({ session: data.session });
}
