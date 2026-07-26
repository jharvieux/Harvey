import { admin } from "../../../lib/supabaseAdmin";
import { memoryRateLimit } from "../../../lib/rate-limiter-memory";

// The consumer side of P-INMEMORY-RATE-LIMIT: a login route that LOOKS rate-limited. The
// leftover-auth limiter-hint regex matches `memoryRateLimit`, so AUTH-no-rate-limit clears this
// file — the silent false negative #1046 filed. The store itself lives in lib/rate-limiter-memory.js,
// where the in-memory detector fires.
export default async function handler(req, res) {
  if (!memoryRateLimit(req.headers["x-forwarded-for"] ?? "anon")) {
    return res.status(429).json({ error: "too many requests" });
  }
  const { data, error } = await admin.auth.signInWithPassword({
    email: req.body.email,
    password: req.body.password,
  });
  if (error) return res.status(401).json({ error: "invalid credentials" });
  res.status(200).json({ session: data.session });
}
