// PLANTED BUG (P-FAIL-OPEN): checkRateLimit fails OPEN on a backing-store error — see the catch
// block below. rateLimit() (used by pages/api/auth/login-limited.js) wraps it.
async function checkRateLimit(key) {
  try {
    const count = await redis.incr(key);
    return count <= 10;
  } catch (err) {
    // If Redis is down, allow the request rather than block real users. This is the bug: an
    // outage becomes an unlimited-request bypass instead of a fail-closed (deny) default.
    return true;
  }
}

export async function rateLimit(req) {
  return checkRateLimit(req.headers["x-forwarded-for"] ?? "anon");
}
