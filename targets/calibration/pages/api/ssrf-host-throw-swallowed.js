const ALLOWED_HOSTS = new Set(["api.trusted.example", "assets.trustedcdn.example"]);

// P-SSRF-HOST-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the fetch() twin of
// P-REDIRECT-HOST-THROW-SWALLOWED, and the adversarial positive the projection-throw sanitizer
// shipped without. Correct WHATWG projection, exact Set membership, a branch that leaves the if —
// but the guard sits inside a `try` whose `catch` swallows, so the server fetches whatever host the
// request named. Present so the arm's three try exclusions are SCORED on harvey-ssrf-fetch and not
// only on harvey-open-redirect: without this row, deleting them left the gate green.
export default async function handler(req, res) {
  const target = req.query.url || "";
  const parsedHost = new URL(target).hostname;
  try {
    if (!ALLOWED_HOSTS.has(parsedHost)) throw new Error("host not allowed");
  } catch (err) {
    res.setHeader("x-fetch-warning", "1");
  }
  const upstream = await fetch(target);
  res.status(200).json({ status: upstream.status });
}
