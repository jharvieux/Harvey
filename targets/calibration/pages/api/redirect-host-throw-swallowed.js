const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// P-REDIRECT-HOST-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the projection arm's
// swallowed-throw shape. Correct WHATWG projection, exact membership, a branch that leaves the if
// — but the guard sits inside a `try` whose `catch` swallows, so the browser is sent to whatever
// host the request named.
export default async function handler(req, res) {
  const next = req.query.next || "";
  const parsedHost = new URL(next).hostname;
  try {
    if (!ALLOWED_HOSTS.includes(parsedHost)) throw new Error("host not allowed");
  } catch (err) {
    res.setHeader("x-redirect-warning", "1");
  }
  res.redirect(next);
}
