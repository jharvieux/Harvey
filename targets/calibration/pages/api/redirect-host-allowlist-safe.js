const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// N-REDIRECT-HOST-ALLOWLIST (NEGATIVE — must NOT be flagged, #1057): the modeled projection
// guard. `new URL(next)` — one argument, so `next` must be an ABSOLUTE URL — projected to
// `.hostname`, exact-match membership, early return on both the parse failure and the rejection.
// Whatever passes is a URL whose WHATWG host is one of two constants, which is exactly the host
// the browser will contact.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    res.status(400).json({ error: "unparseable url" });
    return;
  }
  if (!ALLOWED_HOSTS.includes(parsedHost)) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  res.redirect(next);
}
