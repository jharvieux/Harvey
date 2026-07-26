const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// P-REDIRECT-HOST-BACKSLASH (POSITIVE — must STILL fire, #1057): the host allowlist runs only
// inside an "looks absolute" pre-test, so a backslash-prefixed value skips it entirely.
// `/\evil.tld` fails /^https?:\/\//, walks straight to res.redirect, and every WHATWG parser
// normalises the leading `\` to `/` — the browser reads `//evil.tld` and leaves the site. The
// sanitizer's pattern-inside is anchored on the projection site, so a guard nested behind another
// condition does not clear the path that skips it.
export default async function handler(req, res) {
  const next = req.query.next || "";
  if (/^https?:\/\//i.test(next)) {
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
  }
  res.redirect(next);
}
