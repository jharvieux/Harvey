const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// P-REDIRECT-HOST-USERINFO (POSITIVE — must STILL fire, #1057): the allowlist is an exact-match
// membership test and the failure branch returns, but the HOST PROJECTION is hand-rolled rather
// than `new URL(next).hostname`. For `https://api.trusted.example@evil.tld/` this extractor cuts
// at the first `@` and yields "api.trusted.example", which passes — while a WHATWG parser (every
// browser following the Location header) reads the host as "evil.tld". The #1057 sanitizer is
// anchored on `new URL($X).hostname` for exactly this reason: the soundness comes from the
// parser, not from the guard.
export default async function handler(req, res) {
  const next = req.query.next || "";
  const host = next.replace(/^https?:\/\//i, "").split("/")[0].split("@")[0];
  if (!ALLOWED_HOSTS.includes(host)) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  res.redirect(next);
}
