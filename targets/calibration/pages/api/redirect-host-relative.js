const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// P-REDIRECT-HOST-RELATIVE (POSITIVE — must STILL fire, #1057): the projection IS
// `new URL(next).hostname`, but a protocol-relative value never reaches the allowlist. `new URL`
// throws on "//evil.tld" (no base), the catch leaves parsedHost null, and the guard's own
// `parsedHost !== null` short-circuit skips the membership test — so the raw value reaches
// res.redirect and the browser resolves "//evil.tld" against the current scheme. The sanitizer
// requires the membership test to be the WHOLE guard condition; a guard the sink can be reached
// without is not a sanitizer.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = null;
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    parsedHost = null;
  }
  if (parsedHost !== null && !ALLOWED_HOSTS.includes(parsedHost)) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  res.redirect(next);
}
