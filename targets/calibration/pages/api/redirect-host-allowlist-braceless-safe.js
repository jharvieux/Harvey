const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// N-REDIRECT-HOST-ALLOWLIST-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin
// of N-REDIRECT-HOST-ALLOWLIST — the same WHATWG host-projection guard (#1057), spelled with
// braceless early returns on the parse failure and on the rejection.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    return res.status(400).json({ error: "unparseable url" });
  }
  if (!ALLOWED_HOSTS.includes(parsedHost)) return res.status(403).json({ error: "host not allowed" });
  res.redirect(next);
}
