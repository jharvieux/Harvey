const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// PLANTED BUG (P-REDIRECT-HOST-BRACELESS-NO-RETURN, #1236 SOUNDNESS): the braceless twin of
// P-REDIRECT-HOST-NO-RETURN. Correct projection, exact membership, braceless consequent — but the
// consequent only writes a status, so execution falls through to res.redirect with the rejected
// host intact. A braceless consequent is only a guard when it RETURNS: must STILL fire.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    return res.status(400).json({ error: "unparseable url" });
  }
  if (!ALLOWED_HOSTS.includes(parsedHost)) res.status(403).json({ error: "host not allowed" });
  res.redirect(next);
}
