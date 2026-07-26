// P-REDIRECT-HOST-AFFIX (POSITIVE — must STILL fire, #1057): the projection is the correct
// WHATWG `new URL(next).hostname` and the failure branch returns, but the membership test is an
// AFFIX match, not exact — "evilapi.trusted.example".endsWith("trusted.example") is true, and that
// host is registrable by anyone. This is the #1027 class-1 refusal (affix guards) restated on the
// projection: the sanitizer models `.includes`/`.has` exact membership only.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    res.status(400).json({ error: "unparseable url" });
    return;
  }
  if (!parsedHost.endsWith("trusted.example")) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  res.redirect(next);
}
