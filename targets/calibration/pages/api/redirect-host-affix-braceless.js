const ALLOWED_SUFFIX = "trusted.example";

// PLANTED BUG (P-REDIRECT-HOST-AFFIX-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-REDIRECT-HOST-AFFIX. Correct WHATWG projection, braceless early return — but the membership
// test is `.endsWith`, and `evilapi.trusted.example` is registrable by anyone. The widened
// projection arm still models exact `.includes`/`.has` membership only: must STILL fire.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    return res.status(400).json({ error: "unparseable url" });
  }
  if (!parsedHost.endsWith(ALLOWED_SUFFIX)) return res.status(403).json({ error: "host not allowed" });
  res.redirect(next);
}
