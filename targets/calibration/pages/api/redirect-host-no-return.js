const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// P-REDIRECT-HOST-NO-RETURN (POSITIVE — must STILL fire, #1057): correct projection, exact
// membership, but the rejection branch only writes a status — execution falls through to
// res.redirect with the rejected value intact. The sanitizer matches the whole guard STATEMENT
// (test AND early return), the same constraint #989 proved on the bare `.test()` form.
export default async function handler(req, res) {
  const next = req.query.next || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(next).hostname;
  } catch (e) {
    parsedHost = "";
  }
  if (!ALLOWED_HOSTS.includes(parsedHost)) {
    res.status(403).json({ error: "host not allowed" });
  }
  res.redirect(next);
}
