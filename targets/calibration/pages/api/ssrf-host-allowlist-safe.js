const ALLOWED_HOSTS = new Set(["api.trusted.example", "assets.trustedcdn.example"]);

// N-SSRF-HOST-ALLOWLIST (NEGATIVE — must NOT be flagged, #1057): the modeled projection guard on
// the SSRF side, expressed with the Set-backed membership arm rather than the array arm — the same
// exact-match semantics, so it carries the same soundness.
export default async function handler(req, res) {
  const target = req.query.url || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(target).hostname;
  } catch (e) {
    res.status(400).json({ error: "unparseable url" });
    return;
  }
  if (!ALLOWED_HOSTS.has(parsedHost)) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  const upstream = await fetch(target);
  res.status(200).json({ status: upstream.status });
}
