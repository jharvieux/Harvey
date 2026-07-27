const ALLOWED_HOSTS = new Set(["api.trusted.example", "assets.trustedcdn.example"]);

// N-SSRF-HOST-ALLOWLIST-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-SSRF-HOST-ALLOWLIST — the Set-membership spelling of the projection guard on the fetch side.
export default async function handler(req, res) {
  const target = req.query.url || "";
  let parsedHost = "";
  try {
    parsedHost = new URL(target).hostname;
  } catch (e) {
    return res.status(400).json({ error: "unparseable url" });
  }
  if (!ALLOWED_HOSTS.has(parsedHost)) return res.status(403).json({ error: "host not allowed" });
  const upstream = await fetch(target);
  res.status(200).json({ status: upstream.status });
}
