const ALLOWED_HOSTS = new Set(["api.trusted.example", "assets.trustedcdn.example"]);

// N-SSRF-HOST-ALLOWLIST-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-SSRF-HOST-ALLOWLIST, on the Set-membership spelling. Present so the projection throw arm is
// proven on BOTH rules that carry it rather than on one of them.
export default async function handler(req, res) {
  const target = req.query.url || "";
  const parsedHost = new URL(target).hostname;
  if (!ALLOWED_HOSTS.has(parsedHost)) throw new Error("host not allowed");
  const upstream = await fetch(target);
  res.status(200).json({ status: upstream.status });
}
