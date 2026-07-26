// P-SSRF-HOST-USERINFO (POSITIVE — must STILL fire, #1057): the SSRF twin of
// P-REDIRECT-HOST-USERINFO. Same hand-rolled host extractor, fetch() sink. The projection-guard
// sanitizer is on harvey-ssrf-fetch as well as harvey-open-redirect, so this proves the soundness
// constraint travels with it rather than being enforced on only one of the two rules.
export default async function handler(req, res) {
  const target = req.query.url || "";
  const host = target.replace(/^https?:\/\//i, "").split("/")[0].split("@")[0];
  if (!["api.trusted.example"].includes(host)) {
    res.status(403).json({ error: "host not allowed" });
    return;
  }
  const upstream = await fetch(target);
  res.status(200).json({ status: upstream.status });
}
