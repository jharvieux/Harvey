const ALLOWED_HOSTS = ["api.trusted.example", "assets.trustedcdn.example"];

// N-REDIRECT-HOST-ALLOWLIST-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-REDIRECT-HOST-ALLOWLIST. No try around `new URL` on purpose, and that is the coherent shape
// rather than a convenience: a handler that rejects a disallowed host by throwing wants an
// unparseable URL to throw too, so the try/catch the returning spelling needs is exactly what the
// throwing spelling drops.
export default async function handler(req, res) {
  const next = req.query.next || "";
  const parsedHost = new URL(next).hostname;
  if (!ALLOWED_HOSTS.includes(parsedHost)) throw new Error("host not allowed");
  res.redirect(next);
}
