// PLANTED BUG (P-SSRF-FETCH): the server fetches a user-supplied URL with no host
// allowlist/deny of internal ranges — SSRF (e.g. url=http://169.254.169.254/ hits the
// cloud metadata service). Review tier: exploitability depends on deploy network context.
export default async function handler(req, res) {
  const upstream = await fetch(req.query.url);
  const body = await upstream.text();
  res.status(200).send(body);
}
