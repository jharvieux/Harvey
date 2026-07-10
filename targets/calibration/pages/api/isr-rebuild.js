// PLANTED BUG (P-ISR-REVALIDATE-NOSECRET): an on-demand ISR revalidation endpoint that rebuilds
// any path from the query string with no shared-secret check — anyone can force cache purges/
// rebuilds (cache-stampede DoS, or forcing a stale-content refresh on demand). Semgrep
// harvey-isr-revalidate-nosecret (res.revalidate on a request-controlled path, no secret gate in
// the handler) → review.
export default async function handler(req, res) {
  await res.revalidate(req.query.path);
  res.json({ revalidated: true });
}
