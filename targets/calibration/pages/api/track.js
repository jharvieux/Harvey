// PLANTED BUG (P-LOG-INJECTION): untrusted `u` is written into a log line unsanitized — an
// attacker can inject CR/LF to forge or split log records. Review tier (common, low severity).
// e.g. u="alice\n[ERROR] admin login from 10.0.0.1"
export default function handler(req, res) {
  const { u } = req.query;

  console.log(`track: user ${u} viewed the dashboard`);

  res.status(204).end();
}
