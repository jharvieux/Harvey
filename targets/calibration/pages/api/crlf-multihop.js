// PLANTED BUG (P-CRLF-MULTIHOP, #988): a request-controlled header value reaches res.setHeader
// through a multi-hop source (req.headers dotted access, then a String() transform) — the shape
// BenchProctor and real code use. The old rule only sourced req.query/req.body.$K/req.headers[$H]
// (bracket), so this scored 0%. harvey-crlf-header-injection now sources req.params/req.headers.$H
// (dotted)/bare req.body too → review.
export default function handler(req, res) {
  const raw = req.headers.referer || "";
  const dest = String(raw);
  res.setHeader("X-Redirect-From", dest);
  res.status(200).send("ok");
}
