// PLANTED BUG (P-CRLF-HEADER-INJ): a request-controlled filename is interpolated straight into a
// Content-Disposition response header. A value containing CR/LF can inject additional response
// headers or split the response (header injection / response splitting). Strip CR/LF (or reject)
// before setting the header. Semgrep harvey-crlf-header-injection (req.query taint → res.setHeader
// value) → review.
export default function handler(req, res) {
  res.setHeader("Content-Disposition", `attachment; filename="${req.query.name}"`);
  res.status(200).send("file body");
}
