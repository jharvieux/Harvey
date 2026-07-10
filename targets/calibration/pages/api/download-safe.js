// TRUE NEGATIVE (N-CRLF-SANITIZED): the same download header, but the filename has CR/LF (and
// quotes) stripped before it reaches the header. harvey-crlf-header-injection treats the CR/LF
// strip as a sanitizer, so the tainted value never reaches the sink — cleared.
export default function handler(req, res) {
  const name = req.query.name.replace(/[\r\n"]/g, "");
  res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
  res.status(200).send("file body");
}
