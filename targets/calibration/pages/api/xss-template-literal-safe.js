import { escapeHtml } from "../../lib/escape";

// N-XSS-TEMPLATE-ESCAPED (NEGATIVE — must NOT be flagged, #986): the untrusted name is run through
// escapeHtml before interpolation into the HTML template literal — the XSS is neutralized. (a1)
// transformation-sanitizer subset. harvey-html-template-literal now registers escapeHtml/escape/
// DOMPurify.sanitize/sanitizeHtml/sanitize as sanitizers — cleared.
export default function handler(req, res) {
  const name = escapeHtml(req.query.name);
  res.send(`<html><body><h1>Hello ${name}</h1></body></html>`);
}
