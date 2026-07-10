// NEGATIVE (N-HTML-PLAINTEXT): the request value is returned as a plain JSON field, not interpolated
// into an HTML template literal handed to res.send. harvey-html-template-literal fires only on a
// res.send template literal — cleared.
export default function handler(req, res) {
  res.status(200).json({ name: req.query.name });
}
