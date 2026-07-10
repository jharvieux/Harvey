// PLANTED BUG (P-HTML-TEMPLATE-LITERAL): request input is interpolated into an HTML template literal
// sent straight back with res.send — reflected XSS. harvey-html-template-literal (taint req ->
// res.send of a template literal).
export default function handler(req, res) {
  res.setHeader("Content-Type", "text/html");
  res.send(`<h1>Hello ${req.query.name}</h1>`);
}
