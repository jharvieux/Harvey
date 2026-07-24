// PLANTED BUG (P-XSS-TEMPLATE-LITERAL, #986): the untrusted name is interpolated raw into an HTML
// template literal handed to res.send — reflected XSS. Unguarded twin for the #986 escaper
// sanitizer negative below (proving the sanitizer doesn't swallow a real finding).
export default function handler(req, res) {
  const name = req.query.name;
  res.send(`<html><body><h1>Hello ${name}</h1></body></html>`);
}
