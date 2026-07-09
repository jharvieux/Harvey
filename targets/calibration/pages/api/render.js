import ejs from "ejs";

// PLANTED BUG (P-SSTI): the request body is rendered as an EJS template — server-side template
// injection, which escalates to RCE on EJS. The user controls the template source, not just the
// data. Review tier. e.g. tpl="<%= process.mainModule.require('child_process').execSync('id') %>"
export default function handler(req, res) {
  const html = ejs.render(req.body.tpl, { user: "guest" });
  res.status(200).send(html);
}
