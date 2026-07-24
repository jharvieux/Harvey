import { exec } from "node:child_process";

// PLANTED BUG (P-CMD-METHODFORM-SOURCE, #987): the header is read via the Express METHOD FORM
// req.get('X-Forwarded-For') — a source shape the literal req.headers match missed — and
// interpolated into a shell command. harvey-command-injection with the new req.get/req.header source.
export default function handler(req, res) {
  const fwd = req.get("x-forwarded-for");
  exec(`whois ${fwd}`, (err, out) => {
    res.status(200).json({ out: String(out) });
  });
}
