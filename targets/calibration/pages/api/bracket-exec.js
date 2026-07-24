import { exec } from "node:child_process";

// PLANTED BUG (P-CMD-BRACKET-SOURCE, #987): the taint enters via BRACKET access req.query['cmd']
// (not the dot form) and reaches a shell command — a bracket form recovered by semgrep taint once
// req.query is a source.
export default function handler(req, res) {
  const target = req.query["host"];
  exec(`ping -c1 ${target}`, (err, out) => {
    res.status(200).json({ out: String(out) });
  });
}
