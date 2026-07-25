import { execSync } from "child_process";

// N-CMD-ENUM-GUARD (NEGATIVE — must NOT be flagged, #989): the untrusted subcommand is gated by an
// enum allowlist that returns on failure, so only one of three constants can reach the shell. The
// (a2) validator-guard subset applied to the command-injection sink — proving the guard sanitizer
// generalizes beyond SQL. The unguarded twin (ping.js, P-CMD-EXEC) still fires.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (!["status", "uptime", "whoami"].includes(cmd)) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
