import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// N-CMD-SET-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-CMD-SET-GUARD — the `Set.has` arm, in its block form. Proves the throw widening reaches
// harvey-command-injection and not only the SQL rule.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (!ALLOWED_ACTIONS.has(cmd)) {
    throw new Error("unsupported action");
  }
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
