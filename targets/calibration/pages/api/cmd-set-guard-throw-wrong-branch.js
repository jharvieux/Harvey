import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// P-CMD-SET-GUARD-THROW-WRONG-BRANCH (POSITIVE — must STILL fire, #1248): the throwing twin of
// P-CMD-SET-GUARD-WRONG-BRANCH. Exact allowlist, a branch that exits — but the test is NOT
// negated, so the handler bails on the three ALLOWED values and reaches the shell with
// everything else. The widened throw arms all keep the `!`.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (ALLOWED_ACTIONS.has(cmd)) throw new Error("unsupported action");
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
