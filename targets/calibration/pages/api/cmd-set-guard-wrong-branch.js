import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// PLANTED BUG (P-CMD-SET-GUARD-WRONG-BRANCH, #1236 SOUNDNESS): exact Set membership, braceless
// early return — but the test is NOT negated, so the handler bails on the three ALLOWED actions
// and runs the shell for everything else. The inverted spelling of a guard is not a guard: must
// STILL fire at high.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (ALLOWED_ACTIONS.has(cmd)) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
