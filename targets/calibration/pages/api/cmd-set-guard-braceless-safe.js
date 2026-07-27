import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// N-CMD-SET-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-CMD-SET-GUARD — the `Set.has` arm of the (a2) guard, early-returning without a block.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (!ALLOWED_ACTIONS.has(cmd)) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
