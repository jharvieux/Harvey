import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// N-CMD-SET-GUARD (NEGATIVE — must NOT be flagged, #1027): a Set-backed allowlist is the same
// exact-match membership test as `.includes` on an array, and the failure branch returns.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (!ALLOWED_ACTIONS.has(cmd)) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
