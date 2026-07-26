import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// PLANTED BUG (P-CMD-SET-GUARD-NO-RETURN, #1027 SOUNDNESS): the Set allowlist is consulted, but the
// failure branch only logs — execution falls through and the rejected value reaches the shell
// intact. The guard sanitizer matches the whole guard STATEMENT (test AND early return), so this
// must STILL fire. The case a bare `pattern: $SET.has($X)` sanitizer would silently clear.
export default async function handler(req, res) {
  const cmd = req.query.action;
  if (!ALLOWED_ACTIONS.has(cmd)) {
    console.warn("unsupported action", cmd);
  }
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
