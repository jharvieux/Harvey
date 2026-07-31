import { execSync } from "child_process";

const ALLOWED_ACTIONS = new Set(["status", "uptime", "whoami"]);

// P-CMD-SET-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the swallowed-throw shape on the
// `Set.has` arm, on the command-injection rule. Proves the try exclusion travels with the shared
// sanitizer anchor to every rule that references it, not only to the SQL rule it was written on.
export default async function handler(req, res) {
  const cmd = req.query.action;
  try {
    if (!ALLOWED_ACTIONS.has(cmd)) throw new Error("unsupported action");
  } catch (err) {
    res.setHeader("x-action-warning", "1");
  }
  const out = execSync(`/usr/local/bin/report ${cmd}`).toString();
  res.status(200).json({ out });
}
