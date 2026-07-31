import { execSync } from "child_process";
import { z } from "zod";

// P-CMD-ZOD-ENUM-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the swallowed-throw shape on
// the `z.enum` membership arm — the schema entry's second branch, which carries no
// metavariable-regex conjunct and so has to be proven separately from the `.regex` branch.
export default async function handler(req, res) {
  const parsed = z.enum(["status", "uptime", "whoami"]).safeParse(req.query.action);
  try {
    if (!parsed.success) throw new Error("unsupported action");
  } catch (err) {
    res.setHeader("x-action-warning", "1");
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
