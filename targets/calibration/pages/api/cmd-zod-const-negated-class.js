import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-CONST-DENYLIST, #1630 SOUNDNESS): the hoisted constant binds an anchored
// but NEGATED-class regex — a denylist, not an allowlist. `$(id)` carries no character in the
// denied set. The positive-class half of the constraint moves to the literal with the anchoring
// half; this must STILL fire.
const ACTION = /^[^;&|]+$/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
