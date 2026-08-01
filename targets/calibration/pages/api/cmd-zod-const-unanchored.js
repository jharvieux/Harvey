import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-CONST-UNANCHORED, #1630 SOUNDNESS): the hoisted twin of
// P-CMD-ZOD-UNANCHORED. zod's .regex() uses RegExp.test, which matches anywhere, so
// `status; rm -rf /` passes on its leading `status`. The anchoring constraint follows the regex
// to the literal the const binds; this must STILL fire.
const ACTION = /[a-z]+/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
