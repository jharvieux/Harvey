import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-CONST-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1630): the braceless twin of
// N-CMD-ZOD-CONST-GUARD. Both spellings are registered because both were broken, which is what
// shows the hoisting gap is independent of #1236's braceless widening.
const ACTION = /^[a-z]+$/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
