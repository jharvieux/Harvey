import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-CONST-GUARD-THROW (NEGATIVE — must NOT be flagged, #1630): the hoisted-constant twin of
// N-CMD-ZOD-GUARD-THROW. #1363 closed the hoisting gap for `.test()` in BOTH failure-branch
// spellings and reached no schema arm in either, so the throw spelling carried it too.
const ACTION = /^[a-z]+$/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) throw new Error("unsupported action");
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
