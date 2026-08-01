import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-CONST-UNANCHORED-THROW, #1630 SOUNDNESS): the throw-spelling twin of
// P-CMD-ZOD-CONST-UNANCHORED. The hoisted arm added to the throw guard carries the same anchoring
// constraint as the returning one, so an unanchored hoisted regex must STILL fire.
const ACTION = /[a-z]+/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) throw new Error("unsupported action");
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
