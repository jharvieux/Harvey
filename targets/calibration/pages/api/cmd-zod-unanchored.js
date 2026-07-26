import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-UNANCHORED, #1027 SOUNDNESS): the schema regex has a positive class and
// the failure branch returns, but it is UNANCHORED — zod's .regex() uses RegExp.test, which matches
// anywhere, so `status; rm -rf /` passes on its leading `status`. The anchoring constraint the
// bare-.test() form already carries, proven on the schema path too: this must STILL fire.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/[a-z]+/)
    .safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
