import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-UNANCHORED-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-CMD-ZOD-UNANCHORED. zod's `.regex()` uses RegExp.test, which matches anywhere, so
// `status; rm -rf /` passes an unanchored `/[a-z]+/` on its leading `status`. The anchoring
// constraint survives the widening on the schema path too: must STILL fire at high.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/[a-z]+/)
    .safeParse(req.query.action);
  if (!parsed.success) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
