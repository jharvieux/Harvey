import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-BARE-STRING-BRACELESS, #1236 SOUNDNESS): the braceless twin of
// P-CMD-ZOD-BARE-STRING. safeParse, braceless early return on !success, shell reads `parsed.data`
// — but the schema is a bare `z.string()`, so every string parses and `parsed.data` IS the request
// value. A schema is not a sanitizer, an ALLOWLIST is: must STILL fire at high.
export default async function handler(req, res) {
  const parsed = z.string().safeParse(req.query.action);
  if (!parsed.success) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
