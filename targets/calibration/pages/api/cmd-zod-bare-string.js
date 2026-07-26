import { execSync } from "child_process";
import { z } from "zod";

// PLANTED BUG (P-CMD-ZOD-BARE-STRING, #1027 SOUNDNESS): this wears the whole safe-twin shape —
// safeParse, an early return on !success, and the shell reading `parsed.data` — but the schema is a
// bare z.string(). Every string parses, so `parsed.data` IS the request value: `status; rm -rf /`
// validates and reaches the shell. A schema is only a sanitizer when it carries a real allowlist,
// so this must STILL fire.
export default async function handler(req, res) {
  const parsed = z.string().safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
