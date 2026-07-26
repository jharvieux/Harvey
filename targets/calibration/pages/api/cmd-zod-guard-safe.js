import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-GUARD (NEGATIVE — must NOT be flagged, #1027): the untrusted subcommand goes through a
// zod schema carrying an ANCHORED, POSITIVE-class regex, the failure branch returns, and the shell
// receives `parsed.data` — the value the SCHEMA produced, not the request value. The idiomatic
// Next/Express shape of the (a2) validator guard.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/^[a-z]+$/)
    .safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
