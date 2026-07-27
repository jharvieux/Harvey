import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-ENUM-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-CMD-ZOD-ENUM-GUARD — the `z.enum` membership arm, early-returning without a block.
export default async function handler(req, res) {
  const parsed = z.enum(["status", "uptime", "whoami"]).safeParse(req.query.action);
  if (!parsed.success) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
