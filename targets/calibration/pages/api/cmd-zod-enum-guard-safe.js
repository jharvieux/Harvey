import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-ENUM-GUARD (NEGATIVE — must NOT be flagged, #1027): a z.enum membership list is an
// exact-match allowlist, so `parsed.data` can only ever be one of three constants. The enum arm of
// the schema-validator guard.
export default async function handler(req, res) {
  const parsed = z.enum(["status", "uptime", "whoami"]).safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
