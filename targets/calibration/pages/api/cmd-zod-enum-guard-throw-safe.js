import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-ENUM-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-CMD-ZOD-ENUM-GUARD — the `z.enum` membership arm, rejecting by throw from a block.
export default async function handler(req, res) {
  const parsed = z.enum(["status", "uptime", "whoami"]).safeParse(req.query.action);
  if (!parsed.success) {
    throw new Error("unsupported action");
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
