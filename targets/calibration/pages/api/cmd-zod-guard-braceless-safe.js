import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-GUARD-BRACELESS (NEGATIVE — must NOT be flagged, #1236): the braceless twin of
// N-CMD-ZOD-GUARD — the schema-validator arm, `if (!parsed.success) return <expr>;`.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/^[a-z]+$/)
    .safeParse(req.query.action);
  if (!parsed.success) return res.status(400).json({ error: "unsupported action" });
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
