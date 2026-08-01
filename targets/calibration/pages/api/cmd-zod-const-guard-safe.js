import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-CONST-GUARD (NEGATIVE — must NOT be flagged, #1630): N-CMD-ZOD-GUARD with the schema
// regex HOISTED to a named constant, which is how it is written once the regex is reused. Byte-
// identical logic to the inline spelling; before #1630 only the hoisted one drew a Critical.
const ACTION = /^[a-z]+$/;

export default async function handler(req, res) {
  const parsed = z.string().regex(ACTION).safeParse(req.query.action);
  if (!parsed.success) {
    res.status(400).json({ error: "unsupported action" });
    return;
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
