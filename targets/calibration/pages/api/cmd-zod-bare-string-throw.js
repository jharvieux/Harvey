import { execSync } from "child_process";
import { z } from "zod";

// P-CMD-ZOD-BARE-STRING-THROW (POSITIVE — must STILL fire, #1248): the throwing twin of
// P-CMD-ZOD-BARE-STRING, and the constraint unique to the SCHEMA arm. safeParse, an exiting
// failure branch, the sink reads `parsed.data` — but the schema is a bare `z.string()`, so every
// string parses and `parsed.data` IS the request value. A schema is not a sanitizer, an
// ALLOWLIST is.
export default async function handler(req, res) {
  const parsed = z.string().safeParse(req.query.action);
  if (!parsed.success) throw new Error("unsupported action");
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
