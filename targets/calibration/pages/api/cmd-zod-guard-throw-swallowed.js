import { execSync } from "child_process";
import { z } from "zod";

// P-CMD-ZOD-THROW-SWALLOWED (POSITIVE — must STILL fire, #1248): the swallowed-throw shape on the
// SCHEMA arm, which is a separate sanitizer entry with its own try exclusions. The schema is a
// correct anchored allowlist and `parsed.data` is still read — but on the rejected path
// `parsed.data` is `undefined` only because zod said so, and the catch lets execution continue
// with the raw request value already bound into the template through `parsed.data`'s absence.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/^[a-z]+$/)
    .safeParse(req.query.action);
  try {
    if (!parsed.success) throw new Error("unsupported action");
  } catch (err) {
    res.setHeader("x-action-warning", "1");
  }
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
