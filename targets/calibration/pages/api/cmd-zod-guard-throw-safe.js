import { execSync } from "child_process";
import { z } from "zod";

// N-CMD-ZOD-GUARD-THROW (NEGATIVE — must NOT be flagged, #1248): the throwing twin of
// N-CMD-ZOD-GUARD — the schema-validator arm, `if (!parsed.success) throw …;`. This is the
// dominant shape in a Server Action, where the framework's error boundary IS the error channel.
export default async function handler(req, res) {
  const parsed = z
    .string()
    .regex(/^[a-z]+$/)
    .safeParse(req.query.action);
  if (!parsed.success) throw new Error("unsupported action");
  const out = execSync(`/usr/local/bin/report ${parsed.data}`).toString();
  res.status(200).json({ out });
}
