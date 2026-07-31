const { execSync } = require("child_process");
const { z } = require("zod");

// PLANTED BUG (P-LIB-CMD-ZOD-UNANCHORED, #1631 SOUNDNESS): the schema spelling with an UNANCHORED
// regex — zod's `.regex()` uses RegExp.test, so `report; rm -rf /` parses successfully and
// `parsed.data` IS the injection. Must STILL fire.
export function runReport(name) {
  const parsed = z
    .string()
    .regex(/[a-z0-9-]+/)
    .safeParse(name);
  if (!parsed.success) return null;
  return execSync(`/usr/local/bin/report ${parsed.data}`).toString();
}
