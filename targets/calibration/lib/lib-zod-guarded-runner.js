const { execSync } = require("child_process");
const { z } = require("zod");

// SAFE TWIN (N-LIB-CMD-ZOD-GUARD, #1631): the SCHEMA spelling of the (a2) guard — an anchored,
// positive-class `.regex()` with a returning failure branch, and the shell receives the value the
// schema produced.
export function runReport(name) {
  const parsed = z
    .string()
    .regex(/^[a-z0-9-]+$/)
    .safeParse(name);
  if (!parsed.success) return null;
  return execSync(`/usr/local/bin/report ${parsed.data}`).toString();
}
