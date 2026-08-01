const { execSync } = require("child_process");

// PLANTED BUG (P-LIB-CMD-DENYLIST-GUARD, #1631 SOUNDNESS): the regex is anchored but its class is
// NEGATED — a denylist, not an allowlist. `$(id)` carries no denied character and passes. The
// positive-class half of the constraint is ported too; this must STILL fire.
export function runReport(name) {
  if (!/^[^;&|]+$/.test(name)) return null;
  return execSync(`/usr/local/bin/report ${name}`).toString();
}
