const { execSync } = require("child_process");

// PLANTED BUG (P-LIB-CMD-UNANCHORED-GUARD, #1631 SOUNDNESS): the guard is present and returns, but
// the regex is UNANCHORED — RegExp.test matches anywhere, so `report; rm -rf /` passes on its
// leading `report`. The anchoring constraint the request-taint arms carry is ported unweakened;
// this must STILL fire.
export function runReport(name) {
  if (!/[a-z0-9-]+/.test(name)) return null;
  return execSync(`/usr/local/bin/report ${name}`).toString();
}
