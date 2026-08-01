const { execSync } = require("child_process");

const REPORT = /^[a-z0-9-]+$/;

// PLANTED BUG (P-LIB-CMD-THROW-SWALLOWED, #1631 SOUNDNESS): the guard throws, but its throw is
// caught and swallowed, so execution continues to the shell with the rejected value live. #1248's
// two try exclusions are ported with the throw arm; this must STILL fire.
export function runReport(name) {
  try {
    if (!REPORT.test(name)) throw new Error("bad report name");
  } catch (e) {
    /* logged elsewhere */
  }
  return execSync(`/usr/local/bin/report ${name}`).toString();
}
