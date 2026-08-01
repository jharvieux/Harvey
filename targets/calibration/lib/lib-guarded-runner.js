const { execSync } = require("child_process");

const REPORT = /^[a-z0-9-]+$/;
const JOBS = ["daily", "weekly"];

// SAFE TWIN (N-LIB-CMD-REGEX-GUARD, #1631): the exported param is gated by an ANCHORED,
// positive-class allowlist whose failure branch returns, so the shell never sees a rejected value.
// Before #1631 the library-taint family carried no validator-guard sanitizer at all and this drew a
// Critical.
export function runInline(name) {
  if (!/^[a-z0-9-]+$/.test(name)) return null;
  return execSync(`/usr/local/bin/report ${name}`).toString();
}

// SAFE TWIN (N-LIB-CMD-CONST-GUARD, #1631): the same guard with the regex hoisted to a named const.
export function runHoisted(name) {
  if (!REPORT.test(name)) return null;
  return execSync(`/usr/local/bin/report ${name}`).toString();
}

// SAFE TWIN (N-LIB-CMD-INCLUDES-GUARD, #1631): exact-match membership against an array allowlist.
export function runListed(name) {
  if (!JOBS.includes(name)) return null;
  return execSync(`/usr/local/bin/report ${name}`).toString();
}

// SAFE TWIN (N-LIB-CMD-THROW-GUARD, #1631): the throwing failure branch, outside any try.
export function runThrowing(name) {
  if (!REPORT.test(name)) throw new Error("bad report name");
  return execSync(`/usr/local/bin/report ${name}`).toString();
}
