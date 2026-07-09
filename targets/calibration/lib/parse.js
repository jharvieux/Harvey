// PLANTED BUG (P-REDOS): a regex with a nested quantifier ((a+)+) run against user input —
// catastrophic backtracking (ReDoS). A crafted string like "aaaaaaaaaaaaaaaaaaaa!" hangs the
// event loop. Review tier.
const SUFFIX = new RegExp("^(a+)+$");

export function looksLikeSuffix(s) {
  return SUFFIX.test(s);
}
