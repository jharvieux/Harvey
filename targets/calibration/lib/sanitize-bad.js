// PLANTED BUG (P-INCOMPLETE-SANITIZE): String.replace with a string-literal first argument replaces
// only the FIRST occurrence, so this "sanitizer" leaves every angle bracket after the first intact.
// harvey-incomplete-sanitize.
export function clean(s) {
  return s.replace("<", "").replace(">", "");
}
