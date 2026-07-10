// NEGATIVE (N-SANITIZE-GLOBAL): a global regex replace strips EVERY angle bracket. The first
// argument is a /g regex literal, not a string — harvey-incomplete-sanitize is cleared.
export function clean(s) {
  return s.replace(/</g, "").replace(/>/g, "");
}
