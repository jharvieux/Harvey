// OWASP Nodejs Security CS, Platform Security: "Test regular expressions for ReDoS vulnerabilities."
// Nested quantifier over an overlapping character class — catastrophic backtracking on a long
// non-matching input, so a single request pins the event loop.
const EMAIL_ISH = /^([a-zA-Z0-9]+)+@example\.com$/;

export function looksLikeEmail(input: string): boolean {
  return EMAIL_ISH.test(input);
}

export function parseTags(input: string): string[] {
  return input.split(/(\s*,\s*)+/).filter(Boolean);
}
