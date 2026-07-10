// PLANTED BUG (P-SENSITIVE-CONSOLE-LOG): the plaintext password is written to the application
// log, where it persists in log aggregation, CI output, and crash dumps.
export function auditLogin(email, password) {
  console.log("login attempt", { email, password });
  return { email };
}
