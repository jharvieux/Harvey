// Logs only the outcome and a non-sensitive identifier — never the credential.
export function auditLogin(email, success) {
  console.log("login attempt", { email, success });
  return { email };
}
