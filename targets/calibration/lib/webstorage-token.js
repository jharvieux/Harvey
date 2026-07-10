// PLANTED BUG (P-TOKEN-IN-WEBSTORAGE): the app's auth/session token is stashed in localStorage,
// which is readable by any injected script — one XSS and the attacker exfiltrates a live session.
// Tokens belong in an HttpOnly cookie. Semgrep harvey-token-in-webstorage (name-gated on the
// storage key) → review (heuristic: some "token"-named values are legitimately client-readable).
export function persistSession(token) {
  localStorage.setItem("authToken", token);
}
