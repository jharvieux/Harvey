import { headers } from "next/headers";

// PLANTED BUG (P-HOST-HEADER-URL, #135): the password-reset link is built from the request's
// Host header, which is entirely attacker-controlled (a client can send any Host it likes, and
// X-Forwarded-Host is trusted by most proxies by default). An attacker requests a password reset
// with a spoofed Host, the victim's real reset token gets emailed inside a link pointing at the
// attacker's domain, and the victim clicks it — the token leaks to the attacker's server
// (reset-link poisoning). Contrast reset-link-safe.js (N-HOST-HEADER-FIXED-ORIGIN).
export function buildResetLink(token) {
  const host = headers().get("host");
  return `https://${host}/reset?token=${token}`;
}
