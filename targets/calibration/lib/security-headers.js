// Not next.config.js/middleware.ts/vercel.json on purpose: checkMissingCsp's presence check
// (P-NO-CSP) is a global OR across those three files — a CSP string in any one of them means
// "the app has a CSP", which would incorrectly clear the already-planted P-NO-CSP fixture. These
// CSP header objects live here instead, where only the Semgrep AST rule (harvey-csp-unsafe-inline)
// can see them.

// PLANTED BUG (P-CSP-UNSAFE-INLINE): a CSP is configured, but script-src allows 'unsafe-inline'
// — inline <script> tags execute regardless of the policy, defeating CSP's main XSS mitigation.
export const cspHeader = {
  key: "Content-Security-Policy",
  value: "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
};

// TRUE NEGATIVE (N-CSP-PRESENT): a strict CSP with no 'unsafe-inline'/'unsafe-eval' in
// script-src — harvey-csp-unsafe-inline's metavariable-regex requires that substring and does
// not match this value.
export const cspHeaderStrict = {
  key: "Content-Security-Policy",
  value: "default-src 'self'; script-src 'self'; object-src 'none'",
};
