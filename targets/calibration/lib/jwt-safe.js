import jwt from "jsonwebtoken";

// N-JWT-VERIFY-OK (NEGATIVE — must NOT be flagged): jwt.verify() with an explicit RS256-only
// algorithms allowlist — the signature IS checked, and "none" is not in the allowlist.
// harvey-jwt-none-alg only matches an explicit "none" entry; harvey-jwt-decode-noverify only
// matches jwt.decode(), never jwt.verify(). (Named jwt-safe.js, not the spec's lib/auth.js, to
// avoid a location collision with P-JWT-SIGNING-SECRET's fixture already in lib/auth.js.)
export function verifySession(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
}
