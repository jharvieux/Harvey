import jwt from "jsonwebtoken";

// PLANTED BUG (P-NODE-SECRET-FALLBACK, #595 F-09): a Node module reads the JWT signing secret with a
// hardcoded, human-readable dev-secret fallback — the literal ships in the bundle/history and a
// missing env var silently uses this known value. harvey-edgefn-secret-fallback is Deno-only and
// shape-gated; this name-driven Node rule catches it. harvey-node-secret-fallback → review.
const JWT_SECRET = process.env.JWT_SECRET || "notevault-dev-secret";

// PLANTED BUG (P-JWT-SIGN-NOEXPIRY, #595 F-09): jwt.sign called with no options object, so no
// expiresIn — the session token never expires and can't be revoked by time. harvey-jwt-sign-noexpiry
// → review.
export function signSession(claims: Record<string, unknown>) {
  return jwt.sign(claims, JWT_SECRET);
}
