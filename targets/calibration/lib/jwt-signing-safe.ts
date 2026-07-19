import jwt from "jsonwebtoken";

// TRUE NEGATIVE (N-NODE-SECRET-FAILCLOSED, #595): the same secret-named var, but the fallback is an
// EMPTY string (`?? ""`) — fail-closed, not a hardcoded secret. harvey-node-secret-fallback requires a
// non-empty literal, so this is cleared.
const JWT_SECRET = process.env.JWT_SECRET ?? "";

// TRUE NEGATIVE (N-NODE-FALLBACK-NONSECRET, #595): a non-secret-named var with a literal fallback. The
// $NAME regex gates on secret-shaped names, so APP_BASE_URL does not match — cleared. Proves the rule
// is name-driven, not "any process.env fallback".
export const APP_BASE_URL = process.env.APP_BASE_URL || "https://example.com";

// TRUE NEGATIVE (N-JWT-SIGN-EXPIRY, #595): jwt.sign WITH an expiresIn option. harvey-jwt-sign-noexpiry's
// pattern-not excludes the options literal that carries expiresIn — cleared.
export function signSession(claims: Record<string, unknown>) {
  return jwt.sign(claims, JWT_SECRET, { expiresIn: "15m" });
}
