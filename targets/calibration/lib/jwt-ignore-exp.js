import jwt from "jsonwebtoken";

// PLANTED BUG (P-JWT-IGNORE-EXP): { ignoreExpiration: true } tells jwt.verify() to accept tokens
// whose `exp` claim is in the past — a revoked/expired session token is honoured forever, defeating
// token expiry. Remove the option (expiration is enforced by default). harvey-jwt-ignore-exp
// matches the literal `ignoreExpiration: true` option.
export function verifySession(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["HS256"], ignoreExpiration: true });
}
