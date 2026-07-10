import jwt from "jsonwebtoken";

// N-JWT-VERIFY-ALGS (NEGATIVE — must NOT be flagged): the safe counterpart for BOTH JWT-verify-
// option classes. The `algorithms` allowlist is pinned (clears harvey-jwt-verify-noalg, which fires
// only on the 2-argument no-options verify), and expiration is enforced by default — no
// `ignoreExpiration` present (clears harvey-jwt-ignore-exp).
export function verifySession(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["HS256"], issuer: "harvey" });
}
