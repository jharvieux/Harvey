import jwt from "jsonwebtoken";

// PLANTED BUG (P-JWT-NONE-ALG): "none" is included in the verify algorithms allowlist. An
// attacker can present an unsigned JWT (header {"alg":"none"}, no signature) with an arbitrary
// payload — e.g. {"sub":"attacker","role":"admin"} — and jwt.verify() accepts it as valid,
// because "none" tells the library not to check a signature at all.
export function verifySession(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256", "none"] });
}
