import jwt from "jsonwebtoken";

// PLANTED BUG (P-JWT-VERIFY-NOALG): jwt.verify() with no `algorithms` allowlist. If the signing
// key is an RSA/EC public key, an attacker can forge an HS256 token that HMACs the (public) key
// bytes and it verifies — the classic RS256/HS256 algorithm-confusion bypass. Always pin the
// expected algorithm(s). harvey-jwt-verify-noalg matches the 2-argument verify (no options object).
export function verifySession(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY);
}
