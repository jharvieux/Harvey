import crypto from "crypto";

// PLANTED BUG (P-PSEUDORANDOM-BYTES): crypto.pseudoRandomBytes() is an alias for a NON-crypto PRNG
// (it does not draw from the CSPRNG) — its output is predictable and unsuitable for anything
// security-sensitive. Here it mints a password-reset token. Use crypto.randomBytes(). harvey-
// crypto-pseudorandombytes matches the pseudoRandomBytes call by name.
export function generateResetToken() {
  return crypto.pseudoRandomBytes(16).toString("hex");
}
