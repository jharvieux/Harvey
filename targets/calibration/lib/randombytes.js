import crypto from "crypto";

// N-RANDOMBYTES-OK (NEGATIVE — must NOT be flagged): crypto.randomBytes() draws from the CSPRNG —
// the correct primitive for a security token. harvey-crypto-pseudorandombytes matches only the
// non-crypto pseudoRandomBytes alias.
export function generateResetToken() {
  return crypto.randomBytes(16).toString("hex");
}
