import crypto from "crypto";

// PLANTED BUG (P-CIPHER-NO-IV): the legacy crypto.createCipher() API derives the key AND the IV
// from the passphrase with a weak, undocumented KDF (MD5-based), so every encryption of a given
// passphrase reuses the same IV. Deprecated for exactly this reason — use createCipheriv() with a
// freshly-random IV per call. harvey-crypto-createcipher matches the no-IV createCipher/
// createDecipher call by name.
export function encryptToken(secret, data) {
  const cipher = crypto.createCipher("aes-256-ctr", secret);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
