import crypto from "crypto";

// N-CIPHER-IV-OK (NEGATIVE — must NOT be flagged): createCipheriv() with a freshly-random 16-byte
// IV per call — the correct API. harvey-crypto-createcipher matches only the no-IV createCipher/
// createDecipher functions; the trailing "iv" of createCipheriv is a different identifier.
export function encryptToken(key, data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([iv, cipher.update(data), cipher.final()]);
}
