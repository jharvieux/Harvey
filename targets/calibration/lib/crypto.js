import crypto from "crypto";

// PLANTED BUG (P-WEAK-CIPHER): triple-DES (56-bit-key-equivalent, broken since the 1990s) used
// for encryption. harvey-weak-cipher matches the algorithm literal passed to createCipheriv —
// DES/3DES/RC4 and ECB-mode AES are all cryptographically deprecated (CWE-327).
export function encryptLegacy(key, data) {
  const iv = crypto.randomBytes(8);
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
