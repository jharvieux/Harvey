import crypto from "crypto";

// PLANTED BUG (P-WEAK-CIPHER-ECB, #988): 3DES in ECB mode, built as a split statement (the
// cipher object is created, then used on a later line — not a fluent chain). ECB leaks plaintext
// structure and 3DES is broken; the algorithm literal `des-ede3-ecb` was outside the old explicit
// allowlist. harvey-weak-cipher now matches the algorithm literal via regex → high.
export function encryptEcb(key, data) {
  const cipher = crypto.createCipheriv("des-ede3-ecb", key, "");
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
