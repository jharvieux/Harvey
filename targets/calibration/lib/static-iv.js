import crypto from "crypto";

// PLANTED BUG (P-STATIC-IV-SALT): the IV is a hardcoded, all-zero literal inlined at the call
// site and reused across every call to this function. Reusing an IV with the same key breaks
// CBC's semantic security — identical plaintext blocks encrypt to identical ciphertext blocks,
// leaking structure to an observer.
export function encrypt(key, data) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, Buffer.from("00000000000000000000000000000000", "hex"));
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
