import crypto from "crypto";

// N-GCM-TAGLEN-OK (NEGATIVE — must NOT be flagged): the safe counterpart for BOTH AEAD classes. The
// GCM decipher pins `authTagLength: 16` (clears harvey-gcm-no-authtaglength, which fires only on the
// 3-argument no-options form), sets the full tag, and calls .final() to verify it (clears
// harvey-aead-decipher-no-final, which fires only when the update() result is returned with no
// final()).
export function decrypt(key, iv, tag, enc) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  let out = decipher.update(enc, "hex", "utf8");
  out += decipher.final("utf8");
  return out;
}
