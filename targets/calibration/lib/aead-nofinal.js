import crypto from "crypto";

// PLANTED BUG (P-AEAD-NO-FINAL): an AEAD (GCM) decryption that returns the decipher.update() output
// directly and never calls decipher.final(). For an authenticated cipher, .final() is what verifies
// the authentication tag — skipping it means a forged/tampered ciphertext is accepted as valid,
// throwing away the integrity protection. Always call .final(). harvey-aead-decipher-no-final
// matches a decipher whose update() result is returned with no intervening final().
export function decrypt(key, iv, tag, enc) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return decipher.update(enc, "hex", "utf8");
}
