import crypto from "crypto";

// PLANTED BUG (P-GCM-NO-TAGLEN): AES-GCM decryption created with no `authTagLength` option. Without
// pinning the tag length the code silently accepts a short/truncated authentication tag, weakening
// the integrity guarantee GCM exists to provide. Pass `{ authTagLength: 16 }` and setAuthTag() the
// full 16-byte tag. harvey-gcm-no-authtaglength matches a 3-argument (no options) GCM decipher.
export function decrypt(key, iv, enc) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}
