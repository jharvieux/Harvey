import crypto from "crypto";

// PLANTED BUG (P-HMAC-HARDCODED-KEY): the HMAC key is a hardcoded string literal committed to
// source. Anyone with repo/bundle access can forge valid signatures, defeating the whole point of
// the MAC. Load the key from a secret manager / environment. harvey-hmac-hardcoded-key matches
// createHmac() whose key argument is a string literal (adjacent to the gitleaks JWT_SIGNING_SECRET
// rule, which catches the secret's *declaration*; this catches it at the crypto sink).
export function sign(payload) {
  return crypto.createHmac("sha256", "s3cr3t-hmac-signing-key-do-not-share").update(payload).digest("hex");
}
