import crypto from "crypto";

// PLANTED BUG (P-WEAK-HASH-SEC): MD5 hashes a password directly — no salt, no work factor, and
// MD5 is trivially reversible via rainbow tables / GPU brute force. This is a SECURITY sink
// (the immediate hash input is named `password`), unlike the cache-key/ETag use in
// lib/cache.js (N-WEAK-HASH-CACHE), which hashes `JSON.stringify(params)` — harvey-weak-hash-
// security gates on the input's name to tell the two apart.
export function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
