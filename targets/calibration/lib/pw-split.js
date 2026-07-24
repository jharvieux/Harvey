import crypto from "crypto";

// PLANTED BUG (P-WEAK-HASH-SPLIT, #988): MD5 hashing a password, written as a SPLIT statement —
// the hash is created on one line and .update() called on a later line, not the fluent chain the
// old rule required. The security context is the named .update() argument (`password`), which is
// what keeps the cache-key split form (lib/cache-split.js, generic names) silent.
export function hashPasswordSplit(password) {
  const digest = crypto.createHash("md5");
  digest.update(password);
  return digest.digest("hex");
}
