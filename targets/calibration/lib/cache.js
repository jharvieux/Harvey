import crypto from "crypto";

// N-WEAK-HASH-CACHE (NEGATIVE — must NOT be flagged): MD5 used as a NON-security cache key /
// ETag fingerprint, not for auth/integrity/passwords. Sonar S4790 flags all MD5/SHA-1 use;
// Harvey flags a weak hash only when its output flows into an auth/integrity/signature sink.
export function cacheTag(params) {
  return crypto.createHash("md5").update(JSON.stringify(params)).digest("hex");
}
