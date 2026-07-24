import crypto from "crypto";

// N-WEAK-HASH-CACHE-SPLIT (NEGATIVE — must NOT be flagged, #988): MD5 as a NON-security cache key,
// written as a split statement. This is the precision twin of lib/pw-split.js — the split-statement
// broadening of harvey-weak-hash-security must still NOT fire here, because the .update() argument
// (`JSON.stringify(params)`) and the hash variable (`h`) carry no security name. Per docs/fp-rules.txt,
// a cache-key/ETag MD5 is not a weak-crypto finding.
export function cacheTagSplit(params) {
  const h = crypto.createHash("md5");
  h.update(JSON.stringify(params));
  return h.digest("hex");
}
