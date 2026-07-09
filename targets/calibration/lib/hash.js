import crypto from "crypto";

// N-SHA256-INTEGRITY (NEGATIVE — must NOT be flagged): SHA-256 (not a weak algorithm) used as a
// file-integrity checksum, not a password/token/signature hash. harvey-weak-hash-security only
// matches md5/sha1; sha256 is out of scope for that rule regardless of the sink.
export function checksumFile(fileBuffer) {
  return crypto.createHash("sha256").update(fileBuffer).digest("hex");
}
