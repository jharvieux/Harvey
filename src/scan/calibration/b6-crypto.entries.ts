// Batch B6 — JWT / crypto / randomness (#71, spec §"Batch 8 — JWT / crypto / randomness"). Custom
// Semgrep rules (src/scan/rules/semgrep/crypto.yml) scored against targets/calibration. Tiering
// follows the locked preamble: only ~100%-precision sinks are `high` (free count) — an explicit
// `algorithms:['none']` JWT verify, a weak hash (md5/sha1) whose immediate input is named like a
// password/token/secret/signature (the sink-gating signal that separates it from a non-security
// cache-key hash — N-WEAK-HASH-CACHE, already in base.entries.ts, is reused rather than
// duplicated), a named-weak cipher (DES/RC4/ECB), and an explicit `rejectUnauthorized: false`/
// `NODE_TLS_REJECT_UNAUTHORIZED=0`. The rest (unverified jwt.decode(), a hardcoded/static IV,
// Math.random() feeding a token/secret-named sink, a raw password column with no hash fn) are
// `review` — each needs more context than a static rule can see. The linear-regex-not-ReDoS
// lookalike (N-REDOS-SAFE) already ships in base.entries.ts too. See GROUND-TRUTH.md §B6.

import type { CorpusEntry } from "./types.js";

export const b6CryptoEntries: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  { id: "P-JWT-NONE-ALG", kind: "positive", cls: "JWT verified with algorithms:['none']", location: "jwt.js", match: ["jwt-none-alg", "none"], expectedTier: "high", note: "jwt.verify(token, key, { algorithms: ['RS256', 'none'] }) in lib/jwt.js — an unsigned token with an arbitrary payload verifies successfully. harvey-jwt-none-alg (literal \"none\" in the algorithms array) → high." },
  { id: "P-WEAK-HASH-SEC", kind: "positive", cls: "MD5/SHA-1 in a security sink (password hash)", location: "pw.js", match: ["weak-hash-security", "weak-hash"], expectedTier: "high", note: "crypto.createHash('md5').update(password) in lib/pw.js. harvey-weak-hash-security gates on the .update() argument's name (password/pwd/secret/token/signature) to separate this from the cache-key use in lib/cache.js (N-WEAK-HASH-CACHE) → high." },
  { id: "P-WEAK-CIPHER", kind: "positive", cls: "Weak/broken cipher (3DES)", location: "crypto.js", match: ["weak-cipher"], expectedTier: "high", note: "crypto.createCipheriv('des-ede3-cbc', key, iv) in lib/crypto.js — triple-DES, broken since the 1990s. harvey-weak-cipher (algorithm-literal allowlist: DES/3DES/RC4/ECB) → high." },
  { id: "P-TLS-VERIFY-DISABLED", kind: "positive", cls: "TLS certificate verification disabled", location: "lib/http.js", match: ["tls-verify-disabled", "rejectunauthorized"], expectedTier: "high", note: "new https.Agent({ rejectUnauthorized: false }) in lib/http.js. harvey-tls-verify-disabled → high. (Location keeps the lib/ prefix — the negative N-TLS-VERIFY-ON lives in a distinct file, lib/http-safe.js, so no collision.)" },
  { id: "P-JWT-DECODE-NOVERIFY", kind: "positive", cls: "jwt.decode() used for an authz decision", location: "middleware.ts", match: ["jwt-decode-noverify", "decode"], expectedTier: "review", note: "jwt.decode(token) then trusting the 'role' claim for an authz check in middleware.ts — no signature check, forgeable. harvey-jwt-decode-noverify (heuristic: flags every jwt.decode() call) → review." },
  { id: "P-STATIC-IV-SALT", kind: "positive", cls: "Hardcoded/static IV", location: "static-iv.js", match: ["static-iv"], expectedTier: "review", note: "createCipheriv('aes-256-cbc', key, Buffer.from('000...', 'hex')) in lib/static-iv.js — an all-zero literal IV reused on every call, breaking CBC's semantic security. harvey-static-iv → review." },
  { id: "P-INSECURE-RANDOM", kind: "positive", cls: "Math.random() for a security token", location: "token.js", match: ["insecure-random-token"], expectedTier: "review", note: "generateResetToken() returns Math.random().toString(36) in lib/token.js — a predictable PRNG generating a password-reset token. harvey-insecure-random-token (name-gated to token/secret/otp/session/password/reset) → review." },
  { id: "P-PLAINTEXT-PASSWORD", kind: "positive", cls: "Password stored without hashing", location: "register.js", match: ["plaintext-password"], expectedTier: "review", note: "admin.from('users').insert({ ..., password: req.body.pw }) in pages/api/register.js — the raw request password lands in the DB with no hash step. harvey-plaintext-password → review." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-JWT-VERIFY-OK", kind: "negative", cls: "jwt.verify with an RS256-only allowlist", location: "jwt-safe.js", note: "jwt.verify(token, key, { algorithms: ['RS256'] }) in lib/jwt-safe.js — the signature is checked and 'none' is not in the allowlist. harvey-jwt-none-alg fires only on a literal 'none' entry; harvey-jwt-decode-noverify fires only on jwt.decode() — cleared." },
  { id: "N-RANDOM-NONSEC", kind: "negative", cls: "Math.random() for non-security UI jitter", location: "ui.js", note: "jitterDelay() returns Math.random() * 100 in lib/ui.js. harvey-insecure-random-token only fires inside a function named like token/secret/session/otp/password/reset — 'jitterDelay' doesn't match — cleared." },
  { id: "N-SHA256-INTEGRITY", kind: "negative", cls: "SHA-256 for a non-password integrity checksum", location: "hash.js", note: "checksumFile() hashes a file buffer with sha256 in lib/hash.js. harvey-weak-hash-security fires only on md5/sha1 — sha256 is out of scope regardless of the sink name — cleared." },
  { id: "N-TLS-VERIFY-ON", kind: "negative", cls: "Default HTTPS agent (TLS verification on)", location: "http-safe.js", note: "new https.Agent() with no override in lib/http-safe.js — rejectUnauthorized defaults to true. harvey-tls-verify-disabled fires only on an explicit rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0 — cleared." },
];
