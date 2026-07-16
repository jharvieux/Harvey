// dup/auth/api-key-check.ts — a NEGATIVE fixture for the #360 diverged-clone pass
// (M4-N-DIV-DISTINCT): an independently-written guard in the same auth path. It shares the
// domain (guards, errors, early returns) but not the structure of the require-tenant-*.ts
// pair, so it must NOT be flagged as a diverged clone of anything here.
const KEY_PREFIX = "hk_";
const MIN_KEY_LENGTH = 32;

export function checkApiKeyFormat(candidate: string | undefined): string {
  if (candidate === undefined) {
    throw new Error("missing api key header");
  }
  const trimmed = candidate.trim();
  if (!trimmed.startsWith(KEY_PREFIX)) {
    throw new Error("api key must start with " + KEY_PREFIX);
  }
  if (trimmed.length < MIN_KEY_LENGTH) {
    throw new Error("api key too short");
  }
  for (const ch of trimmed.slice(KEY_PREFIX.length)) {
    if (!/[a-zA-Z0-9]/.test(ch)) {
      throw new Error("api key contains invalid characters");
    }
  }
  return trimmed;
}
