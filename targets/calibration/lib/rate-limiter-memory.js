// PLANTED BUG (P-INMEMORY-RATE-LIMIT, #1046): the attempt counter lives in a module-scope Map, so
// it is process-local. On a serverless host every cold start begins with an empty Map and each
// concurrent instance keeps its own, which makes the real budget (10 × live instances) and resets it
// whenever the platform recycles. The code READS as rate-limited — and `AUTH-no-rate-limit` clears
// any caller of it, because the identifier matches the limiter hint — which is exactly why this
// needs a detector of its own.
const attempts = new Map();

export function memoryRateLimit(key) {
  const n = (attempts.get(key) ?? 0) + 1;
  attempts.set(key, n);
  return n <= 10;
}
