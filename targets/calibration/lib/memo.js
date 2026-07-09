// N-INMEM-CACHE (NEGATIVE — must NOT be flagged): a module-level Map used as a memoization
// CACHE, not a rate limiter. The fp-rules exempt in-process caches; only a structure acting as
// a rate limit / quota / throttle (and gating request admission) is a finding.
const cache = new Map();

export function memoize(key, compute) {
  if (!cache.has(key)) cache.set(key, compute());
  return cache.get(key);
}
