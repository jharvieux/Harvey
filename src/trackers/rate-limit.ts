// Rate-limiting / backoff for bulk ticket filing (#747). fileFindings fires createEpic/createStory/
// setLabels back-to-back; a large audit can trip a tracker's request quota or GitHub's secondary
// rate limit. The pacer adds two things: a configurable MINIMUM SPACING between successive tracker
// calls, and exponential BACKOFF-AND-RETRY on a rate-limit response — honoring a server Retry-After
// when one is sent. Retrying is safe against duplication: a rate-limit response means the write was
// REJECTED (nothing created), and fileFindings' marker dedup catches any true double anyway.
//
// The clock (`now`/`sleep`) is injectable so a test can assert spacing and backoff against a mock
// clock without real time passing.

import { TrackerError } from "./http.js";

interface PacerOptions {
  minIntervalMs?: number; // minimum gap between the start of successive run() calls (default 0)
  maxRetries?: number; // retries on a rate-limit response before giving up (default 5)
  baseBackoffMs?: number; // exponential-backoff base when the server sends no Retry-After (default 1000)
  now?: () => number; // injectable clock (default Date.now)
  sleep?: (ms: number) => Promise<void>; // injectable sleeper (default setTimeout)
}

export interface Pacer {
  run<T>(fn: () => Promise<T>): Promise<T>;
}

// A rate-limit response: HTTP 429, or GitHub's 403 "secondary rate limit". Returns the ms to wait
// before retry (server Retry-After if present, else exponential backoff), or null if `err` is not a
// rate-limit error and should propagate.
export function rateLimitWaitMs(err: unknown, attempt: number, baseBackoffMs: number): number | null {
  if (!(err instanceof TrackerError)) return null;
  const isLimit = err.status === 429 || (err.status === 403 && /rate limit|secondary rate/i.test(err.responseBody));
  if (!isLimit) return null;
  if (typeof err.retryAfterMs === "number") return err.retryAfterMs;
  return baseBackoffMs * 2 ** attempt;
}

export function makePacer(opts: PacerOptions = {}): Pacer {
  const minInterval = opts.minIntervalMs ?? 0;
  const maxRetries = opts.maxRetries ?? 5;
  const baseBackoff = opts.baseBackoffMs ?? 1000;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let lastStart = Number.NEGATIVE_INFINITY;

  return {
    async run<T>(fn: () => Promise<T>): Promise<T> {
      const wait = lastStart + minInterval - now();
      if (wait > 0) await sleep(wait);
      lastStart = now();

      for (let attempt = 0; ; attempt++) {
        try {
          return await fn();
        } catch (err) {
          const backoff = rateLimitWaitMs(err, attempt, baseBackoff);
          if (backoff === null || attempt >= maxRetries) throw err;
          await sleep(backoff);
        }
      }
    },
  };
}
