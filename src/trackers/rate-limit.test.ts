import { describe, expect, it } from "vitest";
import { TrackerError } from "./http.js";
import { makePacer, rateLimitWaitMs } from "./rate-limit.js";

// A mock clock: sleep advances virtual time synchronously, so spacing/backoff are asserted with no
// real time passing.
function mockClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => void (t += ms), get: () => t };
}

const limit429 = () => new TrackerError("POST", "u", 429, "rate limited");

describe("makePacer spacing", () => {
  it("spaces successive run() calls by the minimum interval", async () => {
    const clock = mockClock();
    const pacer = makePacer({ minIntervalMs: 100, now: clock.now, sleep: clock.sleep });
    const starts: number[] = [];
    for (let i = 0; i < 3; i++) await pacer.run(async () => void starts.push(clock.now()));
    expect(starts).toEqual([0, 100, 200]);
  });
});

describe("makePacer backoff", () => {
  it("retries a 429 with exponential backoff and eventually succeeds", async () => {
    const clock = mockClock();
    const pacer = makePacer({ baseBackoffMs: 1000, maxRetries: 5, now: clock.now, sleep: clock.sleep });
    let calls = 0;
    const out = await pacer.run(async () => {
      calls++;
      if (calls < 3) throw limit429();
      return "ok";
    });
    expect(out).toBe("ok");
    expect(calls).toBe(3);
    expect(clock.get()).toBe(3000); // 1000*2^0 + 1000*2^1
  });

  it("honors a server Retry-After over the exponential fallback", async () => {
    const clock = mockClock();
    const pacer = makePacer({ baseBackoffMs: 1000, now: clock.now, sleep: clock.sleep });
    let calls = 0;
    await pacer.run(async () => {
      calls++;
      if (calls < 2) throw new TrackerError("POST", "u", 429, "limited", 5000);
      return "ok";
    });
    expect(clock.get()).toBe(5000);
  });

  it("gives up after maxRetries and rethrows", async () => {
    const clock = mockClock();
    const pacer = makePacer({ baseBackoffMs: 1, maxRetries: 2, now: clock.now, sleep: clock.sleep });
    let calls = 0;
    await expect(
      pacer.run(async () => {
        calls++;
        throw limit429();
      }),
    ).rejects.toBeInstanceOf(TrackerError);
    expect(calls).toBe(3); // initial + 2 retries
  });

  it("propagates a non-rate-limit error immediately without retry", async () => {
    const pacer = makePacer({ maxRetries: 5 });
    let calls = 0;
    await expect(
      pacer.run(async () => {
        calls++;
        throw new TrackerError("POST", "u", 500, "boom");
      }),
    ).rejects.toThrow();
    expect(calls).toBe(1);
  });
});

describe("rateLimitWaitMs", () => {
  it("treats 429 and a 403 secondary-rate-limit body as rate limits, everything else as null", () => {
    expect(rateLimitWaitMs(limit429(), 0, 1000)).toBe(1000);
    expect(rateLimitWaitMs(new TrackerError("POST", "u", 403, "You have exceeded a secondary rate limit"), 0, 1000)).toBe(1000);
    expect(rateLimitWaitMs(new TrackerError("POST", "u", 403, "forbidden"), 0, 1000)).toBeNull();
    expect(rateLimitWaitMs(new TrackerError("POST", "u", 500, "boom"), 0, 1000)).toBeNull();
    expect(rateLimitWaitMs(new Error("plain"), 0, 1000)).toBeNull();
  });
});
