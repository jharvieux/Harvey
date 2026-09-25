import { afterEach, describe, expect, it, vi } from "vitest";
import { TrackerError, trackerFetch } from "./http.js";
import { makePacer, rateLimitWaitMs } from "./rate-limit.js";

// A mock clock: sleep advances virtual time synchronously, so spacing/backoff are asserted with no
// real time passing.
function mockClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms: number) => void (t += ms), get: () => t };
}

const limit429 = () => new TrackerError("POST", "u", 429, "rate limited");

describe("Retry-After response header through trackerFetch and makePacer (#2121)", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each([
    ["numeric seconds", "3", 3000],
    ["fractional seconds", "1.5", 1500],
    ["future HTTP date", "Wed, 01 Jan 2025 00:00:07 GMT", 7000],
    ["past HTTP date clamps to zero", "Tue, 31 Dec 2024 23:59:59 GMT", 0],
    ["negative numeric delay clamps to zero", "-5", 0],
    ["zero delay", "0", 0],
    ["invalid header falls back", "not-a-date", 125],
    ["absent header falls back", undefined, 125],
  ])("honors %s at the actual HTTP boundary", async (_name, header, expectedDelay) => {
    const clock = { now: Date.parse("2025-01-01T00:00:00Z") };
    vi.spyOn(Date, "now").mockImplementation(() => clock.now);
    const sleeps: number[] = [];
    const starts: number[] = [];
    const fetchImpl: typeof fetch = async () => {
      starts.push(clock.now);
      return starts.length === 1
        ? new Response("limited", { status: 429, headers: header === undefined ? {} : { "Retry-After": header } })
        : new Response("accepted", { status: 200 });
    };
    const pacer = makePacer({
      baseBackoffMs: 125, maxRetries: 1, now: () => clock.now,
      sleep: async (ms) => { sleeps.push(ms); clock.now += ms; },
    });
    const result = await pacer.run(() => trackerFetch(fetchImpl, "https://tracker.invalid/items", { method: "GET", headers: {} }));
    expect(await result.text()).toBe("accepted");
    expect(sleeps).toEqual([expectedDelay]);
    expect(starts).toEqual([Date.parse("2025-01-01T00:00:00Z"), Date.parse("2025-01-01T00:00:00Z") + expectedDelay]);
  });

  it.each([
    [429, "limited", 3, [2000, 2000]],
    [403, "You have exceeded a secondary rate limit", 3, [2000, 2000]],
    [403, "Forbidden: missing permission", 1, []],
  ])("bounds actual HTTP %i retries for %s", async (status, body, expectedCalls, expectedSleeps) => {
    const sleeps: number[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(body, { status, headers: { "Retry-After": "2" } }));
    const pacer = makePacer({ maxRetries: 2, sleep: async (ms) => { sleeps.push(ms); } });
    await expect(pacer.run(() => trackerFetch(fetchImpl, "https://tracker.invalid/items", { method: "GET", headers: {} })))
      .rejects.toMatchObject({ status, responseBody: body });
    expect(fetchImpl).toHaveBeenCalledTimes(expectedCalls);
    expect(sleeps).toEqual(expectedSleeps);
  });

  it("uses exponential fallback for repeated responses with an invalid header", async () => {
    const sleeps: number[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response("limited", { status: 429, headers: { "Retry-After": "bad-date" } }));
    const pacer = makePacer({ maxRetries: 2, baseBackoffMs: 125, sleep: async (ms) => { sleeps.push(ms); } });
    await expect(pacer.run(() => trackerFetch(fetchImpl, "https://tracker.invalid/items", { method: "GET", headers: {} })))
      .rejects.toBeInstanceOf(TrackerError);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(sleeps).toEqual([125, 250]);
  });
});

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
