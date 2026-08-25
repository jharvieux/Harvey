import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";
import { executeCapacityScan, type CapacityScanReceipt } from "./capacity-runner.js";

interface OracleTrace {
  readonly total: number;
  readonly completed: number;
  readonly active: number;
  readonly maxActive: number;
  readonly routes: Readonly<Record<string, number>>;
  readonly requests: readonly { sequence: number; path: string }[];
}

interface LoopbackOracle {
  readonly origin: string;
  trace(): OracleTrace;
  waitForIdle(): Promise<void>;
  close(): Promise<void>;
}

interface LoopbackOptions {
  readonly fastDelayMs?: number;
  readonly slowDelayMs?: number;
  readonly errorDelayMs?: number;
}

async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`loopback oracle did not become idle within ${timeoutMs}ms`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function startLoopbackOracle(options: LoopbackOptions = {}): Promise<LoopbackOracle> {
  const routeCounts = new Map<string, number>();
  const requests: { sequence: number; path: string }[] = [];
  let total = 0;
  let completed = 0;
  let active = 0;
  let maxActive = 0;

  const server: Server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://loopback.invalid").pathname;
    total += 1;
    active += 1;
    maxActive = Math.max(maxActive, active);
    routeCounts.set(path, (routeCounts.get(path) ?? 0) + 1);
    requests.push({ sequence: total, path });

    let settled = false;
    let timer: NodeJS.Timeout | null = null;
    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      active -= 1;
      completed += 1;
    };
    response.once("finish", settle);
    response.once("close", settle);

    const delay = path === "/slow" ? (options.slowDelayMs ?? 80) : path === "/error" ? (options.errorDelayMs ?? 20) : (options.fastDelayMs ?? 2);
    timer = setTimeout(() => {
      if (path === "/error") response.statusCode = 503;
      else if (path !== "/fast" && path !== "/slow") response.statusCode = 404;
      else response.statusCode = 204;
      response.end();
    }, delay);
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("loopback oracle did not bind an IP port");

  const trace = (): OracleTrace => ({
    total,
    completed,
    active,
    maxActive,
    routes: Object.freeze(Object.fromEntries([...routeCounts].sort(([left], [right]) => left.localeCompare(right)))),
    requests: Object.freeze(requests.map((request) => Object.freeze({ ...request }))),
  });
  const waitForIdle = async (): Promise<void> => waitUntil(() => active === 0, 2_000);

  return {
    origin: `http://127.0.0.1:${address.port}`,
    trace,
    waitForIdle,
    close: async () => {
      await waitForIdle();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

function contract(origin: string, paths: readonly string[]): Record<string, unknown> {
  return {
    version: 1,
    target: { origin, environment: "local" },
    authorization: { dynamicOptIn: true, connectedOptIn: false, writtenAuthorization: null },
    routes: paths.map((path) => ({ path, method: "GET" })),
    testData: { owner: "vitest-loopback-oracle", disposable: true },
    budget: { concurrency: 3, maxRequests: 9, maxDurationMs: 2_000, requestTimeoutMs: 1_000 },
    warmup: { requests: 2, countTowardBudget: true, applyAbortThresholds: true },
    abort: { maxErrors: 20, maxTimeouts: 20, maxLatencyMs: 900 },
  };
}

function outcomeTotal(receipt: CapacityScanReceipt): number {
  return Object.values(receipt.scheduler.outcomes).reduce((sum, count) => sum + count, 0);
}

function normalizedReceipt(receipt: CapacityScanReceipt): unknown {
  const origin = receipt.parse.target.origin;
  return {
    ...receipt,
    parse: { ...receipt.parse, target: { ...receipt.parse.target, origin: "<loopback>" } },
    admission: { ...receipt.admission, origin: "<loopback>" },
    scheduler: {
      ...receipt.scheduler,
      elapsedMs: "<measured>",
      results: receipt.scheduler.results.map((result) => ({
        ...result,
        url: result.url.replace(origin, "<loopback>"),
        startedOffsetMs: "<measured>",
        durationMs: "<measured>",
      })),
    },
  };
}

function emitTrace(label: string, receipt: CapacityScanReceipt, oracle: OracleTrace): void {
  if (process.env.CAPACITY_TRACE === "1") {
    console.log(label, JSON.stringify({ receipt: normalizedReceipt(receipt), oracle }));
  }
}

describe("bounded capacity scheduler with an independent loopback oracle", () => {
  it("NEGATIVE CONTROL: the oracle reports four when clients bypass the bounded scheduler", async () => {
    const fixture = await startLoopbackOracle({ slowDelayMs: 80 });
    try {
      const responses = await Promise.all(
        Array.from({ length: 4 }, () => fetch(`${fixture.origin}/slow`, { redirect: "manual" })),
      );
      await Promise.all(responses.map(async (response) => response.body?.cancel()));
      await fixture.waitForIdle();

      expect(fixture.trace()).toMatchObject({ total: 4, completed: 4, active: 0, maxActive: 4, routes: { "/slow": 4 } });
    } finally {
      await fixture.close();
    }
  });

  it("never exceeds admitted concurrency and conserves every request-capped attempt", async () => {
    const fixture = await startLoopbackOracle({ slowDelayMs: 60 });
    try {
      const receipt = await executeCapacityScan(contract(fixture.origin, ["/slow"]));
      await fixture.waitForIdle();
      const oracle = fixture.trace();

      expect(receipt.scheduler).toMatchObject({
        attempted: 9,
        concurrencyLimit: 3,
        maxInFlight: 3,
        stopReason: "request-cap",
        threshold: null,
      });
      expect(receipt.scheduler.results).toHaveLength(9);
      expect(receipt.scheduler.results.filter((result) => result.phase === "warmup")).toHaveLength(2);
      expect(outcomeTotal(receipt)).toBe(receipt.scheduler.attempted);
      expect(oracle).toMatchObject({ total: 9, completed: 9, active: 0, maxActive: 3, routes: { "/slow": 9 } });
      emitTrace("CAPACITY_BOUNDED_TRACE", receipt, oracle);
    } finally {
      await fixture.close();
    }
  });

  it("enforces a duration-only cap, aborts in-flight work, and retains every attempt", async () => {
    const fixture = await startLoopbackOracle({ slowDelayMs: 350 });
    try {
      const input = contract(fixture.origin, ["/slow"]);
      Object.assign(input.budget as Record<string, unknown>, {
        concurrency: 2,
        maxRequests: null,
        maxDurationMs: 120,
        requestTimeoutMs: 1_000,
      });
      (input.warmup as Record<string, unknown>).requests = 0;

      const receipt = await executeCapacityScan(input);
      await fixture.waitForIdle();
      const oracle = fixture.trace();

      expect(receipt.scheduler).toMatchObject({ attempted: 2, maxInFlight: 2, stopReason: "duration-cap" });
      expect(receipt.scheduler.results).toHaveLength(2);
      expect(receipt.scheduler.outcomes).toEqual({ success: 0, httpError: 0, transportError: 0, timeout: 0, aborted: 2 });
      expect(outcomeTotal(receipt)).toBe(receipt.scheduler.attempted);
      expect(oracle).toMatchObject({ total: 2, completed: 2, active: 0, maxActive: 2, routes: { "/slow": 2 } });
      emitTrace("CAPACITY_DURATION_TRACE", receipt, oracle);
    } finally {
      await fixture.close();
    }
  });

  it("times out a slow request and stops before dispatching another at the timeout threshold", async () => {
    const fixture = await startLoopbackOracle({ slowDelayMs: 220 });
    try {
      const input = contract(fixture.origin, ["/slow"]);
      Object.assign(input.budget as Record<string, unknown>, { concurrency: 1, maxRequests: 5, requestTimeoutMs: 40 });
      Object.assign(input.abort as Record<string, unknown>, { maxTimeouts: 1, maxLatencyMs: 40 });
      (input.warmup as Record<string, unknown>).requests = 0;

      const receipt = await executeCapacityScan(input);
      await fixture.waitForIdle();
      const oracle = fixture.trace();

      expect(receipt.scheduler).toMatchObject({
        attempted: 1,
        maxInFlight: 1,
        stopReason: "safety-threshold",
        threshold: { kind: "timeouts", attempt: 1, limit: 1, observed: 1 },
        outcomes: { timeout: 1 },
      });
      expect(outcomeTotal(receipt)).toBe(1);
      expect(oracle).toMatchObject({ total: 1, completed: 1, active: 0, maxActive: 1, routes: { "/slow": 1 } });
      emitTrace("CAPACITY_TIMEOUT_TRACE", receipt, oracle);
    } finally {
      await fixture.close();
    }
  });

  it("stops new dispatch on the first error threshold and retains aborted in-flight partials", async () => {
    const fixture = await startLoopbackOracle({ errorDelayMs: 100, slowDelayMs: 400 });
    try {
      const input = contract(fixture.origin, ["/error", "/slow?lane=2", "/slow?lane=3"]);
      (input.budget as Record<string, unknown>).maxRequests = 10;
      Object.assign(input.abort as Record<string, unknown>, { maxErrors: 1, maxLatencyMs: 900 });
      (input.warmup as Record<string, unknown>).requests = 0;

      const receipt = await executeCapacityScan(input);
      await fixture.waitForIdle();
      const oracle = fixture.trace();

      expect(receipt.scheduler).toMatchObject({
        attempted: 3,
        maxInFlight: 3,
        stopReason: "safety-threshold",
        threshold: { kind: "errors", attempt: 1, limit: 1, observed: 1 },
        outcomes: { httpError: 1, aborted: 2 },
      });
      expect(receipt.scheduler.results).toHaveLength(3);
      expect(outcomeTotal(receipt)).toBe(3);
      expect(oracle).toMatchObject({ total: 3, completed: 3, active: 0, maxActive: 3, routes: { "/error": 1, "/slow": 2 } });
      emitTrace("CAPACITY_ABORT_TRACE", receipt, oracle);
    } finally {
      await fixture.close();
    }
  });

  it("observes each disposable fixture branch independently of runner counters", async () => {
    const fixture = await startLoopbackOracle({ fastDelayMs: 2, slowDelayMs: 40, errorDelayMs: 10 });
    try {
      const input = contract(fixture.origin, ["/fast", "/slow", "/error"]);
      Object.assign(input.budget as Record<string, unknown>, { concurrency: 1, maxRequests: 3 });
      Object.assign(input.abort as Record<string, unknown>, { maxErrors: 2, maxLatencyMs: 500 });
      (input.warmup as Record<string, unknown>).requests = 0;

      const receipt = await executeCapacityScan(input);
      await fixture.waitForIdle();
      const oracle = fixture.trace();

      expect(receipt.scheduler.results.map((result) => result.outcome)).toEqual(["success", "success", "http-error"]);
      expect(oracle).toMatchObject({ total: 3, completed: 3, maxActive: 1, routes: { "/error": 1, "/fast": 1, "/slow": 1 } });
      expect(oracle.requests.map((request) => request.path)).toEqual(["/fast", "/slow", "/error"]);
    } finally {
      await fixture.close();
    }
  });
});
