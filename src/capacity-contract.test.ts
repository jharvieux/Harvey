import { describe, expect, it } from "vitest";
import {
  CapacityAdmissionError,
  CapacityContractError,
  admitCapacityContract,
  capacityContractTrace,
  parseCapacityContract,
} from "./capacity-contract.js";
import { executeCapacityScan, type CapacityTransport } from "./capacity-runner.js";

function validContract(origin = "http://127.0.0.1:43123"): Record<string, unknown> {
  return {
    version: 1,
    target: { origin, environment: "local" },
    authorization: { dynamicOptIn: true, connectedOptIn: false, writtenAuthorization: null },
    routes: [{ path: "/fast", method: "GET" }],
    testData: { owner: "capacity-test", disposable: true },
    budget: { concurrency: 2, maxRequests: 4, maxDurationMs: 2_000, requestTimeoutMs: 500 },
    warmup: { requests: 1, countTowardBudget: true, applyAbortThresholds: true },
    abort: { maxErrors: 2, maxTimeouts: 2, maxLatencyMs: 400 },
  };
}

function deletePath(input: Record<string, unknown>, dottedPath: string): void {
  const parts = dottedPath.split(".");
  const leaf = parts.pop();
  if (!leaf) throw new Error("test path must have a leaf");
  let cursor: Record<string, unknown> = input;
  for (const part of parts) {
    const next = cursor[part];
    if (next === null || typeof next !== "object" || Array.isArray(next)) throw new Error(`test path ${dottedPath} is invalid at ${part}`);
    cursor = next as Record<string, unknown>;
  }
  delete cursor[leaf];
}

describe("capacity engagement contract", () => {
  it("parses every authorization and budget field into a redacted normalized trace", () => {
    const parsed = parseCapacityContract(validContract());

    expect(capacityContractTrace(parsed)).toEqual({
      version: 1,
      target: { origin: "http://127.0.0.1:43123", environment: "local" },
      authorization: { dynamicOptIn: true, connectedOptIn: false, writtenAuthorizationRecorded: false },
      routes: [{ path: "/fast", method: "GET" }],
      testData: { owner: "capacity-test", disposable: true },
      budget: { concurrency: 2, maxRequests: 4, maxDurationMs: 2_000, requestTimeoutMs: 500 },
      warmup: { requests: 1, countTowardBudget: true, applyAbortThresholds: true },
      abort: { maxErrors: 2, maxTimeouts: 2, maxLatencyMs: 400 },
    });
  });

  it.each([
    "version",
    "target",
    "target.origin",
    "target.environment",
    "authorization",
    "authorization.dynamicOptIn",
    "authorization.connectedOptIn",
    "authorization.writtenAuthorization",
    "routes",
    "testData",
    "testData.owner",
    "testData.disposable",
    "budget",
    "budget.concurrency",
    "budget.maxRequests",
    "budget.maxDurationMs",
    "budget.requestTimeoutMs",
    "warmup",
    "warmup.requests",
    "warmup.countTowardBudget",
    "warmup.applyAbortThresholds",
    "abort",
    "abort.maxErrors",
    "abort.maxTimeouts",
    "abort.maxLatencyMs",
  ])("fails closed when required field %s is missing", (path) => {
    const input = structuredClone(validContract());
    deletePath(input, path);
    expect(() => parseCapacityContract(input)).toThrow(CapacityContractError);
  });

  it("rejects unknown fields at every object boundary", () => {
    const root = validContract();
    root.surprise = true;
    expect(() => parseCapacityContract(root)).toThrow(/unknown field.*surprise/);

    const nested = validContract();
    (nested.budget as Record<string, unknown>).unlimited = true;
    expect(() => parseCapacityContract(nested)).toThrow(/unknown field.*unlimited/);

    const route = validContract();
    ((route.routes as Record<string, unknown>[])[0] as Record<string, unknown>).origin = "https://capacity.invalid";
    expect(() => parseCapacityContract(route)).toThrow(/unknown field.*origin/);
  });

  it("rejects unsupported versions and contracts with neither a request nor duration cap", () => {
    const future = validContract();
    future.version = 2;
    expect(() => parseCapacityContract(future)).toThrow(/unsupported version 2/);

    const unbounded = validContract();
    (unbounded.budget as Record<string, unknown>).maxRequests = null;
    (unbounded.budget as Record<string, unknown>).maxDurationMs = null;
    expect(() => parseCapacityContract(unbounded)).toThrow(/must set maxRequests, maxDurationMs, or both/);
  });

  it("admits an opted-in loopback contract without connected authorization", () => {
    const admission = admitCapacityContract(parseCapacityContract(validContract()));
    expect(admission.trace).toEqual({
      origin: "http://127.0.0.1:43123",
      environment: "local",
      loopback: true,
      dynamic: "accepted",
      connected: "local-not-required",
      writtenAuthorization: "local-not-required",
      budget: { concurrency: 2, maxRequests: 4, maxDurationMs: 2_000, requestTimeoutMs: 500 },
    });
  });

  it("refuses dynamic, non-loopback, and production traffic before transport call one", async () => {
    const cases = [
      (() => {
        const input = validContract();
        (input.authorization as Record<string, unknown>).dynamicOptIn = false;
        return input;
      })(),
      validContract("https://capacity.invalid"),
      (() => {
        const input = validContract();
        (input.target as Record<string, unknown>).environment = "production";
        return input;
      })(),
    ];

    for (const input of cases) {
      let transportCalls = 0;
      const transport: CapacityTransport = async () => {
        transportCalls += 1;
        return { status: 204 };
      };
      await expect(executeCapacityScan(input, { transport })).rejects.toBeInstanceOf(CapacityAdmissionError);
      expect(transportCalls).toBe(0);
    }
  });

  it("accepts a written non-loopback opt-in using an inert injected transport", async () => {
    const input = validContract("https://capacity.invalid");
    (input.authorization as Record<string, unknown>).connectedOptIn = true;
    (input.authorization as Record<string, unknown>).writtenAuthorization = "engagement-approval-1893";
    (input.budget as Record<string, unknown>).maxRequests = 1;
    (input.warmup as Record<string, unknown>).requests = 0;

    const contacted: string[] = [];
    const receipt = await executeCapacityScan(input, {
      transport: async (request) => {
        contacted.push(request.url);
        return { status: 204 };
      },
    });

    expect(contacted).toEqual(["https://capacity.invalid/fast"]);
    expect(receipt.admission).toMatchObject({ loopback: false, connected: "accepted", writtenAuthorization: "recorded" });
    expect(receipt.scheduler).toMatchObject({ attempted: 1, stopReason: "request-cap" });
    if (process.env.CAPACITY_TRACE === "1") {
      console.log("CAPACITY_AUTHORIZED_TRACE", JSON.stringify(receipt));
    }
  });

  it("rejects an origin-override route before request one", async () => {
    const input = validContract();
    input.routes = [{ path: "//capacity.invalid/escape", method: "GET" }];
    let transportCalls = 0;

    await expect(
      executeCapacityScan(input, {
        transport: async () => {
          transportCalls += 1;
          return { status: 204 };
        },
      }),
    ).rejects.toThrow(/must not override the authorized origin/);
    expect(transportCalls).toBe(0);
  });
});
