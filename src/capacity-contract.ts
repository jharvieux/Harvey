import { isIP } from "node:net";

export const CAPACITY_CONTRACT_VERSION = 1 as const;

const CAPACITY_HARD_LIMITS = Object.freeze({
  concurrency: 256,
  maxRequests: 1_000_000,
  maxDurationMs: 24 * 60 * 60 * 1_000,
  requestTimeoutMs: 5 * 60 * 1_000,
  warmupRequests: 100_000,
});

export type CapacityEnvironment = "local" | "development" | "test" | "staging" | "production";
export type CapacityMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export interface CapacityRoute {
  readonly path: string;
  readonly method: CapacityMethod;
}

export interface CapacityEngagementContract {
  readonly version: typeof CAPACITY_CONTRACT_VERSION;
  readonly target: {
    readonly origin: string;
    readonly environment: CapacityEnvironment;
  };
  readonly authorization: {
    readonly dynamicOptIn: boolean;
    readonly connectedOptIn: boolean;
    readonly writtenAuthorization: string | null;
  };
  readonly routes: readonly CapacityRoute[];
  readonly testData: {
    readonly owner: string;
    readonly disposable: true;
  };
  readonly budget: {
    readonly concurrency: number;
    readonly maxRequests: number | null;
    readonly maxDurationMs: number | null;
    readonly requestTimeoutMs: number;
  };
  readonly warmup: {
    readonly requests: number;
    readonly countTowardBudget: true;
    readonly applyAbortThresholds: true;
  };
  readonly abort: {
    readonly maxErrors: number;
    readonly maxTimeouts: number;
    readonly maxLatencyMs: number;
  };
}

export interface CapacityContractTrace {
  readonly version: typeof CAPACITY_CONTRACT_VERSION;
  readonly target: CapacityEngagementContract["target"];
  readonly authorization: {
    readonly dynamicOptIn: boolean;
    readonly connectedOptIn: boolean;
    readonly writtenAuthorizationRecorded: boolean;
  };
  readonly routes: readonly CapacityRoute[];
  readonly testData: CapacityEngagementContract["testData"];
  readonly budget: CapacityEngagementContract["budget"];
  readonly warmup: CapacityEngagementContract["warmup"];
  readonly abort: CapacityEngagementContract["abort"];
}

export interface CapacityAdmissionTrace {
  readonly origin: string;
  readonly environment: CapacityEnvironment;
  readonly loopback: boolean;
  readonly dynamic: "accepted";
  readonly connected: "local-not-required" | "accepted";
  readonly writtenAuthorization: "local-not-required" | "recorded";
  readonly budget: CapacityEngagementContract["budget"];
}

export interface CapacityAdmission {
  readonly contract: CapacityEngagementContract;
  readonly trace: CapacityAdmissionTrace;
}

export class CapacityContractError extends Error {
  override readonly name = "CapacityContractError";
}

export class CapacityAdmissionError extends Error {
  override readonly name = "CapacityAdmissionError";
}

type JsonRecord = Record<string, unknown>;

const ENVIRONMENTS = new Set<CapacityEnvironment>(["local", "development", "test", "staging", "production"]);
const METHODS = new Set<CapacityMethod>(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const ROUTE_BASE = "http://capacity.invalid";

function contractError(path: string, detail: string): never {
  throw new CapacityContractError(`${path}: ${detail}`);
}

function admissionError(detail: string): never {
  throw new CapacityAdmissionError(`capacity admission refused: ${detail}`);
}

function strictObject(value: unknown, path: string, fields: readonly string[]): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return contractError(path, "must be an object");
  }

  const record = value as JsonRecord;
  const unknown = Object.keys(record).filter((field) => !fields.includes(field)).sort();
  if (unknown.length > 0) contractError(path, `unknown field(s): ${unknown.join(", ")}`);

  const missing = fields.filter((field) => !Object.prototype.hasOwnProperty.call(record, field));
  if (missing.length > 0) contractError(path, `missing field(s): ${missing.join(", ")}`);
  return record;
}

function strictString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) return contractError(path, "must be a non-empty string");
  if (value.trim() !== value) return contractError(path, "must not have leading or trailing whitespace");
  return value;
}

function strictBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") return contractError(path, "must be a boolean");
  return value;
}

function strictInteger(value: unknown, path: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || typeof value !== "number" || value < minimum || value > maximum) {
    return contractError(path, `must be an integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function nullablePositiveInteger(value: unknown, path: string, maximum: number): number | null {
  return value === null ? null : strictInteger(value, path, 1, maximum);
}

function literalTrue(value: unknown, path: string): true {
  if (value !== true) return contractError(path, "must be true");
  return true;
}

function parseOrigin(value: unknown): string {
  const origin = strictString(value, "contract.target.origin");
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return contractError("contract.target.origin", "must be an absolute HTTP(S) origin");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return contractError("contract.target.origin", "must use http or https");
  }
  if (parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.origin !== origin) {
    return contractError("contract.target.origin", `must be the canonical origin ${parsed.origin} with no credentials, path, query, or hash`);
  }
  return parsed.origin;
}

function parseEnvironment(value: unknown): CapacityEnvironment {
  if (typeof value !== "string" || !ENVIRONMENTS.has(value as CapacityEnvironment)) {
    return contractError("contract.target.environment", `must be one of ${[...ENVIRONMENTS].join(", ")}`);
  }
  return value as CapacityEnvironment;
}

function parseMethod(value: unknown, path: string): CapacityMethod {
  if (typeof value !== "string" || !METHODS.has(value as CapacityMethod)) {
    return contractError(path, `must be one of ${[...METHODS].join(", ")}`);
  }
  return value as CapacityMethod;
}

function parseRoutePath(value: unknown, path: string): string {
  const routePath = strictString(value, path);
  if (!routePath.startsWith("/") || routePath.startsWith("//") || routePath.includes("\\")) {
    return contractError(path, "must be an origin-relative path and must not override the authorized origin");
  }

  let parsed: URL;
  try {
    parsed = new URL(routePath, ROUTE_BASE);
  } catch {
    return contractError(path, "must be a valid origin-relative URL path");
  }

  if (parsed.origin !== ROUTE_BASE || parsed.hash || `${parsed.pathname}${parsed.search}` !== routePath) {
    return contractError(path, "must be a canonical origin-relative path without a fragment");
  }
  return routePath;
}

function parseRoutes(value: unknown): readonly CapacityRoute[] {
  if (!Array.isArray(value) || value.length === 0) return contractError("contract.routes", "must be a non-empty array");

  const seen = new Set<string>();
  const routes = value.map((candidate, index): CapacityRoute => {
    const path = `contract.routes[${index}]`;
    const route = strictObject(candidate, path, ["path", "method"]);
    const parsed = Object.freeze({
      path: parseRoutePath(route.path, `${path}.path`),
      method: parseMethod(route.method, `${path}.method`),
    });
    const identity = `${parsed.method} ${parsed.path}`;
    if (seen.has(identity)) contractError(path, `duplicates route ${identity}`);
    seen.add(identity);
    return parsed;
  });
  return Object.freeze(routes);
}

function parseWrittenAuthorization(value: unknown): string | null {
  return value === null ? null : strictString(value, "contract.authorization.writtenAuthorization");
}

function parseVersion(value: unknown): typeof CAPACITY_CONTRACT_VERSION {
  if (value !== CAPACITY_CONTRACT_VERSION) {
    return contractError("contract.version", `unsupported version ${String(value)}; expected ${CAPACITY_CONTRACT_VERSION}`);
  }
  return CAPACITY_CONTRACT_VERSION;
}

export function parseCapacityContract(input: unknown): CapacityEngagementContract {
  const root = strictObject(input, "contract", ["version", "target", "authorization", "routes", "testData", "budget", "warmup", "abort"]);
  const target = strictObject(root.target, "contract.target", ["origin", "environment"]);
  const authorization = strictObject(root.authorization, "contract.authorization", ["dynamicOptIn", "connectedOptIn", "writtenAuthorization"]);
  const testData = strictObject(root.testData, "contract.testData", ["owner", "disposable"]);
  const budget = strictObject(root.budget, "contract.budget", ["concurrency", "maxRequests", "maxDurationMs", "requestTimeoutMs"]);
  const warmup = strictObject(root.warmup, "contract.warmup", ["requests", "countTowardBudget", "applyAbortThresholds"]);
  const abort = strictObject(root.abort, "contract.abort", ["maxErrors", "maxTimeouts", "maxLatencyMs"]);

  const maxRequests = nullablePositiveInteger(budget.maxRequests, "contract.budget.maxRequests", CAPACITY_HARD_LIMITS.maxRequests);
  const maxDurationMs = nullablePositiveInteger(budget.maxDurationMs, "contract.budget.maxDurationMs", CAPACITY_HARD_LIMITS.maxDurationMs);
  if (maxRequests === null && maxDurationMs === null) {
    contractError("contract.budget", "must set maxRequests, maxDurationMs, or both");
  }

  const warmupRequests = strictInteger(warmup.requests, "contract.warmup.requests", 0, CAPACITY_HARD_LIMITS.warmupRequests);
  if (maxRequests !== null && warmupRequests > maxRequests) {
    contractError("contract.warmup.requests", "must not exceed contract.budget.maxRequests");
  }

  return Object.freeze({
    version: parseVersion(root.version),
    target: Object.freeze({
      origin: parseOrigin(target.origin),
      environment: parseEnvironment(target.environment),
    }),
    authorization: Object.freeze({
      dynamicOptIn: strictBoolean(authorization.dynamicOptIn, "contract.authorization.dynamicOptIn"),
      connectedOptIn: strictBoolean(authorization.connectedOptIn, "contract.authorization.connectedOptIn"),
      writtenAuthorization: parseWrittenAuthorization(authorization.writtenAuthorization),
    }),
    routes: parseRoutes(root.routes),
    testData: Object.freeze({
      owner: strictString(testData.owner, "contract.testData.owner"),
      disposable: literalTrue(testData.disposable, "contract.testData.disposable"),
    }),
    budget: Object.freeze({
      concurrency: strictInteger(budget.concurrency, "contract.budget.concurrency", 1, CAPACITY_HARD_LIMITS.concurrency),
      maxRequests,
      maxDurationMs,
      requestTimeoutMs: strictInteger(budget.requestTimeoutMs, "contract.budget.requestTimeoutMs", 1, CAPACITY_HARD_LIMITS.requestTimeoutMs),
    }),
    warmup: Object.freeze({
      requests: warmupRequests,
      countTowardBudget: literalTrue(warmup.countTowardBudget, "contract.warmup.countTowardBudget"),
      applyAbortThresholds: literalTrue(warmup.applyAbortThresholds, "contract.warmup.applyAbortThresholds"),
    }),
    abort: Object.freeze({
      maxErrors: strictInteger(abort.maxErrors, "contract.abort.maxErrors", 1, CAPACITY_HARD_LIMITS.maxRequests),
      maxTimeouts: strictInteger(abort.maxTimeouts, "contract.abort.maxTimeouts", 1, CAPACITY_HARD_LIMITS.maxRequests),
      maxLatencyMs: strictInteger(abort.maxLatencyMs, "contract.abort.maxLatencyMs", 1, CAPACITY_HARD_LIMITS.requestTimeoutMs),
    }),
  });
}

export function capacityContractTrace(contract: CapacityEngagementContract): CapacityContractTrace {
  return Object.freeze({
    version: contract.version,
    target: contract.target,
    authorization: Object.freeze({
      dynamicOptIn: contract.authorization.dynamicOptIn,
      connectedOptIn: contract.authorization.connectedOptIn,
      writtenAuthorizationRecorded: contract.authorization.writtenAuthorization !== null,
    }),
    routes: contract.routes,
    testData: contract.testData,
    budget: contract.budget,
    warmup: contract.warmup,
    abort: contract.abort,
  });
}

function isLoopbackOrigin(origin: string): boolean {
  const hostname = new URL(origin).hostname;
  if (hostname === "localhost" || hostname === "[::1]") return true;
  return isIP(hostname) === 4 && hostname === "127.0.0.1";
}

export function admitCapacityContract(contract: CapacityEngagementContract): CapacityAdmission {
  const loopback = isLoopbackOrigin(contract.target.origin);
  const requiresWrittenAuthorization = !loopback || contract.target.environment === "production";

  if (!contract.authorization.dynamicOptIn) admissionError("dynamicOptIn must be true for capacity traffic");
  if (requiresWrittenAuthorization && !contract.authorization.connectedOptIn) {
    admissionError("production-classified or non-loopback targets require connectedOptIn=true");
  }
  if (requiresWrittenAuthorization && contract.authorization.writtenAuthorization === null) {
    admissionError("production-classified or non-loopback targets require a writtenAuthorization reference");
  }

  return Object.freeze({
    contract,
    trace: Object.freeze({
      origin: contract.target.origin,
      environment: contract.target.environment,
      loopback,
      dynamic: "accepted",
      connected: requiresWrittenAuthorization ? "accepted" : "local-not-required",
      writtenAuthorization: requiresWrittenAuthorization ? "recorded" : "local-not-required",
      budget: contract.budget,
    }),
  });
}
