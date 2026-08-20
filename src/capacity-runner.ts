import { performance } from "node:perf_hooks";
import {
  admitCapacityContract,
  capacityContractTrace,
  parseCapacityContract,
  type CapacityAdmission,
  type CapacityAdmissionTrace,
  type CapacityContractTrace,
  type CapacityMethod,
} from "./capacity-contract.js";

export interface CapacityTransportRequest {
  readonly attempt: number;
  readonly phase: "warmup" | "measure";
  readonly url: string;
  readonly method: CapacityMethod;
  readonly signal: AbortSignal;
}

export interface CapacityTransportResponse {
  readonly status: number;
}

export type CapacityTransport = (request: CapacityTransportRequest) => Promise<CapacityTransportResponse>;

type CapacityAttemptOutcome = "success" | "http-error" | "transport-error" | "timeout" | "aborted";
type CapacityStopReason = "request-cap" | "duration-cap" | "safety-threshold";
type CapacityThresholdKind = "errors" | "timeouts" | "latency";

interface CapacityAttemptResult {
  readonly attempt: number;
  readonly phase: "warmup" | "measure";
  readonly method: CapacityMethod;
  readonly url: string;
  readonly startedOffsetMs: number;
  readonly durationMs: number;
  readonly outcome: CapacityAttemptOutcome;
  readonly status?: number;
  readonly error?: string;
}

interface CapacityThresholdReceipt {
  readonly kind: CapacityThresholdKind;
  readonly attempt: number;
  readonly limit: number;
  readonly observed: number;
}

export interface CapacitySchedulerTrace {
  readonly concurrencyLimit: number;
  readonly requestLimit: number | null;
  readonly durationLimitMs: number | null;
  readonly requestTimeoutMs: number;
  readonly attempted: number;
  readonly maxInFlight: number;
  readonly elapsedMs: number;
  readonly stopReason: CapacityStopReason;
  readonly threshold: CapacityThresholdReceipt | null;
  readonly outcomes: {
    readonly success: number;
    readonly httpError: number;
    readonly transportError: number;
    readonly timeout: number;
    readonly aborted: number;
  };
  readonly results: readonly CapacityAttemptResult[];
}

export interface CapacityScanReceipt {
  readonly receiptVersion: 1;
  readonly parse: CapacityContractTrace;
  readonly admission: CapacityAdmissionTrace;
  readonly scheduler: CapacitySchedulerTrace;
}

interface CapacityRunOptions {
  readonly transport?: CapacityTransport;
}

type RequestAbortReason = "request-timeout" | "duration-cap" | "safety-threshold";

class CapacityRequestAbort extends Error {
  override readonly name = "CapacityRequestAbort";

  constructor(readonly reason: RequestAbortReason) {
    super(reason);
  }
}

function roundedMilliseconds(value: number): number {
  return Math.max(0, Math.round(value));
}

function errorText(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new CapacityRequestAbort(signal.reason as RequestAbortReason));

  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const settle = (action: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      action();
    };
    const onAbort = (): void => settle(() => reject(new CapacityRequestAbort(signal.reason as RequestAbortReason)));

    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => settle(() => resolve(value)),
      (error: unknown) => settle(() => reject(error)),
    );
  });
}

const fetchCapacityTransport: CapacityTransport = async (request) => {
  const response = await fetch(request.url, {
    method: request.method,
    signal: request.signal,
    redirect: "manual",
  });
  await response.body?.cancel();
  return { status: response.status };
};

function validateTransportResponse(response: CapacityTransportResponse): number {
  if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
    throw new Error(`capacity transport returned invalid HTTP status ${String(response.status)}`);
  }
  return response.status;
}

async function runAdmittedCapacity(admission: CapacityAdmission, transport: CapacityTransport): Promise<CapacitySchedulerTrace> {
  const { contract } = admission;
  const startedAt = performance.now();
  const results: CapacityAttemptResult[] = [];
  const active = new Map<number, AbortController>();

  let attempted = 0;
  let maxInFlight = 0;
  let errorCount = 0;
  let timeoutCount = 0;
  let stopReason: CapacityStopReason | null = null;
  let threshold: CapacityThresholdReceipt | null = null;
  let finished = false;
  let deadlineTimer: NodeJS.Timeout | null = null;
  let pumpHandle: NodeJS.Immediate | null = null;
  let resolveDone: (() => void) | null = null;

  const done = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });

  const elapsed = (): number => performance.now() - startedAt;

  const finish = (): void => {
    if (finished) return;
    finished = true;
    if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    if (pumpHandle !== null) clearImmediate(pumpHandle);
    resolveDone?.();
  };

  const abortActive = (reason: RequestAbortReason): void => {
    for (const controller of active.values()) {
      if (!controller.signal.aborted) controller.abort(reason);
    }
  };

  const stop = (reason: Exclude<CapacityStopReason, "request-cap">, receipt: CapacityThresholdReceipt | null = null): void => {
    if (stopReason !== null) return;
    stopReason = reason;
    threshold = receipt;
    abortActive(reason === "duration-cap" ? "duration-cap" : "safety-threshold");
    if (active.size === 0) finish();
  };

  const evaluateThreshold = (result: CapacityAttemptResult): CapacityThresholdReceipt | null => {
    if (result.outcome === "http-error" || result.outcome === "transport-error") {
      errorCount += 1;
      if (errorCount >= contract.abort.maxErrors) {
        return Object.freeze({ kind: "errors", attempt: result.attempt, limit: contract.abort.maxErrors, observed: errorCount });
      }
    }

    if (result.outcome === "timeout") {
      timeoutCount += 1;
      if (timeoutCount >= contract.abort.maxTimeouts) {
        return Object.freeze({ kind: "timeouts", attempt: result.attempt, limit: contract.abort.maxTimeouts, observed: timeoutCount });
      }
    }

    if ((result.outcome === "success" || result.outcome === "http-error") && result.durationMs >= contract.abort.maxLatencyMs) {
      return Object.freeze({ kind: "latency", attempt: result.attempt, limit: contract.abort.maxLatencyMs, observed: result.durationMs });
    }
    return null;
  };

  const shouldDispatch = (): boolean => {
    if (stopReason !== null) return false;
    if (contract.budget.maxRequests !== null && attempted >= contract.budget.maxRequests) return false;
    if (contract.budget.maxDurationMs !== null && elapsed() >= contract.budget.maxDurationMs) {
      stop("duration-cap");
      return false;
    }
    return true;
  };

  const schedulePump = (): void => {
    if (finished || pumpHandle !== null) return;
    pumpHandle = setImmediate(() => {
      pumpHandle = null;
      pump();
    });
  };

  const settleAttempt = async (
    attempt: number,
    phase: "warmup" | "measure",
    method: CapacityMethod,
    url: string,
    controller: AbortController,
    attemptStartedAt: number,
  ): Promise<void> => {
    const timeoutTimer = setTimeout(() => controller.abort("request-timeout" satisfies RequestAbortReason), contract.budget.requestTimeoutMs);
    let outcome: CapacityAttemptOutcome;
    let status: number | undefined;
    let error: string | undefined;

    try {
      const response = await withAbort(
        Promise.resolve().then(() => transport(Object.freeze({ attempt, phase, method, url, signal: controller.signal }))),
        controller.signal,
      );
      status = validateTransportResponse(response);
      outcome = status >= 200 && status <= 299 ? "success" : "http-error";
    } catch (cause) {
      if (cause instanceof CapacityRequestAbort) {
        outcome = cause.reason === "request-timeout" ? "timeout" : "aborted";
        error = cause.reason;
      } else {
        outcome = "transport-error";
        error = errorText(cause);
      }
    } finally {
      clearTimeout(timeoutTimer);
    }

    active.delete(attempt);
    const result = Object.freeze({
      attempt,
      phase,
      method,
      url,
      startedOffsetMs: roundedMilliseconds(attemptStartedAt - startedAt),
      durationMs: roundedMilliseconds(performance.now() - attemptStartedAt),
      outcome,
      status,
      error,
    });
    results.push(result);

    const reached = stopReason === null ? evaluateThreshold(result) : null;
    if (reached !== null) stop("safety-threshold", reached);

    if (active.size === 0 && (stopReason !== null || (contract.budget.maxRequests !== null && attempted >= contract.budget.maxRequests))) {
      finish();
      return;
    }
    schedulePump();
  };

  const launch = (): void => {
    attempted += 1;
    const attempt = attempted;
    const route = contract.routes[(attempt - 1) % contract.routes.length];
    if (!route) throw new Error("capacity contract has no routes after admission");

    const resolved = new URL(route.path, contract.target.origin);
    if (resolved.origin !== contract.target.origin) {
      throw new Error(`capacity route escaped admitted origin before request ${attempt}`);
    }

    const controller = new AbortController();
    active.set(attempt, controller);
    maxInFlight = Math.max(maxInFlight, active.size);
    const phase = attempt <= contract.warmup.requests ? "warmup" : "measure";
    void settleAttempt(attempt, phase, route.method, resolved.href, controller, performance.now());
  };

  function pump(): void {
    if (finished) return;
    while (active.size < contract.budget.concurrency && shouldDispatch()) launch();

    if (active.size === 0) {
      if (stopReason !== null) finish();
      else if (contract.budget.maxRequests !== null && attempted >= contract.budget.maxRequests) finish();
      else schedulePump();
    }
  }

  if (contract.budget.maxDurationMs !== null) {
    deadlineTimer = setTimeout(() => stop("duration-cap"), contract.budget.maxDurationMs);
  }

  pump();
  await done;

  const ordered = Object.freeze([...results].sort((left, right) => left.attempt - right.attempt));
  const outcomes = Object.freeze({
    success: ordered.filter((result) => result.outcome === "success").length,
    httpError: ordered.filter((result) => result.outcome === "http-error").length,
    transportError: ordered.filter((result) => result.outcome === "transport-error").length,
    timeout: ordered.filter((result) => result.outcome === "timeout").length,
    aborted: ordered.filter((result) => result.outcome === "aborted").length,
  });

  return Object.freeze({
    concurrencyLimit: contract.budget.concurrency,
    requestLimit: contract.budget.maxRequests,
    durationLimitMs: contract.budget.maxDurationMs,
    requestTimeoutMs: contract.budget.requestTimeoutMs,
    attempted,
    maxInFlight,
    elapsedMs: roundedMilliseconds(elapsed()),
    stopReason: stopReason ?? "request-cap",
    threshold,
    outcomes,
    results: ordered,
  });
}

export async function executeCapacityScan(input: unknown, options: CapacityRunOptions = {}): Promise<CapacityScanReceipt> {
  const contract = parseCapacityContract(input);
  const parse = capacityContractTrace(contract);
  const admission = admitCapacityContract(contract);
  const scheduler = await runAdmittedCapacity(admission, options.transport ?? fetchCapacityTransport);

  return Object.freeze({
    receiptVersion: 1,
    parse,
    admission: admission.trace,
    scheduler,
  });
}
