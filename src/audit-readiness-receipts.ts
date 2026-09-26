import { createHash } from "node:crypto";
import { delimiter, isAbsolute, relative, sep } from "node:path";
import { constants as osConstants } from "node:os";
import { serializeReadinessPlanV1, validateReadinessPlanV1, type ReadinessPlanV1, type ReadinessStageV1, type ReadinessWorkspaceV1 } from "./audit-readiness.js";
import { type ReadinessAuthorityReceipt, type ReadinessPlanBindingV1, type ReadinessSpawnRequest, type ReadinessStageAdmission } from "./audit-readiness-authority.js";
import { type DisposableCleanupReceipt, type SourceSentinelV1 } from "./disposable-target.js";
import { SecretRegistry, type SecretExcerptContext } from "./secret-argv.js";
import type { ReadinessProcessContainment } from "./bounded-process.js";

type StageId = ReadinessStageV1["id"];
type Admitted = Extract<ReadinessStageAdmission, { status: "admitted" }>;
type Provenance = ReadinessStageV1["provenance"];

/** Structural input boundary shared with the bounded runner; no argv, environment, or raw error objects. */
export interface ReadinessProcessEvidenceV1 {
  state: "exited" | "timed-out" | "aborted" | "spawn-error" | "io-error" | "observer-error" | "redaction-error" | "descendant-cleanup" | "termination-unconfirmed" | "unsupported-platform" | "containment-unavailable";
  containment: ReadinessProcessContainment;
  succeeded: boolean;
  pid: number | null;
  queuedAt: string;
  startedAt: string;
  spawnedAt: string | null;
  firstByteAt: string | null;
  endedAt: string;
  queueDurationMs: number;
  durationMs: number;
  fromFirstByteMs: number | null;
  exit: { at: string; code: number | null; signal: NodeJS.Signals | null } | null;
  close: { at: string; code: number | null; signal: NodeJS.Signals | null } | null;
  errors: { phase: "spawn" | "stdout" | "stderr" | "observer" | "redaction" | "termination"; code: string }[];
  termination: {
    reason: "timeout" | "abort" | "process-error" | "io-error" | "observer-error" | "descendants" | null;
    attempts: { at: string; signal: "SIGTERM" | "SIGKILL"; status: "sent" | "absent" | "failed"; code: string | null }[];
    tree: "not-started" | "absent" | "unconfirmed";
    stdioForcedClosed: boolean;
  };
  stdout: ReadinessStreamEvidenceV1;
  stderr: ReadinessStreamEvidenceV1;
}

interface ReadinessStreamEvidenceV1 {
  bytes: number;
  sha256: string;
  head: string;
  tail: string;
  headBytes: number;
  tailBytes: number;
  omittedBytes: number;
  truncated: boolean;
  redactionTruncated: boolean;
  complete: boolean;
}

export interface ReadinessProcessLimitsV1 {
  timeoutMs: number;
  killGraceMs: number;
  closeGraceMs: number;
  headBytes: number;
  tailBytes: number;
}

interface ReadinessDiagnosticV1 {
  reasonCode: string;
  reason: string;
  provenance: string[];
  falsifier: string;
}

interface ReadinessToolchainV1 {
  executable: string;
  searchPath: string[];
  controller: { node: string; platform: string; arch: string };
  requestedVersion: string | null;
  observedVersion: { status: "observed"; version: string; provenance: string }
    | ({ status: "not-assessed" } & ReadinessDiagnosticV1);
}

interface ReadinessStageReceiptBaseV1 {
  schemaVersion: 1;
  stageId: StageId;
  kind: ReadinessStageV1["kind"];
  workspaceId: ReadinessStageV1["workspaceId"];
  prerequisiteStageIds: StageId[];
  requiredEnvNames: string[];
  environment: { approvedNames: string[]; presentNames: string[] };
  provenance: Provenance;
  authority: ReadinessAuthorityReceipt | null;
  command: { bin: string; args: string[]; plannedCwd: string; actualCwd: string | null; source: { kind: string; path: string; pointer?: string } } | null;
  toolchain: ReadinessToolchainV1 | null;
}

type ProcessExecution = { kind: "process"; limits: ReadinessProcessLimitsV1; process: ReadinessProcessEvidenceV1 };
type LifecycleExecution = { kind: "install-lifecycle"; fulfilledByStageId: StageId; startedAt: string; endedAt: string; durationMs: number };

export type StageReceiptV1 =
  | (ReadinessStageReceiptBaseV1 & { status: "passed"; execution: ProcessExecution | LifecycleExecution })
  | (ReadinessStageReceiptBaseV1 & { status: "failed"; execution: ProcessExecution | { kind: "unverified"; assessedAt: string }; diagnostic: ReadinessDiagnosticV1 })
  | (ReadinessStageReceiptBaseV1 & { status: "not-assessed"; execution: { kind: "not-run"; assessedAt: string }; diagnostic: ReadinessDiagnosticV1; blockedByStageIds: StageId[] });

export interface ReadinessExecutionV1 {
  schemaVersion: 1;
  kind: "harvey-audit-readiness-execution";
  planSha256: string;
  source: SourceSentinelV1;
  status: "passed" | "failed" | "not-assessed";
  stages: StageReceiptV1[];
  cleanup: DisposableCleanupReceipt;
}

type StageExpectationBase = Pick<ReadinessStageV1, "id" | "kind" | "workspaceId" | "prerequisiteStageIds" | "requiredEnvNames" | "safety" | "provenance"> & {
  /** Hash of retained execution configuration before redaction, excluding display prose. */
  configurationSha256: string;
};

/** Redacted evidence expectations, never an executable plan or an admission capability. */
export type ReadinessStageExpectationV1 = StageExpectationBase & (
  | { assessment: "planned"; command: NonNullable<StageReceiptV1["command"]> & { actualCwd: null } }
  | Pick<Extract<ReadinessStageV1, { assessment: "implicit" }>, "assessment" | "fulfilledByStageId" | "reason" | "falsifier">
  | Pick<Extract<ReadinessStageV1, { assessment: "absent" }>, "assessment" | "reasonCode" | "reason" | "falsifier">
  | Pick<Extract<ReadinessStageV1, { assessment: "not-assessed" }>, "assessment" | "reasonCode" | "reason" | "falsifier">
);

export interface ReadinessValidationProjectionV1 {
  originalPlanSha256: string;
  environment: { approvedNames: string[]; presentNames: string[] };
  /** Names/provenance are redacted; V1 identities and their paths are retained or export is withheld. */
  workspaces: ReadinessWorkspaceV1[];
  stages: ReadinessStageExpectationV1[];
  workspaceObservations: ReadinessPlanV1["workspaceInventory"]["observations"];
  applicationWorkspaceIds: ReadinessPlanV1["workspaceInventory"]["applicationWorkspaceIds"];
}

export interface ReadinessReceiptContext {
  /** Connect to B1 before admission; values live only in a private per-run registry. */
  readonly registerSecret: (value: string) => void;
  /** Connect directly to the bounded runner, before it retains stdout/stderr/error text. */
  readonly redact: (text: string, context?: SecretExcerptContext & { stream?: "stdout" | "stderr" | "error" }) => string;
}

interface ReceiptState {
  plan: ReadinessPlanV1;
  planSha256: string;
  registry: SecretRegistry;
  approvedNames: string[];
  presentNames: Set<string>;
  prepared: WeakMap<ReadinessSpawnRequest, StageId>;
}

const states = new WeakMap<ReadinessReceiptContext, ReceiptState>();
const SHA256 = /^[a-f0-9]{64}$/;
const EMPTY_SHA256 = createHash("sha256").digest("hex");
const PROCESS_STATES = ["exited", "timed-out", "aborted", "spawn-error", "io-error", "observer-error", "redaction-error", "descendant-cleanup", "termination-unconfirmed", "unsupported-platform", "containment-unavailable"];

function invalid(part: string): never { throw new Error(`Invalid readiness execution evidence: ${part}.`); }
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("object shape");
  const row = value as Record<string, unknown>;
  if (required.some((key) => !Object.hasOwn(row, key)) || Object.keys(row).some((key) => !required.includes(key) && !optional.includes(key))) invalid("object fields");
  return row;
}
function text(value: unknown): asserts value is string { if (typeof value !== "string" || value.trim() === "" || value.includes("\0")) invalid("text"); }
function integer(value: unknown, minimum = 0): asserts value is number { if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) invalid("integer"); }
function duration(value: unknown): asserts value is number { if (typeof value !== "number" || !Number.isFinite(value) || value < 0) invalid("duration"); }
function instant(value: unknown): asserts value is string { if (typeof value !== "string" || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) invalid("timestamp"); }
function flag(value: unknown): asserts value is boolean { if (typeof value !== "boolean") invalid("boolean"); }
function strings(value: unknown): asserts value is string[] {
  if (!Array.isArray(value)) invalid("text list");
  for (const item of value) text(item);
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b, "en")).map(([key, nested]) => [key, canonical(nested)]));
  return value;
}
function equal(a: unknown, b: unknown): boolean { return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b)); }
function immutable<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const nested of Object.values(value)) immutable(nested);
    Object.freeze(value);
  }
  return value;
}
function stateOf(context: ReadinessReceiptContext): ReceiptState {
  const state = states.get(context);
  if (!state) invalid("unknown receipt context");
  return state;
}
function stageOf(state: ReceiptState, stageId: StageId): ReadinessStageV1 {
  const stage = state.plan.stages.find((row) => row.id === stageId);
  if (!stage) invalid("unplanned stage identity");
  return stage;
}

function assertPublicIdentities(state: ReceiptState, additional: readonly string[] = []): void {
  const { plan } = state;
  const identities = [
    ...additional,
    ...state.approvedNames, ...state.presentNames,
    plan.workspaceInventory.repoRootId,
    ...plan.workspaceInventory.packages.flatMap((workspace) => [workspace.id, workspace.dir, workspace.manifestPath]),
    ...plan.workspaceInventory.applicationWorkspaceIds,
    ...plan.workspaceInventory.observations.flatMap((observation) => [
      observation.kind, ...("path" in observation ? [observation.path] : []),
      ...("glob" in observation ? [observation.glob, observation.sourcePath] : []),
      ...(observation.kind === "excluded" ? [observation.reason] : []),
    ]),
    ...plan.workspaces.flatMap((workspace) => [workspace.id, workspace.dir, workspace.manifestPath, workspace.installStageId, ...workspace.stageIds]),
    ...plan.stages.flatMap((stage) => [stage.id, stage.workspaceId, ...stage.prerequisiteStageIds, ...stage.requiredEnvNames, ...(stage.assessment === "implicit" ? [stage.fulfilledByStageId] : [])]),
  ];
  // V1 embeds source-controlled paths in identities. Redaction would break their binding;
  // even short-value collisions must fail closed instead of exempting the identity text.
  if (identities.some((value) => state.registry.redact(value) !== value)) invalid("producer-known value in identity");
}

/** The context itself is safe to stringify: no plan text, approved value, or environment is enumerable. */
export function createReadinessReceiptContext(planInput: unknown, options: {
  approvedEnvNames: readonly string[];
  environment: Readonly<Record<string, string | undefined>>;
}): ReadinessReceiptContext {
  const plan = immutable(validateReadinessPlanV1(structuredClone(planInput)));
  const approvedNames = [...new Set(options.approvedEnvNames)].sort();
  if (approvedNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name))) invalid("approved environment names");
  const registry = new SecretRegistry({ includeShortValues: true });
  const presentNames = new Set<string>();
  for (const name of approvedNames) {
    const value = Object.hasOwn(options.environment, name) ? options.environment[name] : undefined;
    if (value === undefined || value === "") continue;
    if (typeof value !== "string" || value.includes("\0")) invalid("approved environment value");
    registry.register(value);
    presentNames.add(name);
  }
  const context: ReadinessReceiptContext = Object.freeze({
    registerSecret: (value: string) => { registry.register(value); },
    redact: (value: string, excerpt?: SecretExcerptContext) => registry.redact(value, excerpt ?? "whole"),
  });
  states.set(context, { plan, planSha256: createHash("sha256").update(serializeReadinessPlanV1(plan)).digest("hex"), registry, approvedNames, presentNames, prepared: new WeakMap() });
  return context;
}

/** Call immediately before run(request, ...); request.env is deliberately non-enumerable in B1. */
export function prepareReadinessSpawn(context: ReadinessReceiptContext, admission: Admitted): ReadinessSpawnRequest {
  const state = stateOf(context);
  const stage = stageOf(state, admission.stageId);
  if (admission.status !== "admitted" || admission.authority.stageId !== stage.id || admission.authority.decision !== "allowed"
    || !equal([...admission.authority.approvedEnvNames].sort(), state.approvedNames) || stage.assessment !== "planned") invalid("admission");
  const request = admission.request;
  if (request.shell !== false || request.bin !== stage.command.bin || !equal(request.args, stage.command.args)
    || !isAbsolute(request.cwd) || !Object.isFrozen(request) || !Object.isFrozen(request.env)) invalid("spawn request binding");
  for (const name of admission.authority.approvedEnvNames) {
    const value = Object.hasOwn(request.env, name) ? request.env[name] : undefined;
    if (value !== undefined && value !== "") { state.registry.register(value); state.presentNames.add(name); }
  }
  state.registry.assertArgvClean("readiness execution", [request.bin, ...request.args]);
  state.prepared.set(request, stage.id);
  return request;
}

function safeProvenance(state: ReceiptState, provenance: Provenance): Provenance {
  return provenance.map((row) => ({
    kind: row.kind, path: state.registry.redact(row.path), detail: state.registry.redact(row.detail),
    ...(row.pointer === undefined ? {} : { pointer: state.registry.redact(row.pointer) }),
    ...(row.rawScript === undefined ? {} : { rawScript: state.registry.redact(row.rawScript) }),
  }));
}
function safeAuthority(state: ReceiptState, input: ReadinessAuthorityReceipt | null): ReadinessAuthorityReceipt | null {
  if (input === null) return null;
  validateAuthority(input);
  assertPublicIdentities(state, [input.stageId, ...input.requiredEnvNames, ...input.approvedEnvNames]);
  return {
    stageId: input.stageId, decision: input.decision, effect: input.effect,
    source: state.registry.redact(input.source), reasonCode: state.registry.redact(input.reasonCode),
    reason: state.registry.redact(input.reason), falsifier: state.registry.redact(input.falsifier),
    requiredEnvNames: [...input.requiredEnvNames], approvedEnvNames: [...input.approvedEnvNames],
    lifecycle: input.lifecycle.map((row) => ({ path: state.registry.redact(row.path), pointer: state.registry.redact(row.pointer) })),
  };
}
function diagnostic(state: ReceiptState, input: ReadinessDiagnosticV1): ReadinessDiagnosticV1 {
  validateDiagnostic(input);
  return { reasonCode: state.registry.redact(input.reasonCode), reason: state.registry.redact(input.reason), provenance: input.provenance.map((row) => state.registry.redact(row)), falsifier: state.registry.redact(input.falsifier) };
}
function base(state: ReceiptState, stage: ReadinessStageV1, authority: ReadinessAuthorityReceipt | null, request?: ReadinessSpawnRequest): ReadinessStageReceiptBaseV1 {
  assertPublicIdentities(state);
  return {
    schemaVersion: 1, stageId: stage.id, kind: stage.kind, workspaceId: stage.workspaceId,
    prerequisiteStageIds: [...stage.prerequisiteStageIds], requiredEnvNames: [...stage.requiredEnvNames],
    environment: { approvedNames: [...state.approvedNames], presentNames: [...state.presentNames].sort() },
    provenance: safeProvenance(state, stage.provenance), authority: safeAuthority(state, authority),
    command: stage.assessment === "planned" ? {
      bin: state.registry.redact(stage.command.bin), args: stage.command.args.map((arg) => state.registry.redact(arg)),
      plannedCwd: state.registry.redact(stage.command.cwd), actualCwd: request ? state.registry.redact(request.cwd) : null,
      source: { kind: stage.command.source.kind, path: state.registry.redact(stage.command.source.path), ...(stage.command.source.pointer === undefined ? {} : { pointer: state.registry.redact(stage.command.source.pointer) }) },
    } : null,
    toolchain: request ? {
      executable: state.registry.redact(request.bin), searchPath: (request.env.PATH ?? "").split(delimiter).filter(Boolean).map((path) => state.registry.redact(path)),
      controller: { node: process.version, platform: process.platform, arch: process.arch },
      requestedVersion: state.plan.packageManager.status === "selected" ? state.plan.packageManager.requestedVersion ?? null : null,
      observedVersion: { status: "not-assessed", reasonCode: "version-not-probed", reason: "A package-manager version probe was not executed; the requested version is a declaration only.", provenance: ["admitted executable and toolchain PATH"], falsifier: "Retain a separately authorized version-probe observation for this same toolchain." },
    } : null,
  };
}

/** Fingerprint only configuration retained by the plan; source files not retained there are not inferred. */
export function readinessStageConfigurationSha256(plan: ReadinessPlanV1, stage: ReadinessStageV1): string {
  const manager = plan.packageManager;
  const configuration = {
    assessment: stage.assessment, safety: stage.safety,
    prerequisiteStageIds: [...stage.prerequisiteStageIds].sort(), requiredEnvNames: [...stage.requiredEnvNames].sort(),
    command: stage.assessment === "planned" ? stage.command : null,
    fulfilledByStageId: stage.assessment === "implicit" ? stage.fulfilledByStageId : null,
    packageManager: manager.status === "selected" ? { status: manager.status, manager: manager.manager, requestedVersion: manager.requestedVersion ?? null } : { status: manager.status },
    sources: stage.provenance.map((row) => ({
      kind: row.kind, path: row.path, pointer: row.pointer ?? null, rawScript: row.rawScript ?? null,
    })).sort((a, b) => JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b)), "en")),
  };
  return createHash("sha256").update(JSON.stringify(canonical(configuration))).digest("hex");
}

function stageExpectation(state: ReceiptState, stage: ReadinessStageV1): ReadinessStageExpectationV1 {
  const common: StageExpectationBase = {
    id: stage.id, kind: stage.kind, workspaceId: stage.workspaceId, safety: stage.safety,
    prerequisiteStageIds: [...stage.prerequisiteStageIds], requiredEnvNames: [...stage.requiredEnvNames],
    provenance: safeProvenance(state, stage.provenance), configurationSha256: readinessStageConfigurationSha256(state.plan, stage),
  };
  if (stage.assessment === "planned") {
    const command = base(state, stage, null).command;
    if (!command) invalid("missing planned command expectation");
    return { ...common, assessment: "planned", command: { ...command, actualCwd: null } };
  }
  const explanation = { reason: state.registry.redact(stage.reason), falsifier: state.registry.redact(stage.falsifier) };
  if (stage.assessment === "implicit") return { ...common, ...explanation, assessment: stage.assessment, fulfilledByStageId: stage.fulfilledByStageId };
  return { ...common, ...explanation, assessment: stage.assessment, reasonCode: stage.reasonCode } as ReadinessStageExpectationV1;
}

type ExecutionExpectations = Pick<ReadinessValidationProjectionV1, "originalPlanSha256" | "environment" | "stages">;

function executionExpectations(state: ReceiptState): ExecutionExpectations {
  return {
    originalPlanSha256: state.planSha256,
    environment: { approvedNames: [...state.approvedNames], presentNames: [...state.presentNames].sort() },
    stages: state.plan.stages.map((stage) => stageExpectation(state, stage)),
  };
}

/** Snapshot only after execution and secret registration settle. Nothing in this view authorizes work. */
export function createReadinessValidationProjectionV1(context: ReadinessReceiptContext): ReadinessValidationProjectionV1 {
  const state = stateOf(context);
  assertPublicIdentities(state);
  const redact = (value: string): string => state.registry.redact(value);
  const expectations = executionExpectations(state);
  return immutable({
    ...expectations,
    stages: expectations.stages.sort((a, b) => a.id.localeCompare(b.id, "en")),
    workspaces: state.plan.workspaces.map((workspace) => ({
      id: workspace.id, dir: redact(workspace.dir), manifestPath: redact(workspace.manifestPath),
      ...(workspace.name === undefined ? {} : { name: redact(workspace.name) }),
      installStageId: workspace.installStageId, stageIds: [...workspace.stageIds].sort(),
      provenance: safeProvenance(state, workspace.provenance),
    })).sort((a, b) => a.id.localeCompare(b.id, "en")),
    workspaceObservations: state.plan.workspaceInventory.observations.map((observation) => {
      if (observation.kind === "excluded") return { ...observation };
      return { ...observation, reason: redact(observation.reason) };
    }),
    applicationWorkspaceIds: [...state.plan.workspaceInventory.applicationWorkspaceIds].sort(),
  });
}

/** Raw executable-plan exports remain V1 or are withheld; redacted plans cannot be re-admitted. */
export function prepareReadinessPlanExportV1(context: ReadinessReceiptContext):
  | { status: "ready"; json: string }
  | ({ status: "withheld" } & ReadinessDiagnosticV1) {
  const state = stateOf(context);
  const unsafe = (value: unknown): boolean => {
    if (typeof value === "string") return state.registry.redact(value) !== value;
    if (value && typeof value === "object") return Object.values(value).some(unsafe);
    return false;
  };
  if (unsafe(state.plan)) return {
    status: "withheld", reasonCode: "approved-value-in-plan",
    reason: "The raw executable plan cannot be exported because it contains a producer-known value. A redacted validation descriptor is available only when its identities contain no known values.",
    provenance: ["producer receipt registry and original readiness plan"],
    falsifier: "Remove the known value from the source plan and rediscover it before requesting a raw plan export.",
  };
  return { status: "ready", json: serializeReadinessPlanV1(state.plan) + "\n" };
}

export function createReadinessProcessReceipt(context: ReadinessReceiptContext, admission: Admitted, result: ReadinessProcessEvidenceV1, limits: ReadinessProcessLimitsV1): StageReceiptV1 {
  const state = stateOf(context);
  const stage = stageOf(state, admission.stageId);
  if (state.prepared.get(admission.request) !== stage.id) invalid("unprepared process request");
  validateLimits(limits);
  validateProcess(result, limits);
  const processEvidence = sanitizeProcess(state, result, limits);
  const execution: ProcessExecution = { kind: "process", limits: { ...limits }, process: processEvidence };
  const common = base(state, stage, admission.authority, admission.request);
  if (cleanProcess(processEvidence)) return immutable({ ...common, status: "passed", execution });
  const reasonCode = processEvidence.stdout.truncated || processEvidence.stderr.truncated || processEvidence.stdout.redactionTruncated || processEvidence.stderr.redactionTruncated
    ? "output-truncated" : successfulLifecycle(processEvidence) && !containedWork(processEvidence.containment)
      ? "containment-unproven" : result.state === "exited" ? "process-failed" : result.state;
  return immutable({
    ...common, status: "failed", execution,
    diagnostic: diagnostic(state, {
      reasonCode, reason: `The stage did not produce complete successful process evidence (${reasonCode}).`,
      provenance: [`bounded process observation for ${stage.id}`, ...result.errors.map((error) => `${error.phase}: ${error.code}`)],
      falsifier: "Rerun the authorized stage with verified private-namespace containment; retain actual target spawn, exit 0, close 0, complete bounded streams, matching unprivileged target identity, terminal namespace evidence, and confirmed owned-container removal.",
    }),
  });
}

export function createReadinessNotAssessedReceipt(context: ReadinessReceiptContext, stageId: StageId, input: ReadinessDiagnosticV1 & {
  authority?: ReadinessAuthorityReceipt | null;
  blockedByStageIds?: readonly StageId[];
  assessedAt?: string;
}): StageReceiptV1 {
  const state = stateOf(context);
  const stage = stageOf(state, stageId);
  const assessedAt = input.assessedAt ?? new Date().toISOString();
  instant(assessedAt);
  const blockedByStageIds = [...new Set(input.blockedByStageIds ?? [])].sort();
  if (blockedByStageIds.some((id) => !stage.prerequisiteStageIds.includes(id))) invalid("blocked prerequisite identity");
  return immutable({
    ...base(state, stage, input.authority ?? null), status: "not-assessed", execution: { kind: "not-run", assessedAt },
    diagnostic: diagnostic(state, { reasonCode: input.reasonCode, reason: input.reason, provenance: [...input.provenance], falsifier: input.falsifier }), blockedByStageIds,
  });
}

/** An adapter failure may have started work; missing lifecycle evidence is a failure, never a skip. */
export function createReadinessFailureReceipt(context: ReadinessReceiptContext, stageId: StageId, input: ReadinessDiagnosticV1 & {
  authority?: ReadinessAuthorityReceipt | null;
  assessedAt?: string;
}): StageReceiptV1 {
  const state = stateOf(context);
  const stage = stageOf(state, stageId);
  if (stage.assessment !== "planned") invalid("unverified execution for unplanned stage");
  const assessedAt = input.assessedAt ?? new Date().toISOString();
  instant(assessedAt);
  return immutable({
    ...base(state, stage, input.authority ?? null), status: "failed", execution: { kind: "unverified", assessedAt },
    diagnostic: diagnostic(state, { reasonCode: input.reasonCode, reason: input.reason, provenance: [...input.provenance], falsifier: input.falsifier }),
  });
}

/** A lifecycle observation points at the one actual install; it never invents a second spawn/exit. */
export function createReadinessImplicitReceipt(context: ReadinessReceiptContext, stageId: StageId, fulfilledBy: StageReceiptV1): StageReceiptV1 {
  const state = stateOf(context);
  const stage = stageOf(state, stageId);
  validateStage(executionExpectations(state), fulfilledBy);
  if (stage.assessment !== "implicit" || stage.fulfilledByStageId !== fulfilledBy.stageId || fulfilledBy.kind !== "install"
    || fulfilledBy.status !== "passed" || fulfilledBy.execution.kind !== "process") invalid("install lifecycle evidence");
  return immutable({
    ...base(state, stage, null), toolchain: structuredClone(fulfilledBy.toolchain), status: "passed",
    execution: { kind: "install-lifecycle", fulfilledByStageId: fulfilledBy.stageId, startedAt: fulfilledBy.execution.process.startedAt, endedAt: fulfilledBy.execution.process.endedAt, durationMs: fulfilledBy.execution.process.durationMs },
  });
}

function validateDiagnostic(value: unknown): void {
  const row = object(value, ["reasonCode", "reason", "provenance", "falsifier"]);
  text(row.reasonCode); text(row.reason); strings(row.provenance); text(row.falsifier);
  if (row.provenance.length === 0) invalid("missing diagnostic provenance");
}
function validateAuthority(value: unknown): void {
  const row = object(value, ["stageId", "decision", "effect", "source", "reasonCode", "reason", "falsifier", "requiredEnvNames", "approvedEnvNames", "lifecycle"]);
  text(row.stageId); text(row.source); text(row.reasonCode); text(row.reason); text(row.falsifier);
  strings(row.requiredEnvNames); strings(row.approvedEnvNames);
  if (!["allowed", "denied"].includes(row.decision as string) || !["disposable-local", "target-install", "network-or-service", "unknown"].includes(row.effect as string) || !Array.isArray(row.lifecycle)) invalid("authority decision");
  for (const item of row.lifecycle) { const source = object(item, ["path", "pointer"]); text(source.path); text(source.pointer); }
}
function validateLimits(value: unknown): asserts value is ReadinessProcessLimitsV1 {
  const row = object(value, ["timeoutMs", "killGraceMs", "closeGraceMs", "headBytes", "tailBytes"]);
  integer(row.timeoutMs, 1); integer(row.killGraceMs, 1); integer(row.closeGraceMs, 1); integer(row.headBytes, 1); integer(row.tailBytes, 1);
  if (row.timeoutMs > 2_147_483_647 || row.killGraceMs > 60_000 || row.closeGraceMs > 60_000 || row.headBytes > 1024 * 1024 || row.tailBytes > 1024 * 1024) invalid("process limits");
}
function validateStream(value: unknown, limits: ReadinessProcessLimitsV1): void {
  const row = object(value, ["bytes", "sha256", "head", "tail", "headBytes", "tailBytes", "omittedBytes", "truncated", "redactionTruncated", "complete"]);
  integer(row.bytes); integer(row.headBytes); integer(row.tailBytes); integer(row.omittedBytes);
  flag(row.truncated); flag(row.redactionTruncated); flag(row.complete);
  if (typeof row.sha256 !== "string" || !SHA256.test(row.sha256) || typeof row.head !== "string" || typeof row.tail !== "string"
    || row.headBytes > limits.headBytes || row.tailBytes > limits.tailBytes
    || row.bytes !== row.headBytes + row.tailBytes + row.omittedBytes || row.truncated !== (row.omittedBytes > 0)
    || Buffer.byteLength(row.head) > limits.headBytes || Buffer.byteLength(row.tail) > limits.tailBytes
    || (row.bytes === 0 && (row.sha256 !== EMPTY_SHA256 || row.head !== "" || row.tail !== ""))) invalid("stream conservation/bounds");
}
function validateProcess(value: unknown, limits: ReadinessProcessLimitsV1): asserts value is ReadinessProcessEvidenceV1 {
  const row = object(value, ["state", "containment", "succeeded", "pid", "queuedAt", "startedAt", "spawnedAt", "firstByteAt", "endedAt", "queueDurationMs", "durationMs", "fromFirstByteMs", "exit", "close", "errors", "termination", "stdout", "stderr"]);
  if (!PROCESS_STATES.includes(row.state as string)) invalid("process state");
  flag(row.succeeded); if (row.pid !== null) integer(row.pid, 1);
  instant(row.queuedAt); instant(row.startedAt); instant(row.endedAt); duration(row.queueDurationMs); duration(row.durationMs);
  if (Date.parse(row.queuedAt) > Date.parse(row.startedAt) || Date.parse(row.startedAt) > Date.parse(row.endedAt)) invalid("process time ordering");
  for (const name of ["spawnedAt", "firstByteAt"] as const) {
    if (row[name] !== null) { instant(row[name]); if (Date.parse(row[name]) < Date.parse(row.startedAt) || Date.parse(row[name]) > Date.parse(row.endedAt)) invalid("process observation time"); }
  }
  if ((row.pid === null) !== (row.spawnedAt === null)) invalid("spawn observation");
  if (row.fromFirstByteMs !== null) duration(row.fromFirstByteMs);
  if ((row.fromFirstByteMs === null) !== (row.firstByteAt === null)) invalid("first byte duration");
  for (const name of ["exit", "close"] as const) {
    if (row[name] === null) continue;
    const observation = object(row[name], ["at", "code", "signal"]);
    instant(observation.at); if (observation.code !== null) integer(observation.code, Number.MIN_SAFE_INTEGER);
    if (observation.signal !== null && (typeof observation.signal !== "string" || !Object.hasOwn(osConstants.signals, observation.signal))) invalid("process signal");
    if (Date.parse(observation.at) < Date.parse(row.startedAt) || Date.parse(observation.at) > Date.parse(row.endedAt)) invalid("exit/close time");
  }
  if (!Array.isArray(row.errors)) invalid("process errors");
  for (const item of row.errors) {
    const error = object(item, ["phase", "code"]); text(error.code);
    if (!["spawn", "stdout", "stderr", "observer", "redaction", "termination"].includes(error.phase as string)) invalid("process error phase");
  }
  const termination = object(row.termination, ["reason", "attempts", "tree", "stdioForcedClosed"]);
  if (termination.reason !== null && !["timeout", "abort", "process-error", "io-error", "observer-error", "descendants"].includes(termination.reason as string)) invalid("termination reason");
  if (!["not-started", "absent", "unconfirmed"].includes(termination.tree as string) || !Array.isArray(termination.attempts)) invalid("process tree evidence");
  flag(termination.stdioForcedClosed);
  for (const item of termination.attempts) {
    const attempt = object(item, ["at", "signal", "status", "code"]); instant(attempt.at); if (attempt.code !== null) text(attempt.code);
    if (!["SIGTERM", "SIGKILL"].includes(attempt.signal as string) || !["sent", "absent", "failed"].includes(attempt.status as string)) invalid("termination attempt");
  }
  validateStream(row.stdout, limits); validateStream(row.stderr, limits);
  const process = value as ReadinessProcessEvidenceV1;
  if (process.stdout.bytes + process.stderr.bytes > 0 && process.firstByteAt === null) invalid("missing first byte observation");
  validateContainment(process);
  if (process.succeeded && !successfulLifecycle(process)) invalid("inconsistent successful process");
  if (process.containment.kind === "docker-pid-namespace" && process.succeeded !== (successfulLifecycle(process) && containedWork(process.containment))) invalid("inconsistent contained process success");
}

function validateContainment(process: ReadinessProcessEvidenceV1): void {
  const value = process.containment;
  const kind = (value as ReadinessProcessContainment | null)?.kind;
  if (kind === "native-process-group") {
    const row = object(value, ["kind", "descendantOwnership", "groupObservation"]);
    if (row.descendantOwnership !== "unproven" || row.groupObservation !== process.termination.tree || process.state === "containment-unavailable") invalid("native containment scope");
    return;
  }
  if (kind === "unavailable") {
    const row = object(value, ["kind", "reasonCode"]); text(row.reasonCode);
    if (!["containment-unavailable", "aborted"].includes(process.state) || process.succeeded || process.pid !== null || process.spawnedAt !== null
      || process.exit !== null || process.close !== null || process.firstByteAt !== null || process.termination.tree !== "not-started"
      || process.termination.attempts.length !== 0 || process.termination.stdioForcedClosed
      || process.termination.reason !== (process.state === "aborted" ? "abort" : null)
      || [process.stdout, process.stderr].some((stream) => stream.bytes !== 0 || stream.complete)) invalid("unavailable containment has execution facts");
    return;
  }
  if (kind !== "docker-pid-namespace") invalid("containment kind");
  const row = object(value, ["kind", "imageId", "containerId", "leaseName", "runtimeVersion", "apiVersion", "namespace", "targetWork", "terminalObservation", "metadata", "cleanup", "isolationVerified", "isolation", "targetIdentity", "observerNodeVersion"]);
  if (typeof row.imageId !== "string" || !/^sha256:[a-f0-9]{64}$/.test(row.imageId)
    || (row.containerId !== null && (typeof row.containerId !== "string" || !SHA256.test(row.containerId)))
    || (row.leaseName !== null && (typeof row.leaseName !== "string" || !/^harvey-readiness-[a-f0-9]{32}$/.test(row.leaseName)))) invalid("containment identity");
  text(row.runtimeVersion); text(row.apiVersion);
  if (!/^\d+\.\d+$/.test(row.apiVersion) || Number(row.apiVersion) < 1.44) invalid("containment API version");
  flag(row.isolationVerified);
  if (!["not-started", "terminated", "unconfirmed"].includes(row.namespace as string) || !["not-started", "begun", "unknown"].includes(row.targetWork as string)
    || !["verified", "unavailable"].includes(row.metadata as string) || !["not-required", "removed", "retained"].includes(row.cleanup as string)) invalid("containment observations");
  const isolation = object(row.isolation, ["privatePidNamespace", "network", "noNewPrivileges", "capDrop", "observerCapabilities", "targetUid", "targetGid", "mountScope", "rootfs"]);
  integer(isolation.targetUid); integer(isolation.targetGid);
  if (isolation.privatePidNamespace !== true || isolation.network !== "none" || isolation.noNewPrivileges !== true || isolation.capDrop !== "ALL"
    || !equal(isolation.observerCapabilities, ["SETUID", "SETGID"]) || isolation.mountScope !== "disposable-root-only" || isolation.rootfs !== "private-writable-overlay") invalid("containment hardening");
  if (row.terminalObservation !== null) {
    const terminal = object(row.terminalObservation, ["at", "running", "pid"]); instant(terminal.at);
    const at = Date.parse(terminal.at);
    if (terminal.running !== false || terminal.pid !== 0 || at < Date.parse(process.startedAt) || at > Date.parse(process.endedAt)
      || [process.spawnedAt, process.exit?.at, process.close?.at].some((time) => time != null && Date.parse(time) > at)) invalid("terminal namespace observation");
  }
  if (row.observerNodeVersion !== null && (typeof row.observerNodeVersion !== "string" || !/^v\d+\.\d+\.\d+$/.test(row.observerNodeVersion))) invalid("observer Node version");
  if (row.targetIdentity !== null) {
    const identity = object(row.targetIdentity, ["uid", "gid", "capEff", "noNewPrivileges"]); integer(identity.uid); integer(identity.gid);
    if (identity.uid !== isolation.targetUid || identity.gid !== isolation.targetGid || identity.capEff !== "0000000000000000" || identity.noNewPrivileges !== true
      || row.metadata !== "verified" || row.targetWork !== "begun") invalid("contained target identity");
  }
  if (process.pid !== null) integer(process.pid, 2);
  if (row.namespace === "unconfirmed" && (row.terminalObservation !== null || row.cleanup !== "retained" || process.termination.tree !== "unconfirmed")) invalid("unconfirmed namespace evidence");
  if (row.namespace === "terminated" && (row.terminalObservation === null || row.containerId === null || process.termination.tree !== "absent" || row.cleanup === "not-required")) invalid("terminated namespace evidence");
  if (row.namespace === "not-started" && (row.targetWork !== "not-started" || process.termination.tree !== "not-started" || row.metadata !== "unavailable")) invalid("unstarted namespace evidence");
  if (row.cleanup === "removed" && (row.containerId === null || row.leaseName === null || row.terminalObservation === null)) invalid("owned container removal evidence");
  if (row.cleanup === "not-required" && (row.containerId !== null || row.namespace !== "not-started" || row.terminalObservation !== null)) invalid("unrequired container cleanup");
  if (row.metadata === "unavailable") {
    if (row.targetIdentity !== null || row.observerNodeVersion !== null || process.pid !== null || process.spawnedAt !== null || process.exit !== null || process.close !== null
      || row.targetWork === "begun") invalid("unverified target metadata");
  } else if (row.namespace !== "terminated" || row.isolationVerified !== true || row.observerNodeVersion === null
    || row.targetWork !== (process.pid === null ? "not-started" : "begun")) invalid("verified target metadata");
  if (process.state === "containment-unavailable" && (process.pid !== null || process.exit !== null || process.close !== null || row.targetWork !== "not-started")) invalid("unavailable target lifecycle");
}

/** Generic adapter success describes only the lifecycle that the adapter actually observed. */
function successfulLifecycle(process: ReadinessProcessEvidenceV1): boolean {
  return process.state === "exited" && process.pid !== null && process.spawnedAt !== null
    && process.exit?.code === 0 && process.exit.signal === null && process.close?.code === 0 && process.close.signal === null
    && Date.parse(process.spawnedAt) <= Date.parse(process.exit.at) && Date.parse(process.exit.at) <= Date.parse(process.close.at)
    && process.errors.length === 0 && process.termination.reason === null && process.termination.attempts.length === 0
    && process.termination.tree === "absent" && !process.termination.stdioForcedClosed
    && [process.stdout, process.stderr].every((stream) => stream.complete && !stream.truncated && !stream.redactionTruncated);
}

function containedWork(containment: ReadinessProcessContainment): boolean {
  return containment.kind === "docker-pid-namespace" && containment.containerId !== null && containment.leaseName !== null
    && containment.isolationVerified && containment.namespace === "terminated" && containment.terminalObservation !== null
    && containment.targetWork === "begun" && containment.metadata === "verified" && containment.cleanup === "removed"
    && containment.targetIdentity !== null && containment.isolation.targetUid > 0 && containment.isolation.targetGid > 0;
}

function cleanProcess(process: ReadinessProcessEvidenceV1): boolean {
  return process.succeeded && successfulLifecycle(process) && containedWork(process.containment);
}

function assertContainmentIdentities(state: ReceiptState, containment: ReadinessProcessContainment): void {
  if (containment.kind !== "docker-pid-namespace") return;
  const stringsIn = (value: unknown): string[] => typeof value === "string" ? [value]
    : value && typeof value === "object" ? Object.values(value).flatMap(stringsIn) : [];
  assertPublicIdentities(state, stringsIn(containment));
}

function clipUtf8(value: string, limit: number, tail: boolean): string {
  const characters = [...value];
  if (tail) characters.reverse();
  const retained: string[] = [];
  let bytes = 0;
  for (const character of characters) {
    bytes += Buffer.byteLength(character);
    if (bytes > limit) break;
    retained.push(character);
  }
  return (tail ? retained.reverse() : retained).join("");
}
function sanitizeProcess(state: ReceiptState, input: ReadinessProcessEvidenceV1, limits: ReadinessProcessLimitsV1): ReadinessProcessEvidenceV1 {
  const copy = structuredClone(input);
  assertContainmentIdentities(state, copy.containment);
  if (copy.containment.kind === "unavailable") copy.containment.reasonCode = state.registry.redact(copy.containment.reasonCode);
  for (const stream of [copy.stdout, copy.stderr]) {
    const head = state.registry.redact(stream.head, "head");
    const tail = state.registry.redact(stream.tail, "tail");
    stream.head = clipUtf8(head, limits.headBytes, false);
    stream.tail = clipUtf8(tail, limits.tailBytes, true);
    stream.redactionTruncated ||= stream.head !== head || stream.tail !== tail;
  }
  copy.succeeded &&= [copy.stdout, copy.stderr].every((stream) => !stream.redactionTruncated);
  copy.errors = copy.errors.map((error) => ({ phase: error.phase, code: state.registry.redact(error.code) }));
  copy.termination.attempts = copy.termination.attempts.map((attempt) => ({ ...attempt, code: attempt.code === null ? null : state.registry.redact(attempt.code) }));
  return copy;
}
function validateToolchain(value: unknown): void {
  const row = object(value, ["executable", "searchPath", "controller", "requestedVersion", "observedVersion"]);
  text(row.executable); strings(row.searchPath);
  const controller = object(row.controller, ["node", "platform", "arch"]); text(controller.node); text(controller.platform); text(controller.arch);
  if (row.requestedVersion !== null) text(row.requestedVersion);
  const version = row.observedVersion as Record<string, unknown>;
  if (version?.status === "observed") { object(version, ["status", "version", "provenance"]); text(version.version); text(version.provenance); }
  else {
    object(version, ["status", "reasonCode", "reason", "provenance", "falsifier"]);
    if (version.status !== "not-assessed") invalid("toolchain version");
    validateDiagnostic({ reasonCode: version.reasonCode, reason: version.reason, provenance: version.provenance, falsifier: version.falsifier });
  }
}
function validateStage(expected: ExecutionExpectations, value: unknown): asserts value is StageReceiptV1 {
  const row = value as Record<string, unknown>;
  const common = ["schemaVersion", "stageId", "kind", "workspaceId", "prerequisiteStageIds", "requiredEnvNames", "environment", "provenance", "authority", "command", "toolchain", "status", "execution"];
  object(value, [...common, ...(row?.status === "failed" ? ["diagnostic"] : row?.status === "not-assessed" ? ["diagnostic", "blockedByStageIds"] : [])]);
  if (row.schemaVersion !== 1 || !["passed", "failed", "not-assessed"].includes(row.status as string)) invalid("stage receipt version/status");
  const stage = expected.stages.find((candidate) => candidate.id === row.stageId);
  if (!stage) invalid("unplanned stage identity");
  if (row.kind !== stage.kind || row.workspaceId !== stage.workspaceId || !equal(row.prerequisiteStageIds, stage.prerequisiteStageIds)
    || !equal(row.requiredEnvNames, stage.requiredEnvNames) || !equal(row.provenance, stage.provenance)) invalid("stage plan binding");
  const environment = object(row.environment, ["approvedNames", "presentNames"]);
  strings(environment.approvedNames); strings(environment.presentNames);
  if (!equal(environment.approvedNames, expected.environment.approvedNames) || !equal(environment.presentNames, expected.environment.presentNames)) invalid("environment names");
  if (row.authority !== null) {
    validateAuthority(row.authority);
    const authority = row.authority as ReadinessAuthorityReceipt;
    if (authority.stageId !== stage.id || !equal([...authority.approvedEnvNames].sort(), expected.environment.approvedNames)) invalid("authority stage binding");
  }
  if (stage.assessment === "planned") {
    const command = object(row.command, ["bin", "args", "plannedCwd", "actualCwd", "source"]);
    if (!equal({ ...command, actualCwd: null }, stage.command) || (command.actualCwd !== null && (typeof command.actualCwd !== "string" || !isAbsolute(command.actualCwd)))) invalid("planned command binding");
  } else if (row.command !== null) invalid("unplanned command");
  if (row.toolchain !== null) validateToolchain(row.toolchain);
  const execution = row.execution as Record<string, unknown>;
  if (row.status === "not-assessed") {
    object(execution, ["kind", "assessedAt"]); instant(execution.assessedAt); validateDiagnostic(row.diagnostic); strings(row.blockedByStageIds);
    if (execution.kind !== "not-run" || row.toolchain !== null || (row.command !== null && (row.command as { actualCwd: unknown }).actualCwd !== null)
      || !equal(row.blockedByStageIds, [...new Set(row.blockedByStageIds)].sort()) || row.blockedByStageIds.some((id) => !stage.prerequisiteStageIds.includes(id as StageId))) invalid("withheld stage evidence");
    return;
  }
  if (execution?.kind === "unverified") {
    object(execution, ["kind", "assessedAt"]); instant(execution.assessedAt); validateDiagnostic(row.diagnostic);
    if (row.status !== "failed" || stage.assessment !== "planned" || row.toolchain !== null || (row.command as { actualCwd: unknown }).actualCwd !== null) invalid("unverified failure evidence");
    return;
  }
  if (execution?.kind === "install-lifecycle") {
    object(execution, ["kind", "fulfilledByStageId", "startedAt", "endedAt", "durationMs"]);
    instant(execution.startedAt); instant(execution.endedAt); duration(execution.durationMs);
    if (row.status !== "passed" || stage.assessment !== "implicit" || execution.fulfilledByStageId !== stage.fulfilledByStageId || row.authority !== null || row.toolchain === null) invalid("lifecycle stage binding");
    return;
  }
  object(execution, ["kind", "limits", "process"]);
  validateLimits(execution.limits); validateProcess(execution.process, execution.limits);
  const authority = row.authority as ReadinessAuthorityReceipt | null;
  if (execution.kind !== "process" || stage.assessment !== "planned" || authority?.decision !== "allowed" || row.toolchain === null
    || (row.command as { actualCwd: unknown }).actualCwd === null) invalid("process stage binding");
  if (row.status === "passed" ? !cleanProcess(execution.process) : cleanProcess(execution.process)) invalid("process status mismatch");
  if (row.status === "failed") validateDiagnostic(row.diagnostic);
}

function validateSource(value: unknown): asserts value is SourceSentinelV1 {
  const row = object(value, ["schemaVersion", "sourceRoot", "contentSha256", "entries", "bytes", "git"]);
  if (row.schemaVersion !== 1 || typeof row.sourceRoot !== "string" || !isAbsolute(row.sourceRoot) || typeof row.contentSha256 !== "string" || !SHA256.test(row.contentSha256)) invalid("source sentinel");
  integer(row.entries, 1); integer(row.bytes);
  const git = row.git as Record<string, unknown>;
  if (git?.status === "present") {
    object(git, ["status", "head", "statusSha256"]);
    if ((git.head !== null && (typeof git.head !== "string" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(git.head))) || typeof git.statusSha256 !== "string" || !SHA256.test(git.statusSha256)) invalid("source Git sentinel");
  } else { object(git, ["status"]); if (git.status !== "absent") invalid("source Git status"); }
}
function validateCleanup(value: unknown, source: SourceSentinelV1): asserts value is DisposableCleanupReceipt {
  const row = value as Record<string, unknown>;
  if (row?.status === "not-required") {
    object(row, ["status", "root", "reason"]); text(row.reason); if (row.root !== null) invalid("unrequired cleanup root"); return;
  }
  if (!row || !["passed", "failed"].includes(row.status as string)) invalid("cleanup status");
  if (!Object.hasOwn(row, "removal")) {
    object(row, ["status", "root", "reasonCode", "reason", "falsifier"]); text(row.reasonCode); text(row.reason); text(row.falsifier);
    if (row.status !== "failed" || !["unbound-temporary-root", "unrecognized-target"].includes(row.reasonCode) || (row.root !== null && (typeof row.root !== "string" || !isAbsolute(row.root)))) invalid("failed cleanup"); return;
  }
  object(row, ["status", "root", "startedAt", "endedAt", "durationMs", "removal", "source"]);
  if (typeof row.root !== "string" || !isAbsolute(row.root)) invalid("cleanup root");
  instant(row.startedAt); instant(row.endedAt); duration(row.durationMs);
  if (Date.parse(row.startedAt) > Date.parse(row.endedAt)) invalid("cleanup time ordering");
  const removal = row.removal as Record<string, unknown>;
  if (removal?.status === "removed") object(removal, ["status"]);
  else { object(removal, ["status", "reasonCode", "reason", "falsifier"]); if (removal.status !== "failed") invalid("removal status"); text(removal.reasonCode); text(removal.reason); text(removal.falsifier); }
  const preservation = row.source as Record<string, unknown>;
  if (preservation?.status === "passed") { object(preservation, ["status", "before", "after"]); validateSource(preservation.before); validateSource(preservation.after); if (!equal(preservation.before, preservation.after)) invalid("source preservation mismatch"); }
  else {
    object(preservation, ["status", "before", "reasonCode", "reason", "falsifier"], ["after"]);
    if (preservation.status !== "failed") invalid("source preservation status");
    validateSource(preservation.before); if (preservation.after !== undefined) validateSource(preservation.after);
    text(preservation.reasonCode); text(preservation.reason); text(preservation.falsifier);
    if (!["source-changed", "source-unreadable"].includes(preservation.reasonCode)) invalid("source preservation reason");
  }
  if (!equal(preservation.before, source) || (row.status === "passed") !== (removal.status === "removed" && preservation.status === "passed")) invalid("cleanup/source result binding");
}
function aggregate(stages: readonly StageReceiptV1[], cleanup: DisposableCleanupReceipt): ReadinessExecutionV1["status"] {
  if (cleanup.status === "failed" || stages.some((stage) => stage.status === "failed")) return "failed";
  if (cleanup.status === "not-required" && stages.some((stage) => stage.execution.kind !== "not-run")) return "failed";
  return stages.every((stage) => stage.status === "passed") && cleanup.status === "passed" ? "passed" : "not-assessed";
}
function safeSource(state: ReceiptState, source: SourceSentinelV1): SourceSentinelV1 {
  return { ...structuredClone(source), sourceRoot: state.registry.redact(source.sourceRoot) };
}
function safeCleanup(state: ReceiptState, input: DisposableCleanupReceipt): DisposableCleanupReceipt {
  if (input.status === "not-required") return { ...input, reason: state.registry.redact(input.reason) };
  if (!("source" in input)) return { ...input, root: input.root === null ? null : state.registry.redact(input.root), reason: state.registry.redact(input.reason), falsifier: state.registry.redact(input.falsifier) };
  const source = input.source.status === "passed"
    ? { status: "passed" as const, before: safeSource(state, input.source.before), after: safeSource(state, input.source.after) }
    : { ...input.source, before: safeSource(state, input.source.before), ...(input.source.after === undefined ? {} : { after: safeSource(state, input.source.after) }), reason: state.registry.redact(input.source.reason), falsifier: state.registry.redact(input.source.falsifier) };
  return {
    ...input, root: state.registry.redact(input.root), source,
    removal: input.removal.status === "removed" ? { status: "removed" }
      : { ...input.removal, reasonCode: state.registry.redact(input.removal.reasonCode), reason: state.registry.redact(input.removal.reason), falsifier: state.registry.redact(input.removal.falsifier) },
  };
}
function safeReceipt(state: ReceiptState, input: StageReceiptV1): StageReceiptV1 {
  const receipt = structuredClone(input);
  receipt.provenance = safeProvenance(state, receipt.provenance);
  receipt.authority = safeAuthority(state, receipt.authority);
  if (receipt.command) {
    receipt.command.bin = state.registry.redact(receipt.command.bin);
    receipt.command.args = receipt.command.args.map((arg) => state.registry.redact(arg));
    receipt.command.plannedCwd = state.registry.redact(receipt.command.plannedCwd);
    receipt.command.actualCwd = receipt.command.actualCwd === null ? null : state.registry.redact(receipt.command.actualCwd);
    receipt.command.source.path = state.registry.redact(receipt.command.source.path);
    if (receipt.command.source.pointer !== undefined) receipt.command.source.pointer = state.registry.redact(receipt.command.source.pointer);
  }
  if (receipt.toolchain) {
    receipt.toolchain.executable = state.registry.redact(receipt.toolchain.executable);
    receipt.toolchain.searchPath = receipt.toolchain.searchPath.map((path) => state.registry.redact(path));
    receipt.toolchain.requestedVersion = receipt.toolchain.requestedVersion === null ? null : state.registry.redact(receipt.toolchain.requestedVersion);
    receipt.toolchain.controller = Object.fromEntries(Object.entries(receipt.toolchain.controller).map(([key, value]) => [key, state.registry.redact(value)])) as ReadinessToolchainV1["controller"];
    const version = receipt.toolchain.observedVersion;
    receipt.toolchain.observedVersion = version.status === "observed"
      ? { status: "observed", version: state.registry.redact(version.version), provenance: state.registry.redact(version.provenance) }
      : { status: "not-assessed", ...diagnostic(state, { reasonCode: version.reasonCode, reason: version.reason, provenance: version.provenance, falsifier: version.falsifier }) };
  }
  if (receipt.status !== "passed") receipt.diagnostic = diagnostic(state, receipt.diagnostic);
  if (receipt.execution.kind === "process") receipt.execution.process = sanitizeProcess(state, receipt.execution.process, receipt.execution.limits);
  return receipt;
}
function safeExecution(state: ReceiptState, input: ReadinessExecutionV1): ReadinessExecutionV1 {
  assertPublicIdentities(state);
  // Version/status/time/hash fields are typed observations. Identity text is checked above;
  // it must never be silently exempted from the producer's known-value guard.
  return { ...input, source: safeSource(state, input.source), stages: input.stages.map((stage) => safeReceipt(state, stage)), cleanup: safeCleanup(state, input.cleanup) };
}

/** Exact plan-ID closure is mandatory before any receipt set can be serialized or called clean. */
export function closeReadinessExecutionV1(context: ReadinessReceiptContext, input: {
  binding: ReadinessPlanBindingV1;
  receipts: readonly StageReceiptV1[];
  cleanup: DisposableCleanupReceipt;
}): ReadinessExecutionV1 {
  const state = stateOf(context);
  assertPublicIdentities(state);
  object(input.binding, ["schemaVersion", "planSha256", "source"]);
  if (input.binding.schemaVersion !== 1 || input.binding.planSha256 !== state.planSha256) invalid("plan hash binding");
  validateSource(input.binding.source);
  validateCleanup(input.cleanup, input.binding.source);
  const expected = executionExpectations(state);
  for (const receipt of input.receipts) validateStage(expected, receipt);
  const value: ReadinessExecutionV1 = {
    schemaVersion: 1, kind: "harvey-audit-readiness-execution", planSha256: state.planSha256,
    source: structuredClone(input.binding.source),
    status: aggregate(input.receipts, input.cleanup), stages: structuredClone([...input.receipts]).sort((a, b) => a.stageId.localeCompare(b.stageId, "en")),
    cleanup: structuredClone(input.cleanup),
  };
  return immutable(validateReadinessExecutionV1(context, safeExecution(state, value)));
}

export function validateReadinessExecutionV1(context: ReadinessReceiptContext, input: unknown): ReadinessExecutionV1 {
  const state = stateOf(context);
  assertPublicIdentities(state);
  const execution = validateReadinessExecutionAgainstExpectationsV1(executionExpectations(state), input);
  for (const stage of execution.stages) if (stage.execution.kind === "process") assertContainmentIdentities(state, stage.execution.process.containment);
  return execution;
}

/** Pure evidence checks shared by the live producer and offline importer; never grants execution authority. */
export function validateReadinessExecutionAgainstExpectationsV1(expected: ExecutionExpectations, input: unknown, expectedSource?: SourceSentinelV1): ReadinessExecutionV1 {
  const row = object(input, ["schemaVersion", "kind", "planSha256", "source", "status", "stages", "cleanup"]);
  if (row.schemaVersion !== 1 || row.kind !== "harvey-audit-readiness-execution" || row.planSha256 !== expected.originalPlanSha256 || !Array.isArray(row.stages)) invalid("execution version/plan binding");
  validateSource(row.source); validateCleanup(row.cleanup, row.source);
  if (expectedSource !== undefined) { validateSource(expectedSource); if (!equal(row.source, expectedSource)) invalid("expected source binding"); }
  for (const stage of row.stages) validateStage(expected, stage);
  const stages = row.stages as StageReceiptV1[];
  const ids = stages.map((stage) => stage.stageId);
  const expectedIds = expected.stages.map((stage) => stage.id).sort((a, b) => a.localeCompare(b, "en"));
  if (!equal(ids, expectedIds)) invalid("missing, duplicate, unknown, or unordered stage receipt");
  for (const stage of stages) {
    if (stage.execution.kind === "install-lifecycle") {
      const fulfilledByStageId = stage.execution.fulfilledByStageId;
      const install = stages.find((candidate) => candidate.stageId === fulfilledByStageId);
      if (!install || install.kind !== "install" || install.status !== "passed" || install.execution.kind !== "process"
        || !equal([stage.execution.startedAt, stage.execution.endedAt, stage.execution.durationMs], [install.execution.process.startedAt, install.execution.process.endedAt, install.execution.process.durationMs])
        || !equal(stage.toolchain, install.toolchain)) invalid("missing successful install lifecycle parent");
    }
    if (stage.status === "not-assessed") {
      if (stage.blockedByStageIds.some((id) => stages.find((candidate) => candidate.stageId === id)?.status === "passed")) invalid("successful prerequisite marked blocked");
    } else if (stage.execution.kind !== "unverified" && stage.prerequisiteStageIds.some((id) => stages.find((candidate) => candidate.stageId === id)?.status !== "passed")) invalid("executed stage without successful prerequisite");
    if (stage.execution.kind === "process" && row.cleanup.root !== null && stage.command?.actualCwd) {
      const path = relative(row.cleanup.root, stage.command.actualCwd);
      if (isAbsolute(path) || path === ".." || path.startsWith(`..${sep}`)) invalid("executed cwd outside cleanup root");
      if ("startedAt" in row.cleanup && Date.parse(stage.execution.process.endedAt) > Date.parse(row.cleanup.startedAt)) invalid("cleanup before process evidence closes");
    }
  }
  if (row.status !== aggregate(stages, row.cleanup)) invalid("aggregate status");
  return input as ReadinessExecutionV1;
}

/** Revalidate at the final artifact boundary against the supported environment/error field set. */
export function serializeReadinessExecutionV1(context: ReadinessReceiptContext, input: unknown): string {
  assertPublicIdentities(stateOf(context));
  const value = validateReadinessExecutionV1(context, input);
  const safe = validateReadinessExecutionV1(context, safeExecution(stateOf(context), value));
  return JSON.stringify(safe, null, 2) + "\n";
}
