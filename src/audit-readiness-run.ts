import { type ReadinessPlanV1 } from "./audit-readiness.js";
import {
  createReadinessAdmission,
  validateReadinessEnvironmentNames,
  type ReadinessPlanBindingV1,
  type ReadinessStageAuthorization,
  type ReadinessSpawnRequest,
} from "./audit-readiness-authority.js";
import { executeReadinessPlan, type ReadinessStageOutcome } from "./audit-readiness-exec.js";
import {
  closeReadinessExecutionV1,
  createReadinessFailureReceipt,
  createReadinessImplicitReceipt,
  createReadinessNotAssessedReceipt,
  createReadinessProcessReceipt,
  createReadinessReceiptContext,
  prepareReadinessSpawn,
  prepareReadinessPlanExportV1,
  type ReadinessExecutionV1,
  type ReadinessProcessLimitsV1,
  type StageReceiptV1,
} from "./audit-readiness-receipts.js";
import { createReadinessArtifactsV1 } from "./audit-readiness-artifacts.js";
import type { BoundedProcessResult } from "./bounded-process.js";
import { createReadinessContainedProcessRunner, type ReadinessContainmentConfig } from "./readiness-process-containment.js";
import { cleanupDisposableTarget, createDisposableTarget, retainDisposableTarget, type DisposableCleanupReceipt } from "./disposable-target.js";

const DEFAULT_LIMITS: ReadinessProcessLimitsV1 = {
  timeoutMs: 120_000,
  killGraceMs: 250,
  closeGraceMs: 1_000,
  headBytes: 4_096,
  tailBytes: 4_096,
};

interface BoundReadinessOptions {
  sourceRoot: string;
  plan: ReadinessPlanV1;
  binding: ReadinessPlanBindingV1;
  allowTargetInstall: boolean;
  stageAuthorizations: readonly ReadinessStageAuthorization[];
  approvedEnvNames: readonly string[];
  environment: Readonly<Record<string, string | undefined>>;
  toolchainPath?: string;
  containment?: ReadinessContainmentConfig;
  disposableTempParent?: string;
  limits?: Partial<ReadinessProcessLimitsV1>;
}

interface BoundReadinessResult {
  execution: ReadinessExecutionV1;
  json: string;
  descriptorJson: string;
  descriptorSha256: string;
  executionSha256: string;
  planExport: ReturnType<typeof prepareReadinessPlanExportV1>;
}

function finalizeReadinessArtifacts(
  evidence: ReturnType<typeof createReadinessReceiptContext>,
  binding: ReadinessPlanBindingV1,
  execution: ReadinessExecutionV1,
): BoundReadinessResult {
  const artifacts = createReadinessArtifactsV1(evidence, { binding, execution });
  return {
    execution: artifacts.execution, json: artifacts.executionJson,
    descriptorJson: artifacts.descriptorJson, descriptorSha256: artifacts.descriptorSha256,
    executionSha256: artifacts.executionSha256, planExport: prepareReadinessPlanExportV1(evidence),
  };
}

/** Authorization files contain names and reviewed effects, never environment values. */
export function parseReadinessAuthorizations(value: unknown, planSha256: string): {
  stageAuthorizations: ReadinessStageAuthorization[];
  approvedEnvNames: string[];
  toolchainPath?: string;
  containment?: ReadinessContainmentConfig;
  disposableTempParent?: string;
  limits?: { timeoutMs: number };
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Readiness authorization must be an object.");
  const row = value as Record<string, unknown>;
  if (Object.keys(row).some((key) => !["schemaVersion", "planSha256", "stageAuthorizations", "approvedEnvNames", "toolchainPath", "timeoutMs", "containment", "disposableTempParent"].includes(key))
    || row.schemaVersion !== 1 || row.planSha256 !== planSha256 || !Array.isArray(row.stageAuthorizations)
    || !Array.isArray(row.approvedEnvNames) || row.approvedEnvNames.some((name) => typeof name !== "string")
    || (row.toolchainPath !== undefined && typeof row.toolchainPath !== "string")
    || (row.disposableTempParent !== undefined && (typeof row.disposableTempParent !== "string" || !row.disposableTempParent.startsWith("/") || row.disposableTempParent.includes("\0")))
    || (row.containment !== undefined && (!row.containment || typeof row.containment !== "object" || Array.isArray(row.containment)))
    || (row.timeoutMs !== undefined && (!Number.isSafeInteger(row.timeoutMs) || (row.timeoutMs as number) < 1 || (row.timeoutMs as number) > 3_600_000))) {
    throw new Error("Readiness authorization does not match the exact plan or supported fields.");
  }
  for (const candidate of row.stageAuthorizations) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) throw new Error("Invalid readiness stage authorization.");
    const stage = candidate as Record<string, unknown>;
    if (Object.keys(stage).some((key) => !["stageId", "effect", "source", "reason", "falsifier"].includes(key))
      || [stage.stageId, stage.source, stage.reason, stage.falsifier].some((text) => typeof text !== "string" || !text.trim())
      || !["disposable-local", "target-install", "network-or-service", "unknown"].includes(stage.effect as string)) {
      throw new Error("Invalid readiness stage authorization.");
    }
  }
  return {
    stageAuthorizations: row.stageAuthorizations as ReadinessStageAuthorization[],
    approvedEnvNames: validateReadinessEnvironmentNames(row.approvedEnvNames),
    ...(row.toolchainPath === undefined ? {} : { toolchainPath: row.toolchainPath as string }),
    ...(row.containment === undefined ? {} : { containment: row.containment as ReadinessContainmentConfig }),
    ...(row.disposableTempParent === undefined ? {} : { disposableTempParent: row.disposableTempParent as string }),
    ...(row.timeoutMs === undefined ? {} : { limits: { timeoutMs: row.timeoutMs as number } }),
  };
}

/** Invalid pre-execution configuration has zero process work and retains the complete plan ID set. */
export function discloseReadinessSetupFailure(plan: ReadinessPlanV1, binding: ReadinessPlanBindingV1, redaction?: {
  names: readonly string[];
  environment: Readonly<Record<string, string | undefined>>;
}): BoundReadinessResult {
  const evidence = createReadinessReceiptContext(plan, { approvedEnvNames: [], environment: {} });
  // A rejected grant can still identify operator-supplied values to redact. These names never
  // enter the admission or public approved/present observations, and all stages remain not-run.
  if (redaction) for (const name of validateReadinessEnvironmentNames(redaction.names)) {
    const value = Object.hasOwn(redaction.environment, name) ? redaction.environment[name] : undefined;
    if (value === undefined || value === "") continue;
    if (typeof value !== "string" || value.includes("\0")) throw new Error("Readiness redaction input is invalid.");
    evidence.registerSecret(value);
  }
  const receipts = plan.stages.map((stage) => createReadinessNotAssessedReceipt(evidence, stage.id, {
    reasonCode: "execution-configuration-invalid",
    reason: "Readiness execution was withheld because its plan-bound operator authorization could not be validated.",
    provenance: ["run-audit readiness configuration"],
    falsifier: "Provide a valid authorization file bound to this exact plan and retry the requested execution.",
  }));
  const execution = closeReadinessExecutionV1(evidence, {
    binding, receipts, cleanup: { status: "not-required", root: null, reason: "No disposable target or process was created." },
  });
  return finalizeReadinessArtifacts(evidence, binding, execution);
}

/** Owns the disposable copy, every child receipt, and cleanup after all children settle. */
export async function executeBoundReadinessPlan(options: BoundReadinessOptions): Promise<BoundReadinessResult> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  try { validateReadinessEnvironmentNames(options.approvedEnvNames); }
  catch { return discloseReadinessSetupFailure(options.plan, options.binding); }
  const evidence = createReadinessReceiptContext(options.plan, {
    approvedEnvNames: options.approvedEnvNames,
    environment: options.environment,
  });
  const create = await createDisposableTarget(options.sourceRoot, { tempParent: options.disposableTempParent });
  let receipts: StageReceiptV1[];
  let cleanup: DisposableCleanupReceipt;
  if (create.status !== "ready") {
    cleanup = create.cleanup;
    receipts = options.plan.stages.map((stage) => createReadinessNotAssessedReceipt(evidence, stage.id, {
      reasonCode: create.reasonCode,
      reason: create.reason,
      provenance: ["disposable target creation"],
      falsifier: create.falsifier,
    }));
  } else {
    const target = create.target;
    let stopReason: { reasonCode: string; reason: string; falsifier: string } | null = null;
    let cleanupAllowed = true;
    let invoked = false;
    try {
      const admittedRequests = new WeakMap<ReadinessSpawnRequest, Parameters<typeof prepareReadinessSpawn>[1]>();
      const runner = createReadinessContainedProcessRunner({
        config: options.containment, target, approvedEnvNames: options.approvedEnvNames,
        assertArgv: (request) => {
          const admitted = admittedRequests.get(request);
          if (!admitted) throw new Error("The private process request has no admitted stage.");
          prepareReadinessSpawn(evidence, admitted);
        },
      });
      const available = await runner.probe();
      if (available.status !== "ready") {
        receipts = options.plan.stages.map((stage) => createReadinessNotAssessedReceipt(evidence, stage.id, {
          ...available, provenance: ["local containment runtime preflight"],
        }));
      } else {
        if (options.toolchainPath !== undefined && options.toolchainPath !== available.toolchainPath) throw new Error("The requested toolchain path differs from the selected image.");
        const admission = createReadinessAdmission(options.plan, options.binding, {
          allowTargetInstall: options.allowTargetInstall,
          stageAuthorizations: options.stageAuthorizations,
          approvedEnvNames: options.approvedEnvNames,
          environment: options.environment,
          toolchainPath: available.toolchainPath,
          toolchainScope: { kind: "container-image", imageId: available.imageId },
          registerSecret: evidence.registerSecret,
        });
        const outcomes = await executeReadinessPlan<StageReceiptV1>(admission, target, {
          concurrency: 1,
          executionBarrier: () => stopReason,
          runStage: async (_stage, admitted) => {
            const request = prepareReadinessSpawn(evidence, admitted);
            admittedRequests.set(request, admitted);
            // A transport exception is not evidence that no target work began. Keep the
            // copy and its output lease until the exact owned namespace is observed terminal.
            cleanupAllowed = false;
            invoked = true;
            stopReason = unresolvedOwnership();
            const result = await runner.run(request, {
              timeoutMs: limits.timeoutMs,
              killGraceMs: limits.killGraceMs,
              closeGraceMs: limits.closeGraceMs,
              output: { headBytes: limits.headBytes, tailBytes: limits.tailBytes },
              redact: evidence.redact,
            });
            if (ownedWorkSettled(result)) { cleanupAllowed = true; stopReason = null; }
            if (result.containment.kind === "unavailable") {
              const receipt = createReadinessNotAssessedReceipt(evidence, admitted.stageId, {
                reasonCode: result.containment.reasonCode,
                reason: "The verified containment runtime became unavailable before any target process was started.",
                provenance: ["local containment runtime"],
                falsifier: "Restore the verified local runtime and rerun the exact admitted stage.",
                authority: admitted.authority,
              });
              if (receipt.status === "passed") throw new Error("An unavailable runtime cannot produce a passing stage.");
              return { status: "not-assessed", receipt, ...receipt.diagnostic };
            }
            const receipt = createReadinessProcessReceipt(evidence, admitted, result, limits);
            return receipt.status === "passed"
              ? { status: "passed", receipt }
              : { status: "failed", receipt, ...receipt.diagnostic };
          },
        });
        receipts = receiptsFromOutcomes(evidence, outcomes);
      }
    } catch {
      receipts = options.plan.stages.map((stage) => invoked && stage.assessment === "planned"
        ? createReadinessFailureReceipt(evidence, stage.id, {
          reasonCode: "readiness-adapter-unverified",
          reason: "The execution adapter stopped without complete stage evidence.",
          provenance: ["readiness execution adapter"],
          falsifier: "Rerun with a valid bound plan, stage authorities, and a complete bounded process receipt.",
        })
        : createReadinessNotAssessedReceipt(evidence, stage.id, {
          reasonCode: "readiness-adapter-unverified",
          reason: "The execution configuration or adapter could not be verified before this stage was executed or classified.",
          provenance: ["readiness execution adapter"],
          falsifier: "Rerun with a valid bound plan and complete stage classification.",
        }));
    } finally {
      cleanup = cleanupAllowed
        ? await cleanupDisposableTarget(target)
        : await retainDisposableTarget(target, stopReason ?? unresolvedOwnership());
    }
  }
  const execution = closeReadinessExecutionV1(evidence, { binding: options.binding, receipts, cleanup });
  return finalizeReadinessArtifacts(evidence, options.binding, execution);
}

function unresolvedOwnership() {
  return {
    reasonCode: "owned-workload-unconfirmed",
    reason: "The exact owned workload or its runtime lease has no confirmed terminal cleanup observation; its disposable root is retained and further execution is withheld.",
    falsifier: "Observe termination and release of that exact owned runtime lease before separately remediating the retained root.",
  };
}

function ownedWorkSettled(result: BoundedProcessResult): boolean {
  const containment = result.containment;
  if (containment.kind === "unavailable") return result.pid === null && result.spawnedAt === null && result.exit === null && result.close === null && result.termination.tree === "not-started";
  if (containment.kind !== "docker-pid-namespace" || containment.cleanup === "retained" || containment.namespace === "unconfirmed") return false;
  if (containment.namespace === "not-started" && containment.targetWork === "not-started" && containment.containerId === null && containment.cleanup === "not-required") return true;
  // Missing target metadata remains a failed receipt, but a terminal namespace
  // whose exact container was removed has no workload left holding the copy.
  if (containment.namespace === "not-started") return containment.targetWork === "not-started" && containment.terminalObservation?.running === false && containment.terminalObservation.pid === 0 && containment.cleanup === "removed";
  return containment.namespace === "terminated" && containment.terminalObservation?.running === false && containment.terminalObservation.pid === 0 && containment.cleanup === "removed";
}

function receiptsFromOutcomes(
  evidence: ReturnType<typeof createReadinessReceiptContext>,
  outcomes: ReadinessStageOutcome<StageReceiptV1>[],
): StageReceiptV1[] {
  const byId = new Map(outcomes.map((outcome) => [outcome.stageId, outcome]));
  const converted = new Map<StageReceiptV1["stageId"], StageReceiptV1>();
  const convert = (outcome: ReadinessStageOutcome<StageReceiptV1>): StageReceiptV1 => {
    const existing = converted.get(outcome.stageId);
    if (existing) return existing;
    let receipt: StageReceiptV1;
    if (outcome.execution === "attempted") receipt = outcome.receipt;
    else if (outcome.execution === "adapter-failed") {
      receipt = createReadinessFailureReceipt(evidence, outcome.stageId, {
        reasonCode: outcome.reasonCode, reason: outcome.reason,
        provenance: ["prerequisite-aware scheduler and admitted runner"], falsifier: outcome.falsifier,
        authority: outcome.authority,
      });
    } else {
      const parent = outcome.fulfilledByStageId ? byId.get(outcome.fulfilledByStageId) : undefined;
      const parentReceipt = parent ? convert(parent) : undefined;
      receipt = parentReceipt?.status === "passed" && parentReceipt.kind === "install" && outcome.fulfillment?.status === "passed"
        ? createReadinessImplicitReceipt(evidence, outcome.stageId, parentReceipt)
        : createReadinessNotAssessedReceipt(evidence, outcome.stageId, {
          reasonCode: outcome.reasonCode, reason: outcome.reason,
          provenance: ["prerequisite-aware scheduler"], falsifier: outcome.falsifier,
          ...(outcome.authority ? { authority: outcome.authority } : {}),
          ...(outcome.blockedByStageIds ? { blockedByStageIds: outcome.blockedByStageIds } : {}),
        });
    }
    converted.set(outcome.stageId, receipt);
    return receipt;
  };
  return outcomes.map(convert);
}
