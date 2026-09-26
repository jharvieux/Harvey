import { type ReadinessPlanV1 } from "./audit-readiness.js";
import {
  createReadinessAdmission,
  type ReadinessPlanBindingV1,
  type ReadinessStageAuthorization,
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
import { createBoundedProcessRunner } from "./bounded-process.js";
import { cleanupDisposableTarget, createDisposableTarget, type DisposableCleanupReceipt } from "./disposable-target.js";

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
  limits?: { timeoutMs: number };
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Readiness authorization must be an object.");
  const row = value as Record<string, unknown>;
  if (Object.keys(row).some((key) => !["schemaVersion", "planSha256", "stageAuthorizations", "approvedEnvNames", "toolchainPath", "timeoutMs"].includes(key))
    || row.schemaVersion !== 1 || row.planSha256 !== planSha256 || !Array.isArray(row.stageAuthorizations)
    || !Array.isArray(row.approvedEnvNames) || row.approvedEnvNames.some((name) => typeof name !== "string")
    || (row.toolchainPath !== undefined && typeof row.toolchainPath !== "string")
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
    approvedEnvNames: row.approvedEnvNames as string[],
    ...(row.toolchainPath === undefined ? {} : { toolchainPath: row.toolchainPath as string }),
    ...(row.timeoutMs === undefined ? {} : { limits: { timeoutMs: row.timeoutMs as number } }),
  };
}

/** Invalid pre-execution configuration has zero process work and retains the complete plan ID set. */
export function discloseReadinessSetupFailure(plan: ReadinessPlanV1, binding: ReadinessPlanBindingV1): BoundReadinessResult {
  const evidence = createReadinessReceiptContext(plan, { approvedEnvNames: [], environment: {} });
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
  const evidence = createReadinessReceiptContext(options.plan, {
    approvedEnvNames: options.approvedEnvNames,
    environment: options.environment,
  });
  const create = await createDisposableTarget(options.sourceRoot);
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
    try {
      const admission = createReadinessAdmission(options.plan, options.binding, {
        allowTargetInstall: options.allowTargetInstall,
        stageAuthorizations: options.stageAuthorizations,
        approvedEnvNames: options.approvedEnvNames,
        environment: options.environment,
        ...(options.toolchainPath ? { toolchainPath: options.toolchainPath } : {}),
        registerSecret: evidence.registerSecret,
      });
      const runner = createBoundedProcessRunner({ concurrency: 1 });
      const outcomes = await executeReadinessPlan<StageReceiptV1>(admission, target, {
        concurrency: 1,
        runStage: async (_stage, admitted) => {
          const request = prepareReadinessSpawn(evidence, admitted);
          const result = await runner.run(request, {
            timeoutMs: limits.timeoutMs,
            killGraceMs: limits.killGraceMs,
            closeGraceMs: limits.closeGraceMs,
            output: { headBytes: limits.headBytes, tailBytes: limits.tailBytes },
            redact: evidence.redact,
          });
          const receipt = createReadinessProcessReceipt(evidence, admitted, result, limits);
          return receipt.status === "passed"
            ? { status: "passed", receipt }
            : { status: "failed", receipt, ...receipt.diagnostic };
        },
      });
      receipts = receiptsFromOutcomes(evidence, outcomes);
    } catch {
      receipts = options.plan.stages.map((stage) => stage.assessment === "planned"
        ? createReadinessFailureReceipt(evidence, stage.id, {
          reasonCode: "readiness-adapter-unverified",
          reason: "The execution adapter stopped without complete stage evidence.",
          provenance: ["readiness execution adapter"],
          falsifier: "Rerun with a valid bound plan, stage authorities, and a complete bounded process receipt.",
        })
        : createReadinessNotAssessedReceipt(evidence, stage.id, {
          reasonCode: "readiness-adapter-unverified",
          reason: "The execution adapter stopped before this non-executable stage could be classified.",
          provenance: ["readiness execution adapter"],
          falsifier: "Rerun with a valid bound plan and complete stage classification.",
        }));
    } finally {
      cleanup = await cleanupDisposableTarget(target);
    }
  }
  const execution = closeReadinessExecutionV1(evidence, { binding: options.binding, receipts, cleanup });
  return finalizeReadinessArtifacts(evidence, options.binding, execution);
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
