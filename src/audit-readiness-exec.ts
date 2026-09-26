import { type ReadinessStageV1, validateReadinessPlanV1 } from "./audit-readiness.js";
import { admitReadinessStage, type ReadinessAdmissionContext, type ReadinessAuthorityReceipt, type ReadinessStageAdmission } from "./audit-readiness-authority.js";
import type { DisposableTarget } from "./disposable-target.js";

type StageId = ReadinessStageV1["id"];
type PlannedStage = Extract<ReadinessStageV1, { assessment: "planned" }>;
type AdmittedStage = Extract<ReadinessStageAdmission, { status: "admitted" }>;

interface StageReason {
  reasonCode: string;
  reason: string;
  falsifier: string;
}

/** The adapter owns lifecycle evidence and redaction; the scheduler never retains raw process output. */
export type ReadinessStageRunResult<Receipt> =
  | { status: "passed"; receipt: Receipt }
  | (StageReason & { status: "failed" | "not-assessed"; receipt: Receipt });

/** Mutual declarations permit overlap; an undeclared stage holds the entire target output tree. */
export interface ReadinessStageIndependence {
  stageId: StageId;
  reason: string;
  provenance: string;
  falsifier: string;
}

interface OutcomeBase {
  stageId: StageId;
  provenance: ReadinessStageV1["provenance"];
  independence?: ReadinessStageIndependence;
  fulfilledByStageId?: StageId;
}

export type ReadinessStageOutcome<Receipt> = OutcomeBase & (
  | { status: "passed"; execution: "attempted"; authority: ReadinessAuthorityReceipt; receipt: Receipt }
  | (StageReason & { status: "failed" | "not-assessed"; execution: "attempted"; authority: ReadinessAuthorityReceipt; receipt: Receipt })
  | (StageReason & { status: "failed"; execution: "adapter-failed"; authority: ReadinessAuthorityReceipt })
  | (StageReason & {
      status: "not-assessed";
      execution: "withheld";
      authority?: ReadinessAuthorityReceipt;
      blockedByStageIds?: StageId[];
      fulfillment?: { stageId: StageId; status: "passed" | "failed" | "not-assessed"; receipt?: Receipt };
    })
);

export interface ReadinessExecutionOptions<Receipt> {
  /** A small explicit bound, including admission work already holding a stage's output lock. */
  concurrency: number;
  runStage: (stage: PlannedStage, admission: AdmittedStage) => Promise<ReadinessStageRunResult<Receipt>>;
  /** Supplied by the execution caller; never inferred from script names or different workspaces. */
  independence?: readonly ReadinessStageIndependence[];
}

function nonempty(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function independenceFor<Receipt>(stages: readonly ReadinessStageV1[], options: ReadinessExecutionOptions<Receipt>): Map<StageId, ReadinessStageIndependence> {
  if (!Number.isSafeInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 4 || typeof options.runStage !== "function") {
    throw new Error("Readiness execution requires a concurrency limit from 1 to 4 and a stage runner.");
  }
  if (options.independence !== undefined && !Array.isArray(options.independence)) throw new Error("Readiness independence declarations must be an array.");
  const plannedIds = new Set(stages.filter((stage) => stage.assessment === "planned").map((stage) => stage.id));
  const declarations = new Map<StageId, ReadinessStageIndependence>();
  for (const row of options.independence ?? []) {
    if (!row || !plannedIds.has(row.stageId) || declarations.has(row.stageId) || !nonempty(row.reason) || !nonempty(row.provenance) || !nonempty(row.falsifier)) {
      throw new Error("Readiness independence requires one unique planned stage ID, reason, provenance, and falsifier per declaration.");
    }
    declarations.set(row.stageId, { stageId: row.stageId, reason: row.reason, provenance: row.provenance, falsifier: row.falsifier });
  }
  return declarations;
}

function baseFor(stage: ReadinessStageV1, independence?: ReadinessStageIndependence): OutcomeBase {
  return {
    stageId: stage.id,
    provenance: stage.provenance.map((row) => ({ ...row })),
    ...(independence ? { independence: { ...independence } } : {}),
    ...(stage.assessment === "implicit" ? { fulfilledByStageId: stage.fulfilledByStageId } : {}),
  };
}

function validResult<Receipt>(result: ReadinessStageRunResult<Receipt>): boolean {
  if (!result || typeof result !== "object" || !Object.hasOwn(result, "receipt") || result.receipt === undefined) return false;
  return result.status === "passed" || (["failed", "not-assessed"].includes(result.status)
    && "reasonCode" in result && nonempty(result.reasonCode) && nonempty(result.reason) && nonempty(result.falsifier));
}

async function runAdmittedStage<Receipt>(context: ReadinessAdmissionContext, target: DisposableTarget, stage: PlannedStage, base: OutcomeBase, runStage: ReadinessExecutionOptions<Receipt>["runStage"]): Promise<ReadinessStageOutcome<Receipt>> {
  let admission: ReadinessStageAdmission;
  try {
    admission = await admitReadinessStage(context, stage.id, target);
  } catch {
    return {
      ...base, status: "not-assessed", execution: "withheld", reasonCode: "admission-failed",
      reason: "Stage admission could not verify execution authority; no command was handed to the runner.",
      falsifier: "Retry with an authentic bound admission context and an active disposable target whose stage root can be verified.",
    };
  }
  if (admission.status === "not-assessed") {
    return { ...base, status: "not-assessed", execution: "withheld", authority: admission.authority, reasonCode: admission.reasonCode, reason: admission.reason, falsifier: admission.falsifier };
  }
  try {
    const result = await runStage(stage, admission);
    if (!validResult(result)) {
      return {
        ...base, status: "failed", execution: "adapter-failed", authority: admission.authority, reasonCode: "runner-result-invalid",
        reason: "The stage runner returned no valid outcome with retained execution evidence.",
        falsifier: "Return one typed passed, failed, or not-assessed outcome with a receipt and a reason/falsifier for each non-passed result.",
      };
    }
    if (result.status === "passed") return { ...base, status: "passed", execution: "attempted", authority: admission.authority, receipt: result.receipt };
    return { ...base, status: result.status, execution: "attempted", authority: admission.authority, receipt: result.receipt, reasonCode: result.reasonCode, reason: result.reason, falsifier: result.falsifier };
  } catch {
    // Exceptions may contain command output or environment values. Only the receipt adapter may retain/redact those bytes.
    return {
      ...base, status: "failed", execution: "adapter-failed", authority: admission.authority, reasonCode: "runner-threw",
      reason: "The admitted stage runner failed before returning a complete execution receipt.",
      falsifier: "Run the admitted stage through a lifecycle adapter that settles with complete bounded evidence on success and failure.",
    };
  }
}

function fulfillmentFor<Receipt>(stage: ReadinessStageV1, outcomes: ReadonlyMap<StageId, ReadinessStageOutcome<Receipt>>) {
  if (stage.assessment !== "implicit") return {};
  const parent = outcomes.get(stage.fulfilledByStageId);
  if (!parent) return {};
  return { fulfillment: { stageId: parent.stageId, status: parent.status, ...("receipt" in parent ? { receipt: parent.receipt } : {}) } };
}

/**
 * Configuration/plan errors reject before execution. A denied, failed, or throwing stage is an outcome,
 * never a fatal gate for its siblings or the caller's independent M1–M10 collection. Cleanup belongs
 * to the caller, after this promise settles and the returned stage evidence has been finalized.
 */
export async function executeReadinessPlan<Receipt>(context: ReadinessAdmissionContext, target: DisposableTarget, options: ReadinessExecutionOptions<Receipt>): Promise<ReadinessStageOutcome<Receipt>[]> {
  const plan = validateReadinessPlanV1(context.plan);
  const stages = [...plan.stages].sort((a, b) => a.id.localeCompare(b.id));
  const declarations = independenceFor(stages, options);
  const { concurrency, runStage } = options;
  const pending = new Set(stages.map((stage) => stage.id));
  const outcomes = new Map<StageId, ReadinessStageOutcome<Receipt>>();
  const satisfied = new Set<StageId>();
  const active = new Map<StageId, Promise<void>>();

  while (pending.size > 0 || active.size > 0) {
    const pendingBefore = pending.size;
    for (const stage of stages) {
      if (!pending.has(stage.id)) continue;
      const base = baseFor(stage, declarations.get(stage.id));
      if (stage.assessment === "absent" || stage.assessment === "not-assessed") {
        outcomes.set(stage.id, { ...base, status: "not-assessed", execution: "withheld", reasonCode: stage.reasonCode, reason: stage.reason, falsifier: stage.falsifier });
        pending.delete(stage.id);
        continue;
      }
      if (stage.prerequisiteStageIds.some((id) => !outcomes.has(id))) continue;
      const blockedBy = stage.prerequisiteStageIds.filter((id) => !satisfied.has(id)).sort();
      if (blockedBy.length > 0) {
        outcomes.set(stage.id, {
          ...base, status: "not-assessed", execution: "withheld", reasonCode: "prerequisite-not-passed", blockedByStageIds: blockedBy,
          reason: `Required stages did not pass: ${blockedBy.map((id) => `${id} (${outcomes.get(id)?.status})`).join(", ")}. This dependent stage was not run.`,
          falsifier: "Obtain passing execution evidence for every named prerequisite, or passing evidence for its explicitly declared install fulfillment, then rerun this unchanged plan.",
          ...fulfillmentFor(stage, outcomes),
        });
        pending.delete(stage.id);
        continue;
      }
      if (stage.assessment === "implicit") {
        outcomes.set(stage.id, { ...base, status: "not-assessed", execution: "withheld", reasonCode: "covered-by-install-lifecycle", reason: stage.reason, falsifier: stage.falsifier, ...fulfillmentFor(stage, outcomes) });
        satisfied.add(stage.id);
        pending.delete(stage.id);
        continue;
      }
      if (active.size >= concurrency || (active.size > 0 && (!declarations.has(stage.id) || [...active.keys()].some((id) => !declarations.has(id))))) continue;
      pending.delete(stage.id);
      // Reserve the slot/output tree BEFORE asynchronous admission, so realpath checks never sit in a ready queue.
      const task = Promise.resolve().then(() => runAdmittedStage(context, target, stage, base, runStage)).then((outcome) => {
        outcomes.set(stage.id, outcome);
        if (outcome.status === "passed") satisfied.add(stage.id);
      }).finally(() => { active.delete(stage.id); });
      active.set(stage.id, task);
    }
    if (pending.size < pendingBefore) continue;
    if (active.size > 0) await Promise.race(active.values());
    else if (pending.size > 0) {
      // A valid V1 DAG always makes progress; losing that property must never produce partial closure.
      throw new Error("Readiness scheduler cannot resolve the remaining validated stage prerequisites.");
    }
  }

  const result = [...outcomes.values()].sort((a, b) => a.stageId.localeCompare(b.stageId));
  if (result.length !== stages.length || result.some((row, index) => row.stageId !== stages[index]?.id)) {
    throw new Error("Readiness outcomes do not close exactly once over the validated plan IDs.");
  }
  return result;
}
