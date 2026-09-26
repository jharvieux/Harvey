import { createHash } from "node:crypto";
import { READINESS_STAGE_KINDS, readinessStageId, serializeReadinessPlanV1, validateReadinessPlanV1 } from "./audit-readiness.js";
import { type ReadinessPlanBindingV1 } from "./audit-readiness-authority.js";
import {
  createReadinessValidationProjectionV1, serializeReadinessExecutionV1,
  validateReadinessExecutionAgainstExpectationsV1, readinessStageConfigurationSha256,
  type ReadinessExecutionV1, type ReadinessReceiptContext,
  type ReadinessStageExpectationV1, type ReadinessValidationProjectionV1,
} from "./audit-readiness-receipts.js";
import { type SourceSentinelV1 } from "./disposable-target.js";

interface ReadinessArtifactProofV1 {
  kind: "schema-and-declared-bindings";
  executionAuthenticity: "not-established";
  executionAuthority: "none";
  workloadContainment: "not-established-by-artifact-validation";
  redaction: "producer-known-values";
}

/** A producer-issued evidence view; it is neither an executable plan nor independent execution proof. */
export interface ReadinessValidationDescriptorV1 extends ReadinessValidationProjectionV1 {
  schemaVersion: 1;
  kind: "harvey-audit-readiness-validation";
  planSchemaVersion: 1;
  source: SourceSentinelV1;
  execution: {
    schemaVersion: 1;
    kind: "harvey-audit-readiness-execution";
    encoding: "utf8";
    sha256: string;
    bytes: number;
  };
  proof: ReadinessArtifactProofV1;
}

export interface ReadinessOfflineExpectationsV1 {
  descriptorSha256?: string;
  executionSha256?: string;
  originalPlanSha256?: string;
  sourceContentSha256?: string;
  sourceGitHead?: string | null;
  /** Optional original input check. Public redacted expectations are never re-admitted as a plan. */
  originalPlan?: unknown;
}

interface ReadinessArtifactPairV1 {
  descriptor: ReadinessValidationDescriptorV1;
  execution: ReadinessExecutionV1;
  descriptorSha256: string;
  executionSha256: string;
}

const PROOF: ReadinessArtifactProofV1 = Object.freeze({
  kind: "schema-and-declared-bindings", executionAuthenticity: "not-established", executionAuthority: "none",
  workloadContainment: "not-established-by-artifact-validation", redaction: "producer-known-values",
});
const SHA256 = /^[a-f0-9]{64}$/;
const EXPECTATION_KEYS = ["descriptorSha256", "executionSha256", "originalPlanSha256", "sourceContentSha256", "sourceGitHead", "originalPlan"] as const;
const SHARED_INSTALL = readinessStageId("workspace:root", "install");

function invalid(part: string): never { throw new Error(`Invalid readiness artifact: ${part}.`); }
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid("object shape");
  const row = value as Record<string, unknown>;
  if (required.some((key) => !Object.hasOwn(row, key)) || Object.keys(row).some((key) => !required.includes(key) && !optional.includes(key))) invalid("object fields");
  return row;
}
function text(value: unknown, empty = false): asserts value is string {
  if (typeof value !== "string" || (!empty && value.trim() === "") || value.includes("\0")) invalid("text");
}
function strings(value: unknown): asserts value is string[] {
  if (!Array.isArray(value)) invalid("string list");
  for (const item of value) text(item);
}
function unique(value: unknown, ordered = false): asserts value is string[] {
  strings(value);
  if (new Set(value).size !== value.length || (ordered && JSON.stringify(value) !== JSON.stringify([...value].sort()))) invalid("duplicate or unordered names/edges");
}
function sha(value: unknown): asserts value is string { if (typeof value !== "string" || !SHA256.test(value)) invalid("sha256"); }
function hash(value: string): string { return createHash("sha256").update(value, "utf8").digest("hex"); }
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b, "en")).map(([key, nested]) => [key, canonical(nested)]));
  return value;
}
function equal(a: unknown, b: unknown): boolean { return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b)); }
function immutable<T>(value: T): T {
  if (value && typeof value === "object") { for (const nested of Object.values(value)) immutable(nested); Object.freeze(value); }
  return value;
}
function parse(value: string): unknown {
  if (typeof value !== "string") invalid("JSON text");
  try { return JSON.parse(value) as unknown; } catch { return invalid("JSON syntax"); }
}
function workspaceId(value: unknown): asserts value is `workspace:${string}` {
  text(value);
  if (!value.startsWith("workspace:") || value.length === "workspace:".length) invalid("workspace identity");
  const path = value.slice("workspace:".length);
  if (path.includes("\\") || path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) invalid("workspace identity");
}
function manifestWorkspaceId(path: unknown): `workspace:${string}` {
  text(path);
  if (path !== "package.json" && !path.endsWith("/package.json")) invalid("workspace observation manifest path");
  const id = `workspace:${path === "package.json" ? "root" : path.slice(0, -"/package.json".length)}`;
  workspaceId(id);
  return id;
}

/** Only retained identity facts participate; producer-redacted prose is not raw-plan evidence. */
function identityPopulation(value: Pick<ReadinessValidationProjectionV1, "workspaces" | "applicationWorkspaceIds" | "workspaceObservations"> & {
  stages: readonly (Pick<ReadinessStageExpectationV1, "id" | "kind" | "workspaceId" | "prerequisiteStageIds" | "requiredEnvNames" | "assessment" | "safety"> & { fulfilledByStageId?: string })[];
}): unknown {
  return {
    workspaces: value.workspaces.map((workspace) => ({
      id: workspace.id, dir: workspace.dir, manifestPath: workspace.manifestPath,
      installStageId: workspace.installStageId, stageIds: [...workspace.stageIds].sort(),
    })).sort((a, b) => a.id.localeCompare(b.id, "en")),
    stages: value.stages.map((stage) => ({
      id: stage.id, kind: stage.kind, workspaceId: stage.workspaceId, assessment: stage.assessment, safety: stage.safety,
      prerequisiteStageIds: [...stage.prerequisiteStageIds].sort(), requiredEnvNames: [...stage.requiredEnvNames].sort(),
      fulfilledByStageId: stage.fulfilledByStageId ?? null,
    })).sort((a, b) => a.id.localeCompare(b.id, "en")),
    applicationWorkspaceIds: [...value.applicationWorkspaceIds].sort(),
    observations: value.workspaceObservations.map((observation) => ({
      kind: observation.kind, ...("path" in observation ? { path: observation.path } : {}),
      ...("glob" in observation ? { glob: observation.glob, sourcePath: observation.sourcePath } : {}),
      ...(observation.kind === "excluded" ? { reason: observation.reason } : {}),
    })).sort((a, b) => JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b)), "en")),
  };
}
function provenance(value: unknown): void {
  if (!Array.isArray(value)) invalid("provenance");
  for (const item of value) {
    const row = object(item, ["kind", "path", "detail"], ["pointer", "rawScript"]);
    if (!["manifest-script", "supported-config", "package-manager-evidence", "workspace-observation"].includes(row.kind as string)) invalid("provenance kind");
    text(row.path); text(row.detail);
    if (row.pointer !== undefined) text(row.pointer, true);
    if (row.rawScript !== undefined) { text(row.rawScript, true); if (row.kind !== "manifest-script") invalid("raw script provenance"); }
  }
}
function validateStageExpectation(value: unknown): asserts value is ReadinessStageExpectationV1 {
  const assessment = (value as Record<string, unknown> | null)?.assessment;
  const common = ["id", "kind", "workspaceId", "prerequisiteStageIds", "requiredEnvNames", "safety", "provenance", "configurationSha256", "assessment"];
  const row = object(value, [...common, ...(assessment === "planned" ? ["command"] : assessment === "implicit" ? ["fulfilledByStageId", "reason", "falsifier"] : ["reasonCode", "reason", "falsifier"])]);
  workspaceId(row.workspaceId); sha(row.configurationSha256);
  if (!READINESS_STAGE_KINDS.includes(row.kind as ReadinessStageExpectationV1["kind"]) || row.id !== readinessStageId(row.workspaceId, row.kind as ReadinessStageExpectationV1["kind"])) invalid("stage identity/kind");
  unique(row.prerequisiteStageIds); unique(row.requiredEnvNames); provenance(row.provenance);
  if (row.requiredEnvNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name))) invalid("required environment names");
  const safety = assessment === "planned" ? (row.kind === "install" ? "executes-install-lifecycle" : "executes-target-script") : assessment === "implicit" ? "covered-by-install-lifecycle" : "non-executable";
  if (row.safety !== safety) invalid("stage safety");
  if (assessment === "planned") {
    const command = object(row.command, ["bin", "args", "plannedCwd", "actualCwd", "source"]);
    text(command.bin); strings(command.args); text(command.plannedCwd);
    if (command.actualCwd !== null) invalid("expected command cwd");
    const source = object(command.source, ["kind", "path"], ["pointer"]);
    if (source.kind !== (row.kind === "install" ? "package-manager-install" : "package-manager-script")) invalid("command source kind");
    text(source.path); if (source.pointer !== undefined) text(source.pointer, true);
  } else {
    text(row.reason); text(row.falsifier);
    if (assessment === "implicit") { if (row.fulfilledByStageId !== SHARED_INSTALL) invalid("implicit install parent"); }
    else if (assessment === "absent") { if (!["missing-script-and-config", "placeholder-script"].includes(row.reasonCode as string)) invalid("absent reason code"); }
    else if (assessment === "not-assessed") { if (!["package-manager-not-selected", "supported-config-without-script", "unreadable-config", "unreadable-manifest", "ambiguous-scripts"].includes(row.reasonCode as string)) invalid("not-assessed reason code"); }
    else invalid("assessment");
  }
}

function validateProjection(row: Record<string, unknown>): asserts row is Record<string, unknown> & ReadinessValidationProjectionV1 {
  sha(row.originalPlanSha256);
  const environment = object(row.environment, ["approvedNames", "presentNames"]);
  unique(environment.approvedNames, true); unique(environment.presentNames, true);
  if (environment.approvedNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name)) || environment.presentNames.some((name) => !(environment.approvedNames as string[]).includes(name))) invalid("environment name observations");
  if (!Array.isArray(row.workspaces) || !Array.isArray(row.stages)) invalid("plan collections");
  for (const stage of row.stages) validateStageExpectation(stage);
  const stages = row.stages as ReadinessStageExpectationV1[];
  const stageIds = stages.map((stage) => stage.id);
  if (new Set(stageIds).size !== stageIds.length || !equal(stageIds, [...stageIds].sort((a, b) => a.localeCompare(b, "en")))) invalid("duplicate or unordered stages");
  const byStage = new Map(stages.map((stage) => [stage.id, stage]));
  const workspaceIds: string[] = [];
  const referenced = new Set<string>();
  for (const item of row.workspaces) {
    const workspace = object(item, ["id", "dir", "manifestPath", "installStageId", "stageIds", "provenance"], ["name"]);
    workspaceId(workspace.id); text(workspace.dir); text(workspace.manifestPath);
    const dir = workspace.id === "workspace:root" ? "." : workspace.id.slice("workspace:".length);
    if (workspace.dir !== dir || workspace.manifestPath !== (dir === "." ? "package.json" : `${dir}/package.json`)) invalid("workspace identity paths");
    if (workspace.name !== undefined) text(workspace.name, true);
    provenance(workspace.provenance); unique(workspace.stageIds, true);
    workspaceIds.push(workspace.id);
    if (workspace.installStageId !== SHARED_INSTALL || !workspace.stageIds.includes(SHARED_INSTALL) || workspace.stageIds.length !== READINESS_STAGE_KINDS.length) invalid("workspace stage reference closure");
    const referencedKinds = new Set<string>();
    for (const id of workspace.stageIds) {
      const stage = byStage.get(id as ReadinessStageExpectationV1["id"]);
      if (!stage || (stage.kind !== "install" && stage.workspaceId !== workspace.id)) invalid("unknown or borrowed workspace stage");
      referencedKinds.add(stage.kind); referenced.add(id);
    }
    if (READINESS_STAGE_KINDS.some((kind) => !referencedKinds.has(kind))) invalid("workspace stage kinds");
  }
  if (new Set(workspaceIds).size !== workspaceIds.length || !equal(workspaceIds, [...workspaceIds].sort((a, b) => a.localeCompare(b, "en")))) invalid("duplicate or unordered workspaces");
  if (!workspaceIds.includes("workspace:root")) invalid("missing root workspace");
  if (!byStage.has(SHARED_INSTALL) || referenced.size !== stageIds.length || stageIds.some((id) => !referenced.has(id))) invalid("unreferenced plan stage");
  for (const stage of stages) {
    if (!workspaceIds.includes(stage.workspaceId) && stage.workspaceId !== "workspace:root") invalid("stage workspace");
    const prerequisites: string[] = stage.kind === "install" ? [] : [SHARED_INSTALL];
    if (["build", "typecheck", "test"].includes(stage.kind)) {
      const codegen = byStage.get(readinessStageId(stage.workspaceId, "codegen"));
      if (codegen && codegen.assessment !== "absent") prerequisites.push(codegen.id);
    }
    if (!equal([...stage.prerequisiteStageIds].sort(), prerequisites.sort()) || stage.prerequisiteStageIds.some((id) => !byStage.has(id) || id === stage.id)) invalid("stage prerequisite closure");
    if (stage.assessment === "implicit" && !stage.prerequisiteStageIds.includes(stage.fulfilledByStageId)) invalid("implicit prerequisite");
  }
  unique(row.applicationWorkspaceIds, true);
  for (const id of row.applicationWorkspaceIds) workspaceId(id);
  if (!Array.isArray(row.workspaceObservations)) invalid("workspace observations");
  const negativelyExcludedIds = new Set<string>();
  const observations = new Set<string>();
  for (const item of row.workspaceObservations) {
    const kind = (item as Record<string, unknown> | null)?.kind;
    const observation = object(item, kind === "excluded" ? ["kind", "path", "glob", "sourcePath", "reason"] : kind === "unreadable-manifest" ? ["kind", "path", "reason"] : ["kind", "glob", "sourcePath", "reason"]);
    const key = JSON.stringify(canonical(observation));
    if (observations.has(key)) invalid("duplicate workspace observation");
    observations.add(key);
    text(observation.reason);
    if (kind === "excluded") {
      if (!["implicit-directory-policy", "negative-workspace-glob"].includes(observation.reason)) invalid("excluded workspace reason");
      text(observation.path); text(observation.glob); text(observation.sourcePath);
      const excludedId = manifestWorkspaceId(observation.path);
      if (observation.reason === "negative-workspace-glob") negativelyExcludedIds.add(excludedId);
    } else if (kind === "unreadable-manifest") {
      if (!workspaceIds.includes(manifestWorkspaceId(observation.path))) invalid("unreadable workspace observation population");
    } else if (kind === "unresolved-glob" || kind === "invalid-glob") { text(observation.glob); text(observation.sourcePath); }
    else invalid("workspace observation kind");
  }
  if (row.applicationWorkspaceIds.some((id) => !workspaceIds.includes(id) && !negativelyExcludedIds.has(id))) invalid("application workspace population");
}

function validateDescriptor(input: unknown): ReadinessValidationDescriptorV1 {
  const row = object(input, ["schemaVersion", "kind", "planSchemaVersion", "originalPlanSha256", "source", "environment", "workspaces", "stages", "workspaceObservations", "applicationWorkspaceIds", "execution", "proof"]);
  if (row.schemaVersion !== 1 || row.kind !== "harvey-audit-readiness-validation" || row.planSchemaVersion !== 1) invalid("descriptor version/kind");
  validateProjection(row);
  const execution = object(row.execution, ["schemaVersion", "kind", "encoding", "sha256", "bytes"]);
  if (execution.schemaVersion !== 1 || execution.kind !== "harvey-audit-readiness-execution" || execution.encoding !== "utf8" || !Number.isSafeInteger(execution.bytes) || (execution.bytes as number) < 1) invalid("execution artifact metadata");
  sha(execution.sha256);
  object(row.proof, Object.keys(PROOF));
  if (!equal(row.proof, PROOF)) invalid("proof scope");
  return input as ReadinessValidationDescriptorV1;
}

/** Pure import of already-read artifact bytes. Hashes bind files, not authenticity or fresh execution. */
export function parseReadinessArtifactsV1(input: { descriptorJson: string; executionJson: string }, expected: ReadinessOfflineExpectationsV1 = {}): ReadinessArtifactPairV1 & {
  matchedExpectations: (keyof ReadinessOfflineExpectationsV1)[];
  proof: "schema-and-declared-bindings";
} {
  const inputs = object(input, ["descriptorJson", "executionJson"]);
  if (typeof inputs.descriptorJson !== "string" || typeof inputs.executionJson !== "string") invalid("artifact strings");
  object(expected, [], EXPECTATION_KEYS);
  const descriptor = validateDescriptor(parse(input.descriptorJson));
  const descriptorSha256 = hash(input.descriptorJson);
  const executionSha256 = hash(input.executionJson);
  if (executionSha256 !== descriptor.execution.sha256 || Buffer.byteLength(input.executionJson, "utf8") !== descriptor.execution.bytes) invalid("execution file digest/bytes");
  const execution = validateReadinessExecutionAgainstExpectationsV1(descriptor, parse(input.executionJson), descriptor.source);
  const actual: Omit<ReadinessOfflineExpectationsV1, "originalPlan"> = {
    descriptorSha256, executionSha256, originalPlanSha256: descriptor.originalPlanSha256,
    sourceContentSha256: descriptor.source.contentSha256,
    ...(descriptor.source.git.status === "present" ? { sourceGitHead: descriptor.source.git.head } : {}),
  };
  const matchedExpectations: (keyof ReadinessOfflineExpectationsV1)[] = [];
  for (const key of EXPECTATION_KEYS) {
    if (!Object.hasOwn(expected, key)) continue;
    if (key === "originalPlan") {
      let planSha256: string;
      let plan: ReturnType<typeof validateReadinessPlanV1>;
      try { plan = validateReadinessPlanV1(expected.originalPlan); planSha256 = hash(serializeReadinessPlanV1(plan)); }
      catch { return invalid("original plan"); }
      if (planSha256 !== descriptor.originalPlanSha256) invalid("original plan binding");
      if (!equal(identityPopulation(descriptor), identityPopulation({
        workspaces: plan.workspaces, stages: plan.stages, applicationWorkspaceIds: plan.workspaceInventory.applicationWorkspaceIds,
        workspaceObservations: plan.workspaceInventory.observations,
      }))) invalid("original workspace identity population");
      const originalStages = new Map(plan.stages.map((stage) => [stage.id, stage]));
      if (originalStages.size !== descriptor.stages.length || descriptor.stages.some((stage) => {
        const original = originalStages.get(stage.id);
        return !original || readinessStageConfigurationSha256(plan, original) !== stage.configurationSha256;
      })) invalid("original stage configuration binding");
    } else {
      const value = expected[key];
      if (key === "sourceGitHead") {
        if (value !== null && (typeof value !== "string" || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value))) invalid("expected source Git head");
      } else sha(value);
      if (value !== actual[key]) invalid("caller expectation binding");
    }
    matchedExpectations.push(key);
  }
  return immutable({ descriptor, execution, descriptorSha256, executionSha256, matchedExpectations, proof: "schema-and-declared-bindings" });
}

/** Final producer boundary: retain original plan identity while binding redacted expectations and exact file bytes. */
export function createReadinessArtifactsV1(context: ReadinessReceiptContext, input: {
  binding: ReadinessPlanBindingV1;
  execution: ReadinessExecutionV1;
}): ReadinessArtifactPairV1 & { descriptorJson: string; executionJson: string } {
  object(input, ["binding", "execution"]);
  object(input.binding, ["schemaVersion", "planSha256", "source"]);
  const projection = createReadinessValidationProjectionV1(context);
  if (input.binding.schemaVersion !== 1 || input.binding.planSha256 !== projection.originalPlanSha256) invalid("producer plan binding");
  const executionJson = serializeReadinessExecutionV1(context, input.execution);
  const source = { ...structuredClone(input.binding.source), sourceRoot: context.redact(input.binding.source.sourceRoot) };
  const descriptor: ReadinessValidationDescriptorV1 = {
    schemaVersion: 1, kind: "harvey-audit-readiness-validation", planSchemaVersion: 1,
    ...projection, source,
    execution: { schemaVersion: 1, kind: "harvey-audit-readiness-execution", encoding: "utf8", sha256: hash(executionJson), bytes: Buffer.byteLength(executionJson, "utf8") },
    proof: { ...PROOF },
  };
  const descriptorJson = JSON.stringify(canonical(descriptor), null, 2) + "\n";
  const validated = parseReadinessArtifactsV1({ descriptorJson, executionJson }, { originalPlanSha256: input.binding.planSha256 });
  return immutable({ descriptor: validated.descriptor, execution: validated.execution, descriptorSha256: validated.descriptorSha256, executionSha256: validated.executionSha256, descriptorJson, executionJson });
}
