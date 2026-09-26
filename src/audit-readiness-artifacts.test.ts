import { createHash } from "node:crypto";
import fs from "node:fs";
import fsPromises, { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import childProcess from "node:child_process";
import http from "node:http";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverReadinessPlan, serializeReadinessPlanV1, type ReadinessPlanV1 } from "./audit-readiness.js";
import { bindReadinessPlanV1 } from "./audit-readiness-authority.js";
import { captureSourceSentinel, type SourceSentinelV1 } from "./disposable-target.js";
import {
  closeReadinessExecutionV1, createReadinessNotAssessedReceipt, createReadinessReceiptContext,
  createReadinessValidationProjectionV1, prepareReadinessPlanExportV1, serializeReadinessExecutionV1, validateReadinessExecutionV1,
  type ReadinessExecutionV1,
} from "./audit-readiness-receipts.js";
import { createReadinessArtifactsV1, parseReadinessArtifactsV1, type ReadinessValidationDescriptorV1 } from "./audit-readiness-artifacts.js";

const roots: string[] = [];
const CANARY = "artifact-approved-canary-not-a-live-secret-ff53bc1";
const digest = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
afterEach(async () => { vi.restoreAllMocks(); for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

function produce(plan: ReadinessPlanV1, source: SourceSentinelV1, value: string) {
  const binding = bindReadinessPlanV1(plan, source);
  const context = createReadinessReceiptContext(plan, {
    approvedEnvNames: ["UNSET_OPTION", "ARTIFACT_TOKEN"], environment: { ARTIFACT_TOKEN: value },
  });
  const receipts = plan.stages.map((stage) => createReadinessNotAssessedReceipt(context, stage.id, {
    reasonCode: "fixture-withheld", reason: `The fixture withheld execution ${value}.`, provenance: [`operator fixture ${value}`], falsifier: `Authorize after reviewing ${value}.`,
    assessedAt: "2026-09-25T00:00:00.000Z",
    blockedByStageIds: stage.prerequisiteStageIds,
  }));
  const execution = closeReadinessExecutionV1(context, {
    binding, receipts, cleanup: { status: "not-required", root: null, reason: "This schema fixture does no target process work." },
  });
  return { plan, binding, context, ...createReadinessArtifactsV1(context, { binding, execution }) };
}

async function fixture(value = CANARY, scriptValue = value, options: { member?: string; excluded?: boolean; unreadable?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "harvey-artifact-contract-")); roots.push(root);
  const member = options.member ?? "child";
  await mkdir(join(root, "packages", member), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({
    name: "artifact-fixture", packageManager: "npm@10.9.2", workspaces: ["packages/*", "missing/*", ...(options.excluded ? [`!packages/${member}`] : [])],
    scripts: { postinstall: "prisma generate", build: `node build.cjs # ${scriptValue}`, test: "node test.cjs" },
  }));
  await writeFile(join(root, "packages", member, "package.json"), options.unreadable ? "{invalid" : JSON.stringify({ name: "child", scripts: { codegen: "node generate.cjs", build: "node build.cjs" } }));
  await writeFile(join(root, "package-lock.json"), '{"lockfileVersion":3,"packages":{}}');
  const source = await captureSourceSentinel(root);
  return produce(discoverReadinessPlan(root), source, value);
}

function replaceExecution(pair: ReturnType<typeof produce>, execution: unknown, descriptorInput = pair.descriptor) {
  const executionJson = JSON.stringify(execution, null, 2) + "\n";
  const descriptor = structuredClone(descriptorInput);
  descriptor.execution.sha256 = digest(executionJson);
  descriptor.execution.bytes = Buffer.byteLength(executionJson);
  return { executionJson, descriptorJson: JSON.stringify(descriptor, null, 2) + "\n" };
}

describe("producer-owned readiness artifacts", () => {
  it("round trips into a fresh module with no private context or environment values", async () => {
    const pair = await fixture();
    expect(pair.executionJson).not.toContain(CANARY);
    expect(pair.descriptorJson).not.toContain(CANARY);
    expect(pair.descriptor.originalPlanSha256).toBe(digest(serializeReadinessPlanV1(pair.plan)));
    expect(pair.descriptorSha256).toBe(digest(pair.descriptorJson));
    expect(pair.descriptor.originalPlanSha256).not.toBe(pair.descriptorSha256);
    vi.resetModules();
    const freshArtifacts = await import("./audit-readiness-artifacts.js");
    const freshReceipts = await import("./audit-readiness-receipts.js");
    expect(() => freshReceipts.validateReadinessExecutionV1(pair.context, pair.execution)).toThrow(/unknown receipt context/);
    const parsed = freshArtifacts.parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }, {
      descriptorSha256: pair.descriptorSha256, executionSha256: pair.executionSha256,
      originalPlanSha256: pair.binding.planSha256, sourceContentSha256: pair.binding.source.contentSha256, originalPlan: pair.plan,
    });
    expect(parsed.execution).toEqual(pair.execution);
    expect(parsed.descriptor.environment).toEqual({ approvedNames: ["ARTIFACT_TOKEN", "UNSET_OPTION"], presentNames: ["ARTIFACT_TOKEN"] });
    expect(parsed.matchedExpectations).toEqual(["descriptorSha256", "executionSha256", "originalPlanSha256", "sourceContentSha256", "originalPlan"]);
    expect(parsed.proof).toBe("schema-and-declared-bindings");
    expect(parsed.descriptor.proof).toMatchObject({ executionAuthority: "none", executionAuthenticity: "not-established", workloadContainment: "not-established-by-artifact-validation" });
    expect(Object.isFrozen(parsed.execution.stages[0])).toBe(true);
  });

  it("performs offline import with filesystem, child-process, network and environment access forbidden", async () => {
    const pair = await fixture();
    const refuse = () => { throw new Error("Offline import attempted external work"); };
    const spies = [
      vi.spyOn(fs, "readFileSync").mockImplementation(refuse), vi.spyOn(fs, "existsSync").mockImplementation(refuse),
      vi.spyOn(fsPromises, "readFile").mockImplementation(refuse), vi.spyOn(fsPromises, "stat").mockImplementation(refuse),
      vi.spyOn(childProcess, "spawn").mockImplementation(refuse), vi.spyOn(childProcess, "execFile").mockImplementation(refuse),
      vi.spyOn(http, "request").mockImplementation(refuse), vi.spyOn(https, "request").mockImplementation(refuse),
    ];
    const env = Object.getOwnPropertyDescriptor(process, "env")!;
    let first: ReturnType<typeof parseReadinessArtifactsV1>;
    let second: ReturnType<typeof parseReadinessArtifactsV1>;
    try {
      Object.defineProperty(process, "env", { configurable: true, get: refuse });
      first = parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }, { originalPlan: pair.plan });
      second = parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson });
    } finally { Object.defineProperty(process, "env", env); }
    expect(first.execution).toEqual(second.execution);
    for (const spy of spies) { expect(spy).not.toHaveBeenCalled(); spy.mockRestore(); }
  });

  it.each([CANARY, "q", "npm"])("redacts supported free-text sinks for a known value %s when identities stay safe", async (value) => {
    const pair = await fixture(value);
    const build = pair.descriptor.stages.find((stage) => stage.workspaceId === "workspace:root" && stage.kind === "build")!;
    const script = build.provenance.find((source) => source.rawScript !== undefined)!.rawScript!;
    expect(script).not.toContain(value);
    expect(script).toContain("[REDACTED]");
    expect(pair.descriptor.stages.map((stage) => stage.id)).toEqual(pair.plan.stages.map((stage) => stage.id).sort((a, b) => a.localeCompare(b, "en")));
    expect(pair.descriptor.originalPlanSha256).toBe(pair.binding.planSha256);
    expect(parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }).execution).toEqual(pair.execution);
    if (value === "npm" && build.assessment === "planned") expect(build.command.bin).toBe("[REDACTED]");
  });

  it.each([
    { member: CANARY }, { member: CANARY, excluded: true }, { member: CANARY, unreadable: true },
  ])("refuses known-value identities across every public artifact boundary: %j", async (options) => {
    // Register after a valid packet exists to test revalidation of stale, formerly safe values.
    const pair = await fixture("", "ordinary script", options);
    const known = createReadinessReceiptContext(pair.plan, { approvedEnvNames: ["ARTIFACT_TOKEN"], environment: { ARTIFACT_TOKEN: CANARY } });
    pair.context.registerSecret(CANARY);
    const refusal = "Invalid readiness execution evidence: producer-known value in identity.";
    for (const context of [known, pair.context]) {
      const attempts = [
        () => createReadinessValidationProjectionV1(context),
        () => validateReadinessExecutionV1(context, pair.execution),
        () => serializeReadinessExecutionV1(context, pair.execution),
        () => createReadinessArtifactsV1(context, { binding: pair.binding, execution: pair.execution }),
        () => closeReadinessExecutionV1(context, { binding: pair.binding, receipts: pair.execution.stages, cleanup: pair.execution.cleanup }),
        () => createReadinessNotAssessedReceipt(context, pair.plan.stages[0]!.id, {
          reasonCode: "withheld", reason: "No target execution.", provenance: ["schema fixture"], falsifier: "Review the identity.",
        }),
      ];
      for (const attempt of attempts) {
        expect(attempt).toThrow(new Error(refusal));
        try { attempt(); } catch (error) { expect(String(error)).not.toContain(CANARY); }
      }
      const withheld = prepareReadinessPlanExportV1(context);
      expect(withheld).toMatchObject({ status: "withheld", reasonCode: "approved-value-in-plan" });
      expect(withheld).not.toHaveProperty("json");
      expect(JSON.stringify(withheld)).not.toContain(CANARY);
    }
  });

  it("refuses short-value and nested identity collisions instead of exempting typed strings", async () => {
    const pair = await fixture("", "ordinary script");
    const root = pair.descriptor.workspaces.find((workspace) => workspace.id === "workspace:root")!;
    const implicit = pair.descriptor.stages.find((stage) => stage.assessment === "implicit")!;
    const values = ["a", "ARTIFACT_TOKEN", root.id, root.installStageId, root.stageIds[0]!, pair.descriptor.applicationWorkspaceIds[0]!,
      implicit.prerequisiteStageIds[0]!, implicit.assessment === "implicit" ? implicit.fulfilledByStageId : "unreachable"];
    for (const value of values) {
      const context = createReadinessReceiptContext(pair.plan, { approvedEnvNames: ["ARTIFACT_TOKEN"], environment: { ARTIFACT_TOKEN: value } });
      expect(() => createReadinessValidationProjectionV1(context)).toThrow(/producer-known value in identity/);
      expect(() => serializeReadinessExecutionV1(context, pair.execution)).toThrow(/producer-known value in identity/);
      if (value !== "ARTIFACT_TOKEN") expect(prepareReadinessPlanExportV1(context).status).toBe("withheld");
    }
  });

  it("withholds observation scope selectors containing known values without rewriting their scope", async () => {
    const pair = await fixture("", "ordinary script", { excluded: true });
    for (const value of ["unresolved-glob", "missing/*", "!packages/child", "package.json", "negative-workspace-glob"]) {
      const context = createReadinessReceiptContext(pair.plan, { approvedEnvNames: ["ARTIFACT_TOKEN"], environment: { ARTIFACT_TOKEN: value } });
      expect(() => createReadinessValidationProjectionV1(context)).toThrow(/producer-known value in identity/);
      expect(() => serializeReadinessExecutionV1(context, pair.execution)).toThrow(/producer-known value in identity/);
      expect(() => createReadinessArtifactsV1(context, { binding: pair.binding, execution: pair.execution })).toThrow(/producer-known value in identity/);
      expect(prepareReadinessPlanExportV1(context).status).toBe("withheld");
    }
    for (const key of ["glob", "sourcePath"] as const) {
      const plan = structuredClone(pair.plan);
      const observation = plan.workspaceInventory.observations.find((row) => row.kind === "unresolved-glob")!;
      if (observation.kind !== "unresolved-glob") throw new Error("expected unresolved fixture glob");
      observation[key] = `scope-${CANARY}`;
      const context = createReadinessReceiptContext(plan, { approvedEnvNames: ["ARTIFACT_TOKEN"], environment: { ARTIFACT_TOKEN: CANARY } });
      expect(() => createReadinessValidationProjectionV1(context)).toThrow(new Error("Invalid readiness execution evidence: producer-known value in identity."));
      expect(prepareReadinessPlanExportV1(context).status).toBe("withheld");
    }
  });

  it("refuses known values in supplied nested authority identities at receipt and execution boundaries", async () => {
    const pair = await fixture();
    const stage = pair.plan.stages.find((row) => row.kind === "build")!;
    const authority = {
      stageId: stage.id, decision: "denied" as const, effect: "unknown" as const,
      source: "schema fixture", reasonCode: "withheld", reason: "No target execution.", falsifier: "Review the stage.",
      requiredEnvNames: [] as string[], approvedEnvNames: [...pair.descriptor.environment.approvedNames], lifecycle: [],
    };
    for (const identity of [
      { ...authority, stageId: `stage:workspace:${CANARY}:build` as const },
      { ...authority, requiredEnvNames: [CANARY] },
      { ...authority, approvedEnvNames: [CANARY] },
    ]) {
      expect(() => createReadinessNotAssessedReceipt(pair.context, stage.id, {
        reasonCode: authority.reasonCode, reason: authority.reason, falsifier: authority.falsifier, provenance: ["schema fixture"], authority: identity,
      })).toThrow(/producer-known value in identity/);
    }
    const execution = structuredClone(pair.execution);
    execution.stages.find((row) => row.stageId === stage.id)!.authority = { ...authority, requiredEnvNames: [CANARY] };
    expect(() => serializeReadinessExecutionV1(pair.context, execution)).toThrow(/producer-known value in identity/);
  });

  it("withholds unsafe raw plan bytes and preserves the original schema for a safe export", async () => {
    const unsafe = await fixture();
    expect(serializeReadinessPlanV1(unsafe.plan)).toContain(CANARY);
    const withheld = prepareReadinessPlanExportV1(unsafe.context);
    expect(withheld).toMatchObject({ status: "withheld", reasonCode: "approved-value-in-plan" });
    expect(withheld).not.toHaveProperty("json");
    expect(JSON.stringify(withheld)).not.toContain(CANARY);
    const safe = await fixture(CANARY, "ordinary public script text");
    const ready = prepareReadinessPlanExportV1(safe.context);
    expect(ready).toEqual({ status: "ready", json: serializeReadinessPlanV1(safe.plan) + "\n" });
  });

  it("binds exact execution bytes and caller-pinned descriptor bytes separately", async () => {
    const pair = await fixture();
    const input = { descriptorJson: pair.descriptorJson, executionJson: pair.executionJson };
    expect(() => parseReadinessArtifactsV1({ ...input, executionJson: input.executionJson + " " })).toThrow(/digest\/bytes/);
    expect(() => parseReadinessArtifactsV1({ ...input, executionJson: input.executionJson.slice(0, -1) })).toThrow(/digest\/bytes/);
    const descriptor = structuredClone(pair.descriptor); descriptor.execution.bytes++;
    expect(() => parseReadinessArtifactsV1({ ...input, descriptorJson: JSON.stringify(descriptor) })).toThrow(/digest\/bytes/);
    expect(() => parseReadinessArtifactsV1({ ...input, descriptorJson: input.descriptorJson + " " }, { descriptorSha256: pair.descriptorSha256 })).toThrow(/caller expectation/);
    expect(() => parseReadinessArtifactsV1(input, { executionSha256: "0".repeat(64) })).toThrow(/caller expectation/);
    expect(() => parseReadinessArtifactsV1(input, { originalPlanSha256: "0".repeat(64) })).toThrow(/caller expectation/);
  });

  it("rejects producer and offline source substitution even when a replacement source is schema-valid", async () => {
    const pair = await fixture();
    const binding = structuredClone(pair.binding); binding.source.contentSha256 = "0".repeat(64);
    expect(() => createReadinessArtifactsV1(pair.context, { binding, execution: pair.execution })).toThrow(/expected source binding/);
    const execution = structuredClone(pair.execution); execution.source.contentSha256 = "0".repeat(64);
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, execution))).toThrow(/expected source binding/);
    const descriptor = structuredClone(pair.descriptor); descriptor.source = execution.source;
    const substituted = replaceExecution(pair, execution, descriptor);
    expect(() => parseReadinessArtifactsV1(substituted, { sourceContentSha256: pair.binding.source.contentSha256 })).toThrow(/caller expectation/);
    expect(() => parseReadinessArtifactsV1(substituted, { descriptorSha256: pair.descriptorSha256 })).toThrow(/caller expectation/);
    // Replacing an entire unanchored set can be self-consistent; it never becomes authentic.
    expect(parseReadinessArtifactsV1(substituted).descriptor.proof.executionAuthenticity).toBe("not-established");
  });

  it("rejects unrelated original plans, unsupported options, and false Git expectations", async () => {
    const pair = await fixture();
    const plan = structuredClone(pair.plan); plan.stages[0]!.provenance[0]!.detail += " changed";
    const input = { descriptorJson: pair.descriptorJson, executionJson: pair.executionJson };
    expect(() => parseReadinessArtifactsV1(input, { originalPlan: plan })).toThrow(/original plan binding/);
    expect(() => parseReadinessArtifactsV1(input, { originalPlan: { schemaVersion: 2 } })).toThrow(/original plan/);
    const descriptor = structuredClone(pair.descriptor); descriptor.stages[0]!.configurationSha256 = "0".repeat(64);
    expect(() => parseReadinessArtifactsV1({ ...input, descriptorJson: JSON.stringify(descriptor) }, { originalPlan: pair.plan })).toThrow(/original stage configuration/);
    expect(() => parseReadinessArtifactsV1(input, { sourceGitHead: null })).toThrow(/caller expectation/);
    expect(() => parseReadinessArtifactsV1(input, { environment: {} } as never)).toThrow(/object fields/);
    expect(() => parseReadinessArtifactsV1({ ...input, context: pair.context } as never)).toThrow(/object fields/);
  });

  it("retains one shared install receipt, all workspace references, and plan observations", async () => {
    const pair = await fixture();
    const parsed = parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson });
    const install = parsed.execution.stages.filter((stage) => stage.kind === "install");
    expect(install).toHaveLength(1);
    expect(parsed.descriptor.workspaces).toHaveLength(2);
    expect(parsed.descriptor.workspaces.flatMap((workspace) => workspace.stageIds)).toHaveLength(12);
    expect(parsed.descriptor.workspaces.every((workspace) => workspace.stageIds.includes(install[0]!.stageId))).toBe(true);
    expect(parsed.descriptor.stages).toHaveLength(11);
    expect(parsed.execution.stages).toHaveLength(11);
    expect(parsed.execution.stages.filter((stage) => stage.execution.kind === "process")).toHaveLength(0);
    expect(parsed.descriptor.workspaceObservations).toContainEqual(expect.objectContaining({ kind: "unresolved-glob", glob: "missing/*" }));
  });

  it("rejects orphan application identities and binds the original application population", async () => {
    const pair = await fixture();
    const descriptor = structuredClone(pair.descriptor);
    descriptor.applicationWorkspaceIds = ["workspace:never-enumerated"];
    const orphan = replaceExecution(pair, pair.execution, descriptor);
    expect(() => parseReadinessArtifactsV1(orphan)).toThrow(/application workspace population/);
    expect(() => parseReadinessArtifactsV1(orphan, { originalPlan: pair.plan })).toThrow(/application workspace population/);
    for (const ids of [[], ["workspace:root"]] as ReadinessValidationDescriptorV1["applicationWorkspaceIds"][]) {
      descriptor.applicationWorkspaceIds = ids;
      const replaced = replaceExecution(pair, pair.execution, descriptor);
      // Original-plan anchors additionally bind discovery completeness; membership validates the supplied population.
      expect(parseReadinessArtifactsV1(replaced).descriptor.proof.executionAuthenticity).toBe("not-established");
      expect(() => parseReadinessArtifactsV1(replaced, { originalPlan: pair.plan })).toThrow(/original workspace identity population/);
    }
  });

  it("preserves explicit negative-exclusion application evidence and legitimate empty populations", async () => {
    const empty = await fixture(CANARY, "ordinary script", { excluded: true });
    expect(empty.descriptor.applicationWorkspaceIds).toEqual([]);
    expect(parseReadinessArtifactsV1({ descriptorJson: empty.descriptorJson, executionJson: empty.executionJson }, { originalPlan: empty.plan }).descriptor.workspaces).toHaveLength(1);
    const plan = structuredClone(empty.plan);
    // V1 also admits the historical app census when an explicit negative-glob row explains it.
    plan.workspaceInventory.applicationWorkspaceIds = ["workspace:packages/child"];
    const pair = produce(plan, empty.binding.source, CANARY);
    expect(parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }, { originalPlan: plan }).descriptor.applicationWorkspaceIds).toEqual(["workspace:packages/child"]);
    const edits: ((d: ReadinessValidationDescriptorV1) => void)[] = [
      (d) => { d.workspaceObservations = d.workspaceObservations.filter((row) => row.kind !== "excluded"); },
      (d) => { const row = d.workspaceObservations.find((row) => row.kind === "excluded")!; if (row.kind === "excluded") row.reason = "implicit-directory-policy"; },
      (d) => { const row = d.workspaceObservations.find((row) => row.kind === "excluded")!; if (row.kind === "excluded") row.path = "packages/other/package.json"; },
      (d) => { const row = d.workspaceObservations.find((row) => row.kind === "excluded")!; if (row.kind === "excluded") row.path = "packages/child"; },
      (d) => { const row = d.workspaceObservations.find((row) => row.kind === "excluded")!; if (row.kind === "excluded") row.path = "packages/../child/package.json"; },
    ];
    for (const edit of edits) {
      const descriptor = structuredClone(pair.descriptor); edit(descriptor);
      expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, descriptor))).toThrow(/Invalid readiness artifact/);
    }
    const descriptor = structuredClone(pair.descriptor);
    descriptor.applicationWorkspaceIds = [];
    descriptor.workspaceObservations = descriptor.workspaceObservations.filter((row) => row.kind !== "excluded");
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, descriptor), { originalPlan: plan })).toThrow(/original workspace identity population/);
  });

  it("requires the root workspace and its complete references even when child-only receipts close", async () => {
    const pair = await fixture();
    const descriptor = structuredClone(pair.descriptor);
    const execution = structuredClone(pair.execution);
    descriptor.workspaces = descriptor.workspaces.filter((workspace) => workspace.id !== "workspace:root");
    descriptor.stages = descriptor.stages.filter((stage) => stage.workspaceId !== "workspace:root" || stage.kind === "install");
    execution.stages = execution.stages.filter((stage) => stage.workspaceId !== "workspace:root" || stage.kind === "install");
    expect(descriptor.stages).toHaveLength(6);
    expect(execution.stages).toHaveLength(6);
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, execution, descriptor))).toThrow(/missing root workspace/);
    descriptor.workspaces.push(structuredClone(pair.descriptor.workspaces.find((workspace) => workspace.id === "workspace:root")!));
    descriptor.workspaces.sort((a, b) => a.id.localeCompare(b.id, "en"));
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, execution, descriptor))).toThrow(/unknown or borrowed workspace stage/);
  });

  it("binds the original observation population and scope selectors while allowing redacted prose", async () => {
    const original = await fixture();
    const plan = structuredClone(original.plan);
    const glob = plan.workspaceInventory.observations.find((row) => row.kind === "unresolved-glob")!;
    if (glob.kind !== "unresolved-glob") throw new Error("expected unresolved fixture glob");
    glob.reason += ` ${CANARY}`;
    const pair = produce(plan, original.binding.source, CANARY);
    expect(pair.descriptor.workspaceObservations).not.toEqual(plan.workspaceInventory.observations);
    expect(pair.descriptorJson).not.toContain(CANARY);
    expect(parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }, { originalPlan: plan }).descriptor.workspaceObservations).toHaveLength(1);
    for (const key of ["glob", "sourcePath", "kind"] as const) {
      const substituted = structuredClone(pair.descriptor);
      const observation = substituted.workspaceObservations[0]!;
      if (observation.kind !== "unresolved-glob") throw new Error("expected unresolved fixture glob");
      if (key === "kind") observation.kind = "invalid-glob";
      else observation[key] = key === "glob" ? "other-unresolved/*" : "other-scope-input.yml";
      expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, substituted), { originalPlan: plan })).toThrow(/original workspace identity population/);
    }
    const removed = structuredClone(pair.descriptor); removed.workspaceObservations = [];
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, removed), { originalPlan: plan })).toThrow(/original workspace identity population/);
    const duplicate = structuredClone(pair.descriptor); duplicate.workspaceObservations.push(duplicate.workspaceObservations[0]!);
    for (const expected of [{}, { originalPlan: plan }]) {
      expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, duplicate), expected)).toThrow(/duplicate workspace observation/);
    }
    const orphan = structuredClone(pair.descriptor);
    orphan.workspaceObservations.push({ kind: "unreadable-manifest", path: "never-enumerated/package.json", reason: "Unproven read failure." });
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, orphan))).toThrow(/unreadable workspace observation population/);
    const extra = structuredClone(pair.descriptor);
    extra.workspaceObservations.push({ kind: "unreadable-manifest", path: "package.json", reason: "Unsupported extra read failure." });
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, extra), { originalPlan: plan })).toThrow(/original workspace identity population/);
    const unsupported = structuredClone(pair.descriptor);
    Object.assign(unsupported.workspaceObservations[0]!, { kind: "unknown-observation" });
    expect(() => parseReadinessArtifactsV1(replaceExecution(pair, pair.execution, unsupported))).toThrow(/workspace observation kind/);
  });

  it("detects config changes hidden by redaction while ignoring presentation and collection order", async () => {
    const first = await fixture();
    const second = await fixture("other-approved-canary-14e5ad9-not-a-live-secret");
    const build = (descriptor: ReadinessValidationDescriptorV1) => descriptor.stages.find((stage) => stage.workspaceId === "workspace:root" && stage.kind === "build")!;
    expect(build(first.descriptor).provenance).toEqual(build(second.descriptor).provenance);
    expect(build(first.descriptor).configurationSha256).not.toBe(build(second.descriptor).configurationSha256);
    const cosmetic = structuredClone(first.plan);
    cosmetic.workspaces.reverse(); cosmetic.stages.reverse();
    for (const stage of cosmetic.stages) { stage.provenance.reverse(); for (const source of stage.provenance) source.detail = "Updated display wording"; }
    const reordered = produce(cosmetic, first.binding.source, CANARY);
    expect(reordered.descriptor.stages.map((stage) => [stage.id, stage.configurationSha256])).toEqual(first.descriptor.stages.map((stage) => [stage.id, stage.configurationSha256]));
    expect(reordered.descriptor.workspaces.map((workspace) => [workspace.id, workspace.stageIds])).toEqual(first.descriptor.workspaces.map((workspace) => [workspace.id, workspace.stageIds]));
  });

  it("rejects descriptor schema, name, graph and reference corruption without guessing a plan", async () => {
    const pair = await fixture();
    const edits: ((descriptor: ReadinessValidationDescriptorV1) => void)[] = [
      (d) => { (d as { schemaVersion: number }).schemaVersion = 2; },
      (d) => { delete (d as Partial<typeof d>).originalPlanSha256; },
      (d) => { Object.assign(d, { environmentValues: {} }); },
      (d) => { d.workspaces.push(d.workspaces[0]!); },
      (d) => { d.workspaces[0]!.stageIds.pop(); },
      (d) => { d.workspaces[0]!.stageIds[0] = "stage:workspace:unknown:build"; d.workspaces[0]!.stageIds.sort(); },
      (d) => { d.stages.push(d.stages[0]!); },
      (d) => { d.stages.pop(); },
      (d) => { d.environment.presentNames.push("UNAPPROVED"); d.environment.presentNames.sort(); },
      (d) => { d.environment.approvedNames.push(d.environment.approvedNames[0]!); },
      (d) => { d.stages[0]!.safety = "non-executable"; },
      (d) => { d.stages[0]!.prerequisiteStageIds.push(d.stages[0]!.id); },
      (d) => { const stage = d.stages.find((row) => row.assessment === "planned")!; if (stage.assessment === "planned") (stage.command as { actualCwd: string | null }).actualCwd = "/tmp"; },
      (d) => { const stage = d.stages.find((row) => row.assessment === "implicit")!; if (stage.assessment === "implicit") stage.fulfilledByStageId = "stage:workspace:root:build"; },
      (d) => { (d.proof as { workloadContainment: string }).workloadContainment = "complete"; },
    ];
    for (const edit of edits) {
      const descriptor = structuredClone(pair.descriptor); edit(descriptor);
      expect(() => parseReadinessArtifactsV1({ descriptorJson: JSON.stringify(descriptor), executionJson: pair.executionJson })).toThrow(/Invalid readiness/);
    }
  });

  it("keeps both live and offline paths strict after recomputing a mutated file's digest", async () => {
    const pair = await fixture();
    const edits: ((execution: ReadinessExecutionV1) => void)[] = [
      (e) => { (e as { schemaVersion: number }).schemaVersion = 2; },
      (e) => { e.stages.pop(); },
      (e) => { e.stages.push(e.stages[0]!); },
      (e) => { e.stages.reverse(); },
      (e) => { e.planSha256 = "0".repeat(64); },
      (e) => { e.stages[0]!.workspaceId = "workspace:unknown"; },
      (e) => { e.stages[0]!.environment.approvedNames = []; },
      (e) => { e.stages[0]!.environment.presentNames = []; },
      (e) => { e.stages[0]!.provenance[0]!.detail += " altered"; },
      (e) => { e.stages[0]!.command!.args.push("extra"); },
      (e) => { e.stages[0]!.command!.actualCwd = "/tmp"; },
      (e) => { Object.assign(e.stages[0]!, { env: { TOKEN: "forbidden" } }); },
      (e) => { const stage = e.stages[0]!; if (stage.status === "not-assessed") stage.diagnostic.provenance = []; },
      (e) => { const stage = e.stages[0]!; if (stage.status === "not-assessed") stage.blockedByStageIds = [stage.stageId]; },
      (e) => { const stage = e.stages[0]!; if (stage.execution.kind === "not-run") stage.execution.assessedAt = "yesterday"; },
      (e) => { e.status = "passed"; },
      (e) => { e.cleanup.root = "/tmp"; },
    ];
    for (const edit of edits) {
      const execution = structuredClone(pair.execution); edit(execution);
      expect(() => validateReadinessExecutionV1(pair.context, execution)).toThrow(/Invalid readiness/);
      expect(() => parseReadinessArtifactsV1(replaceExecution(pair, execution))).toThrow(/Invalid readiness/);
    }
  });
});
