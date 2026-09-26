import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverReadinessPlan, type ReadinessStageV1 } from "./audit-readiness.js";
import { admitReadinessStage, bindReadinessPlanV1, createReadinessAdmission, type ReadinessSpawnRequest, type ReadinessStageAdmission } from "./audit-readiness-authority.js";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget } from "./disposable-target.js";
import { createReadinessArtifactsV1, parseReadinessArtifactsV1 } from "./audit-readiness-artifacts.js";
import { createBoundedProcessRunner } from "./bounded-process.js";
import {
  closeReadinessExecutionV1, createReadinessFailureReceipt, createReadinessImplicitReceipt, createReadinessNotAssessedReceipt,
  createReadinessProcessReceipt, createReadinessReceiptContext, prepareReadinessSpawn,
  serializeReadinessExecutionV1, validateReadinessExecutionV1,
  type ReadinessProcessEvidenceV1, type ReadinessProcessLimitsV1, type ReadinessReceiptContext, type StageReceiptV1,
} from "./audit-readiness-receipts.js";

const roots: string[] = [];
const limits: ReadinessProcessLimitsV1 = { timeoutMs: 3000, killGraceMs: 100, closeGraceMs: 100, headBytes: 256, tailBytes: 256 };
const secret = "dummy-receipt-canary-6dd7bd319f-not-a-live-credential";
type Admitted = Extract<ReadinessStageAdmission, { status: "admitted" }>;
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

async function fixture(mode: "success" | "failure" | "timeout" | "truncated" | "missing" | "boundary" = "success", implicit = false) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "harvey-receipt-test-")));
  roots.push(root);
  const source = join(root, "source");
  const scratch = join(root, "scratch");
  const tools = join(root, "tools");
  await Promise.all([mkdir(source), mkdir(scratch), mkdir(tools)]);
  await writeFile(join(source, "package.json"), JSON.stringify({ name: "receipt-fixture", version: "1.0.0", packageManager: "npm@10.9.2", scripts: {
    ...(implicit ? { postinstall: "prisma generate" } : { codegen: "node worker.cjs" }),
    build: "node worker.cjs", typecheck: "node worker.cjs", lint: "node worker.cjs", test: `node worker.cjs # ${secret}`,
  } }));
  await writeFile(join(source, "package-lock.json"), JSON.stringify({ name: "receipt-fixture", version: "1.0.0", lockfileVersion: 3, packages: {} }));
  await writeFile(join(source, "worker.cjs"), `
    const fs = require('node:fs');
    fs.writeFileSync('physical-stage-ran', 'spawned');
    const testing = true;
    if (testing && ${JSON.stringify(mode)} === 'boundary') {
      process.stdout.write('H'.repeat(244) + process.env.RECEIPT_TOKEN + 'M'.repeat(2048) + process.env.RECEIPT_TOKEN + 'Z'.repeat(233) + 'STDOUT-TAIL');
      process.stderr.write('H'.repeat(244) + process.env.RECEIPT_TOKEN + 'M'.repeat(2048) + process.env.RECEIPT_TOKEN + 'Z'.repeat(226) + 'FINAL-STDERR-TAIL');
    } else {
      process.stdout.write('BEGIN ' + process.env.RECEIPT_TOKEN + ' STDOUT-END\\n');
      process.stderr.write('ERROR ' + process.env.RECEIPT_TOKEN + ' ');
      if (testing && ${JSON.stringify(mode)} === 'truncated') {
        process.stdout.write('X'.repeat(2048) + process.env.RECEIPT_TOKEN + ' STDOUT-TAIL');
        process.stderr.write('Y'.repeat(2048) + process.env.RECEIPT_TOKEN + ' FINAL-STDERR-TAIL');
      } else process.stderr.write('FINAL-STDERR-TAIL');
    }
    if (testing && ${JSON.stringify(mode)} === 'failure') process.exitCode = 19;
    if (testing && ${JSON.stringify(mode)} === 'timeout') {
      process.on('SIGTERM', () => { process.stderr.write(' ' + process.env.RECEIPT_TOKEN + ' FINAL-TIMEOUT-TAIL'); process.exit(7); });
      setInterval(() => {}, 1000);
    }
  `);
  if (mode !== "missing") {
    await writeFile(join(tools, "npm"), `#!${process.execPath}\nrequire(require('node:path').join(process.cwd(), 'worker.cjs'));\n`);
    await chmod(join(tools, "npm"), 0o755);
  }
  const before = await captureSourceSentinel(source);
  const plan = discoverReadinessPlan(source);
  const binding = bindReadinessPlanV1(plan, before);
  const context = createReadinessReceiptContext(plan, { approvedEnvNames: ["RECEIPT_TOKEN"], environment: { RECEIPT_TOKEN: secret } });
  const admission = createReadinessAdmission(plan, binding, {
    allowTargetInstall: true,
    stageAuthorizations: plan.stages.filter((stage) => stage.assessment === "planned").map((stage) => ({
      stageId: stage.id, effect: stage.kind === "install" ? "target-install" : "disposable-local",
      source: `operator fixture approval ${secret}`, reason: "Only the disposable fixture is touched.", falsifier: "The child touches an external service or original source.",
    })),
    approvedEnvNames: ["RECEIPT_TOKEN"], environment: { RECEIPT_TOKEN: secret }, toolchainPath: tools, registerSecret: context.registerSecret,
  });
  const created = await createDisposableTarget(source, { tempParent: scratch });
  if (created.status !== "ready") throw new Error("fixture target unavailable");
  return { root, source, plan, binding, context, admission, target: created.target, mode };
}

/** This physical native helper proves only its own process group, never readiness containment. */
async function observe(request: ReadinessSpawnRequest, context: ReadinessReceiptContext, outputLimits = limits): Promise<ReadinessProcessEvidenceV1> {
  return createBoundedProcessRunner().run(request, {
    ...outputLimits, output: { headBytes: outputLimits.headBytes, tailBytes: outputLimits.tailBytes }, redact: context.redact,
  });
}

async function execute(f: Awaited<ReturnType<typeof fixture>>, outputLimits = limits): Promise<StageReceiptV1[]> {
  const install = f.plan.stages.find((row) => row.kind === "install")!;
  const admission = await admitReadinessStage(f.admission, install.id, f.target);
  if (admission.status !== "admitted") throw new Error("fixture install admission missing");
  const result = await observe(prepareReadinessSpawn(f.context, admission), f.context, outputLimits);
  const receipt = createReadinessProcessReceipt(f.context, admission, result, outputLimits);
  return withheld(f).map((row) => row.stageId === install.id ? receipt : row);
}

/** SCHEMA ONLY: invented containment facts exercise validation; no container or target is run. */
function schemaOnlyContainedProcess(): ReadinessProcessEvidenceV1 {
  const at = new Date().toISOString();
  const stream = (head: string) => ({ bytes: Buffer.byteLength(head), sha256: createHash("sha256").update(head).digest("hex"), head, tail: "", headBytes: Buffer.byteLength(head), tailBytes: 0, omittedBytes: 0, truncated: false, redactionTruncated: false, complete: true });
  return {
    state: "exited", succeeded: true, pid: 2, queuedAt: at, startedAt: at, spawnedAt: at, firstByteAt: at, endedAt: at,
    queueDurationMs: 0, durationMs: 0, fromFirstByteMs: 0, exit: { at, code: 0, signal: null }, close: { at, code: 0, signal: null }, errors: [],
    termination: { reason: null, attempts: [], tree: "absent", stdioForcedClosed: false },
    stdout: stream("schema-only output"), stderr: stream("schema-only stderr"),
    containment: {
      kind: "docker-pid-namespace", imageId: `sha256:${"a".repeat(64)}`, containerId: "b".repeat(64), leaseName: `harvey-readiness-${"c".repeat(32)}`,
      runtimeVersion: "28.5.1", apiVersion: "1.51", namespace: "terminated", targetWork: "begun", terminalObservation: { at, running: false, pid: 0 },
      metadata: "verified", cleanup: "removed", isolationVerified: true,
      isolation: { privatePidNamespace: true, network: "none", noNewPrivileges: true, capDrop: "ALL", observerCapabilities: ["SETUID", "SETGID"], targetUid: 1000, targetGid: 1000, mountScope: "disposable-root-only", rootfs: "private-writable-overlay" },
      targetIdentity: { uid: 1000, gid: 1000, capEff: "0000000000000000", noNewPrivileges: true }, observerNodeVersion: "v24.13.0",
    },
  };
}

async function schemaOnlyReceipts(f: Awaited<ReturnType<typeof fixture>>): Promise<StageReceiptV1[]> {
  const receipts: StageReceiptV1[] = [];
  for (const kind of ["install", "codegen", "build", "typecheck", "lint", "test"] as const) {
    const stage = f.plan.stages.find((row) => row.kind === kind)!;
    if (stage.assessment === "implicit") receipts.push(createReadinessImplicitReceipt(f.context, stage.id, receipts.find((row) => row.stageId === stage.fulfilledByStageId)!));
    else {
      const admission = await admitReadinessStage(f.admission, stage.id, f.target);
      if (admission.status !== "admitted") throw new Error("schema fixture admission missing");
      prepareReadinessSpawn(f.context, admission);
      receipts.push(createReadinessProcessReceipt(f.context, admission, schemaOnlyContainedProcess(), limits));
    }
  }
  return receipts;
}

function withheld(f: Awaited<ReturnType<typeof fixture>>): StageReceiptV1[] {
  return f.plan.stages.map((stage) => createReadinessNotAssessedReceipt(f.context, stage.id, {
    reasonCode: "operator-withheld", reason: `Execution was withheld ${secret}.`, provenance: [`operator decision ${secret}`], falsifier: "Authorize the stage after reviewing its effects.",
  }));
}

function processStage(receipts: StageReceiptV1[], kind: ReadinessStageV1["kind"] = "install") {
  const receipt = receipts.find((row) => row.kind === kind)!;
  if (receipt.execution.kind !== "process") throw new Error("expected a physical process receipt");
  return receipt;
}

/** Rebind the file hash so malformed lifecycle facts must fail the shared evidence core itself. */
function importChanged(f: Awaited<ReturnType<typeof fixture>>, original: ReturnType<typeof closeReadinessExecutionV1>, changed = original) {
  const pair = createReadinessArtifactsV1(f.context, { binding: f.binding, execution: original });
  const executionJson = JSON.stringify(changed, null, 2) + "\n";
  const descriptor = structuredClone(pair.descriptor);
  descriptor.execution.sha256 = createHash("sha256").update(executionJson).digest("hex");
  descriptor.execution.bytes = Buffer.byteLength(executionJson);
  return parseReadinessArtifactsV1({ descriptorJson: JSON.stringify(descriptor), executionJson });
}

function docker(process: ReadinessProcessEvidenceV1) {
  if (process.containment.kind !== "docker-pid-namespace") throw new Error("expected schema-only Docker evidence");
  return process.containment;
}

function noTargetFacts(process: ReadinessProcessEvidenceV1): void {
  process.succeeded = false; process.pid = null; process.spawnedAt = null; process.exit = null; process.close = null;
  process.firstByteAt = null; process.fromFirstByteMs = null;
  for (const stream of [process.stdout, process.stderr]) Object.assign(stream, { bytes: 0, sha256: createHash("sha256").digest("hex"), head: "", tail: "", headBytes: 0, tailBytes: 0, omittedBytes: 0, truncated: false, redactionTruncated: false, complete: false });
}

describe("schema-only contained receipt guards (no container execution)", () => {
  it("requires complete exact containment proof in both live and offline validation", async () => {
    const f = await fixture();
    const receipts = await schemaOnlyReceipts(f);
    const original = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    expect(original.status).toBe("passed");
    expect(importChanged(f, original).execution).toEqual(original);
    const edits: [string, (p: ReadinessProcessEvidenceV1) => void][] = [
      ["missing containment", (p) => { delete (p as Partial<typeof p>).containment; }],
      ["native group cannot substitute for ownership", (p) => { p.containment = { kind: "native-process-group", descendantOwnership: "unproven", groupObservation: "absent" }; }],
      ["unknown arm", (p) => { Object.assign(p.containment, { kind: "imagined-sandbox" }); }],
      ["extra proof field", (p) => { Object.assign(p.containment, { ownershipGuaranteed: true }); }],
      ["mutable image tag", (p) => { docker(p).imageId = "node:latest"; }],
      ["partial container ID", (p) => { docker(p).containerId = "b".repeat(12); }],
      ["unowned lease", (p) => { docker(p).leaseName = "another-container"; }],
      ["missing lease", (p) => { docker(p).leaseName = null; }],
      ["invalid API", (p) => { docker(p).apiVersion = "old"; }],
      ["observer is not target pid", (p) => { p.pid = 1; }],
      ["unverified isolation", (p) => { docker(p).isolationVerified = false; }],
      ["missing terminal proof", (p) => { docker(p).terminalObservation = null; }],
      ["running namespace", (p) => { Object.assign(docker(p).terminalObservation!, { running: true }); }],
      ["nonzero namespace pid", (p) => { Object.assign(docker(p).terminalObservation!, { pid: 17 }); }],
      ["future namespace proof", (p) => { docker(p).terminalObservation!.at = "2099-01-01T00:00:00.000Z"; }],
      ["extra namespace field", (p) => { Object.assign(docker(p).terminalObservation!, { exitCode: 0 }); }],
      ["unknown work", (p) => { docker(p).targetWork = "unknown"; }],
      ["unverified metadata", (p) => { docker(p).metadata = "unavailable"; }],
      ["retained container cannot pass", (p) => { docker(p).cleanup = "retained"; }],
      ["missing target identity", (p) => { docker(p).targetIdentity = null; }],
      ["wrong target UID", (p) => { docker(p).targetIdentity!.uid++; }],
      ["wrong target GID", (p) => { docker(p).targetIdentity!.gid++; }],
      ["root UID", (p) => { docker(p).targetIdentity!.uid = docker(p).isolation.targetUid = 0; }],
      ["root GID", (p) => { docker(p).targetIdentity!.gid = docker(p).isolation.targetGid = 0; }],
      ["target capabilities", (p) => { Object.assign(docker(p).targetIdentity!, { capEff: "0000000000000001" }); }],
      ["target privileges", (p) => { Object.assign(docker(p).targetIdentity!, { noNewPrivileges: false }); }],
      ["missing observer version", (p) => { docker(p).observerNodeVersion = null; }],
      ["extra target identity", (p) => { Object.assign(docker(p).targetIdentity!, { user: "root" }); }],
      ["inconsistent Docker success flag", (p) => { p.succeeded = false; }],
    ];
    for (const key of Object.keys(docker(schemaOnlyContainedProcess()))) edits.push([`missing ${key}`, (p) => { delete (docker(p) as unknown as Record<string, unknown>)[key]; }]);
    for (const [key, bad] of Object.entries({ privatePidNamespace: false, network: "host", noNewPrivileges: false, capDrop: "NONE", observerCapabilities: ["SETUID", "SETGID", "SYS_ADMIN"], mountScope: "host", rootfs: "shared", targetUid: -1, targetGid: "1000" })) {
      edits.push([`altered isolation ${key}`, (p) => { Object.assign(docker(p).isolation, { [key]: bad }); }]);
      edits.push([`missing isolation ${key}`, (p) => { delete (docker(p).isolation as unknown as Record<string, unknown>)[key]; }]);
    }
    for (const [label, edit] of edits) {
      const changed = structuredClone(original);
      const stage = processStage(changed.stages, "test");
      if (stage.execution.kind !== "process") throw new Error("schema fixture process missing");
      edit(stage.execution.process);
      expect(() => validateReadinessExecutionV1(f.context, changed), label).toThrow(/Invalid readiness/);
      expect(() => importChanged(f, original, changed), label).toThrow(/Invalid readiness/);
    }
  });

  it("preserves factual failed, unconfirmed, retained and no-target-work evidence", async () => {
    const f = await fixture();
    const admission = await admitReadinessStage(f.admission, f.plan.stages.find((row) => row.kind === "install")!.id, f.target) as Admitted;
    prepareReadinessSpawn(f.context, admission);
    const variants: ((p: ReadinessProcessEvidenceV1) => void)[] = [
      (p) => { p.succeeded = false; docker(p).cleanup = "retained"; p.errors.push({ phase: "termination", code: "CONTAINER_REMOVAL_UNCONFIRMED" }); },
      (p) => {
        noTargetFacts(p); p.state = "observer-error"; docker(p).metadata = "unavailable"; docker(p).targetWork = "unknown"; docker(p).targetIdentity = null; docker(p).observerNodeVersion = null;
        p.errors.push({ phase: "observer", code: "OBSERVER_METADATA_UNVERIFIED" }); p.termination.stdioForcedClosed = true;
      },
      (p) => {
        noTargetFacts(p); p.state = "termination-unconfirmed";
        Object.assign(docker(p), { containerId: null, namespace: "unconfirmed", targetWork: "unknown", terminalObservation: null, metadata: "unavailable", targetIdentity: null, observerNodeVersion: null, cleanup: "retained" });
        p.termination.tree = "unconfirmed"; p.termination.stdioForcedClosed = true; p.errors.push({ phase: "termination", code: "NAMESPACE_TERMINATION_UNCONFIRMED" });
      },
      (p) => {
        noTargetFacts(p); p.state = "containment-unavailable";
        Object.assign(docker(p), { namespace: "not-started", targetWork: "not-started", metadata: "unavailable", targetIdentity: null, observerNodeVersion: null, isolationVerified: false });
        p.termination.tree = "not-started"; p.errors.push({ phase: "spawn", code: "ABORTED_BEFORE_START" });
      },
      (p) => {
        noTargetFacts(p); p.state = "containment-unavailable";
        p.containment = { kind: "unavailable", reasonCode: "containment-not-configured" }; p.termination.tree = "not-started";
      },
    ];
    const receipts = variants.map((edit) => { const p = schemaOnlyContainedProcess(); edit(p); return createReadinessProcessReceipt(f.context, admission, p, limits); });
    const cleanup = await cleanupDisposableTarget(f.target);
    for (const receipt of receipts) {
      expect(receipt.status).toBe("failed");
      const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: withheld(f).map((row) => row.kind === "install" ? receipt : row), cleanup });
      expect(importChanged(f, execution).execution).toEqual(execution);
      const forged = structuredClone(execution); const row = forged.stages.find((row) => row.kind === "install")!;
      Object.assign(row, { status: "passed" }); delete (row as Partial<Extract<StageReceiptV1, { status: "failed" }>>).diagnostic;
      expect(() => validateReadinessExecutionV1(f.context, forged)).toThrow(/process status mismatch/);
      expect(() => importChanged(f, execution, forged)).toThrow(/process status mismatch/);
    }
  });

  it("binds exact valid proof identities to pinned artifact bytes without claiming authenticity", async () => {
    const f = await fixture();
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: await schemaOnlyReceipts(f), cleanup: await cleanupDisposableTarget(f.target) });
    const pair = createReadinessArtifactsV1(f.context, { binding: f.binding, execution });
    expect(parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson: pair.executionJson }, { executionSha256: pair.executionSha256, descriptorSha256: pair.descriptorSha256 }).proof).toBe("schema-and-declared-bindings");
    for (const edit of [
      (p: ReadinessProcessEvidenceV1) => { docker(p).imageId = `sha256:${"d".repeat(64)}`; },
      (p: ReadinessProcessEvidenceV1) => { docker(p).containerId = "e".repeat(64); },
      (p: ReadinessProcessEvidenceV1) => { docker(p).leaseName = `harvey-readiness-${"f".repeat(32)}`; },
      (p: ReadinessProcessEvidenceV1) => { docker(p).isolation.targetUid = docker(p).targetIdentity!.uid = 1001; },
    ]) {
      const changed = structuredClone(execution);
      const row = processStage(changed.stages);
      if (row.execution.kind !== "process") throw new Error("schema fixture process missing");
      edit(row.execution.process);
      const executionJson = JSON.stringify(changed, null, 2) + "\n";
      const descriptor = structuredClone(pair.descriptor);
      descriptor.execution.sha256 = createHash("sha256").update(executionJson).digest("hex");
      descriptor.execution.bytes = Buffer.byteLength(executionJson);
      const files = { descriptorJson: JSON.stringify(descriptor), executionJson };
      expect(parseReadinessArtifactsV1(files).proof).toBe("schema-and-declared-bindings");
      expect(() => parseReadinessArtifactsV1({ descriptorJson: pair.descriptorJson, executionJson })).toThrow(/digest\/bytes/);
      expect(() => parseReadinessArtifactsV1(files, { executionSha256: pair.executionSha256 })).toThrow(/caller expectation binding/);
      expect(() => parseReadinessArtifactsV1(files, { descriptorSha256: pair.descriptorSha256 })).toThrow(/caller expectation binding/);
    }
  });

  it("refuses late known-value collisions in exact containment identities at every public boundary", async () => {
    const f = await fixture();
    const install = f.plan.stages.find((row) => row.kind === "install")!;
    const admission = await admitReadinessStage(f.admission, install.id, f.target) as Admitted;
    const receipts = await schemaOnlyReceipts(f);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    const proof = docker(schemaOnlyContainedProcess());
    for (const value of [proof.imageId, proof.containerId!, proof.leaseName!, proof.runtimeVersion, proof.apiVersion, proof.observerNodeVersion!, proof.targetIdentity!.capEff]) {
      const context = createReadinessReceiptContext(f.plan, { approvedEnvNames: ["RECEIPT_TOKEN"], environment: { RECEIPT_TOKEN: secret } });
      context.registerSecret(value); prepareReadinessSpawn(context, admission);
      for (const attempt of [
        () => createReadinessProcessReceipt(context, admission, schemaOnlyContainedProcess(), limits),
        () => validateReadinessExecutionV1(context, execution),
        () => serializeReadinessExecutionV1(context, execution),
        () => closeReadinessExecutionV1(context, { binding: f.binding, receipts, cleanup: execution.cleanup }),
        () => createReadinessArtifactsV1(context, { binding: f.binding, execution }),
      ]) expect(attempt).toThrow(new Error("Invalid readiness execution evidence: producer-known value in identity."));
    }
  });
});

describe("versioned receipt closure", () => {
  it("retains real native lifecycle facts but refuses readiness success without containment", async () => {
    const f = await fixture();
    const receipts = await execute(f);
    const cleanup = await cleanupDisposableTarget(f.target);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: [...receipts].reverse(), cleanup });
    expect(execution.status).toBe("failed");
    expect(execution.stages.map((row) => row.stageId)).toEqual(f.plan.stages.map((row) => row.id).sort());
    expect(execution.stages).toHaveLength(6);
    for (const receipt of execution.stages) {
      if (receipt.kind !== "install") { expect(receipt.status).toBe("not-assessed"); continue; }
      expect(receipt).toMatchObject({ status: "failed", diagnostic: { reasonCode: "containment-unproven" } });
      expect(receipt.environment).toEqual({ approvedNames: ["RECEIPT_TOKEN"], presentNames: ["RECEIPT_TOKEN"] });
      expect(receipt.command?.actualCwd).toBe(f.target.targetRoot);
      expect(receipt.toolchain?.observedVersion.status).toBe("not-assessed");
      if (receipt.execution.kind !== "process") throw new Error("missing process evidence");
      expect(receipt.execution.process).toMatchObject({ state: "exited", succeeded: true, exit: { code: 0 }, close: { code: 0 }, termination: { tree: "absent" } });
      expect(receipt.execution.process.stderr.head + receipt.execution.process.stderr.tail).toContain("FINAL-STDERR-TAIL");
      expect(receipt.execution.process.stdout.sha256).toBe(createHash("sha256").update(`BEGIN ${secret} STDOUT-END\n`).digest("hex"));
    }
    const serialized = serializeReadinessExecutionV1(f.context, execution);
    expect(serialized).not.toContain(secret);
    expect(serialized).toContain("[REDACTED]");
    expect(serialized).not.toContain('"env":');
    expect(JSON.stringify(f.context)).toBe("{}");
    expect(validateReadinessExecutionV1(f.context, JSON.parse(serialized))).toEqual(execution);
    expect(importChanged(f, execution).execution).toEqual(execution);
    await expect(lstat(f.target.root)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(f.source, "physical-stage-ran"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["failure", "timeout", "truncated"] as const)("counts a physical %s and retains redacted final stderr", async (mode) => {
    const f = await fixture(mode);
    const receipts = await execute(f, mode === "timeout" ? { ...limits, timeoutMs: 400 } : limits);
    const cleanup = await cleanupDisposableTarget(f.target);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup });
    expect(importChanged(f, execution).execution).toEqual(execution);
    const test = processStage(execution.stages);
    expect(test.status).toBe("failed");
    expect(execution.status).toBe("failed");
    if (test.execution.kind !== "process") throw new Error("process missing");
    const stderr = test.execution.process.stderr;
    expect(stderr.head + stderr.tail).toContain(mode === "timeout" ? "FINAL-TIMEOUT-TAIL" : "FINAL-STDERR-TAIL");
    if (mode === "truncated") expect(stderr).toMatchObject({ truncated: true, complete: true });
    if (mode === "timeout") expect(test.execution.process).toMatchObject({ state: "timed-out", termination: { reason: "timeout", attempts: [{ signal: "SIGTERM", status: "sent" }] } });
    if (mode === "failure") expect(test.execution.process.exit?.code).toBe(19);
    expect(serializeReadinessExecutionV1(f.context, execution)).not.toContain(secret);
  });

  it("redacts physical secret fragments at both retained boundaries while preserving the final stderr bytes", async () => {
    const f = await fixture("boundary");
    const receipts = await execute(f);
    const test = processStage(receipts);
    if (test.execution.kind !== "process") throw new Error("missing process");
    for (const stream of [test.execution.process.stdout, test.execution.process.stderr]) {
      expect(stream.truncated).toBe(true);
      expect(stream.head).not.toContain(secret.slice(0, 12));
      expect(stream.tail).not.toContain(secret.slice(-12));
      expect(stream.head).toContain("[REDACTED]");
      expect(stream.tail).toContain("[REDACTED]");
    }
    expect(test.execution.process.stderr.tail.endsWith("FINAL-STDERR-TAIL")).toBe(true);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    expect(execution.status).toBe("failed");
    expect(serializeReadinessExecutionV1(f.context, execution)).not.toContain(secret);
  });

  it("turns a real missing executable into failed evidence with no invented spawn or exit", async () => {
    const f = await fixture("missing");
    const install = f.plan.stages.find((row) => row.kind === "install")!;
    const admission = await admitReadinessStage(f.admission, install.id, f.target) as Admitted;
    const result = await observe(prepareReadinessSpawn(f.context, admission), f.context);
    const receipt = createReadinessProcessReceipt(f.context, admission, result, limits);
    expect(receipt.status).toBe("failed");
    expect(result).toMatchObject({ state: "spawn-error", pid: null, spawnedAt: null, exit: null, errors: [{ phase: "spawn", code: "ENOENT" }] });
    const receipts = withheld(f).map((row) => row.stageId === install.id ? receipt : row);
    expect(closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) }).status).toBe("failed");
  });

  it("schema-only: binds lifecycle references to a contained install and rejects missing or failed fulfillment", async () => {
    const f = await fixture("success", true);
    const receipts = await schemaOnlyReceipts(f);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    const codegen = execution.stages.find((row) => row.kind === "codegen")!;
    expect(codegen.status).toBe("passed");
    expect(codegen.execution.kind).toBe("install-lifecycle");
    expect(codegen.execution).not.toHaveProperty("process");
    const changed = structuredClone(execution);
    changed.stages = changed.stages.filter((row) => row.kind !== "install");
    expect(() => validateReadinessExecutionV1(f.context, changed)).toThrow(/missing|duplicate/);
    expect(() => importChanged(f, execution, changed)).toThrow(/missing|duplicate/);
    expect(() => createReadinessImplicitReceipt(f.context, codegen.stageId, withheld(f).find((row) => row.kind === "install")!)).toThrow(/lifecycle/);
  });

  it("schema-only: rejects missing/duplicate/unknown stage IDs, raw fields and absent lifecycle observations", async () => {
    const f = await fixture();
    const receipts = await schemaOnlyReceipts(f);
    const cleanup = await cleanupDisposableTarget(f.target);
    for (const rows of [[...receipts, receipts[0]!], receipts.slice(1)]) {
      expect(() => closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: rows, cleanup })).toThrow(/missing|duplicate/);
    }
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup });
    const mutate = (edit: (value: Record<string, unknown>) => void) => {
      const value = structuredClone(execution);
      const receipt = value.stages.find((row) => row.kind === "test")!;
      if (receipt.execution.kind !== "process") throw new Error("missing process");
      edit(receipt.execution.process as unknown as Record<string, unknown>);
      expect(() => validateReadinessExecutionV1(f.context, value)).toThrow(/Invalid readiness/);
      expect(() => importChanged(f, execution, value)).toThrow(/Invalid readiness/);
    };
    mutate((value) => { delete value.close; });
    mutate((value) => { value.close = null; });
    mutate((value) => { value.spawnedAt = null; });
    mutate((value) => { value.env = { RECEIPT_TOKEN: secret }; });
    mutate((value) => { value.rawError = new Error(secret); });
    mutate((value) => { (value.stdout as { complete: boolean }).complete = false; });
    mutate((value) => { (value.stderr as { truncated: boolean }).truncated = true; });
    mutate((value) => { (value.termination as { tree: string }).tree = "unconfirmed"; });
    mutate((value) => { value.queuedAt = "not-a-timestamp"; });
    mutate((value) => { value.queuedAt = "2099-01-01T00:00:00.000Z"; });
    mutate((value) => { value.durationMs = -1; });
    mutate((value) => { value.pid = 0; });
    mutate((value) => { value.fromFirstByteMs = null; });
    mutate((value) => { (value.exit as { signal: string | null }).signal = "NOT_A_SIGNAL"; });
    mutate((value) => { (value.close as { code: number }).code = 1; });
    mutate((value) => { (value.stdout as { omittedBytes: number }).omittedBytes++; });
    mutate((value) => { (value.stdout as { sha256: string }).sha256 = "not-a-digest"; });
    mutate((value) => { (value.stdout as { head: string }).head = "x".repeat(limits.headBytes + 1); });
    mutate((value) => { (value.termination as { stdioForcedClosed: boolean }).stdioForcedClosed = true; });
    const unknown = structuredClone(execution);
    unknown.stages[0]!.stageId = "stage:workspace:unknown:test";
    expect(() => validateReadinessExecutionV1(f.context, unknown)).toThrow(/identity/);
    expect(() => importChanged(f, execution, unknown)).toThrow(/identity/);
  });

  it("schema-only passed stages cannot override physical cleanup identity failure or source mutation", async () => {
    for (const failure of ["cleanup", "source"] as const) {
      const f = await fixture();
      const receipts = await schemaOnlyReceipts(f);
      if (failure === "cleanup") { await rename(f.target.root, f.target.root + "-moved"); await mkdir(f.target.root); }
      else await writeFile(join(f.source, "mutation-canary"), "changed");
      const cleanup = await cleanupDisposableTarget(f.target);
      expect(cleanup.status).toBe("failed");
      const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup });
      expect(execution.status).toBe("failed");
      const forged = structuredClone(execution); forged.status = "passed";
      expect(() => serializeReadinessExecutionV1(f.context, forged)).toThrow(/aggregate/);
      expect(() => importChanged(f, execution, forged)).toThrow(/aggregate/);
    }
  });

  it("requires reason/provenance/falsifier for withheld rows and redacts final serializer inputs", async () => {
    const f = await fixture();
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: withheld(f), cleanup: await cleanupDisposableTarget(f.target) });
    expect(execution.status).toBe("not-assessed");
    const unsafe = structuredClone(execution);
    const receipt = unsafe.stages[0]!;
    if (receipt.status !== "not-assessed") throw new Error("expected withheld receipt");
    receipt.diagnostic.reason = `withheld ${secret}`;
    receipt.diagnostic.provenance = [secret];
    receipt.diagnostic.falsifier = `supply ${secret}`;
    expect(serializeReadinessExecutionV1(f.context, unsafe)).not.toContain(secret);
    receipt.diagnostic.provenance = [];
    expect(() => serializeReadinessExecutionV1(f.context, unsafe)).toThrow(/provenance/);
  });

  it("counts adapter failures without inventing process facts or treating unknown execution as a skip", async () => {
    const f = await fixture();
    const stage = f.plan.stages.find((row) => row.kind === "test")!;
    const failure = createReadinessFailureReceipt(f.context, stage.id, {
      reasonCode: "runner-threw", reason: `The adapter failed ${secret}.`, provenance: ["scheduler runner boundary"], falsifier: "Retain a settled lifecycle receipt for this stage.",
    });
    expect(failure).toMatchObject({ status: "failed", execution: { kind: "unverified" } });
    expect(failure.execution).not.toHaveProperty("process");
    const receipts = withheld(f).map((row) => row.stageId === stage.id ? failure : row);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    expect(execution.status).toBe("failed");
    expect(serializeReadinessExecutionV1(f.context, execution)).not.toContain(secret);
    const forged = structuredClone(execution);
    (forged.stages.find((row) => row.kind === "test") as { status: string }).status = "passed";
    expect(() => validateReadinessExecutionV1(f.context, forged)).toThrow(/Invalid readiness/);
  });

  it("does not bless unprepared process facts and physically refuses short values in argv before spawn", async () => {
    const f = await fixture();
    const stage = f.plan.stages.find((row) => row.kind === "install")!;
    const admission = await admitReadinessStage(f.admission, stage.id, f.target) as Admitted;
    const result = await observe(admission.request, f.context);
    expect(() => createReadinessProcessReceipt(f.context, admission, result, limits)).toThrow(/unprepared/);
    await rm(join(f.target.targetRoot, "physical-stage-ran"));
    f.context.registerSecret("npm");
    await expect((async () => {
      const request = prepareReadinessSpawn(f.context, admission);
      await observe(request, f.context);
    })()).rejects.toThrow(/refusing to spawn/);
    await expect(readFile(join(f.target.targetRoot, "physical-stage-ran"))).rejects.toMatchObject({ code: "ENOENT" });
    await cleanupDisposableTarget(f.target);
  });
});
