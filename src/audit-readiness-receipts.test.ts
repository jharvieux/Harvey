import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverReadinessPlan, type ReadinessStageV1 } from "./audit-readiness.js";
import { admitReadinessStage, bindReadinessPlanV1, createReadinessAdmission, type ReadinessSpawnRequest, type ReadinessStageAdmission } from "./audit-readiness-authority.js";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget } from "./disposable-target.js";
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
    const testing = process.argv.includes('test');
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

/** Collect actual child observations for the receipt adapter; B2 separately owns the production lifecycle. */
async function observe(request: ReadinessSpawnRequest, context: ReadinessReceiptContext, timeout: boolean, outputLimits = limits): Promise<ReadinessProcessEvidenceV1> {
  const startedAt = new Date().toISOString();
  const monotonicStart = performance.now();
  let spawnedAt: string | null = null;
  let firstByteAt: string | null = null;
  let firstByteTime: number | null = null;
  let exit: ReadinessProcessEvidenceV1["exit"] = null;
  const errors: ReadinessProcessEvidenceV1["errors"] = [];
  const attempts: ReadinessProcessEvidenceV1["termination"]["attempts"] = [];
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const child = spawn(request.bin, [...request.args], { cwd: request.cwd, env: request.env, shell: false, stdio: ["ignore", "pipe", "pipe"] });
  const safeguard = setTimeout(() => child.kill("SIGKILL"), 4000);
  const received = (chunks: Buffer[]) => (chunk: Buffer) => {
    chunks.push(chunk);
    if (firstByteAt !== null) return;
    firstByteAt = new Date().toISOString(); firstByteTime = performance.now();
    if (timeout) timer = setTimeout(() => {
      timedOut = true;
      attempts.push({ at: new Date().toISOString(), signal: "SIGTERM", status: child.kill("SIGTERM") ? "sent" : "absent", code: null });
    }, 50);
  };
  child.stdout.on("data", received(stdout)); child.stderr.on("data", received(stderr));
  child.on("spawn", () => { spawnedAt = new Date().toISOString(); });
  child.on("error", (error: NodeJS.ErrnoException) => { errors.push({ phase: "spawn", code: error.code ?? "SPAWN_ERROR" }); });
  child.on("exit", (code, signal) => { exit = { at: new Date().toISOString(), code, signal }; });
  const close = await new Promise<NonNullable<ReadinessProcessEvidenceV1["close"]>>((resolve) => {
    child.on("close", (code, signal) => resolve({ at: new Date().toISOString(), code, signal }));
  });
  clearTimeout(timer); clearTimeout(safeguard);
  const endedAt = new Date().toISOString();
  const evidence = (chunks: Buffer[], stream: "stdout" | "stderr") => {
    const bytes = Buffer.concat(chunks);
    const headBytes = Math.min(outputLimits.headBytes, bytes.length);
    const tailBytes = Math.min(outputLimits.tailBytes, bytes.length - headBytes);
    const head = bytes.subarray(0, headBytes).toString("utf8");
    const tail = bytes.subarray(bytes.length - tailBytes).toString("utf8");
    return {
      bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex"), headBytes, tailBytes,
      head: context.redact(head, { stream, boundary: "head", before: "", after: bytes.subarray(headBytes).toString("utf8") }),
      tail: context.redact(tail, { stream, boundary: "tail", before: bytes.subarray(0, bytes.length - tailBytes).toString("utf8"), after: "" }),
      omittedBytes: bytes.length - headBytes - tailBytes, truncated: bytes.length > headBytes + tailBytes,
      redactionTruncated: false, complete: true,
    };
  };
  const output = evidence(stdout, "stdout"); const errorOutput = evidence(stderr, "stderr");
  return {
    state: timedOut ? "timed-out" : errors.length ? "spawn-error" : "exited",
    succeeded: !timedOut && errors.length === 0 && close.code === 0 && close.signal === null && !output.truncated && !errorOutput.truncated,
    pid: child.pid ?? null, queuedAt: startedAt, startedAt, spawnedAt, firstByteAt, endedAt,
    queueDurationMs: 0, durationMs: performance.now() - monotonicStart,
    fromFirstByteMs: firstByteTime === null ? null : performance.now() - firstByteTime,
    exit, close, errors, stdout: output, stderr: errorOutput,
    termination: { reason: timedOut ? "timeout" : errors.length ? "process-error" : null, attempts, tree: child.pid ? "absent" : "not-started", stdioForcedClosed: false },
  };
}

async function execute(f: Awaited<ReturnType<typeof fixture>>, outputLimits = limits): Promise<StageReceiptV1[]> {
  const receipts: StageReceiptV1[] = [];
  for (const kind of ["install", "codegen", "build", "typecheck", "lint", "test"] as const) {
    const stage = f.plan.stages.find((row) => row.kind === kind)!;
    if (stage.assessment === "implicit") {
      receipts.push(createReadinessImplicitReceipt(f.context, stage.id, receipts.find((row) => row.stageId === stage.fulfilledByStageId)!));
      continue;
    }
    const admission = await admitReadinessStage(f.admission, stage.id, f.target);
    if (admission.status !== "admitted") {
      receipts.push(createReadinessNotAssessedReceipt(f.context, stage.id, { ...admission, authority: admission.authority, provenance: [admission.authority.source] }));
      continue;
    }
    const request = prepareReadinessSpawn(f.context, admission);
    const result = await observe(request, f.context, f.mode === "timeout" && kind === "test", outputLimits);
    receipts.push(createReadinessProcessReceipt(f.context, admission, result, outputLimits));
  }
  return receipts;
}

function withheld(f: Awaited<ReturnType<typeof fixture>>): StageReceiptV1[] {
  return f.plan.stages.map((stage) => createReadinessNotAssessedReceipt(f.context, stage.id, {
    reasonCode: "operator-withheld", reason: `Execution was withheld ${secret}.`, provenance: [`operator decision ${secret}`], falsifier: "Authorize the stage after reviewing its effects.",
  }));
}

function processStage(receipts: StageReceiptV1[], kind: ReadinessStageV1["kind"] = "test") {
  const receipt = receipts.find((row) => row.kind === kind)!;
  if (receipt.execution.kind !== "process") throw new Error("expected a physical process receipt");
  return receipt;
}

describe("versioned receipt closure", () => {
  it("retains real success facts, names-only environment, source/argv provenance and canonical independent stages", async () => {
    const f = await fixture();
    const receipts = await execute(f);
    const cleanup = await cleanupDisposableTarget(f.target);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts: [...receipts].reverse(), cleanup });
    expect(execution.status).toBe("passed");
    expect(execution.stages.map((row) => row.stageId)).toEqual(f.plan.stages.map((row) => row.id).sort());
    expect(execution.stages).toHaveLength(6);
    for (const receipt of execution.stages) {
      expect(receipt.status).toBe("passed");
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
    await expect(lstat(f.target.root)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(f.source, "physical-stage-ran"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["failure", "timeout", "truncated"] as const)("counts a physical %s and retains redacted final stderr", async (mode) => {
    const f = await fixture(mode);
    const receipts = await execute(f);
    const cleanup = await cleanupDisposableTarget(f.target);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup });
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
    const result = await observe(prepareReadinessSpawn(f.context, admission), f.context, false);
    const receipt = createReadinessProcessReceipt(f.context, admission, result, limits);
    expect(receipt.status).toBe("failed");
    expect(result).toMatchObject({ state: "spawn-error", pid: null, spawnedAt: null, exit: null, errors: [{ phase: "spawn", code: "ENOENT" }] });
    const receipts = withheld(f).map((row) => row.stageId === install.id ? receipt : row);
    expect(closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) }).status).toBe("failed");
  });

  it("references the real install lifecycle and rejects a missing or failed fulfillment", async () => {
    const f = await fixture("success", true);
    const receipts = await execute(f);
    const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup: await cleanupDisposableTarget(f.target) });
    const codegen = execution.stages.find((row) => row.kind === "codegen")!;
    expect(codegen.status).toBe("passed");
    expect(codegen.execution.kind).toBe("install-lifecycle");
    expect(codegen.execution).not.toHaveProperty("process");
    const changed = structuredClone(execution);
    changed.stages = changed.stages.filter((row) => row.kind !== "install");
    expect(() => validateReadinessExecutionV1(f.context, changed)).toThrow(/missing|duplicate/);
    expect(() => createReadinessImplicitReceipt(f.context, codegen.stageId, withheld(f).find((row) => row.kind === "install")!)).toThrow(/lifecycle/);
  });

  it("rejects missing/duplicate/unknown stage IDs, extra raw fields and absent lifecycle observations", async () => {
    const f = await fixture();
    const receipts = await execute(f);
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
    };
    mutate((value) => { delete value.close; });
    mutate((value) => { value.close = null; });
    mutate((value) => { value.spawnedAt = null; });
    mutate((value) => { value.env = { RECEIPT_TOKEN: secret }; });
    mutate((value) => { value.rawError = new Error(secret); });
    mutate((value) => { (value.stdout as { complete: boolean }).complete = false; });
    mutate((value) => { (value.stderr as { truncated: boolean }).truncated = true; });
    mutate((value) => { (value.termination as { tree: string }).tree = "unconfirmed"; });
    const unknown = structuredClone(execution);
    unknown.stages[0]!.stageId = "stage:workspace:unknown:test";
    expect(() => validateReadinessExecutionV1(f.context, unknown)).toThrow(/identity/);
  });

  it("never reports clean after a physical cleanup identity failure or source mutation", async () => {
    for (const failure of ["cleanup", "source"] as const) {
      const f = await fixture();
      const receipts = await execute(f);
      if (failure === "cleanup") { await rename(f.target.root, f.target.root + "-moved"); await mkdir(f.target.root); }
      else await writeFile(join(f.source, "mutation-canary"), "changed");
      const cleanup = await cleanupDisposableTarget(f.target);
      expect(cleanup.status).toBe("failed");
      const execution = closeReadinessExecutionV1(f.context, { binding: f.binding, receipts, cleanup });
      expect(execution.status).toBe("failed");
      const forged = structuredClone(execution); forged.status = "passed";
      expect(() => serializeReadinessExecutionV1(f.context, forged)).toThrow(/aggregate/);
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
    const result = await observe(admission.request, f.context, false);
    expect(() => createReadinessProcessReceipt(f.context, admission, result, limits)).toThrow(/unprepared/);
    await rm(join(f.target.targetRoot, "physical-stage-ran"));
    f.context.registerSecret("npm");
    await expect((async () => {
      const request = prepareReadinessSpawn(f.context, admission);
      await observe(request, f.context, false);
    })()).rejects.toThrow(/refusing to spawn/);
    await expect(readFile(join(f.target.targetRoot, "physical-stage-ran"))).rejects.toMatchObject({ code: "ENOENT" });
    await cleanupDisposableTarget(f.target);
  });
});
