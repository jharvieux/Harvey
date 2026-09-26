import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_MODULES } from "./audit-coverage.js";
import { type ModuleRunner, type RunContext, runAudit } from "./audit-runner.js";
import { discoverReadinessPlan, type ReadinessPlanV1, type ReadinessStageV1 } from "./audit-readiness.js";
import { bindReadinessPlanV1, createReadinessAdmission, type ReadinessAuthorityOptions } from "./audit-readiness-authority.js";
import { executeReadinessPlan, type ReadinessExecutionOptions, type ReadinessStageIndependence, type ReadinessStageOutcome, type ReadinessStageRunResult } from "./audit-readiness-exec.js";
import type { Finding } from "./findings.js";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget, type DisposableTarget } from "./disposable-target.js";

const roots: string[] = [];
const targets: DisposableTarget[] = [];
type StageId = ReadinessStageV1["id"];
type TestReceipt = { stageId: StageId; result: string };
const normalScripts = { codegen: "node runner.cjs codegen", build: "node runner.cjs build", typecheck: "node runner.cjs typecheck", lint: "node runner.cjs lint", test: "node runner.cjs test" };

const script = `const fs = require('node:fs');
const kind = process.argv[2] === 'prisma' ? 'codegen' : process.argv[2];
process.stdout.write('started ' + kind + '\\n');
fs.writeFileSync(kind + '.marker', JSON.stringify({ kind, cwd: process.cwd(), pid: process.pid }));
if (kind === 'codegen' && fs.existsSync('fail-codegen')) process.exitCode = 7;
`;

afterEach(async () => {
  for (const target of targets.splice(0)) await cleanupDisposableTarget(target);
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

function authorityFor(plan: ReadinessPlanV1, overrides: Partial<ReadinessAuthorityOptions> = {}): ReadinessAuthorityOptions {
  return {
    allowTargetInstall: true,
    stageAuthorizations: plan.stages.filter((row) => row.assessment === "planned").map((row) => ({
      stageId: row.id, effect: row.kind === "install" ? "target-install" : "disposable-local",
      source: "operator reviewed fixture scripts", reason: "The fixture only writes disposable marker files.",
      falsifier: "A fixture script reaches a service or the original source.",
    })),
    approvedEnvNames: [], environment: {},
    ...overrides,
  };
}

async function fixture(options: {
  scripts?: Record<string, string>;
  workspace?: boolean;
  failCodegen?: boolean;
  requiredEnv?: boolean;
  authority?: (plan: ReadinessPlanV1) => Partial<ReadinessAuthorityOptions>;
} = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "harvey-readiness-dag-test-")));
  roots.push(root);
  const source = join(root, "source");
  const scratch = join(root, "scratch");
  await mkdir(source);
  await mkdir(scratch);
  const packageJson = {
    name: "dag-fixture", version: "1.0.0", private: true, packageManager: "npm@10.9.2",
    scripts: options.scripts ?? normalScripts,
    ...(options.workspace ? { workspaces: ["apps/*"] } : {}),
  };
  await writeFile(join(source, "package.json"), JSON.stringify(packageJson));
  await writeFile(join(source, "package-lock.json"), JSON.stringify({ name: "dag-fixture", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": packageJson } }));
  await writeFile(join(source, "runner.cjs"), script);
  if (options.workspace) {
    await mkdir(join(source, "apps/plain"), { recursive: true });
    await writeFile(join(source, "apps/plain/package.json"), JSON.stringify({ name: "plain-fixture", version: "1.0.0", scripts: { test: "node ../../runner.cjs test" } }));
  }
  if (options.failCodegen) await writeFile(join(source, "fail-codegen"), "Fail only the required code generator.");
  if (options.requiredEnv) await writeFile(join(source, "vitest.config.ts"), "export default { token: process.env.READINESS_TEST_TOKEN };\n");
  const plan = discoverReadinessPlan(source);
  const binding = bindReadinessPlanV1(plan, await captureSourceSentinel(source));
  const created = await createDisposableTarget(source, { tempParent: scratch });
  if (created.status !== "ready") throw new Error(JSON.stringify(created));
  targets.push(created.target);
  const context = createReadinessAdmission(plan, binding, authorityFor(plan, options.authority?.(plan)));
  return { root, source, plan, binding, context, target: created.target };
}

function stage(plan: ReadinessPlanV1, kind: ReadinessStageV1["kind"], workspaceId = "workspace:root") {
  const row = plan.stages.find((candidate) => candidate.kind === kind && candidate.workspaceId === workspaceId);
  if (!row) throw new Error(`Missing fixture stage ${workspaceId}:${kind}.`);
  return row;
}

function outcome<Receipt>(rows: ReadinessStageOutcome<Receipt>[], id: StageId): ReadinessStageOutcome<Receipt> {
  const row = rows.find((candidate) => candidate.stageId === id);
  if (!row) throw new Error(`Missing outcome ${id}.`);
  return row;
}

function pass(row: ReadinessStageV1): ReadinessStageRunResult<TestReceipt> {
  return { status: "passed", receipt: { stageId: row.id, result: "completed fixture" } };
}

function failure(row: ReadinessStageV1): ReadinessStageRunResult<TestReceipt> {
  return { status: "failed", receipt: { stageId: row.id, result: "exit 7" }, reasonCode: "command-failed", reason: "The fixture exited 7.", falsifier: "Run the fixture without its failure switch." };
}

function independent(plan: ReadinessPlanV1): ReadinessStageIndependence[] {
  return plan.stages.filter((row) => row.assessment === "planned").map((row) => ({
    stageId: row.id, reason: "Each fixture operation uses a distinct marker or deferred test gate.",
    provenance: "Fixture source and gate ownership reviewed by the test caller.",
    falsifier: "Two fixture stages read or modify the same output before their prerequisites close.",
  }));
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

function assertClosure<Receipt>(plan: ReadinessPlanV1, rows: ReadinessStageOutcome<Receipt>[]) {
  expect(rows.map((row) => row.stageId)).toEqual(plan.stages.map((row) => row.id).sort((a, b) => a.localeCompare(b)));
  expect(new Set(rows.map((row) => row.stageId)).size).toBe(plan.stages.length);
}

describe("readiness dependency closure", () => {
  it("retains the shared execution lease after an unresolved workload and withholds independent ready stages", async () => {
    const { plan, context, target } = await fixture();
    const attempted: StageId[] = [];
    let unresolved = false;
    const rows = await executeReadinessPlan(context, target, {
      concurrency: 1,
      executionBarrier: () => unresolved ? { reasonCode: "owned-workload-unconfirmed", reason: "The fixture's owned namespace has no terminal observation.", falsifier: "Observe termination of that exact namespace before releasing its output lease." } : null,
      runStage: async (row) => { attempted.push(row.id); unresolved = true; return failure(row); },
    });
    expect(attempted).toEqual([stage(plan, "install").id]);
    expect(outcome(rows, stage(plan, "lint").id)).toMatchObject({ status: "not-assessed", execution: "withheld", reasonCode: "owned-workload-unconfirmed" });
    assertClosure(plan, rows);
  });

  it.each(["failed", "not-assessed", "throw", "invalid"] as const)("normalizes a %s codegen result and continues only independent branches", async (mode) => {
    const { plan, context, target } = await fixture({ workspace: true });
    const attempted: StageId[] = [];
    const rows = await executeReadinessPlan<TestReceipt>(context, target, {
      concurrency: 2,
      runStage: async (row, admission) => {
        attempted.push(row.id);
        expect(admission.request).toMatchObject({ bin: row.command.bin, args: row.command.args, cwd: join(target.targetRoot, row.command.cwd), shell: false });
        expect(Object.isFrozen(row)).toBe(true);
        if (row.kind !== "codegen") return pass(row);
        if (mode === "throw") throw new Error("SECRET_CANARY_THROWN_ADAPTER_VALUE");
        if (mode === "invalid") return { status: "passed" } as ReadinessStageRunResult<TestReceipt>;
        return { ...failure(row), status: mode, reasonCode: mode === "failed" ? "command-failed" : "executable-unavailable", reason: "The generator did not complete.", falsifier: "Complete the required generator." };
      },
    });
    assertClosure(plan, rows);
    expect(outcome(rows, stage(plan, "codegen").id).status).toBe(mode === "not-assessed" ? "not-assessed" : "failed");
    for (const kind of ["build", "typecheck", "test"] as const) {
      const id = stage(plan, kind).id;
      expect(attempted).not.toContain(id);
      expect(outcome(rows, id)).toMatchObject({ status: "not-assessed", execution: "withheld", reasonCode: "prerequisite-not-passed", blockedByStageIds: [stage(plan, "codegen").id] });
      expect(outcome(rows, id).provenance).toEqual(stage(plan, kind).provenance);
      expect(outcome(rows, id)).toHaveProperty("falsifier", expect.any(String));
    }
    expect(outcome(rows, stage(plan, "lint").id).status).toBe("passed");
    expect(outcome(rows, stage(plan, "test", "workspace:apps/plain").id).status).toBe("passed");
    expect(attempted.indexOf(stage(plan, "lint").id)).toBeGreaterThan(attempted.indexOf(stage(plan, "codegen").id));
    expect(JSON.stringify(rows)).not.toContain("SECRET_CANARY_THROWN_ADAPTER_VALUE");
  });

  it("withholds missing scripts, authority, and environment before invoking the runner", async () => {
    const { plan, context, target } = await fixture({
      scripts: { build: normalScripts.build, lint: normalScripts.lint, test: normalScripts.test }, requiredEnv: true,
      authority: (plan) => ({ stageAuthorizations: authorityFor(plan).stageAuthorizations.filter((row) => row.stageId !== stage(plan, "lint").id) }),
    });
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    const rows = await executeReadinessPlan(context, target, { concurrency: 4, runStage });
    expect(runStage.mock.calls.map(([row]) => row.kind)).toEqual(["install", "build"]);
    expect(outcome(rows, stage(plan, "codegen").id)).toMatchObject({ status: "not-assessed", reasonCode: "missing-script-and-config", execution: "withheld" });
    expect(outcome(rows, stage(plan, "lint").id)).toMatchObject({ status: "not-assessed", reasonCode: "authority-missing", authority: { decision: "denied" } });
    expect(outcome(rows, stage(plan, "test").id)).toMatchObject({ status: "not-assessed", reasonCode: "required-environment-missing", authority: { requiredEnvNames: ["READINESS_TEST_TOKEN"] } });
    assertClosure(plan, rows);
  });

  it("retains missing-script evidence even when install and all executable descendants are withheld", async () => {
    const { plan, context, target } = await fixture({ scripts: { build: normalScripts.build }, authority: () => ({ allowTargetInstall: false }) });
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    const rows = await executeReadinessPlan(context, target, { concurrency: 2, runStage });
    expect(runStage).not.toHaveBeenCalled();
    expect(outcome(rows, stage(plan, "install").id)).toMatchObject({ status: "not-assessed", reasonCode: "target-install-not-authorized" });
    expect(outcome(rows, stage(plan, "build").id)).toMatchObject({ status: "not-assessed", reasonCode: "prerequisite-not-passed" });
    expect(outcome(rows, stage(plan, "codegen").id)).toMatchObject({ status: "not-assessed", reasonCode: "missing-script-and-config" });
    assertClosure(plan, rows);
  });

  it.each([true, false])("links implicit codegen to the actual install receipt (install passed: %s)", async (installPassed) => {
    const { plan, context, target } = await fixture({ scripts: { build: normalScripts.build, postinstall: "npm run generate", generate: "node runner.cjs codegen" } });
    const runStage = vi.fn(async (row: ReadinessStageV1) => row.kind === "install" && !installPassed ? failure(row) : pass(row));
    const rows = await executeReadinessPlan(context, target, { concurrency: 2, runStage });
    expect(stage(plan, "codegen").assessment).toBe("implicit");
    const install = outcome(rows, stage(plan, "install").id);
    const codegen = outcome(rows, stage(plan, "codegen").id);
    expect(codegen).toMatchObject({ status: "not-assessed", execution: "withheld", fulfilledByStageId: install.stageId, fulfillment: { stageId: install.stageId, status: install.status } });
    if (codegen.execution !== "withheld" || !("receipt" in install)) throw new Error("Expected linked install evidence.");
    expect(codegen.fulfillment?.receipt).toBe(install.receipt);
    expect(codegen).not.toHaveProperty("receipt");
    expect(runStage.mock.calls.some(([row]) => row.kind === "codegen")).toBe(false);
    expect(outcome(rows, stage(plan, "build").id).status).toBe(installPassed ? "passed" : "not-assessed");
    assertClosure(plan, rows);
  });

  it("normalizes admission exceptions without handing a command to the runner", async () => {
    const { plan, context, target } = await fixture();
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    const rows = await executeReadinessPlan({ ...context }, target, { concurrency: 1, runStage });
    expect(runStage).not.toHaveBeenCalled();
    expect(outcome(rows, stage(plan, "install").id)).toMatchObject({ status: "not-assessed", reasonCode: "admission-failed" });
    assertClosure(plan, rows);
  });

  it.each(["duplicate", "dangling", "cycle"] as const)("rejects %s plan closure before any admission or runner side effect", async (fault) => {
    const { context, target } = await fixture();
    const plan = structuredClone(context.plan);
    if (fault === "duplicate") plan.stages.push(structuredClone(plan.stages[0]!));
    if (fault === "dangling") stage(plan, "build").prerequisiteStageIds.push("stage:workspace:missing:codegen");
    if (fault === "cycle") stage(plan, "install").prerequisiteStageIds.push(stage(plan, "build").id);
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    await expect(executeReadinessPlan({ ...context, plan }, target, { concurrency: 2, runStage })).rejects.toThrow(/duplicate|dangling|cycle|prerequisites inconsistent/);
    expect(runStage).not.toHaveBeenCalled();
  });

  it("orders outcomes by stable ID when the plan and completion orders differ", async () => {
    const { plan, binding, target } = await fixture({ workspace: true });
    const shuffled = { ...plan, stages: [...plan.stages].reverse() };
    const context = createReadinessAdmission(shuffled, binding, authorityFor(plan));
    const completed: StageId[] = [];
    const rows = await executeReadinessPlan(context, target, { concurrency: 3, independence: independent(plan), runStage: async (row) => {
      if (row.kind === "codegen") await delay(10);
      completed.push(row.id);
      return pass(row);
    } });
    assertClosure(plan, rows);
    expect(completed).not.toEqual(rows.filter((row) => row.execution === "attempted").map((row) => row.stageId));
  });
});

describe("readiness output locks and concurrency", () => {
  it.each(["none", "one-sided"] as const)("serializes shared output trees with %s independence declarations", async (mode) => {
    const { plan, context, target } = await fixture({ workspace: true });
    let running = 0;
    let maximum = 0;
    const rows = await executeReadinessPlan(context, target, {
      concurrency: 4,
      independence: mode === "none" ? [] : independent(plan).filter((row) => row.stageId === stage(plan, "lint").id),
      runStage: async (row) => {
        running += 1;
        maximum = Math.max(maximum, running);
        await delay(2);
        running -= 1;
        return pass(row);
      },
    });
    expect(maximum).toBe(1);
    assertClosure(plan, rows);
  });

  it("caps admitted work and starts a newly ready descendant while an independent sibling is still running", async () => {
    const { plan, context, target } = await fixture();
    const releaseCodegen = deferred();
    const releaseLint = deferred();
    const releaseDescendants = deferred();
    const firstWave = deferred();
    const buildStarted = deferred();
    const trace: { kind: string; event: "start" | "end"; at: number }[] = [];
    let running = 0;
    let maximum = 0;
    const executing = executeReadinessPlan(context, target, { concurrency: 2, independence: independent(plan), runStage: async (row) => {
      running += 1;
      maximum = Math.max(maximum, running);
      trace.push({ kind: row.kind, event: "start", at: performance.now() });
      if (running === 2) firstWave.resolve();
      if (row.kind === "codegen") await releaseCodegen.promise;
      if (row.kind === "lint") await releaseLint.promise;
      if (["build", "typecheck", "test"].includes(row.kind)) {
        if (row.kind === "build") buildStarted.resolve();
        await releaseDescendants.promise;
      }
      trace.push({ kind: row.kind, event: "end", at: performance.now() });
      running -= 1;
      return pass(row);
    } });
    try {
      await firstWave.promise;
      expect(running).toBe(2);
      const started = trace.filter((row) => row.event === "start").map((row) => row.kind);
      expect(started[0]).toBe("install");
      expect(started.slice(1).sort()).toEqual(["codegen", "lint"]);
      releaseCodegen.resolve();
      await buildStarted.promise;
      expect(running).toBe(2);
      expect(trace.some((row) => row.kind === "lint" && row.event === "end")).toBe(false);
    } finally {
      releaseCodegen.resolve(); releaseLint.resolve(); releaseDescendants.resolve();
      await executing;
    }
    const rows = await executing;
    const time = (kind: string, event: "start" | "end") => trace.find((row) => row.kind === kind && row.event === event)!.at;
    expect(time("build", "start")).toBeGreaterThanOrEqual(time("codegen", "end"));
    expect(time("build", "start")).toBeLessThanOrEqual(time("lint", "end"));
    expect(maximum).toBe(2);
    assertClosure(plan, rows);
  });

  it("fills an available slot after implicit fulfillment without waiting for an unrelated long stage", async () => {
    const { plan, context, target } = await fixture({ scripts: { build: normalScripts.build, lint: normalScripts.lint, postinstall: "npm run generate", generate: "node runner.cjs codegen" } });
    const releaseLint = deferred();
    const started: string[] = [];
    const executing = executeReadinessPlan(context, target, { concurrency: 2, independence: independent(plan), runStage: async (row) => {
      started.push(row.kind);
      if (row.kind === "lint") await releaseLint.promise;
      return pass(row);
    } });
    try {
      await vi.waitFor(() => { expect(started).toEqual(expect.arrayContaining(["build", "lint"])); }, { timeout: 2000 });
      expect(started[0]).toBe("install");
      expect(started.slice(1).sort()).toEqual(["build", "lint"]);
    } finally { releaseLint.resolve(); await executing; }
    assertClosure(plan, await executing);
  });

  it("rechecks stage-root admission only after the shared output lock is acquired", async () => {
    const { plan, context, target, root } = await fixture({ workspace: true });
    const workspace = join(target.targetRoot, "apps/plain");
    const rows = await executeReadinessPlan(context, target, { concurrency: 4, runStage: async (row) => {
      if (row.kind === "install") {
        await rm(workspace, { recursive: true });
        const { symlink } = await import("node:fs/promises");
        await symlink(root, workspace);
      }
      return pass(row);
    } });
    expect(outcome(rows, stage(plan, "test", "workspace:apps/plain").id)).toMatchObject({ status: "not-assessed", execution: "withheld" });
    expect(outcome(rows, stage(plan, "test", "workspace:apps/plain").id)).not.toHaveProperty("receipt");
  });

  it.each([0, -1, 1.5, 5, NaN])("rejects invalid concurrency %s before a runner call", async (concurrency) => {
    const { context, target } = await fixture();
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    await expect(executeReadinessPlan(context, target, { concurrency, runStage })).rejects.toThrow(/concurrency/);
    expect(runStage).not.toHaveBeenCalled();
  });

  it.each(["duplicate", "unknown", "unevidenced", "absent"] as const)("rejects %s independence declarations before a runner call", async (fault) => {
    const { plan, context, target } = await fixture({ workspace: true });
    const declaration = independent(plan)[0]!;
    const independence = fault === "duplicate" ? [declaration, declaration]
      : [{ ...declaration, ...(fault === "unknown" ? { stageId: "stage:workspace:unknown:test" as StageId } : fault === "absent" ? { stageId: stage(plan, "codegen", "workspace:apps/plain").id } : { provenance: "" }) }];
    const runStage = vi.fn(async (row: ReadinessStageV1) => pass(row));
    await expect(executeReadinessPlan(context, target, { concurrency: 2, independence, runStage })).rejects.toThrow(/independence/);
    expect(runStage).not.toHaveBeenCalled();
  });
});

interface PhysicalReceipt {
  stageId: StageId;
  exitCode: number | null;
  signal: string | null;
  firstByteAt: number | null;
  closedAt: number;
  cwd: string;
}

const runPhysical: ReadinessExecutionOptions<PhysicalReceipt>["runStage"] = async (row, admission) => new Promise((resolve) => {
  const request = admission.request;
  const child = spawn(request.bin, [...request.args], { cwd: request.cwd, env: request.env, shell: request.shell, stdio: ["ignore", "pipe", "pipe"] });
  let firstByteAt: number | null = null;
  let errored = false;
  const timer = setTimeout(() => { errored = true; child.kill("SIGKILL"); }, 10_000);
  child.stdout.on("data", () => { firstByteAt ??= performance.now(); });
  child.stderr.on("data", () => { firstByteAt ??= performance.now(); });
  child.once("error", () => { errored = true; });
  child.once("close", (exitCode, signal) => {
    clearTimeout(timer);
    const receipt = { stageId: row.id, exitCode, signal, firstByteAt, closedAt: performance.now(), cwd: request.cwd };
    resolve(exitCode === 0 && signal === null && !errored
      ? { status: "passed", receipt }
      : { status: "failed", receipt, reasonCode: "physical-command-failed", reason: "The real fixture command did not close successfully.", falsifier: "Remove the fixture fault and observe a successful close." });
  });
});

async function marker(target: DisposableTarget, kind: string, relativeDirectory = ".") {
  return JSON.parse(await readFile(join(target.targetRoot, relativeDirectory, `${kind}.marker`), "utf8")) as { kind: string; cwd: string; pid: number };
}

describe("physical readiness dependency controls", () => {
  it.each([true, false])("physically withholds invalid descendants and continues after codegen failure (fault enabled: %s)", async (failCodegen) => {
    const { plan, context, target, source } = await fixture({ scripts: { codegen: normalScripts.codegen, build: normalScripts.build, lint: normalScripts.lint }, workspace: true, failCodegen });
    const rows = await executeReadinessPlan(context, target, { concurrency: 3, runStage: runPhysical });
    assertClosure(plan, rows);
    expect(outcome(rows, stage(plan, "codegen").id).status).toBe(failCodegen ? "failed" : "passed");
    expect((await marker(target, "codegen")).cwd).toBe(target.targetRoot);
    expect((await marker(target, "lint")).cwd).toBe(target.targetRoot);
    expect((await marker(target, "test", "apps/plain")).cwd).toBe(join(target.targetRoot, "apps/plain"));
    if (failCodegen) await expect(lstat(join(target.targetRoot, "build.marker"))).rejects.toMatchObject({ code: "ENOENT" });
    else expect((await marker(target, "build")).cwd).toBe(target.targetRoot);
    const codegen = outcome(rows, stage(plan, "codegen").id);
    const lint = outcome(rows, stage(plan, "lint").id);
    if (!("receipt" in codegen) || !("receipt" in lint)) throw new Error("Expected physical process receipts.");
    expect(codegen.receipt.exitCode).toBe(failCodegen ? 7 : 0);
    expect(lint.receipt.exitCode).toBe(0);
    expect(lint.receipt.firstByteAt).not.toBeNull();
    expect(lint.receipt.firstByteAt!).toBeGreaterThan(codegen.receipt.closedAt);
    await expect(lstat(join(source, "codegen.marker"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("fulfills implicit codegen through the actual install lifecycle without spawning codegen twice", async () => {
    const { plan, context, target } = await fixture({ scripts: { build: normalScripts.build, postinstall: "npm run generate", generate: "node runner.cjs codegen" } });
    const attempted: StageId[] = [];
    const rows = await executeReadinessPlan(context, target, { concurrency: 2, runStage: async (row, admission) => {
      attempted.push(row.id);
      return runPhysical(row, admission);
    } });
    expect((await marker(target, "codegen")).cwd).toBe(target.targetRoot);
    expect((await marker(target, "build")).cwd).toBe(target.targetRoot);
    expect(attempted).toEqual([stage(plan, "install").id, stage(plan, "build").id]);
    expect(outcome(rows, stage(plan, "codegen").id)).toMatchObject({ status: "not-assessed", execution: "withheld", fulfilledByStageId: stage(plan, "install").id, fulfillment: { status: "passed", receipt: { exitCode: 0 } } });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });
});

describe("readiness failures leave the audit orchestrator independent", () => {
  it("preserves all ten module results when the scheduler's runner rejects", async () => {
    const { context, target } = await fixture();
    const invocations: string[] = [];
    const runners: ModuleRunner[] = AUDIT_MODULES.map((module) => {
      const finding: Finding = {
        id: `${module}-READINESS-CONTINUITY`, module, title: `Retained ${module} fixture finding`,
        severity: "Medium", confidence: "Confirmed", category: "Readiness continuity fixture", taxonomy: "fixture",
        location: `${module}.ts:1`, status: "open", evidence: `Unchanged ${module} evidence`,
        impact: "The finding must survive readiness failure.", fix: "Preserve independent audit collection.", value: 3, ease: 3, safety: 3,
      };
      return { module, producers: [], run: () => {
        invocations.push(module);
        return { kind: "examined", unitsExamined: 1, scope: "unchanged fixture unit", detail: `fixture ${module}`, findings: [finding] };
      } };
    });
    const auditContext: RunContext = {
      targetDir: target.sourceRoot, env: { connected: false, dynamic: false, llm: false },
      exec: async () => { throw new Error("The fixture modules use no external tools."); },
      exists: () => true, isGitRepoRoot: () => false,
    };
    const baseline = await runAudit(runners, auditContext);
    expect(baseline.findings.map((finding) => finding.id)).toEqual(AUDIT_MODULES.map((module) => `${module}-READINESS-CONTINUITY`));
    for (const mode of ["passed", "failed"] as const) {
      invocations.length = 0;
      const readiness = executeReadinessPlan(context, target, { concurrency: 2, runStage: async (row) => {
        if (mode === "failed" && row.kind === "codegen") throw new Error("failed readiness adapter");
        return pass(row);
      } });
      const observed = await runAudit(runners, auditContext);
      const rows = await readiness;
      expect(rows.some((row) => row.status === "failed")).toBe(mode === "failed");
      expect(invocations).toEqual([...AUDIT_MODULES]);
      expect(observed).toEqual(baseline);
      expect(Object.values(observed.findingsByModule).flat()).toEqual(baseline.findings);
    }
  });
});
