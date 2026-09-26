import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverReadinessPlan, type ReadinessStageV1 } from "./audit-readiness.js";
import { bindReadinessPlanV1 } from "./audit-readiness-authority.js";
import { discloseReadinessSetupFailure, executeBoundReadinessPlan, parseReadinessAuthorizations } from "./audit-readiness-run.js";
import { captureSourceSentinel } from "./disposable-target.js";
import type { ReadinessContainmentConfig } from "./readiness-process-containment.js";
import { parseReadinessArtifactsV1 } from "./audit-readiness-artifacts.js";

const roots: string[] = [];
const containment: ReadinessContainmentConfig | undefined = process.env.HARVEY_READINESS_DOCKER_SOCKET && process.env.HARVEY_READINESS_DOCKER_IMAGE ? {
  kind: "docker-local", socketPath: process.env.HARVEY_READINESS_DOCKER_SOCKET, imageId: process.env.HARVEY_READINESS_DOCKER_IMAGE,
} : undefined;
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

async function fixture(failCodegen = false) {
  const root = await mkdtemp(join(process.env.HARVEY_READINESS_SHARED_PARENT ?? tmpdir(), "harvey-readiness-integrated-"));
  roots.push(root);
  const source = join(root, "source");
  const tools = join(root, "tools");
  await Promise.all([mkdir(source), mkdir(tools)]);
  const pkg = {
    name: "integrated-readiness-fixture", version: "1.0.0", private: true, packageManager: "npm@10.9.2",
    scripts: { codegen: "node generator.cjs", build: "node builder.cjs", lint: "node linter.cjs", test: "node tester.cjs" },
  };
  await writeFile(join(source, "package.json"), JSON.stringify(pkg));
  await writeFile(join(source, "package-lock.json"), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": pkg } }));
  await writeFile(join(source, "source-canary"), "unchanged source");
  for (const [kind, file] of Object.entries({ codegen: "generator.cjs", build: "builder.cjs", lint: "linter.cjs", test: "tester.cjs" })) {
    await writeFile(join(source, file), `require('node:fs').writeFileSync('${kind}.marker', process.cwd()); process.stdout.write('stage ${kind} ' + process.env.READINESS_TOKEN); ${kind === "codegen" && failCodegen ? "process.exitCode=7;" : ""}`);
  }
  const npm = join(tools, "npm");
  await writeFile(npm, `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const kind = args.includes('install') || args.includes('ci') ? 'install' : args.find((value) => ['codegen','build','lint','test'].includes(value)) || 'unknown';
fs.writeFileSync(kind + '.marker', JSON.stringify({ cwd: process.cwd(), pid: process.pid }));
process.stdout.write('stage ' + kind + ' ' + process.env.READINESS_TOKEN + '\\n');
if (kind === 'codegen' && ${failCodegen}) process.exitCode = 7;
`);
  await chmod(npm, 0o755);
  const sentinel = await captureSourceSentinel(source);
  const plan = discoverReadinessPlan(source);
  const binding = bindReadinessPlanV1(plan, sentinel);
  const authorizations = plan.stages.filter((stage) => stage.assessment === "planned").map((stage) => ({
    stageId: stage.id, effect: stage.kind === "install" ? "target-install" as const : "disposable-local" as const,
    source: "operator-reviewed physical fixture", reason: "Only disposable marker files are written.",
    falsifier: "A stage writes outside the disposable copy or contacts a service.",
  }));
  const run = () => executeBoundReadinessPlan({
    sourceRoot: source, plan, binding, allowTargetInstall: true, stageAuthorizations: authorizations,
    approvedEnvNames: ["READINESS_TOKEN"], environment: { READINESS_TOKEN: "fixture-secret" }, containment,
    disposableTempParent: root,
    limits: { timeoutMs: 5_000, headBytes: 2_048, tailBytes: 512 },
  });
  return { source, sentinel, plan, run, root, authorizations };
}

function row(stages: readonly { kind: ReadinessStageV1["kind"] }[], kind: ReadinessStageV1["kind"]) {
  const found = stages.find((stage) => stage.kind === kind);
  if (!found) throw new Error(`missing ${kind} stage`);
  return found;
}

describe("bound readiness production composition (#1897)", () => {
  it("redacts a rejected grant's independently valid names without recording approval or spawning", async () => {
    const state = await fixture();
    const manifestPath = join(state.source, "package.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { scripts: Record<string, string> };
    manifest.scripts.build += " # fixture-secret";
    await writeFile(manifestPath, JSON.stringify(manifest));
    const plan = discoverReadinessPlan(state.source);
    const binding = bindReadinessPlanV1(plan, await captureSourceSentinel(state.source));
    const result = discloseReadinessSetupFailure(plan, binding, { names: ["READINESS_TOKEN"], environment: { READINESS_TOKEN: "fixture-secret" } });
    expect(result.json).not.toContain("fixture-secret");
    expect(result.descriptorJson).not.toContain("fixture-secret");
    expect(result.planExport.status).toBe("withheld");
    expect(JSON.parse(result.descriptorJson).environment).toEqual({ approvedNames: [], presentNames: [] });
    expect(result.execution.stages.every((stage) => stage.status === "not-assessed" && stage.execution.kind === "not-run")).toBe(true);
    let valueReads = 0;
    const protectedEnvironment = Object.defineProperty({}, "NODE_OPTIONS", { get() { valueReads++; return "unsafe"; } });
    expect(() => discloseReadinessSetupFailure(plan, binding, { names: ["NODE_OPTIONS"], environment: protectedEnvironment })).toThrow(/protected/);
    expect(valueReads).toBe(0);
  });

  it("binds operator authorization to the exact plan and refuses values or malformed effect rows", async () => {
    const state = await fixture();
    const binding = bindReadinessPlanV1(state.plan, state.sentinel);
    const authorized = { schemaVersion: 1, planSha256: binding.planSha256, stageAuthorizations: [], approvedEnvNames: ["READINESS_TOKEN"], timeoutMs: 500 };
    expect(parseReadinessAuthorizations(authorized, binding.planSha256)).toEqual({ stageAuthorizations: [], approvedEnvNames: ["READINESS_TOKEN"], limits: { timeoutMs: 500 } });
    for (const invalid of [
      { ...authorized, planSha256: "0".repeat(64) },
      { ...authorized, environment: { READINESS_TOKEN: "fixture-secret" } },
      { ...authorized, stageAuthorizations: [null] },
      { ...authorized, stageAuthorizations: [{ stageId: state.plan.stages[0]!.id, effect: "arbitrary", source: "operator", reason: "reason", falsifier: "falsifier" }] },
      { ...authorized, timeoutMs: 0 },
    ]) expect(() => parseReadinessAuthorizations(invalid, binding.planSha256)).toThrow();
    const result = discloseReadinessSetupFailure(state.plan, binding);
    expect(result.execution.stages.map((stage) => stage.stageId).sort()).toEqual(state.plan.stages.map((stage) => stage.id).sort());
    expect(result.execution.stages.every((stage) => stage.status === "not-assessed" && stage.execution.kind === "not-run")).toBe(true);
    expect(result.execution.cleanup).toMatchObject({ status: "not-required", root: null });
  });

  it.skipIf(!containment)("executes the exact plan in a removed disposable copy and emits one real receipt per stage", async () => {
    const fixtureState = await fixture();
    const { execution, json } = await fixtureState.run();
    expect(execution.stages).toHaveLength(fixtureState.plan.stages.length);
    expect(new Set(execution.stages.map((stage) => stage.stageId)).size).toBe(execution.stages.length);
    expect(execution.cleanup).toMatchObject({ status: "passed", removal: { status: "removed" }, source: { status: "passed" } });
    for (const kind of ["install", "codegen", "build", "lint", "test"] as const) {
      expect(row(execution.stages, kind)).toMatchObject({ status: "passed", execution: { kind: "process", process: { succeeded: true, exit: { code: 0 }, close: { code: 0 }, containment: { kind: "docker-pid-namespace", imageId: containment!.imageId, namespace: "terminated", targetWork: "begun", metadata: "verified", cleanup: "removed" } } } });
    }
    expect(row(execution.stages, "typecheck")).toMatchObject({ status: "not-assessed" });
    expect(json).not.toContain("fixture-secret");
    expect(await readFile(join(fixtureState.source, "source-canary"), "utf8")).toBe("unchanged source");
    expect(await captureSourceSentinel(fixtureState.source)).toEqual(fixtureState.sentinel);
  });

  it.skipIf(!containment)("counts a failed generator, withholds only descendants and still runs independent lint", async () => {
    const fixtureState = await fixture(true);
    const { execution } = await fixtureState.run();
    expect(row(execution.stages, "codegen")).toMatchObject({ status: "failed", execution: { kind: "process", process: { close: { code: 7 } } } });
    expect(row(execution.stages, "build")).toMatchObject({ status: "not-assessed", diagnostic: { reasonCode: "prerequisite-not-passed" } });
    expect(row(execution.stages, "lint")).toMatchObject({ status: "passed", execution: { kind: "process" } });
    expect(execution.cleanup.status).toBe("passed");
    expect(execution.status).toBe("failed");
  });

  it("discloses unconfigured containment without executing a host fallback", async () => {
    const state = await fixture();
    const result = await executeBoundReadinessPlan({ sourceRoot: state.source, plan: state.plan,
      binding: bindReadinessPlanV1(state.plan, state.sentinel), allowTargetInstall: true,
      stageAuthorizations: state.authorizations, approvedEnvNames: [], environment: {}, disposableTempParent: state.root });
    expect(result.execution.stages).toHaveLength(state.plan.stages.length);
    expect(result.execution.stages.every((stage) => stage.status === "not-assessed" && stage.execution.kind === "not-run")).toBe(true);
    expect(result.execution.cleanup).toMatchObject({ status: "passed", removal: { status: "removed" }, source: { status: "passed" } });
    expect(parseReadinessArtifactsV1({ descriptorJson: result.descriptorJson, executionJson: result.json }).execution).toEqual(result.execution);
    expect(await captureSourceSentinel(state.source)).toEqual(state.sentinel);
  });

  it("withholds every executable stage without a stage-specific operator authorization", async () => {
    const fixtureState = await fixture();
    const { execution } = await executeBoundReadinessPlan({
      sourceRoot: fixtureState.source, plan: fixtureState.plan,
      binding: bindReadinessPlanV1(fixtureState.plan, fixtureState.sentinel),
      allowTargetInstall: false, stageAuthorizations: [], approvedEnvNames: [], environment: {},
      containment, disposableTempParent: fixtureState.root,
      limits: { timeoutMs: 3_000 },
    });
    expect(execution.stages.every((stage) => stage.status === "not-assessed")).toBe(true);
    expect(execution.stages.filter((stage) => stage.kind === "install")).toMatchObject([{ status: "not-assessed", diagnostic: { reasonCode: containment ? "authority-missing" : "containment-not-configured" } }]);
    expect(execution.cleanup.status).toBe("passed");
  });
});
