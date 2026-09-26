import { execFile } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { discoverReadinessPlan, type ReadinessPlanV1, type ReadinessStageV1 } from "./audit-readiness.js";
import { admitReadinessStage, bindReadinessPlanV1, createReadinessAdmission, type ReadinessAuthorityOptions, type ReadinessStageAdmission, type ReadinessStageAuthorization } from "./audit-readiness-authority.js";
import { captureSourceSentinel, cleanupDisposableTarget, createDisposableTarget, type DisposableTarget } from "./disposable-target.js";
import { executeBoundReadinessPlan } from "./audit-readiness-run.js";

const exec = promisify(execFile);
const roots: string[] = [];

afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });

async function fixture(options: { requiredEnv?: boolean | string; postinstall?: boolean; implicitPostinstall?: boolean; lockfile?: boolean } = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "harvey-readiness-authority-test-")));
  roots.push(root);
  const source = join(root, "source");
  const scratch = join(root, "scratch");
  await mkdir(source);
  await mkdir(scratch);
  await writeFile(join(source, "package.json"), JSON.stringify({
    name: "fixture",
    version: "1.0.0",
    packageManager: "npm@10.9.2",
    scripts: { build: "node runner.cjs", typecheck: "node runner.cjs", lint: "node runner.cjs", test: "node runner.cjs", ...(options.implicitPostinstall ? { postinstall: "prisma generate" } : options.postinstall ? { postinstall: "node postinstall.cjs" } : {}) },
  }));
  if (options.lockfile !== false) await writeFile(join(source, "package-lock.json"), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "fixture", version: "1.0.0" } } }));
  await writeFile(join(source, "runner.cjs"), `const fs=require('node:fs');fs.writeFileSync('stage-ran',JSON.stringify({cwd:process.cwd(),token:process.env.TEST_CREDENTIAL,nodeEnv:process.env.NODE_ENV,unapproved:process.env.HARVEY_UNAPPROVED_TEST,names:Object.keys(process.env),dotenv:fs.existsSync('.env')}));`);
  await writeFile(join(source, "postinstall.cjs"), "require('node:fs').writeFileSync('install-ran','declared postinstall executed');");
  await writeFile(join(source, ".env"), "TEST_CREDENTIAL=UNAPPROVED_DOTENV_CANARY");
  if (options.requiredEnv) await writeFile(join(source, "vitest.config.ts"), `export default { value: process.env.${typeof options.requiredEnv === "string" ? options.requiredEnv : "TEST_CREDENTIAL"} };\n`);
  if (options.implicitPostinstall) await writeFile(join(source, "codegen.ts"), "export default { key: process.env.GENERATOR_TOKEN };\n");
  const before = await captureSourceSentinel(source);
  const plan = discoverReadinessPlan(source);
  const binding = bindReadinessPlanV1(plan, before);
  const created = await createDisposableTarget(source, { tempParent: scratch });
  if (created.status !== "ready") throw new Error(JSON.stringify(created));
  return { root, source, scratch, plan, binding, target: created.target };
}

function optionsFor(plan: ReadinessPlanV1, overrides: Partial<ReadinessAuthorityOptions> = {}): ReadinessAuthorityOptions {
  return {
    allowTargetInstall: true,
    stageAuthorizations: plan.stages.filter((stage) => stage.assessment === "planned").map((stage) => ({
      stageId: stage.id,
      effect: stage.kind === "install" ? "target-install" : "disposable-local",
      source: "operator reviewed fixture effects",
      reason: "The fixture performs only approved work inside the disposable directory.",
      falsifier: "A fixture reads or writes original source or reaches an external service.",
    })),
    approvedEnvNames: [],
    environment: {},
    ...overrides,
  };
}

function stage(plan: ReadinessPlanV1, kind: ReadinessStageV1["kind"]): ReadinessStageV1 {
  const found = plan.stages.find((row) => row.kind === kind);
  if (!found) throw new Error("fixture stage missing");
  return found;
}

async function runIfAdmitted(admission: ReadinessStageAdmission): Promise<boolean> {
  if (admission.status !== "admitted") return false;
  await exec(admission.request.bin, [...admission.request.args], { cwd: admission.request.cwd, env: admission.request.env, shell: admission.request.shell, timeout: 10_000, maxBuffer: 16 * 1024 });
  return true;
}

async function noMarker(target: DisposableTarget, name = "stage-ran"): Promise<void> {
  await expect(lstat(join(target.targetRoot, name))).rejects.toMatchObject({ code: "ENOENT" });
}

describe("stage and effect authority", () => {
  it("keeps image toolchain admission separate from host path observations and target directories", async () => {
    const { plan, binding, target } = await fixture();
    const toolchainPath = "/harvey-image-only-toolchain-1897/bin";
    const toolchainScope = { kind: "container-image" as const, imageId: `sha256:${"c".repeat(64)}` };
    const host = createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath }));
    expect(await admitReadinessStage(host, stage(plan, "test").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "toolchain-path-invalid" });
    const image = createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath, toolchainScope }));
    const admitted = await admitReadinessStage(image, stage(plan, "test").id, target);
    expect(admitted.status).toBe("admitted");
    if (admitted.status !== "admitted") throw new Error("expected image-scoped admission");
    expect(admitted.request.env.PATH).toBe(toolchainPath);
    const targetPath = createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath: target.targetRoot, toolchainScope }));
    expect(await admitReadinessStage(targetPath, stage(plan, "test").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "toolchain-path-invalid" });
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainScope }))).toThrow(/probed immutable image/);
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath, toolchainScope: { ...toolchainScope, imageId: "mutable-tag" } }))).toThrow(/probed immutable image/);
    await noMarker(target);
  });

  it("does zero target work without a stage authorization and runs the same exact plan command when granted", async () => {
    const { plan, binding, target, source } = await fixture();
    const test = stage(plan, "test");
    const unapproved = createReadinessAdmission(plan, binding, optionsFor(plan, { stageAuthorizations: [] }));
    const denial = await admitReadinessStage(unapproved, test.id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "authority-missing", authority: { decision: "denied" } });
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target);
    const approved = createReadinessAdmission(plan, binding, optionsFor(plan));
    const admission = await admitReadinessStage(approved, test.id, target);
    expect(admission.status).toBe("admitted");
    if (admission.status !== "admitted" || test.assessment !== "planned") throw new Error("expected planned admission");
    expect(admission.request).toMatchObject({ bin: test.command.bin, args: test.command.args, cwd: target.targetRoot, shell: false });
    expect(await runIfAdmitted(admission)).toBe(true);
    expect(JSON.parse(await readFile(join(target.targetRoot, "stage-ran"), "utf8"))).toMatchObject({ cwd: target.targetRoot, dotenv: false });
    await expect(lstat(join(source, "stage-ran"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("withholds install and postinstall without --allow-target-install; the granted pair physically executes only in the copy", async () => {
    const { plan, binding, target, source } = await fixture({ postinstall: true });
    const install = stage(plan, "install");
    const deniedContext = createReadinessAdmission(plan, binding, optionsFor(plan, { allowTargetInstall: false }));
    const denial = await admitReadinessStage(deniedContext, install.id, target);
    const unauthorizedSpawn = await runIfAdmitted(denial);
    await noMarker(target, "install-ran");
    expect(unauthorizedSpawn).toBe(false);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "target-install-not-authorized", authority: { lifecycle: [{ path: "package.json", pointer: "/scripts/postinstall" }] } });
    const grantedContext = createReadinessAdmission(plan, binding, optionsFor(plan));
    const admission = await admitReadinessStage(grantedContext, install.id, target);
    expect(admission.status).toBe("admitted");
    expect(await runIfAdmitted(admission)).toBe(true);
    expect(await readFile(join(target.targetRoot, "install-ran"), "utf8")).toBe("declared postinstall executed");
    await expect(lstat(join(source, "install-ran"))).rejects.toMatchObject({ code: "ENOENT" });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it.each(["network-or-service", "unknown"] as const)("does not let target-install grant authorize %s effects", async (effect) => {
    const { plan, binding, target } = await fixture({ postinstall: true });
    const authorization = optionsFor(plan);
    authorization.stageAuthorizations = authorization.stageAuthorizations.map((row) => ({ ...row, effect }));
    const context = createReadinessAdmission(plan, binding, authorization);
    for (const kind of ["install", "test"] as const) {
      const denial = await admitReadinessStage(context, stage(plan, kind).id, target);
      expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "effect-not-authorized" });
      expect(await runIfAdmitted(denial)).toBe(false);
    }
    await noMarker(target);
    await noMarker(target, "install-ran");
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("applies implicit postinstall codegen environment requirements and effect refusals to its parent install", async () => {
    const { plan, binding, target } = await fixture({ implicitPostinstall: true });
    const install = stage(plan, "install");
    const codegen = stage(plan, "codegen");
    expect(codegen.assessment).toBe("implicit");
    const missing = createReadinessAdmission(plan, binding, optionsFor(plan));
    expect(await admitReadinessStage(missing, install.id, target)).toMatchObject({ status: "not-assessed", reasonCode: "required-environment-missing", authority: { requiredEnvNames: ["GENERATOR_TOKEN"] } });
    const approvedOptions = optionsFor(plan, { approvedEnvNames: ["GENERATOR_TOKEN"], environment: { GENERATOR_TOKEN: "APPROVED_GENERATOR_VALUE" } });
    const approved = createReadinessAdmission(plan, binding, approvedOptions);
    expect((await admitReadinessStage(approved, install.id, target)).status).toBe("admitted");
    const external = createReadinessAdmission(plan, binding, { ...approvedOptions, stageAuthorizations: [...approvedOptions.stageAuthorizations, { stageId: codegen.id, effect: "network-or-service", source: "operator review", reason: "The generator contacts an external service.", falsifier: "Configure local-only generation." }] });
    const denial = await admitReadinessStage(external, install.id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "lifecycle-effect-not-authorized" });
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target, "install-ran");
  });

  it("does not transfer install authority to a separate build/test/lint command", async () => {
    const { plan, binding, target } = await fixture();
    const options = optionsFor(plan);
    options.stageAuthorizations = options.stageAuthorizations.map((row) => ({ ...row, effect: "target-install" }));
    const context = createReadinessAdmission(plan, binding, options);
    for (const kind of ["build", "typecheck", "lint", "test"] as const) {
      expect(await admitReadinessStage(context, stage(plan, kind).id, target)).toMatchObject({ status: "not-assessed", reasonCode: "effect-scope-mismatch" });
    }
    await noMarker(target);
  });

  it("withholds a manager-field-only install instead of silently falling back to non-lockfile provisioning", async () => {
    const { plan, binding, target } = await fixture({ lockfile: false });
    const context = createReadinessAdmission(plan, binding, optionsFor(plan));
    expect(await admitReadinessStage(context, stage(plan, "install").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "lockfile-required" });
    await noMarker(target, "install-ran");
  });

  it("preserves absent and implicit plan arms without granting a synthetic command", async () => {
    const { plan, binding, target, source } = await fixture();
    const context = createReadinessAdmission(plan, binding, optionsFor(plan));
    expect(await admitReadinessStage(context, stage(plan, "codegen").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "missing-script-and-config" });
    const pkg = JSON.parse(await readFile(join(source, "package.json"), "utf8"));
    pkg.scripts.postinstall = "prisma generate";
    await writeFile(join(source, "package.json"), JSON.stringify(pkg));
    const implicitPlan = discoverReadinessPlan(source);
    const implicitContext = createReadinessAdmission(implicitPlan, bindReadinessPlanV1(implicitPlan, await captureSourceSentinel(source)), optionsFor(implicitPlan));
    const implicit = await admitReadinessStage(implicitContext, stage(implicitPlan, "codegen").id, target);
    expect(implicit).toMatchObject({ status: "not-assessed", reasonCode: "covered-by-install-lifecycle" });
    expect(await runIfAdmitted(implicit)).toBe(false);
  });
});

describe("environment names and values", () => {
  it.each([
    { label: "present but unapproved", names: [] as string[], environment: { TEST_CREDENTIAL: "SECRET_CANARY_APPROVED" } },
    { label: "approved but absent", names: ["TEST_CREDENTIAL"], environment: {} },
    { label: "approved but empty", names: ["TEST_CREDENTIAL"], environment: { TEST_CREDENTIAL: "" } },
  ])("withholds a required value that is $label", async ({ names, environment }) => {
    const { plan, binding, target } = await fixture({ requiredEnv: true });
    const context = createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: names, environment }));
    const denial = await admitReadinessStage(context, stage(plan, "test").id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "required-environment-missing" });
    expect(JSON.stringify(denial)).not.toContain("SECRET_CANARY_APPROVED");
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target);
  });

  it("passes only approved values, registers them before spawning, and hides values from JSON receipts", async () => {
    const { plan, binding, target } = await fixture({ requiredEnv: true });
    const registered: string[] = [];
    const secret = "SECRET_CANARY_APPROVED_VALUE_123";
    const ambient = process.env.HARVEY_UNAPPROVED_TEST;
    process.env.HARVEY_UNAPPROVED_TEST = "SECRET_CANARY_AMBIENT_VALUE_456";
    try {
      const context = createReadinessAdmission(plan, binding, optionsFor(plan, {
        approvedEnvNames: ["TEST_CREDENTIAL"],
        environment: { TEST_CREDENTIAL: secret, HARVEY_UNAPPROVED_TEST: "SECRET_CANARY_SUPPLIED_VALUE_789", NODE_OPTIONS: "--require /unsafe.js", PATH: "/unapproved/toolchain" },
        registerSecret: (value) => registered.push(value),
      }));
      expect(registered).toEqual([secret]);
      const admission = await admitReadinessStage(context, stage(plan, "test").id, target);
      expect(admission.status).toBe("admitted");
      if (admission.status !== "admitted") throw new Error("expected admission");
      expect(JSON.stringify(admission)).not.toContain(secret);
      expect(JSON.stringify(context)).not.toContain(secret);
      expect(admission.request.env.TEST_CREDENTIAL).toBe(secret);
      expect(admission.request.env.NODE_OPTIONS).toBeUndefined();
      expect(admission.request.env.HOME).toBe(join(target.root, "home"));
      expect(admission.request.env.TMPDIR).toBe(join(target.root, "tmp"));
      expect(admission.request.env.npm_config_cache).toBe(join(target.root, "cache", "npm"));
      expect(admission.request.env.npm_config_userconfig).toBe(join(target.root, "home", ".npmrc"));
      expect(admission.request.env.COREPACK_ENABLE_NETWORK).toBe("0");
      expect(await runIfAdmitted(admission)).toBe(true);
      const observed = JSON.parse(await readFile(join(target.targetRoot, "stage-ran"), "utf8"));
      expect(observed).toMatchObject({ token: secret, dotenv: false });
      expect(observed.unapproved).toBeUndefined();
      expect(observed.names).not.toContain("HARVEY_UNAPPROVED_TEST");
      expect((await cleanupDisposableTarget(target)).status).toBe("passed");
    } finally {
      if (ambient === undefined) delete process.env.HARVEY_UNAPPROVED_TEST;
      else process.env.HARVEY_UNAPPROVED_TEST = ambient;
    }
  });

  it.each([
    "NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE", "NODE_REDIRECT_WARNINGS", "NODE_COMPILE_CACHE",
    "NODE_REPL_HISTORY", "NODE_REPL_EXTERNAL_MODULE", "NODE_EXTRA_CA_CERTS", "NODE_ICU_DATA", "NODE_DEBUG",
    "NODE_ENV_", "NODE_ENV_TOKEN", "NODE_ENVIRONMENT", "NODE_FUTURE_RUNTIME_CONTROL", "NODE_",
    "BUN_OPTIONS", "BUN_RUNTIME_TRANSPILER_CACHE_PATH", "BUN_INSTALL_CACHE_DIR", "BUN_FUTURE_RUNTIME_CONTROL", "BUN_",
    "TS_NODE_COMPILER_OPTIONS", "TS_NODE_PROJECT", "TSX_TSCONFIG_PATH", "TSX_CACHE_DIR",
    "OPENSSL_CONF", "OPENSSL_MODULES", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "UV_THREADPOOL_SIZE",
    "PATH", "HOME", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "NPM_CONFIG_USERCONFIG", "BASH_ENV", "BASHOPTS",
    "GIT_CONFIG", "HTTP_PROXY", "FORCE_COLOR", "INVALID-NAME", "node_env", "Node_Env",
  ])("refuses approved environment overrides of %s", async (name) => {
    const { plan, binding } = await fixture();
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: [name], environment: { [name]: "value" } }))).toThrow(/protected runtime\/toolchain control/);
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: [name], environment: {} }))).toThrow(/protected runtime\/toolchain control/);
  });

  it("rejects reserved application credential names before reading values and without echoing either", async () => {
    const { plan, binding } = await fixture();
    const name = "NODE_PRIVATE_CREDENTIAL_CANARY";
    const value = "PRIVATE_RUNTIME_VALUE_CANARY";
    const reads: string[] = [];
    const registered: string[] = [];
    const environment: Record<string, string | undefined> = {};
    for (const key of ["APP_SECRET", name]) Object.defineProperty(environment, key, { get: () => { reads.push(key); return value; } });
    let error: unknown;
    try {
      createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: ["APP_SECRET", name], environment, registerSecret: (secret) => registered.push(secret) }));
    } catch (caught) { error = caught; }
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toContain("reserved even when used for application credentials");
    expect(String(error)).not.toContain(name);
    expect(String(error)).not.toContain(value);
    expect(reads).toEqual([]);
    expect(registered).toEqual([]);
  });

  it.each(["NODE_REDIRECT_WARNINGS", "NODE_ENV_TOKEN", "BUN_RUNTIME_TRANSPILER_CACHE_PATH", "TS_NODE_PROJECT"])("discloses required protected %s as policy refusal rather than a missing value", async (name) => {
    const { plan, binding, target } = await fixture({ requiredEnv: name });
    const context = createReadinessAdmission(plan, binding, optionsFor(plan));
    const denial = await admitReadinessStage(context, stage(plan, "test").id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "required-environment-protected", authority: { requiredEnvNames: [name] } });
    expect(denial.authority.reason).toContain("reserved even when used for application credentials");
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target);
  });

  it.each([
    "NODE", "NODEENV", "NODE_ENV", "NODEJS_TOKEN", "BUN", "BUNNY_TOKEN", "TS_NODEJS_TOKEN", "TSXTOKEN",
    "APP_NODE_OPTIONS", "APP_BUN_OPTIONS", "APP_TSX_CACHE_DIR", "OPENSSLKEY", "SSL_CERT_FILE_TOKEN", "SSLKEYLOGFILE_TOKEN", "UV_SERVICE_TOKEN",
  ])("keeps neighboring application name %s admissible and its value private", async (name) => {
    const { plan, binding, target } = await fixture();
    const value = "APPLICATION_VALUE_CANARY";
    const registered: string[] = [];
    const context = createReadinessAdmission(plan, binding, optionsFor(plan, {
      approvedEnvNames: [name], environment: { [name]: value }, registerSecret: (secret) => registered.push(secret),
    }));
    const admission = await admitReadinessStage(context, stage(plan, "test").id, target);
    expect(admission.status).toBe("admitted");
    if (admission.status !== "admitted") throw new Error("expected application environment admission");
    expect(admission.request.env[name]).toBe(value);
    expect(registered).toEqual([value]);
    expect(JSON.stringify(admission)).not.toContain(value);
    expect(JSON.stringify(context)).not.toContain(value);
  });

  it.each([
    { value: "development", kind: "test" as const },
    { value: "production", kind: "build" as const },
    { value: "test", kind: "lint" as const },
  ])("passes explicitly approved NODE_ENV=$value without changing value privacy on $kind argv", async ({ value, kind }) => {
    const { plan, binding, target } = await fixture();
    const registered: string[] = [];
    const context = createReadinessAdmission(plan, binding, optionsFor(plan, {
      approvedEnvNames: ["NODE_ENV"], environment: { NODE_ENV: value }, registerSecret: (secret) => registered.push(secret),
    }));
    const admission = await admitReadinessStage(context, stage(plan, kind).id, target);
    expect(registered).toEqual([value]);
    expect(admission.status).toBe("admitted");
    if (admission.status !== "admitted") throw new Error("expected NODE_ENV application-mode admission");
    expect(admission.request.env.NODE_ENV).toBe(value);
    expect(Object.keys(admission.request)).not.toContain("env");
    expect(await runIfAdmitted(admission)).toBe(true);
    expect(JSON.parse(await readFile(join(target.targetRoot, "stage-ran"), "utf8"))).toMatchObject({ nodeEnv: value });
    expect((await cleanupDisposableTarget(target)).status).toBe("passed");
  });

  it("does not inherit NODE_ENV without approval or treat its argv-colliding value as public", async () => {
    const { plan, binding, target } = await fixture();
    const test = stage(plan, "test");
    const unapproved = createReadinessAdmission(plan, binding, optionsFor(plan, { environment: { NODE_ENV: "development" } }));
    const admission = await admitReadinessStage(unapproved, test.id, target);
    if (admission.status !== "admitted") throw new Error("expected clean environment admission");
    expect(admission.request.env.NODE_ENV).toBeUndefined();
    const approved = createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: ["NODE_ENV"], environment: { NODE_ENV: "test" } }));
    const denial = await admitReadinessStage(approved, test.id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "unsafe-argv" });
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target);
  });

  it.each(["NODE_REDIRECT_WARNINGS", "NODE_COMPILE_CACHE"])("withholds %s before the bound runner can alter original source", async (name) => {
    const { root, source, plan } = await fixture();
    const canary = join(source, "original-warning-canary");
    const cache = join(source, "original-cache-canary");
    await writeFile(canary, "original warning canary\n");
    await mkdir(cache);
    await writeFile(join(cache, "keep"), "original cache canary");
    const before = await captureSourceSentinel(source);
    const binding = bindReadinessPlanV1(plan, before);
    const tools = join(root, "tools");
    const commandStarted = join(root, "command-started");
    await mkdir(tools);
    await writeFile(join(tools, "npm"), `#!${process.execPath}
require('node:fs').writeFileSync(${JSON.stringify(commandStarted)}, 'command started');
process.emitWarning('runtime-output-canary');
`);
    await chmod(join(tools, "npm"), 0o755);
    const value = name === "NODE_REDIRECT_WARNINGS" ? canary : cache;
    const result = await executeBoundReadinessPlan({
      sourceRoot: source, plan, binding,
      ...optionsFor(plan, { approvedEnvNames: [name], environment: { [name]: value }, toolchainPath: tools }),
      limits: { timeoutMs: 3_000, headBytes: 512, tailBytes: 512 },
    });
    expect(await captureSourceSentinel(source)).toEqual(before);
    expect(await readFile(canary, "utf8")).toBe("original warning canary\n");
    expect(await readFile(join(cache, "keep"), "utf8")).toBe("original cache canary");
    await expect(lstat(commandStarted)).rejects.toMatchObject({ code: "ENOENT" });
    expect(result.execution.stages.every((row) => row.execution.kind !== "process")).toBe(true);
    expect(result.execution.cleanup).toMatchObject({ status: "passed", source: { status: "passed" }, removal: { status: "removed" } });
    expect(result.json).not.toContain(value);
    expect(result.json).not.toContain("runtime-output-canary");
  });

  it.each([{ value: "npm", kind: "test" as const }, { value: "typecheck", kind: "typecheck" as const }])("rejects a $value approved value in argv, including values below the shared secret-length floor", async ({ value, kind }) => {
    const { plan, binding, target } = await fixture();
    const context = createReadinessAdmission(plan, binding, optionsFor(plan, { approvedEnvNames: ["TEST_CREDENTIAL"], environment: { TEST_CREDENTIAL: value } }));
    const denial = await admitReadinessStage(context, stage(plan, kind).id, target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "unsafe-argv" });
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(target);
  });
});

describe("bound immutable admission", () => {
  it("rejects a different target or changed source even when plan stage IDs and commands are identical", async () => {
    const first = await fixture();
    const second = await fixture();
    const context = createReadinessAdmission(first.plan, first.binding, optionsFor(first.plan));
    expect(await admitReadinessStage(context, stage(first.plan, "test").id, second.target)).toMatchObject({ status: "not-assessed", reasonCode: "source-binding-mismatch" });
    await writeFile(join(first.source, "new-source.txt"), "changed after binding");
    const created = await createDisposableTarget(first.source, { tempParent: first.scratch });
    if (created.status !== "ready") throw new Error(JSON.stringify(created));
    const denial = await admitReadinessStage(context, stage(first.plan, "test").id, created.target);
    expect(denial).toMatchObject({ status: "not-assessed", reasonCode: "source-binding-mismatch" });
    expect(await runIfAdmitted(denial)).toBe(false);
    await noMarker(created.target);
  });

  it("freezes exact upstream commands and does not accept a mutated plan under an old binding", async () => {
    const { plan, binding, target } = await fixture();
    const context = createReadinessAdmission(plan, binding, optionsFor(plan));
    const original = stage(plan, "test");
    if (original.assessment !== "planned") throw new Error("missing command");
    original.command.args[1] = "build";
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan))).toThrow();
    const admission = await admitReadinessStage(context, original.id, target);
    if (admission.status !== "admitted") throw new Error("expected frozen original admission");
    expect(admission.request.args).toEqual(["run", "test"]);
    expect(Object.isFrozen(admission.request)).toBe(true);
    expect(Object.isFrozen(admission.request.args)).toBe(true);
    expect(Object.isFrozen(context.plan)).toBe(true);
  });

  it("rejects unknown schema versions, duplicate grants, and grants outside the plan", async () => {
    const { plan, binding } = await fixture();
    expect(() => createReadinessAdmission({ ...plan, schemaVersion: 2 }, binding, optionsFor(plan))).toThrow(/schemaVersion/);
    const options = optionsFor(plan);
    const first = options.stageAuthorizations[0]!;
    expect(() => createReadinessAdmission(plan, binding, { ...options, stageAuthorizations: [first, first] })).toThrow(/unique planned stage/);
    expect(() => createReadinessAdmission(plan, binding, { ...options, stageAuthorizations: [{ ...first, stageId: "stage:workspace:unowned:test" }] })).toThrow(/unique planned stage/);
    expect(() => createReadinessAdmission(plan, { ...binding, planSha256: "0".repeat(64) }, options)).toThrow(/execution binding/);
  });

  it("does not authorize a stage after a copied link escapes or cleanup begins", async () => {
    const { plan, binding, target, source } = await fixture();
    const context = createReadinessAdmission(plan, binding, optionsFor(plan));
    await symlink(source, join(target.targetRoot, "source-link"));
    expect(await admitReadinessStage(context, stage(plan, "test").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "run-link-escape" });
    await cleanupDisposableTarget(target);
    expect(await admitReadinessStage(context, stage(plan, "test").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "inactive-target" });
  });

  it("refuses source-provided toolchain directories, including an external alias into source", async () => {
    const { root, plan, binding, target, source } = await fixture();
    const alias = join(root, "toolchain-alias");
    await symlink(source, alias);
    for (const toolchainPath of [source, alias]) {
      const context = createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath }));
      expect(await admitReadinessStage(context, stage(plan, "test").id, target)).toMatchObject({ status: "not-assessed", reasonCode: "toolchain-path-invalid" });
    }
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath: "." }))).toThrow(/absolute directories/);
    expect(() => createReadinessAdmission(plan, binding, optionsFor(plan, { toolchainPath: `${dirname(process.execPath)}:` }))).toThrow(/absolute directories/);
    await noMarker(target);
  });

  it("does not reread mutable authorization and environment input after admission setup", async () => {
    const { plan, binding, target } = await fixture({ requiredEnv: true });
    const environment = { TEST_CREDENTIAL: "FIRST_APPROVED_VALUE" };
    const options = optionsFor(plan, { approvedEnvNames: ["TEST_CREDENTIAL"], environment });
    const context = createReadinessAdmission(plan, binding, options);
    environment.TEST_CREDENTIAL = "LATER_UNAPPROVED_VALUE";
    (options.stageAuthorizations as ReadinessStageAuthorization[]).splice(0);
    const admission = await admitReadinessStage(context, stage(plan, "test").id, target);
    if (admission.status !== "admitted") throw new Error("expected frozen admission");
    expect(admission.request.env.TEST_CREDENTIAL).toBe("FIRST_APPROVED_VALUE");
    expect(JSON.stringify(admission)).not.toContain("FIRST_APPROVED_VALUE");
  });
});
