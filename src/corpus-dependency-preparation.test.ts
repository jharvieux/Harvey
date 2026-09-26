import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, symlinkSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inspectCorpusDependencyInputs, prepareCorpusDependencies } from "./corpus-dependency-preparation.js";
import { readEntriesLstatSafe, readRecursiveSafe } from "./fs-walk.js";

describe("relocatable corpus dependency preparation (#1872)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  function fixture(manager: "npm" | "pnpm" | "yarn"): string {
    const dir = mkdtempSync(join(tmpdir(), `harvey-dependency-${manager}-`));
    dirs.push(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: `${manager}-fixture`,
      private: true,
      ...(manager === "pnpm" ? { dependencies: { "is-number": "7.0.0" } } : {}),
    }));
    if (manager === "npm") {
      writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "npm-fixture", lockfileVersion: 3, requires: true, packages: { "": { name: "npm-fixture" } } }));
    } else if (manager === "pnpm") {
      writeFileSync(join(dir, "pnpm-lock.yaml"), [
        "lockfileVersion: '9.0'",
        "settings:",
        "  autoInstallPeers: true",
        "  excludeLinksFromLockfile: false",
        "importers:",
        "  .:",
        "    dependencies:",
        "      is-number:",
        "        specifier: 7.0.0",
        "        version: 7.0.0",
        "packages:",
        "  is-number@7.0.0:",
        "    resolution: {integrity: sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==}",
        "    engines: {node: '>=0.12.0'}",
        "snapshots:",
        "  is-number@7.0.0: {}",
        "",
      ].join("\n"));
    } else {
      writeFileSync(join(dir, "yarn.lock"), "# yarn lockfile v1\n");
    }
    return dir;
  }

  function symlinksUnder(root: string): string[] {
    const found: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readEntriesLstatSafe(dir)) {
        if (entry.isSymbolicLink) found.push(entry.path);
        else if (entry.isDirectory) walk(entry.path);
      }
    };
    walk(root);
    return found;
  }

  it.each(["npm", "pnpm", "yarn"] as const)("materializes %s cold then offline from the same content address", async (manager) => {
    const targetA = fixture(manager);
    const targetB = fixture(manager);
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-cache-"));
    dirs.push(cacheDir);
    const invocations: { bin: string; args: string[]; cwd: string }[] = [];
    const common = {
      cacheDir,
      targetRevision: "same-pin",
      targetTree: "same-tree",
      packageManagerVersion: "exact-1.2.3",
      runInstall: (invocation: { bin: string; args: string[]; cwd: string }) => invocations.push(invocation),
    };
    const cold = await prepareCorpusDependencies({ ...common, targetDir: targetA });
    const warm = await prepareCorpusDependencies({ ...common, targetDir: targetB });

    expect(cold.status).toBe("miss");
    expect(warm.status).toBe("hit");
    expect(warm.key).toBe(cold.key);
    expect(invocations.map((invocation) => invocation.bin)).toEqual([manager, manager]);
    expect(invocations[1]!.args).toContain("--offline");
    expect(invocations.flatMap((invocation) => invocation.args).every((arg) => !arg.includes("node_modules"))).toBe(true);
    if (manager === "pnpm") expect(invocations[0]!.args).toContain("--config.enableGlobalVirtualStore=false");
  });

  it.each(["npm", "pnpm", "yarn"] as const)("runs the real %s package manager across different checkout paths", async (manager) => {
    const targetA = fixture(manager);
    const targetB = fixture(manager);
    const cacheDir = mkdtempSync(join(tmpdir(), `harvey-real-${manager}-store-`));
    dirs.push(cacheDir);
    const events: string[] = [];
    const cacheArgument = manager === "pnpm" ? relative(process.cwd(), cacheDir) : cacheDir;
    const common = { cacheDir: cacheArgument, targetRevision: "same-pin", targetTree: "same-tree", onEvent: (event: string) => events.push(event) };
    const cold = await prepareCorpusDependencies({ ...common, targetDir: targetA });
    const warm = await prepareCorpusDependencies({ ...common, targetDir: targetB });
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: true, packageManager: manager });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: true, packageManager: manager, key: cold.key });
    expect(events).toContainEqual(expect.stringContaining(`DEPENDENCY PREP HIT ${manager}`));
    if (manager === "pnpm") {
      expect(resolve(cacheArgument)).toBe(cacheDir);
      expect(readRecursiveSafe(targetA).some((path) => path.includes("harvey-real-pnpm-store"))).toBe(false);
      expect(symlinksUnder(cacheDir)).toEqual([]);
      expect(readRecursiveSafe(cacheDir).some((path) => /(^|\/)node_modules(\/|$)/.test(path))).toBe(false);
    }
  });

  it("canonicalizes a relative cache root before changing to the target cwd", async () => {
    const target = fixture("pnpm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-relative-store-"));
    dirs.push(cacheDir);
    const cacheArgument = relative(process.cwd(), cacheDir);
    const invocations: { args: string[]; cwd: string }[] = [];
    await prepareCorpusDependencies({
      targetDir: target,
      cacheDir: cacheArgument,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.1.3",
      runInstall: (invocation) => invocations.push(invocation),
    });
    const storeFlag = invocations[0]!.args.indexOf("--store-dir");
    const storeDir = invocations[0]!.args[storeFlag + 1]!;
    expect(storeFlag).toBeGreaterThan(-1);
    expect(storeDir.startsWith(cacheDir)).toBe(true);
    expect(storeDir.startsWith(target)).toBe(false);
    expect(invocations[0]!.cwd).toBe(target);
  });

  it("binds lockfile, manager version, runtime/install config, and target identity independently of checkout path", async () => {
    const targetA = fixture("npm");
    const targetB = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-identity-"));
    dirs.push(cacheDir);
    const runInstall = vi.fn();
    const build = async (targetDir: string, packageManagerVersion = "11.12.1", targetTree = "tree") => await prepareCorpusDependencies({
      targetDir, cacheDir, targetRevision: "pin", targetTree, packageManagerVersion, runInstall,
    });
    const first = await build(targetA);
    expect((await build(targetB)).status).toBe("hit");
    expect((await build(targetB, "11.12.2")).key).not.toBe(first.key);
    expect((await build(targetB, "11.12.1", "other-tree")).key).not.toBe(first.key);
    writeFileSync(join(targetB, ".npmrc"), "legacy-peer-deps=true\n");
    expect((await build(targetB)).key).not.toBe(first.key);
    writeFileSync(join(targetB, "package-lock.json"), JSON.stringify({ name: "npm-fixture", lockfileVersion: 3, packages: { "": { name: "changed" } } }));
    expect((await build(targetB)).key).not.toBe(first.key);
  });

  it("fails cacheability on conflicting locks, manager declarations, or declared executable versions", async () => {
    const multipleLocks = fixture("pnpm");
    writeFileSync(join(multipleLocks, "package-lock.json"), '{"lockfileVersion":3,"packages":{"":{}}}\n');
    expect(inspectCorpusDependencyInputs(multipleLocks, "pnpm", "11.12.1").packageManagerReason).toContain("multiple package-manager lockfile families");

    const declarationMismatch = fixture("npm");
    const mismatchPackage = JSON.parse(readFileSync(join(declarationMismatch, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(declarationMismatch, "package.json"), JSON.stringify({ ...mismatchPackage, packageManager: "pnpm@11.12.1" }));
    expect(inspectCorpusDependencyInputs(declarationMismatch, "npm", "11.12.1").packageManagerReason).toContain("declares pnpm but lockfile detection selected npm");

    const versionMismatch = fixture("npm");
    const versionPackage = JSON.parse(readFileSync(join(versionMismatch, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(versionMismatch, "package.json"), JSON.stringify({ ...versionPackage, packageManager: "npm@11.12.0" }));
    expect(inspectCorpusDependencyInputs(versionMismatch, "npm", "11.12.1").packageManagerReason).toContain("executable is 11.12.1");
  });

  it.each([
    { manager: "npm" as const, file: "package.json", change: (text: string) => JSON.stringify({ ...JSON.parse(text), dependencies: { alias: "npm:is-number@7.0.0" } }) },
    { manager: "pnpm" as const, file: "pnpm-workspace.yaml", change: () => "packages: ['.']\ncatalog:\n  react: 19.0.0\n" },
    { manager: "yarn" as const, file: ".yarnrc.yml", change: () => "packageExtensions:\n  example@*:\n    dependencies:\n      react: 19.0.0\n" },
  ])("binds adversarial $manager alias/catalog/workspace installation shape", ({ manager, file, change }) => {
    const targetA = fixture(manager);
    const targetB = fixture(manager);
    const before = inspectCorpusDependencyInputs(targetA, manager, "exact-1.2.3");
    const path = join(targetB, file);
    writeFileSync(path, change(existsSync(path) ? readFileSync(path, "utf8") : "{}"));
    const changed = inspectCorpusDependencyInputs(targetB, manager, "exact-1.2.3");
    expect(changed.installConfiguration).not.toBe(before.installConfiguration);
  });

  it("invalidates preparation when any install-visible environment value changes", async () => {
    const targetA = fixture("npm");
    const targetB = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-environment-"));
    dirs.push(cacheDir);
    const runInstall = vi.fn();
    const baseEnvironment = { HOME: "/identity/home-a", PATH: "/identity/bin-a", TMPDIR: "/identity/tmp-a" };
    const build = async (targetDir: string, environment: NodeJS.ProcessEnv) => await prepareCorpusDependencies({
      targetDir,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      environment,
      runInstall,
    });
    const first = await build(targetA, baseEnvironment);
    expect(await build(targetB, baseEnvironment)).toMatchObject({ status: "hit", key: first.key });
    for (const [name, value] of [["HOME", "/identity/home-b"], ["PATH", "/identity/bin-b"], ["TMPDIR", "/identity/tmp-b"]] as const) {
      const moved = await build(targetB, { ...baseEnvironment, [name]: value });
      expect(moved.status).toBe("miss");
      expect(moved.key).not.toBe(first.key);
    }
  });

  it("keeps quality results fresh for executable Knip control config and install hooks", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "knip.js"), "module.exports = { entry: [process.env.DYNAMIC_ENTRY] };\n");
    const pkg = JSON.parse(readFileSync(join(target, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(target, "package.json"), JSON.stringify({ ...pkg, scripts: { postinstall: "node fetch-current-state.js" } }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-dynamic-"));
    dirs.push(cacheDir);
    const options = {
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    };
    const cold = await prepareCorpusDependencies(options);
    const warm = await prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.key });
    expect(warm.reason).toContain("install lifecycle scripts can observe time/network state");
    expect(warm.reason).toContain("executable framework/plugin configuration Knip may load can observe time/network/unkeyed state");
    expect(warm.reason).toContain("knip.js");
  });

  it("keeps installed transitive lifecycle scripts non-cacheable after clean and offline materialization", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "package-lock.json"), JSON.stringify({
      name: "npm-fixture",
      lockfileVersion: 3,
      packages: {
        "": { name: "npm-fixture", dependencies: { "stateful-dependency": "1.0.0" } },
        "node_modules/stateful-dependency": {
          name: "stateful-dependency",
          version: "1.0.0",
          integrity: "sha512-fixture",
          hasInstallScript: true,
        },
      },
    }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-transitive-lifecycle-"));
    dirs.push(cacheDir);
    const runInstall = () => {
      const dependency = join(target, "node_modules", "stateful-dependency");
      mkdirSync(dependency, { recursive: true });
      writeFileSync(join(dependency, "package.json"), JSON.stringify({
        name: "stateful-dependency",
        version: "1.0.0",
        scripts: { postinstall: "node rewrite-project.js" },
      }));
    };
    const options = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.12.1", runInstall };
    const cold = await prepareCorpusDependencies(options);
    const warm = await prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.key });
    expect(warm.reason).toContain("resolved npm packages declare lifecycle execution in the lockfile");
    expect(warm.reason).toContain("installed dependency lifecycle scripts can observe or mutate project state");
    expect(warm.reason).toContain("stateful-dependency@1.0.0 (postinstall)");
  });

  it("keeps an enumerable installed dependency tree with no lifecycle scripts cacheable", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "package-lock.json"), JSON.stringify({
      name: "npm-fixture",
      lockfileVersion: 3,
      packages: {
        "": { name: "npm-fixture", dependencies: { "plain-dependency": "1.0.0" } },
        "node_modules/plain-dependency": { name: "plain-dependency", version: "1.0.0", integrity: "sha512-fixture" },
      },
    }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-no-lifecycle-"));
    dirs.push(cacheDir);
    const runInstall = () => {
      const dependency = join(target, "node_modules", "plain-dependency");
      mkdirSync(dependency, { recursive: true });
      writeFileSync(join(dependency, "package.json"), JSON.stringify({ name: "plain-dependency", version: "1.0.0" }));
    };
    const options = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.12.1", runInstall };
    const cold = await prepareCorpusDependencies(options);
    const warm = await prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: true });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: true, key: cold.key });
  });

  it("fails fresh when the lock resolves dependencies but their installed lifecycle surface is absent", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "package-lock.json"), JSON.stringify({
      name: "npm-fixture",
      lockfileVersion: 3,
      packages: {
        "": { name: "npm-fixture", dependencies: { opaque: "1.0.0" } },
        "node_modules/opaque": { name: "opaque", version: "1.0.0", integrity: "sha512-fixture" },
      },
    }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-opaque-lifecycle-"));
    dirs.push(cacheDir);
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    expect(result).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(result.reason).toContain("installed dependency lifecycle reachability could not be proven");
    expect(result.reason).toContain("no physical installed package manifests were enumerable");
  });

  it.each([
    {
      label: "Vite's default provider config",
      configure: (target: string) => writeFileSync(join(target, "vite.config.js"), "module.exports = { build: { lib: { entry: process.env.ENTRY } } };\n"),
      expected: "vite.config.js",
    },
    {
      label: "a non-Vite provider config in a declared workspace",
      configure: (target: string) => {
        const pkg = JSON.parse(readFileSync(join(target, "package.json"), "utf8")) as Record<string, unknown>;
        writeFileSync(join(target, "package.json"), JSON.stringify({ ...pkg, workspaces: ["packages/*"] }));
        mkdirSync(join(target, "packages", "app"), { recursive: true });
        writeFileSync(join(target, "packages", "app", "package.json"), '{"name":"workspace-app","private":true}\n');
        writeFileSync(join(target, "packages", "app", "jest.config.cjs"), "module.exports = () => ({ roots: [process.env.HOME] });\n");
      },
      expected: "packages/app/jest.config.cjs",
    },
    {
      label: "a custom executable provider input named only by static Knip config",
      configure: (target: string) => {
        mkdirSync(join(target, "tooling"));
        writeFileSync(join(target, "tooling", "runtime.ts"), "export default { entry: [process.env.ENTRY] };\n");
        writeFileSync(join(target, "knip.json"), JSON.stringify({ vite: { config: ["tooling/runtime.ts"] } }));
      },
      expected: "tooling/runtime.ts",
    },
  ])("marks quality non-cacheable for $label", async ({ configure, expected }) => {
    const target = fixture("npm");
    configure(target);
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-provider-config-"));
    dirs.push(cacheDir);
    const options = {
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    };
    const cold = await prepareCorpusDependencies(options);
    const warm = await prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.key });
    expect(warm.reason).toContain("executable framework/plugin configuration Knip may load can observe time/network/unkeyed state");
    expect(warm.reason).toContain(expected);
  });

  it("resolves package-manager brace workspaces with Knip's own glob semantics", async () => {
    const target = fixture("npm");
    const pkg = JSON.parse(readFileSync(join(target, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(target, "package.json"), JSON.stringify({ ...pkg, workspaces: ["packages/{app,lib}"] }));
    for (const name of ["app", "lib"]) {
      mkdirSync(join(target, "packages", name), { recursive: true });
      writeFileSync(join(target, "packages", name, "package.json"), JSON.stringify({ name: `workspace-${name}`, private: true }));
    }
    writeFileSync(join(target, "packages", "app", "vite.config.js"), "module.exports = { build: { lib: { entry: process.env.HOME } } };\n");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-brace-workspace-"));
    dirs.push(cacheDir);
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    expect(result).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(result.reason).toContain("packages/app/vite.config.js");
  });

  it("keeps quality fresh when package-manager workspace declarations are not enumerable", async () => {
    const target = fixture("npm");
    const pkg = JSON.parse(readFileSync(join(target, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(target, "package.json"), JSON.stringify({ ...pkg, workspaces: "packages/*" }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-unknown-workspace-"));
    dirs.push(cacheDir);
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    expect(result).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(result.reason).toContain("package.json#workspaces is not a statically enumerable string array");
  });

  it("fails safe when Knip's executable input set cannot be proven", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "knip.json"), "{ this is not static JSON }\n");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-unknown-config-"));
    dirs.push(cacheDir);
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    expect(result).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(result.reason).toContain("Knip's complete executable configuration input set could not be proven");
    expect(result.reason).toContain("knip.json could not be parsed");
  });

  it("keeps benign static Knip and provider configuration cacheable", async () => {
    const target = fixture("npm");
    writeFileSync(join(target, "knip.jsonc"), '{\n  // Static paths are content-addressed by the target tree.\n  "entry": ["src/index.ts"]\n}\n');
    writeFileSync(join(target, ".eslintrc.json"), '{"extends":[]}\n');
    writeFileSync(join(target, "tsconfig.json"), '{"compilerOptions":{"strict":true}}\n');
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-static-config-"));
    dirs.push(cacheDir);
    const options = {
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    };
    const cold = await prepareCorpusDependencies(options);
    const warm = await prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: true });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: true, key: cold.key });
  });

  it("yields the event loop while the real Knip configuration child runs", async () => {
    const target = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-knip-heartbeat-"));
    dirs.push(cacheDir);
    let heartbeats = 0;
    const heartbeat = setInterval(() => { heartbeats += 1; }, 1);
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    clearInterval(heartbeat);
    expect(result).toMatchObject({ complete: true, status: "miss" });
    expect(heartbeats).toBeGreaterThan(0);
  });

  it("closes Knip discovery stdin and retains a real nonzero child status", async () => {
    const target = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-knip-stdin-"));
    dirs.push(cacheDir);
    const preload = join(cacheDir, "stdin-control.cjs");
    const marker = join(cacheDir, "stdin-ended");
    writeFileSync(preload, String.raw`
const fs = require("node:fs");
if (process.env.HARVEY_KNIP_STDIN_CONTROL === "wait") {
  let inputEnded = false;
  let watchdog;
  process.stdin.resume();
  process.stdin.once("end", () => {
    inputEnded = true;
    if (watchdog) clearTimeout(watchdog);
    fs.writeFileSync(process.env.HARVEY_KNIP_STDIN_MARKER, "ended");
  });
  const originalWrite = process.stdout.write;
  process.stdout.write = function (...args) {
    const chunk = args[0];
    const nonempty = typeof chunk === "string" ? Buffer.byteLength(chunk) > 0 : (chunk?.byteLength ?? 0) > 0;
    if (!inputEnded && !watchdog && nonempty) watchdog = setTimeout(() => process.exit(37), 250);
    return Reflect.apply(originalWrite, this, args);
  };
  const delay = Number(process.env.HARVEY_KNIP_STARTUP_DELAY_MS ?? 0);
  const deadline = performance.now() + delay;
  while (performance.now() < deadline) { /* controlled preload startup delay */ }
} else if (process.env.HARVEY_KNIP_STDIN_CONTROL === "nonzero") {
  process.exit(37);
}
`);
    const originalNodeOptions = process.env.NODE_OPTIONS;
    const originalControl = process.env.HARVEY_KNIP_STDIN_CONTROL;
    const originalMarker = process.env.HARVEY_KNIP_STDIN_MARKER;
    const originalDelay = process.env.HARVEY_KNIP_STARTUP_DELAY_MS;
    process.env.NODE_OPTIONS = `${originalNodeOptions ?? ""} --require=${preload}`.trim();
    process.env.HARVEY_KNIP_STDIN_MARKER = marker;
    process.env.HARVEY_KNIP_STARTUP_DELAY_MS = "350";
    const options = {
      targetDir: target,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    };
    try {
      process.env.HARVEY_KNIP_STDIN_CONTROL = "wait";
      const completed = await prepareCorpusDependencies(options);
      expect(completed).toMatchObject({ complete: true, status: "miss", cacheable: true });
      expect(readFileSync(marker, "utf8")).toBe("ended");

      rmSync(marker);
      const missingEof = await new Promise<{ code?: number | string | null; stdout: string }>((resolveRun) => {
        execFile(process.execPath, ["--eval", 'process.stdout.write("READY")'], {
          cwd: target,
          env: process.env,
          encoding: "utf8",
        }, (error, stdout) => resolveRun({ code: error?.code, stdout }));
      });
      expect(missingEof).toEqual({ code: 37, stdout: "READY" });

      process.env.HARVEY_KNIP_STDIN_CONTROL = "nonzero";
      const failed = await prepareCorpusDependencies({ ...options, targetRevision: "nonzero" });
      expect(failed).toMatchObject({ complete: true, status: "miss", cacheable: false });
      expect(failed.reason).toContain("discovery process failed (status 37, signal none, code none)");
    } finally {
      if (originalNodeOptions === undefined) delete process.env.NODE_OPTIONS;
      else process.env.NODE_OPTIONS = originalNodeOptions;
      if (originalControl === undefined) delete process.env.HARVEY_KNIP_STDIN_CONTROL;
      else process.env.HARVEY_KNIP_STDIN_CONTROL = originalControl;
      if (originalMarker === undefined) delete process.env.HARVEY_KNIP_STDIN_MARKER;
      else process.env.HARVEY_KNIP_STDIN_MARKER = originalMarker;
      if (originalDelay === undefined) delete process.env.HARVEY_KNIP_STARTUP_DELAY_MS;
      else process.env.HARVEY_KNIP_STARTUP_DELAY_MS = originalDelay;
    }
  });

  it("rejects a corrupt receipt visibly and performs a clean install", async () => {
    const target = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-corrupt-"));
    dirs.push(cacheDir);
    const events: string[] = [];
    const runInstall = vi.fn();
    const options = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.12.1", runInstall, onEvent: (event: string) => events.push(event) };
    const cold = await prepareCorpusDependencies(options);
    const receipt = join(cacheDir, readRecursiveSafe(cacheDir).find((path) => path.startsWith("dependency-preparation/receipts/") && path.endsWith(".json"))!);
    writeFileSync(receipt, JSON.stringify({ schema: 0, key: cold.key }));
    expect((await prepareCorpusDependencies(options)).status).toBe("miss");
    expect(events).toContainEqual(expect.stringContaining("DEPENDENCY PREP REJECT npm"));
    expect(JSON.parse(readFileSync(receipt, "utf8"))).toMatchObject({ schema: 3 });
    expect(runInstall).toHaveBeenCalledTimes(2);
  });

  it("rejects an incomplete restored store, retries clean, and keeps a failed retry fail-loud", async () => {
    const target = fixture("pnpm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-incomplete-"));
    dirs.push(cacheDir);
    const events: string[] = [];
    const seed = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.1.3", onEvent: (event: string) => events.push(event) };
    await prepareCorpusDependencies({ ...seed, runInstall: vi.fn() });
    let calls = 0;
    const repaired = await prepareCorpusDependencies({ ...seed, runInstall: () => { calls += 1; if (calls === 1) throw new Error("offline store corrupt"); } });
    expect(repaired.status).toBe("miss");
    expect(calls).toBe(2);
    expect(events).toContainEqual(expect.stringContaining("offline materialization failed"));

    const receipt = join(cacheDir, readRecursiveSafe(cacheDir).find((path) => path.startsWith("dependency-preparation/receipts/") && path.endsWith(".json"))!);
    rmSync(receipt, { force: true });
    let fallbackCalls = 0;
    const failed = await prepareCorpusDependencies({ ...seed, runInstall: () => {
      fallbackCalls += 1;
      mkdirSync(join(target, "node_modules"), { recursive: true });
      writeFileSync(join(target, "node_modules", "partial.js"), "rejected population\n");
      throw new Error("clean install unavailable");
    } });
    expect(failed).toMatchObject({ status: "incomplete", complete: false, cacheable: false });
    expect(existsSync(join(target, "node_modules", "partial.js"))).toBe(false);
    expect(fallbackCalls).toBe(2);
    expect(events).toContainEqual(expect.stringContaining("M5-knip will preserve its did-not-run/degraded semantics"));
  });

  it("does not claim a reproducible preparation without an integrity-bearing lockfile", async () => {
    const target = fixture("npm");
    rmSync(join(target, "package-lock.json"));
    mkdirSync(join(target, "node_modules"));
    const result = await prepareCorpusDependencies({
      targetDir: target,
      cacheDir: mkdtempSync(join(tmpdir(), "harvey-dependency-no-lock-")),
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      runInstall: vi.fn(),
    });
    expect(result).toMatchObject({ status: "non-cacheable", complete: true, cacheable: false });
    expect(result.reason).toContain("no package-manager lockfile");
  });

  it("rejects partial installation links without following them into a separate dependency tree (#2047)", async () => {
    const target = fixture("npm");
    const external = fixture("npm");
    mkdirSync(join(external, "node_modules"));
    writeFileSync(join(external, "node_modules/keep.txt"), "separate tree");
    symlinkSync(external, join(target, "linked-workspace"), "dir");
    const result = await prepareCorpusDependencies({
      targetDir: target, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.12.1",
      runInstall: () => {
        symlinkSync(join(external, "missing"), join(target, "node_modules"), "dir");
        throw new Error("install failed after linking a partial tree");
      },
    });
    expect(result.complete).toBe(false);
    expect(() => lstatSync(join(target, "node_modules"))).toThrow();
    expect(readFileSync(join(external, "node_modules/keep.txt"), "utf8")).toBe("separate tree");
  });
});
