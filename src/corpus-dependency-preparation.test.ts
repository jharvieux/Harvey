import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { prepareCorpusDependencies } from "./corpus-dependency-preparation.js";
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

  it.each(["npm", "pnpm", "yarn"] as const)("materializes %s cold then offline from the same content address", (manager) => {
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
    const cold = prepareCorpusDependencies({ ...common, targetDir: targetA });
    const warm = prepareCorpusDependencies({ ...common, targetDir: targetB });

    expect(cold.status).toBe("miss");
    expect(warm.status).toBe("hit");
    expect(warm.key).toBe(cold.key);
    expect(invocations.map((invocation) => invocation.bin)).toEqual([manager, manager]);
    expect(invocations[1]!.args).toContain("--offline");
    expect(invocations.flatMap((invocation) => invocation.args).every((arg) => !arg.includes("node_modules"))).toBe(true);
    if (manager === "pnpm") expect(invocations[0]!.args).toContain("--config.enableGlobalVirtualStore=false");
  });

  it.each(["npm", "pnpm", "yarn"] as const)("runs the real %s package manager across different checkout paths", (manager) => {
    const targetA = fixture(manager);
    const targetB = fixture(manager);
    const cacheDir = mkdtempSync(join(tmpdir(), `harvey-real-${manager}-store-`));
    dirs.push(cacheDir);
    const events: string[] = [];
    const cacheArgument = manager === "pnpm" ? relative(process.cwd(), cacheDir) : cacheDir;
    const common = { cacheDir: cacheArgument, targetRevision: "same-pin", targetTree: "same-tree", onEvent: (event: string) => events.push(event) };
    const cold = prepareCorpusDependencies({ ...common, targetDir: targetA });
    const warm = prepareCorpusDependencies({ ...common, targetDir: targetB });
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

  it("canonicalizes a relative cache root before changing to the target cwd", () => {
    const target = fixture("pnpm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-relative-store-"));
    dirs.push(cacheDir);
    const cacheArgument = relative(process.cwd(), cacheDir);
    const invocations: { args: string[]; cwd: string }[] = [];
    prepareCorpusDependencies({
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

  it("binds lockfile, manager version, runtime/install config, and target identity independently of checkout path", () => {
    const targetA = fixture("npm");
    const targetB = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-identity-"));
    dirs.push(cacheDir);
    const runInstall = vi.fn();
    const build = (targetDir: string, packageManagerVersion = "11.12.1", targetTree = "tree") => prepareCorpusDependencies({
      targetDir, cacheDir, targetRevision: "pin", targetTree, packageManagerVersion, runInstall,
    });
    const first = build(targetA);
    expect(build(targetB).status).toBe("hit");
    expect(build(targetB, "11.12.2").key).not.toBe(first.key);
    expect(build(targetB, "11.12.1", "other-tree").key).not.toBe(first.key);
    writeFileSync(join(targetB, ".npmrc"), "legacy-peer-deps=true\n");
    expect(build(targetB).key).not.toBe(first.key);
    writeFileSync(join(targetB, "package-lock.json"), JSON.stringify({ name: "npm-fixture", lockfileVersion: 3, packages: { "": { name: "changed" } } }));
    expect(build(targetB).key).not.toBe(first.key);
  });

  it("invalidates preparation when any install-visible environment value changes", () => {
    const targetA = fixture("npm");
    const targetB = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-environment-"));
    dirs.push(cacheDir);
    const runInstall = vi.fn();
    const baseEnvironment = { HOME: "/identity/home-a", PATH: "/identity/bin-a", TMPDIR: "/identity/tmp-a" };
    const build = (targetDir: string, environment: NodeJS.ProcessEnv) => prepareCorpusDependencies({
      targetDir,
      cacheDir,
      targetRevision: "pin",
      targetTree: "tree",
      packageManagerVersion: "11.12.1",
      environment,
      runInstall,
    });
    const first = build(targetA, baseEnvironment);
    expect(build(targetB, baseEnvironment)).toMatchObject({ status: "hit", key: first.key });
    for (const [name, value] of [["HOME", "/identity/home-b"], ["PATH", "/identity/bin-b"], ["TMPDIR", "/identity/tmp-b"]] as const) {
      const moved = build(targetB, { ...baseEnvironment, [name]: value });
      expect(moved.status).toBe("miss");
      expect(moved.key).not.toBe(first.key);
    }
  });

  it("keeps quality results fresh for executable Knip control config and install hooks", () => {
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
    const cold = prepareCorpusDependencies(options);
    const warm = prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.key });
    expect(warm.reason).toContain("install lifecycle scripts can observe time/network state");
    expect(warm.reason).toContain("executable framework/plugin configuration Knip may load can observe time/network/unkeyed state");
    expect(warm.reason).toContain("knip.js");
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
  ])("marks quality non-cacheable for $label", ({ configure, expected }) => {
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
    const cold = prepareCorpusDependencies(options);
    const warm = prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: false });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: false, key: cold.key });
    expect(warm.reason).toContain("executable framework/plugin configuration Knip may load can observe time/network/unkeyed state");
    expect(warm.reason).toContain(expected);
  });

  it("resolves package-manager brace workspaces with Knip's own glob semantics", () => {
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
    const result = prepareCorpusDependencies({
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

  it("keeps quality fresh when package-manager workspace declarations are not enumerable", () => {
    const target = fixture("npm");
    const pkg = JSON.parse(readFileSync(join(target, "package.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(target, "package.json"), JSON.stringify({ ...pkg, workspaces: "packages/*" }));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-unknown-workspace-"));
    dirs.push(cacheDir);
    const result = prepareCorpusDependencies({
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

  it("fails safe when Knip's executable input set cannot be proven", () => {
    const target = fixture("npm");
    writeFileSync(join(target, "knip.json"), "{ this is not static JSON }\n");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-unknown-config-"));
    dirs.push(cacheDir);
    const result = prepareCorpusDependencies({
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

  it("keeps benign static Knip and provider configuration cacheable", () => {
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
    const cold = prepareCorpusDependencies(options);
    const warm = prepareCorpusDependencies(options);
    expect(cold).toMatchObject({ status: "miss", complete: true, cacheable: true });
    expect(warm).toMatchObject({ status: "hit", complete: true, cacheable: true, key: cold.key });
  });

  it("rejects a corrupt receipt visibly and performs a clean install", () => {
    const target = fixture("npm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-corrupt-"));
    dirs.push(cacheDir);
    const events: string[] = [];
    const runInstall = vi.fn();
    const options = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.12.1", runInstall, onEvent: (event: string) => events.push(event) };
    const cold = prepareCorpusDependencies(options);
    const receipt = join(cacheDir, readRecursiveSafe(cacheDir).find((path) => path.startsWith("dependency-preparation/receipts/") && path.endsWith(".json"))!);
    writeFileSync(receipt, JSON.stringify({ schema: 0, key: cold.key }));
    expect(prepareCorpusDependencies(options).status).toBe("miss");
    expect(events).toContainEqual(expect.stringContaining("DEPENDENCY PREP REJECT npm"));
    expect(JSON.parse(readFileSync(receipt, "utf8"))).toMatchObject({ schema: 2 });
    expect(runInstall).toHaveBeenCalledTimes(2);
  });

  it("rejects an incomplete restored store, retries clean, and keeps a failed retry fail-loud", () => {
    const target = fixture("pnpm");
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-dependency-incomplete-"));
    dirs.push(cacheDir);
    const events: string[] = [];
    const seed = { targetDir: target, cacheDir, targetRevision: "pin", targetTree: "tree", packageManagerVersion: "11.1.3", onEvent: (event: string) => events.push(event) };
    prepareCorpusDependencies({ ...seed, runInstall: vi.fn() });
    let calls = 0;
    const repaired = prepareCorpusDependencies({ ...seed, runInstall: () => { calls += 1; if (calls === 1) throw new Error("offline store corrupt"); } });
    expect(repaired.status).toBe("miss");
    expect(calls).toBe(2);
    expect(events).toContainEqual(expect.stringContaining("offline materialization failed"));

    const receipt = join(cacheDir, readRecursiveSafe(cacheDir).find((path) => path.startsWith("dependency-preparation/receipts/") && path.endsWith(".json"))!);
    rmSync(receipt, { force: true });
    let fallbackCalls = 0;
    const failed = prepareCorpusDependencies({ ...seed, runInstall: () => {
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

  it("does not claim a reproducible preparation without an integrity-bearing lockfile", () => {
    const target = fixture("npm");
    rmSync(join(target, "package-lock.json"));
    mkdirSync(join(target, "node_modules"));
    const result = prepareCorpusDependencies({
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
});
