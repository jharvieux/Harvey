import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { prepareCorpusDependencies } from "./corpus-dependency-preparation.js";
import { observePackageManager } from "./corpus-package-manager.js";
import { runCorpusScanner } from "./corpus-scanner-runner.js";
import type { PackageManager } from "./package-manager.js";

describe("target-declared npm selection reaches dependency preparation (#2047)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  function fixture(manager: PackageManager = "npm", nativeVersion = "8.8.8", selectedVersion = "9.9.9") {
    const root = mkdtempSync(join(tmpdir(), "harvey-declared-manager-")); dirs.push(root);
    const targetDir = join(root, "target");
    const bin = join(root, "bin");
    mkdirSync(targetDir); mkdirSync(bin);
    writeFileSync(join(targetDir, "package.json"), JSON.stringify({ name: "declared-manager", private: true, packageManager: `${manager}@9.9.9` }));
    writeFileSync(join(targetDir, manager === "npm" ? "package-lock.json" : manager === "pnpm" ? "pnpm-lock.yaml" : "yarn.lock"), manager === "npm" ? '{"lockfileVersion":3,"packages":{"":{}}}\n' : manager === "pnpm" ? "lockfileVersion: '9.0'\npackages: {}\n" : "# yarn lockfile v1\n");
    writeFileSync(join(targetDir, "index.ts"), "export const live = true;\n");
    writeFileSync(join(targetDir, "dead.ts"), "export const dead = true;\n");
    for (const [name, version] of [["native", nativeVersion], ["selected", selectedVersion]]) {
      const dir = join(root, name!); mkdirSync(dir);
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: manager, version }));
      writeFileSync(join(dir, "manager.cjs"), String.raw`
const fs = require("node:fs");
fs.appendFileSync("invocations.jsonl", JSON.stringify({version:${JSON.stringify(version)}, argv:process.argv, env:process.env}) + "\n");
if (process.argv.includes("--version")) { console.log(${JSON.stringify(version)}); process.exit(0); }
fs.mkdirSync("node_modules", {recursive:true});
`);
    }
    writeFileSync(join(bin, manager), `#!${process.execPath}\nconst entry = ${JSON.stringify(join(root, "native/manager.cjs"))}; process.argv[1] = entry; require(entry);\n`, { mode: 0o755 });
    writeFileSync(join(bin, "corepack"), String.raw`#!${process.execPath}
const fs = require("node:fs");
fs.writeFileSync("corepack-argv.json", JSON.stringify(process.argv.slice(2)));
if (fs.existsSync("provision-fail")) { console.error("ERR_DECLARED_NPM_SETUP: provisioning refused"); process.exit(43); }
if (fs.existsSync("rewrite-input")) fs.appendFileSync("package.json", "\n");
const entry = ${JSON.stringify(join(root, "selected/manager.cjs"))};
process.argv = [process.execPath, entry, ...process.argv.slice(3)]; require(entry);
`, { mode: 0o755 });
    return {
      root, targetDir, bin, cacheDir: join(root, "cache"), targetRevision: "pin", targetTree: "tree",
      environment: { ...process.env, PATH: `${bin}:${process.env.PATH}`, COREPACK_HOME: join(root, "corepack"), COREPACK_ENABLE_NETWORK: "0", HARVEY_UNKEYED_SELECTOR: "must not reach manager" },
    };
  }

  it("selects the declaration after a host mismatch and binds installs to its observed executable/runtime", () => {
    const f = fixture();
    const original = readFileSync(join(f.targetDir, "package.json"));
    const result = prepareCorpusDependencies(f);
    expect(result).toMatchObject({ complete: true, status: "miss", packageManagerVersion: "9.9.9" });
    const stages = result.installation!.stages;
    expect(stages.map((stage) => [stage.stage, stage.selected?.version])).toEqual([["version-probe", "8.8.8"], ["version-probe", "9.9.9"], ["frozen", "9.9.9"]]);
    expect(stages[1]!.command).toEqual([join(f.bin, "corepack"), "npm@9.9.9", "--version"]);
    expect(stages[2]!.command.slice(0, 2)).toEqual([stages[1]!.selected!.nodeExecutable, stages[1]!.selected!.executable]);
    expect(stages[2]!.selected).toMatchObject({
      executable: realpathSync(join(f.root, "selected/manager.cjs")),
      executableSha256: createHash("sha256").update(readFileSync(join(f.root, "selected/manager.cjs"))).digest("hex"),
      nodeExecutable: realpathSync(process.execPath), nodeVersion: process.version,
    });
    const invocations = readFileSync(join(f.targetDir, "invocations.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line) as { env: NodeJS.ProcessEnv });
    expect(invocations).toHaveLength(3);
    expect(invocations.every(({ env }) => env.HARVEY_UNKEYED_SELECTOR === undefined && env.COREPACK_ENV_FILE === "0" && env.COREPACK_HOME === f.environment.COREPACK_HOME)).toBe(true);
    expect(readFileSync(join(f.targetDir, "package.json"))).toEqual(original);
  });

  it("keeps an exact native npm available without requiring Corepack", () => {
    const f = fixture("npm", "9.9.9");
    rmSync(join(f.bin, "corepack"));
    const result = prepareCorpusDependencies({ ...f, environment: { ...f.environment, PATH: f.bin } });
    expect(result).toMatchObject({ complete: true, packageManagerVersion: "9.9.9" });
    expect(result.installation?.stages.map((stage) => stage.stage)).toEqual(["version-probe", "frozen"]);
  });

  it("refuses an unsatisfied declaration when Corepack is unavailable", () => {
    const f = fixture();
    rmSync(join(f.bin, "corepack"));
    const result = prepareCorpusDependencies({ ...f, environment: { ...f.environment, PATH: f.bin } });
    expect(result).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("corepack executable was not found") });
    expect(result.installation?.stages).toHaveLength(2);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
  });

  it("rejects a provisioned manager that still disagrees with the declaration", () => {
    const f = fixture("npm", "8.8.8", "10.10.10");
    const result = prepareCorpusDependencies(f);
    expect(result).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("declares npm@9.9.9 but the executable is 10.10.10") });
    expect(result.installation?.stages).toHaveLength(2);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
  });

  it("rejects setup that rewrites the original target input bytes", () => {
    const f = fixture();
    writeFileSync(join(f.targetDir, "rewrite-input"), "yes");
    const result = prepareCorpusDependencies(f);
    expect(result).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("changed target-owned install inputs") });
    expect(result.installation?.stages).toHaveLength(2);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
  });

  it.each(["pnpm", "yarn"] as const)("keeps %s mismatch rejection without changing its selector policy", (manager) => {
    const f = fixture(manager);
    const result = prepareCorpusDependencies(f);
    expect(result).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining(`declares ${manager}@9.9.9 but the executable is 8.8.8`) });
    expect(result.installation?.stages).toHaveLength(1);
    expect(existsSync(join(f.targetDir, "corepack-argv.json"))).toBe(false);
  });

  it("delivers the failed declared-version setup through the quality consumer and client HTML", async () => {
    const f = fixture();
    writeFileSync(join(f.targetDir, "provision-fail"), "yes");
    const result = prepareCorpusDependencies(f);
    expect(result).toMatchObject({ complete: false, status: "incomplete" });
    expect(result.installation?.stages.at(-1)).toMatchObject({ stage: "version-probe", outcome: "failed", exitCode: 43, reason: expect.stringContaining("ERR_DECLARED_NPM_SETUP") });
    const scan = await runCorpusScanner({ repoRoot: process.cwd(), targetDir: f.targetDir, targetConfig: "declared npm failure", script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir], dependencyPreparation: result });
    expect(scan.findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("ERR_DECLARED_NPM_SETUP") }));
    const meta = { client: "Install evidence", subtitle: "#2047", date: "2026-09-12", commit: "control", auditor: "Harvey", confidential: true, overallHealth: 5, tenantIsolation: "Not assessed", authModel: "Fixture", headline: "Preparation failure", scope: "quality control", methodology: "Quality scan", outOfScope: "Other modules" };
    expect(buildHtml({ meta, findings: scan.findings })).toContain("ERR_DECLARED_NPM_SETUP");
  });

  it("runs actual Corepack and npm offline, ignores target env expansion, and materializes a local provider", async () => {
    const f = fixture();
    const host = observePackageManager("npm", "version-probe", { bin: "npm", args: ["--version"], cwd: process.cwd(), env: process.env });
    expect(host.outcome).toBe("completed");
    const npm = host.selected!;
    const npmRoot = dirname(dirname(npm.executable));
    const npmManifest = JSON.parse(readFileSync(join(npmRoot, "package.json"), "utf8")) as { name: string; version: string; bin: Record<string, string> };
    expect(npmManifest).toMatchObject({ name: "npm", version: npm.version });
    // Seed Corepack's local cache from the installed native distribution; this test needs no
    // registry and executes real Corepack/npm code, not the fake selected manager above.
    const nativeHome = join(f.root, "native-home");
    const environment = { ...f.environment, HOME: nativeHome, COREPACK_HOME: undefined, XDG_CACHE_HOME: undefined, LOCALAPPDATA: undefined, COREPACK_ENABLE_PROJECT_SPEC: "1", COREPACK_ENABLE_STRICT: "1" };
    const cachedNpm = join(nativeHome, ".cache/node/corepack/v1/npm", npm.version);
    cpSync(npmRoot, cachedNpm, { recursive: true });
    writeFileSync(join(cachedNpm, ".corepack"), JSON.stringify({ locator: { name: "npm", reference: npm.version }, bin: npmManifest.bin, hash: `sha512.${createHash("sha512").update(readFileSync(npm.executable)).digest("hex")}` }));
    rmSync(join(f.bin, "corepack"));
    const provider = join(f.targetDir, "vendor/local-provider"); mkdirSync(provider, { recursive: true });
    writeFileSync(join(provider, "package.json"), '{"name":"local-provider","version":"1.0.0","main":"index.js"}\n');
    writeFileSync(join(provider, "index.js"), 'require("node:fs").writeFileSync("provider-consumed", "yes"); module.exports = {};\n');
    writeFileSync(join(f.targetDir, "package.json"), JSON.stringify({ name: "declared-manager", private: true, packageManager: `npm@${npm.version}`, dependencies: { "local-provider": "file:vendor/local-provider" } }));
    writeFileSync(join(f.targetDir, "package-lock.json"), JSON.stringify({ name: "declared-manager", lockfileVersion: 3, packages: { "": { name: "declared-manager", dependencies: { "local-provider": "file:vendor/local-provider" } }, "node_modules/local-provider": { resolved: "vendor/local-provider", link: true }, "vendor/local-provider": { version: "1.0.0" } } }));
    writeFileSync(join(f.targetDir, "knip.config.ts"), 'import "local-provider"; export default {entry:["index.ts"],project:["*.ts"]};\n');
    writeFileSync(join(f.targetDir, ".corepack.env"), `COREPACK_HOME=${join(f.root, "wrong-target-cache")}\nCOREPACK_ENABLE_NETWORK=0\n`);
    const names = ["package.json", "package-lock.json", "knip.config.ts", ".corepack.env"];
    const originals = names.map((name) => readFileSync(join(f.targetDir, name)));
    const unbounded = observePackageManager("npm", "version-probe", { bin: "corepack", launcherArgs: [`npm@${npm.version}`], args: ["--version"], cwd: f.targetDir, env: { ...environment, COREPACK_ENV_FILE: undefined } });
    expect(unbounded).toMatchObject({ outcome: "failed", reason: expect.stringContaining("Network access disabled") });
    const cold = prepareCorpusDependencies({ ...f, environment });
    const warm = prepareCorpusDependencies({ ...f, environment });
    expect(cold).toMatchObject({ complete: true, status: "miss", packageManagerVersion: npm.version });
    expect(warm).toMatchObject({ complete: true, status: "hit", key: cold.key });
    for (const result of [cold, warm]) {
      expect(result.installation?.stages.map((stage) => stage.selected?.version)).toEqual(["8.8.8", npm.version, npm.version]);
      const probe = result.installation!.stages[1]!.selected!;
      expect(probe).toMatchObject({ executable: realpathSync(join(cachedNpm, "bin/npm-cli.js")), nodeExecutable: npm.nodeExecutable, nodeVersion: npm.nodeVersion, executableSha256: npm.executableSha256 });
      expect(result.installation!.stages[2]!.command.slice(0, 2)).toEqual([probe.nodeExecutable, probe.executable]);
    }
    expect(warm.installation!.stages.at(-1)!.command).toContain("--offline");
    expect(existsSync(join(f.targetDir, "node_modules/local-provider/index.js"))).toBe(true);
    expect(names.map((name) => readFileSync(join(f.targetDir, name)))).toEqual(originals);
    const scan = await runCorpusScanner({ repoRoot: process.cwd(), targetDir: f.targetDir, targetConfig: "native declared npm", script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir], dependencyPreparation: warm });
    expect(scan.findings.some((finding) => finding.id === "M5-98")).toBe(false);
    expect(scan.findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("configuration could not be inspected");
    expect(readFileSync(join(f.targetDir, "provider-consumed"), "utf8")).toBe("yes");
    const failed = prepareCorpusDependencies({ ...f, environment: { ...environment, COREPACK_HOME: join(f.root, "empty-cache") } });
    expect(failed).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("Network access disabled") });
    expect(failed.installation?.stages).toHaveLength(2);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    expect(names.map((name) => readFileSync(join(f.targetDir, name)))).toEqual(originals);
  });
});
