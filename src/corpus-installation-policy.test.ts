import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { inspectCorpusDependencyInputs, prepareCorpusDependencies, releaseCorpusDependencies, type DependencyPreparationResult } from "./corpus-dependency-preparation.js";
import { runCorpusScanner } from "./corpus-scanner-runner.js";
import { EXTERNAL_CORPUS, type CorpusInstallationPolicy } from "./scan/external-corpus.js";

// Execute both shipping propagation boundaries without starting unrelated corpus scanners.
function installThroughCorpus(targetDir: string, policy: CorpusInstallationPolicy, cacheDir: string): DependencyPreparationResult {
  const source = readFileSync(join(process.cwd(), "src/cli/corpus-drift.ts"), "utf8");
  const ast = ts.createSourceFile("corpus-drift.ts", source, ts.ScriptTarget.Latest, true);
  const helper = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === "installTargetDeps")!.getText(ast);
  let declaration = "";
  let registration = "";
  let collection = "";
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.name.getText(ast) === "dependencyPreparation" && node.initializer?.getText(ast).includes("installTargetDeps")) declaration = `const ${node.getText(ast)};`;
    if (ts.isExpressionStatement(node) && node.getText(ast).startsWith("dependencyPreparationsBySlug[target.slug] =")) registration = node.getText(ast);
    if (ts.isIfStatement(node) && node.expression.getText(ast) === "dependencyPreparation") collection = node.getText(ast);
    ts.forEachChild(node, visit);
  };
  visit(ast);
  expect(declaration).not.toBe("");
  const serializer = ast.statements.find((node) => ts.isIfStatement(node) && node.expression.getText(ast) === "jsonOut")!.getText(ast);
  const bindings = {
    prepareCorpusDependencies, phaseCacheDir: undefined, phaseTarget: "policy-control", scanDir: targetDir,
    target: { slug: policy.targetSlug, commit: policy.targetRevision, installationPolicy: policy },
    targetTreeIdentity: "fixture-tree", targetPhaseCacheDir: cacheDir, install: true,
    timed: (_name: string, fn: () => unknown) => fn(),
    writeFileSync, jsonOut: join(targetDir, "corpus-policy.json"), rows: [], findingsBySlug: {},
    dependencyPreparationsBySlug: {}, detectorRecordsBySlug: {}, mechanicalContextBySlug: {}, currentExecution: undefined,
  };
  const code = ts.transpileModule(`const dependencyPreparations = [];\n${registration}\n${helper}\n${declaration}\n${collection}\n${serializer}`, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  return new Function(...Object.keys(bindings), `${code}\nreturn dependencyPreparation;`)(...Object.values(bindings)) as DependencyPreparationResult;
}

describe("revision-bound corpus installation policy (#2047)", () => {
  const dirs: string[] = [];
  const preparations: DependencyPreparationResult[] = [];
  afterEach(() => {
    preparations.splice(0).forEach((preparation) => releaseCorpusDependencies(preparation));
    vi.unstubAllEnvs();
    dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
  });
  function fixture() {
    const root = mkdtempSync(join(tmpdir(), "harvey-operator-policy-")); dirs.push(root);
    const targetDir = join(root, "target"); const bin = join(root, "bin"); const manager = join(root, "manager");
    for (const dir of [targetDir, bin, manager]) mkdirSync(dir);
    writeFileSync(join(targetDir, "package.json"), '{"name":"policy-fixture","private":true}\n');
    writeFileSync(join(targetDir, "package-lock.json"), '{"lockfileVersion":3,"packages":{"":{}}}\n');
    writeFileSync(join(targetDir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters: {.: {}}\npackages: {}\n");
    writeFileSync(join(targetDir, "index.ts"), "export const live = true;\n");
    writeFileSync(join(targetDir, "dead.ts"), "export const dead = true;\n");
    writeFileSync(join(targetDir, "knip.config.ts"), 'import "./node_modules/policy-provider/index.js"; export default {entry:["index.ts"],project:["*.ts"]};\n');
    writeFileSync(join(manager, "package.json"), '{"name":"pnpm","version":"11.1.3"}\n');
    writeFileSync(join(manager, "manager.cjs"), String.raw`
const fs = require("node:fs");
const mode = fs.existsSync("mode") ? fs.readFileSync("mode", "utf8") : "success";
fs.appendFileSync("invocations.jsonl", JSON.stringify(process.argv.slice(2)) + "\n");
if (process.argv.includes("--version")) { console.log(require("./package.json").version); process.exit(0); }
fs.mkdirSync("node_modules/policy-provider", {recursive:true});
fs.writeFileSync("node_modules/policy-provider/package.json", '{"name":"policy-provider","version":"1.0.0"}');
fs.writeFileSync("node_modules/policy-provider/index.js", 'require("node:fs").writeFileSync("provider-consumed", "yes"); module.exports = {};');
if (mode === "rewrite-install") { fs.appendFileSync("package-lock.json", "\n"); fs.appendFileSync("pnpm-lock.yaml", "\n"); fs.writeFileSync(".npmrc", "offline=true\n"); }
if (mode === "change-identity") fs.appendFileSync(__filename, "\n");
if (mode === "install-fail") { console.log("ERR_POLICY_INSTALL: rejected partial provider"); process.exit(42); }
`);
    writeFileSync(join(bin, "corepack"), String.raw`#!${process.execPath}
const fs = require("node:fs");
const mode = fs.existsSync("mode") ? fs.readFileSync("mode", "utf8") : "success";
fs.writeFileSync("selector-args.json", JSON.stringify(process.argv.slice(2)));
if (mode === "setup-fail") { console.error("ERR_POLICY_SETUP: provisioning refused"); process.exit(43); }
if (mode === "rewrite-setup") for (const file of ["package.json", "package-lock.json", "pnpm-lock.yaml"]) fs.appendFileSync(file, "\n");
const entry = ${JSON.stringify(join(manager, "manager.cjs"))};
process.argv = [process.execPath, entry, ...process.argv.slice(3)]; require(entry);
`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    const policy: CorpusInstallationPolicy = {
      kind: "operator-selected", targetSlug: "policy-fixture", targetRevision: "1".repeat(40), sourceRoot: ".",
      packageManager: "pnpm", packageManagerVersion: "11.1.3", lockfile: "pnpm-lock.yaml",
      installConfigurationSha256: inspectCorpusDependencyInputs(targetDir, "pnpm", "11.1.3").installConfiguration,
      provenance: "Operator fixture permission: both original locks conflict; never reuse this installation.",
    };
    return { root, targetDir, manager, policy, cacheDir: join(root, "cache"), targetSlug: policy.targetSlug, targetRevision: policy.targetRevision, targetTree: "fixture-tree", sourceRoot: "." };
  }
  function prepare(options: Parameters<typeof prepareCorpusDependencies>[0]) {
    const result = prepareCorpusDependencies(options); preparations.push(result); return result;
  }

  it("configures only the approved Flori pin, manager, lock and original input identity", () => {
    const configured = EXTERNAL_CORPUS.filter((target) => target.installationPolicy);
    expect(configured).toHaveLength(1);
    const target = configured[0]!;
    expect(target).toMatchObject({ slug: "flori-web", commit: "908eaff6fcf598c0fe1043faaaecb6a4083c90d5", installationPolicy: {
      targetSlug: "flori-web", targetRevision: target.commit, packageManager: "pnpm", packageManagerVersion: "11.1.3", lockfile: "pnpm-lock.yaml",
      installConfigurationSha256: "bf830351e2b7fa6817e9abf0751d3f2b152a7f1f9677145449966d1625a27df2",
    } });
    expect(target.modules["M5-knip"]).toMatchObject({ counted: 54, total: 54 });
  });

  it("requires both shipping policy transfers before the installed M5 provider can reach the client", async () => {
    const f = fixture();
    const first = installThroughCorpus(f.targetDir, f.policy, f.cacheDir); preparations.push(first);
    const second = installThroughCorpus(f.targetDir, f.policy, f.cacheDir); preparations.push(second);
    for (const result of [first, second]) {
      expect(result).toMatchObject({ complete: true, status: "non-cacheable", cacheable: false, sourceTreeCacheable: false, packageManagerVersion: "11.1.3" });
      expect(result.key).toBeUndefined();
      expect(result.installation!.operatorPolicy).toMatchObject({ admission: "accepted", policy: f.policy, sourceResolution: { status: "not-assessed", reason: "conflicting-evidence" }, installConfigurationSha256: f.policy.installConfigurationSha256 });
      expect(result.installation!.operatorPolicy!.lockfiles).toEqual(["package-lock.json", "pnpm-lock.yaml"].map((path) => ({ path, sha256: createHash("sha256").update(readFileSync(join(f.targetDir, path))).digest("hex") })));
      expect(result.installation!.stages.map((stage) => [stage.stage, stage.outcome, stage.selected?.version])).toEqual([["version-probe", "completed", "11.1.3"], ["frozen", "completed", "11.1.3"]]);
      expect(result.installation!.stages[1]!.command.slice(0, 2)).toEqual([result.installation!.stages[0]!.selected!.nodeExecutable, result.installation!.stages[0]!.selected!.executable]);
    }
    expect(first.installation!.dependencyStore).not.toBe(second.installation!.dependencyStore);
    expect(existsSync(f.cacheDir)).toBe(false);
    expect(JSON.parse(readFileSync(join(f.targetDir, "corpus-policy.json"), "utf8")).dependencyPreparations[f.targetSlug][0]).toEqual(JSON.parse(JSON.stringify(second)));
    expect(JSON.parse(readFileSync(join(f.targetDir, "selector-args.json"), "utf8"))).toEqual(["pnpm@11.1.3", "--version"]);
    const run = (dependencyPreparation: DependencyPreparationResult) => runCorpusScanner({ repoRoot: process.cwd(), targetDir: f.targetDir, targetConfig: "operator policy consumer", script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir], dependencyPreparation, cache: { dir: f.cacheDir, mode: "read-write", targetRevision: f.targetRevision, targetTree: f.targetTree } });
    const success = await run(second);
    expect(success.findings.some((row) => ["M5-98", "M5-00"].includes(row.id))).toBe(false);
    expect(success.cacheRecord).toBeUndefined();
    expect(readFileSync(join(f.targetDir, "provider-consumed"), "utf8")).toBe("yes");
    rmSync(join(f.targetDir, "provider-consumed"));
    writeFileSync(join(f.targetDir, "mode"), "install-fail");
    const failed = installThroughCorpus(f.targetDir, f.policy, f.cacheDir); preparations.push(failed);
    const failure = await run(failed);
    expect(failed).toMatchObject({ complete: false, status: "incomplete", reason: expect.stringContaining("ERR_POLICY_INSTALL") });
    expect(failed.installation!.stages.at(-1)).toMatchObject({ stage: "frozen", outcome: "failed", exitCode: 42 });
    expect(JSON.parse(readFileSync(join(f.targetDir, "corpus-policy.json"), "utf8")).dependencyPreparations[f.targetSlug][0]).toEqual(JSON.parse(JSON.stringify(failed)));
    expect(failure.findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining(f.policy.provenance) }));
    expect(existsSync(join(f.targetDir, "provider-consumed"))).toBe(false);
    const meta = { client: "Policy evidence", subtitle: "#2047", date: "2026-09-12", commit: f.targetRevision, auditor: "Harvey", confidential: true, overallHealth: 5, tenantIsolation: "Not assessed", authModel: "Fixture", headline: "Preparation failure", scope: "quality control", methodology: "Quality scan", outOfScope: "Other modules" };
    expect(buildHtml({ meta, findings: failure.findings })).toContain("ERR_POLICY_INSTALL");
  }, 30_000);

  it.each([
    ["target", { targetSlug: "different" }], ["revision", { targetRevision: "2".repeat(40) }],
    ["source root", { sourceRoot: "nextjs" }], ["extra flags", { installFlags: ["--ignore-scripts"] }],
  ])("rejects a different %s before provisioning", (_name, change) => {
    const f = fixture();
    const result = prepare({ ...f, installationPolicy: f.policy, ...change });
    expect(result).toMatchObject({ complete: false, status: "incomplete" });
    expect(result.installation!.operatorPolicy!.admission).toBe("rejected");
    expect(result.installation!.stages).toEqual([]);
    expect(existsSync(join(f.targetDir, "selector-args.json"))).toBe(false);
  });

  it.each(["package.json", "package-lock.json", "pnpm-lock.yaml"])("rejects changed original %s input bytes", (name) => {
    const f = fixture(); writeFileSync(join(f.targetDir, name), `${readFileSync(join(f.targetDir, name), "utf8")}\n`);
    const result = prepare({ ...f, installationPolicy: f.policy });
    expect(result.reason).toContain("does not match the original install-input identity");
    expect(result.installation!.stages).toEqual([]);
  });

  it.each([
    { packageManager: "npm@11.1.3" }, { packageManager: "pnpm@11.1.3" },
    { devEngines: { packageManager: { name: "pnpm", version: "11.1.3" } } },
  ])("cannot override a target declaration even when its input digest is refreshed: %j", (declaration) => {
    const f = fixture(); writeFileSync(join(f.targetDir, "package.json"), JSON.stringify({ name: "policy-fixture", ...declaration }));
    f.policy.installConfigurationSha256 = inspectCorpusDependencyInputs(f.targetDir, "pnpm", "11.1.3").installConfiguration;
    const result = prepare({ ...f, installationPolicy: f.policy });
    expect(result.complete).toBe(false); expect(result.installation!.stages).toEqual([]);
  });

  it.each([{ packageManager: "npm" }, { packageManagerVersion: "latest" }, { packageManagerVersion: "11.1.3 --offline" }, { lockfile: "package-lock.json" }])("rejects an unsupported policy descriptor: %j", (change) => {
    const f = fixture();
    const result = prepare({ ...f, installationPolicy: { ...f.policy, ...change } as CorpusInstallationPolicy });
    expect(result.complete).toBe(false); expect(result.installation!.stages).toEqual([]);
  });

  it.each([{ name: "pnpm", version: "11.18.0" }, { name: "npm", version: "11.1.3" }])("rejects the wrong observed manager identity: %j", (identity) => {
    const f = fixture(); writeFileSync(join(f.manager, "package.json"), JSON.stringify(identity));
    const result = prepare({ ...f, installationPolicy: f.policy });
    expect(result.complete).toBe(false); expect(result.installation!.stages).toHaveLength(1);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
  });

  it.each(["setup-fail", "install-fail", "rewrite-setup", "rewrite-install", "change-identity"])("rejects %s without fallback and restores both original locks", (mode) => {
    const f = fixture(); const before = ["package.json", "package-lock.json", "pnpm-lock.yaml"].map((path) => readFileSync(join(f.targetDir, path)));
    writeFileSync(join(f.targetDir, "mode"), mode);
    const result = prepare({ ...f, installationPolicy: f.policy });
    expect(result).toMatchObject({ complete: false, status: "incomplete", cacheable: false });
    expect(result.installation!.stages.some((stage) => ["legacy", "offline"].includes(stage.stage))).toBe(false);
    expect(["package.json", "package-lock.json", "pnpm-lock.yaml"].map((path) => readFileSync(join(f.targetDir, path)))).toEqual(before);
    expect(result.installation!.operatorPolicy!.lockfiles).toEqual(["package-lock.json", "pnpm-lock.yaml"].map((path, index) => ({ path, sha256: createHash("sha256").update(before[index + 1]!).digest("hex") })));
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    expect(existsSync(join(f.targetDir, ".npmrc"))).toBe(false);
  });
});
