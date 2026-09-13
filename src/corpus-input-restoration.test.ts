import { createHash } from "node:crypto";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHtml } from "../report-template/render.mjs";
import { inspectCorpusDependencyInputs, prepareCorpusDependencies, releaseCorpusDependencies, type DependencyPreparationResult } from "./corpus-dependency-preparation.js";
import { runCorpusScanner } from "./corpus-scanner-runner.js";
import type { CorpusInstallationPolicy } from "./scan/external-corpus.js";

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

describe("operator install-input restoration boundary (#2047)", () => {
  const dirs: string[] = [];
  const preparations: DependencyPreparationResult[] = [];
  afterEach(() => {
    preparations.splice(0).forEach((result) => releaseCorpusDependencies(result));
    vi.unstubAllEnvs();
    dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true }));
  });
  function fixture(mode: string) {
    const root = mkdtempSync(join(tmpdir(), "harvey-input-restoration-")); dirs.push(root);
    const targetDir = join(root, "owned", "target"), bin = join(root, "bin"), manager = join(root, "manager"), outside = join(root, "outside");
    for (const path of [join(targetDir, "nested"), bin, manager, outside]) mkdirSync(path, { recursive: true });
    const originals = new Map([
      ["package.json", '{"name":"restoration-fixture","private":true}\n'],
      ["package-lock.json", '{"lockfileVersion":3,"packages":{"":{}}}\n'],
      ["pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters: {.: {}}\npackages: {}\n"],
      ["nested/package.json", '{"name":"original-nested"}\n'],
    ]);
    for (const [path, content] of originals) writeFileSync(join(targetDir, path), content);
    const sentinels = new Map([
      ["package.json", '{"name":"external-sentinel"}\n'], [".npmrc", "external configuration sentinel\n"],
      ["lock", mode.endsWith("identical-link") ? originals.get("pnpm-lock.yaml")! : "external lock sentinel\n"],
    ]);
    for (const [path, content] of sentinels) writeFileSync(join(outside, path), content);
    mkdirSync(join(outside, "node_modules")); writeFileSync(join(outside, "node_modules", "sentinel"), "external dependency sentinel");
    writeFileSync(join(targetDir, "index.ts"), "export const live = true;\n");
    writeFileSync(join(targetDir, "knip.config.ts"), 'import "./node_modules/restoration-provider/index.js"; export default { entry:["index.ts"], project:["*.ts"] };\n');
    const mutation = String.raw`
const target = ${JSON.stringify(targetDir)}, outside = ${JSON.stringify(outside)}, mode = ${JSON.stringify(mode)};
const lock = require("node:path").join(target, "pnpm-lock.yaml");
const variant = mode.replace(/^(setup|install)-/, "");
if (["file-link", "identical-link", "dangling-link", "hard-link", "file-directory", "deleted-lock"].includes(variant)) {
  fs.rmSync(lock);
  if (variant.endsWith("link")) {
    if (variant === "hard-link") fs.linkSync(outside + "/lock", lock);
    else fs.symlinkSync(outside + (variant === "dangling-link" ? "/missing" : "/lock"), lock);
  } else if (variant === "file-directory") fs.mkdirSync(lock);
}
if (variant.startsWith("parent-")) {
  fs.rmSync(target + "/nested", { recursive:true });
  if (variant === "parent-link") fs.symlinkSync(outside, target + "/nested");
  if (variant === "parent-file") fs.writeFileSync(target + "/nested", "replacement file");
}
if (variant === "new-parent-link") fs.symlinkSync(outside, target + "/new-inputs");
if (variant.startsWith("root-")) {
  fs.rmSync(target, { recursive:true });
  if (variant === "root-link") fs.symlinkSync(outside, target);
  if (variant === "root-file") fs.writeFileSync(target, "replacement root");
}
if (variant === "restoration-denied") { fs.rmSync(lock); fs.chmodSync(target, 0o500); }
if (variant === "ancestor-link") {
  const parent = require("node:path").dirname(target);
  fs.renameSync(parent, parent + "-moved"); fs.symlinkSync(outside, parent);
}
`;
    writeFileSync(join(manager, "package.json"), '{"name":"pnpm","version":"11.1.3"}\n');
    writeFileSync(join(manager, "manager.cjs"), String.raw`
const fs = require("node:fs");
if (process.argv.includes("--version")) { console.log("11.1.3"); process.exit(0); }
fs.mkdirSync("node_modules/restoration-provider", { recursive:true });
fs.writeFileSync("node_modules/restoration-provider/package.json", '{"name":"restoration-provider","version":"1.0.0"}');
fs.writeFileSync("node_modules/restoration-provider/index.js", 'require("node:fs").writeFileSync("provider-consumed", "yes");');
${mode.startsWith("install-") ? mutation : ""}
`);
    writeFileSync(join(bin, "corepack"), String.raw`#!${process.execPath}
const fs = require("node:fs");
fs.writeFileSync(${JSON.stringify(join(root, "selector-ran"))}, "yes");
${mode.startsWith("setup-") ? mutation : ""}
const entry = ${JSON.stringify(join(manager, "manager.cjs"))};
process.argv = [process.execPath, entry, ...process.argv.slice(3)]; require(entry);
`, { mode: 0o755 });
    vi.stubEnv("PATH", `${bin}:${process.env.PATH}`);
    const policy: CorpusInstallationPolicy = {
      kind: "operator-selected", targetSlug: "restoration-fixture", targetRevision: "1".repeat(40), sourceRoot: ".",
      packageManager: "pnpm", packageManagerVersion: "11.1.3", lockfile: "pnpm-lock.yaml",
      installConfigurationSha256: inspectCorpusDependencyInputs(targetDir, "pnpm", "11.1.3").installConfiguration,
      provenance: "Operator restoration fixture: preserve both conflicting locks and reject changed topology.",
    };
    return { root, targetDir, outside, originals, sentinels, policy, cacheDir: join(root, "cache"), targetSlug: policy.targetSlug, targetRevision: policy.targetRevision, targetTree: "fixture-tree", sourceRoot: "." };
  }
  function assertSentinels(f: ReturnType<typeof fixture>) {
    for (const [path, content] of f.sentinels) expect(readFileSync(join(f.outside, path), "utf8")).toBe(content);
    expect(readFileSync(join(f.outside, "node_modules", "sentinel"), "utf8")).toBe("external dependency sentinel");
  }
  function assertRejected(f: ReturnType<typeof fixture>, result: DependencyPreparationResult) {
    expect(result).toMatchObject({ complete: false, status: "incomplete", cacheable: false, sourceTreeCacheable: false });
    expect(result.installation!.operatorPolicy).toMatchObject({ policy: f.policy, installConfigurationSha256: f.policy.installConfigurationSha256, sourceResolution: { status: "not-assessed", reason: "conflicting-evidence" } });
    expect(result.installation!.operatorPolicy!.lockfiles).toEqual(["package-lock.json", "pnpm-lock.yaml"].map((path) => ({ path, sha256: createHash("sha256").update(f.originals.get(path)!).digest("hex") })));
    expect(result.installation!.stages.some((stage) => ["offline", "legacy"].includes(stage.stage))).toBe(false);
    expect(existsSync(result.installation!.dependencyStore)).toBe(false);
    if (result.installation!.dependencyStore !== "unavailable") expect(existsSync(dirname(dirname(dirname(dirname(result.installation!.dependencyStore)))))).toBe(false);
    assertSentinels(f);
  }

  it.each([
    "setup-file-link", "setup-file-directory", "setup-parent-file", "setup-root-deleted",
    "install-file-link", "install-identical-link", "install-dangling-link", "install-hard-link", "install-file-directory",
    "install-parent-link", "install-parent-file", "install-parent-deleted", "install-new-parent-link",
    "install-root-link", "install-root-file", "install-root-deleted", "install-deleted-lock",
  ])("restores %s without following external topology or losing rejection evidence", (mode) => {
    const f = fixture(mode);
    const result = installThroughCorpus(f.targetDir, f.policy, f.cacheDir); preparations.push(result);
    assertRejected(f, result);
    for (const [path, content] of f.originals) {
      expect(lstatSync(join(f.targetDir, path)).isFile()).toBe(true);
      expect(readFileSync(join(f.targetDir, path), "utf8")).toBe(content);
    }
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    expect(existsSync(join(f.targetDir, "new-inputs"))).toBe(false);
    expect(JSON.parse(readFileSync(join(f.targetDir, "corpus-policy.json"), "utf8")).dependencyPreparations[f.targetSlug][0]).toEqual(JSON.parse(JSON.stringify(result)));
  });

  it("records a changed ancestor without repairing or cleaning through the lost boundary", () => {
    const f = fixture("install-ancestor-link");
    const result = prepareCorpusDependencies({ ...f, installationPolicy: f.policy }); preparations.push(result);
    assertRejected(f, result);
    expect(result.reason).toContain("boundary changed outside the owned target");
    expect(lstatSync(dirname(f.targetDir)).isSymbolicLink()).toBe(true);
    for (const [path, content] of f.originals) expect(readFileSync(join(`${dirname(f.targetDir)}-moved`, "target", path), "utf8")).toBe(content);
  });

  it.each(["file-directory", "dangling-link", "hard-link"])("refuses an un-restorable initial %s before setup and leaves the original topology untouched", (mode) => {
    const f = fixture("success"), lock = join(f.targetDir, "pnpm-lock.yaml");
    rmSync(lock);
    if (mode === "file-directory") mkdirSync(lock);
    else if (mode === "hard-link") linkSync(join(f.outside, "lock"), lock);
    else symlinkSync(join(f.outside, "missing"), lock);
    const initial = lstatSync(lock);
    const result = prepareCorpusDependencies({ ...f, installationPolicy: f.policy }); preparations.push(result);
    expect(result).toMatchObject({ complete: false, status: "incomplete", installation: { stages: [], operatorPolicy: { policy: f.policy, admission: "rejected" } } });
    expect(result.reason).toMatch(/regular|symbolic link/);
    expect(lstatSync(lock).ino).toBe(initial.ino);
    expect(existsSync(join(f.root, "selector-ran"))).toBe(false);
    expect(result.installation!.dependencyStore).toBe("unavailable");
    assertSentinels(f);
  });

  it("retains observed stages when restoration is denied and releases the private store", () => {
    const f = fixture("install-restoration-denied");
    try {
      const result = prepareCorpusDependencies({ ...f, installationPolicy: f.policy }); preparations.push(result);
      assertRejected(f, result);
      expect(result.reason).toContain("operator input restoration incomplete");
      expect(result.reason).toContain("EACCES");
      expect(result.installation!.stages.map((stage) => stage.stage)).toEqual(["version-probe", "frozen"]);
    } finally { chmodSync(f.targetDir, 0o700); }
  });

  it("records private-store setup failure with the original policy and locks before provisioning", () => {
    const f = fixture("success");
    const missing = join(f.root, "missing-temp"); vi.stubEnv("TMPDIR", missing);
    const result = prepareCorpusDependencies({ ...f, installationPolicy: f.policy }); preparations.push(result);
    assertRejected(f, result);
    expect(result.reason).toContain("ENOENT");
    expect(result.installation!.stages).toEqual([]);
    expect(existsSync(join(f.root, "selector-ran"))).toBe(false);
  });

  it("retains install evidence and performs cleanup when an event consumer throws", () => {
    const f = fixture("success");
    const result = prepareCorpusDependencies({ ...f, installationPolicy: f.policy, onEvent(message) {
      if (message.startsWith("DEPENDENCY PREP OPERATOR")) throw new Error("EVENT_CONSUMER_FAILURE");
    } }); preparations.push(result);
    assertRejected(f, result);
    expect(result.reason).toContain("EVENT_CONSUMER_FAILURE");
    expect(result.installation!.stages.map((stage) => stage.stage)).toEqual(["version-probe", "frozen"]);
    expect(existsSync(join(f.targetDir, "node_modules"))).toBe(false);
    for (const [path, content] of f.originals) expect(readFileSync(join(f.targetDir, path), "utf8")).toBe(content);
  });

  it("delivers the topology failure and original lock evidence through the real M5 client consumer", async () => {
    const f = fixture("install-file-directory");
    const preparation = installThroughCorpus(f.targetDir, f.policy, f.cacheDir); preparations.push(preparation);
    const result = await runCorpusScanner({ repoRoot: process.cwd(), targetDir: f.targetDir, targetConfig: "restoration failure consumer", script: "quality-scan", scanner: "quality-scan", scriptArgs: [f.targetDir], dependencyPreparation: preparation });
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("not a regular file") }));
    expect(existsSync(join(f.targetDir, "provider-consumed"))).toBe(false);
    const meta = { client: "Restoration evidence", subtitle: "#2047", date: "2026-09-12", commit: f.targetRevision, auditor: "Harvey", confidential: true, overallHealth: 5, tenantIsolation: "Not assessed", authModel: "Fixture", headline: "Preparation failure", scope: "quality control", methodology: "Quality scan", outOfScope: "Other modules" };
    const html = buildHtml({ meta, findings: result.findings });
    expect(html).toContain("not a regular file"); expect(html).toContain(f.policy.provenance);
    expect(JSON.parse(readFileSync(join(f.targetDir, "corpus-policy.json"), "utf8")).dependencyPreparations[f.targetSlug][0].installation.operatorPolicy.lockfiles).toEqual(preparation.installation!.operatorPolicy!.lockfiles);
  });
});
