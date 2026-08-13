import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CORPUS_CACHEABLE_SCANNERS } from "./corpus-scanner-cache.js";
import { buildCorpusScannerCache } from "./corpus-scanner-identity.js";
import { discoverTransitiveImplementationFiles } from "./scan/mechanical-phase-identity.js";

describe("cacheable corpus scanner identity (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("registers all three deterministic corpus scanners for content-addressed caching", () => {
    expect(CORPUS_CACHEABLE_SCANNERS).toEqual(["detect-static", "quality-scan", "mutation-detect-only"]);
  });

  it("does not walk or key installed packages for either cacheable scanner", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-source-identity-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-source-cache-"));
    dirs.push(targetDir, cacheDir);
    const sourceOnly = CORPUS_CACHEABLE_SCANNERS.filter((scanner) => scanner !== "quality-scan");
    const build = (scanner: (typeof CORPUS_CACHEABLE_SCANNERS)[number]) => buildCorpusScannerCache({
      repoRoot: process.cwd(),
      cacheDir,
      mode: "read-write",
      scanner,
      targetDir,
      targetRevision: "pin",
      targetTree: "tree",
      targetConfig: "root",
      invocationArgs: [targetDir],
      dependencyPreparationKey: scanner === "quality-scan" ? "preparation-key" : undefined,
    });
    const before = Object.fromEntries(sourceOnly.map((scanner) => [scanner, build(scanner).externalInputs]));
    mkdirSync(join(targetDir, "node_modules", "provider"), { recursive: true });
    writeFileSync(join(targetDir, "node_modules", "provider", "config.js"), "module.exports = { changed: true };\n");
    const after = Object.fromEntries(sourceOnly.map((scanner) => [scanner, build(scanner).externalInputs]));

    expect(after).toEqual(before);
    expect(JSON.stringify(after)).not.toContain("config.js");
  });

  it("requires and binds the validated dependency-preparation receipt for quality-scan", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-quality-identity-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-quality-cache-"));
    dirs.push(targetDir, cacheDir);
    const build = (dependencyPreparationKey?: string) => buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "quality-scan", targetDir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root", dependencyPreparationKey,
      invocationArgs: [targetDir],
    });
    expect(() => build()).toThrow("complete reproducible dependency-preparation receipt");
    expect(build("receipt-a").externalInputs.dependencyPreparation).not.toBe(build("receipt-b").externalInputs.dependencyPreparation);
  });

  it("binds every environment value passed to quality execution", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-quality-environment-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-quality-environment-cache-"));
    dirs.push(targetDir, cacheDir);
    writeFileSync(join(targetDir, "source.ts"), "export const source = true;\n");
    const baseEnvironment = { HOME: "/quality/home-a", PATH: "/quality/bin-a", TMPDIR: "/quality/tmp-a" };
    const first = buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "quality-scan", targetDir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root", dependencyPreparationKey: "preparation-key", environment: baseEnvironment,
      invocationArgs: [targetDir],
    });
    expect(JSON.parse(first.externalInputs.environment!)).toEqual({
      CI: "true", HOME: "/quality/home-a", NO_COLOR: "1", PATH: "/quality/bin-a", TMPDIR: "/quality/tmp-a",
    });
  });

  it("binds normalized effective invocation flags without binding a checkout path", () => {
    const targetA = mkdtempSync(join(tmpdir(), "harvey-corpus-invocation-a-"));
    const targetB = mkdtempSync(join(tmpdir(), "harvey-corpus-invocation-b-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-invocation-cache-"));
    dirs.push(targetA, targetB, cacheDir);
    const build = (targetDir: string, flag: string) => buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "mutation-detect-only", targetDir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root", invocationArgs: [targetDir, "--detect-only", flag],
    });
    expect(build(targetA, "--flag-a").externalInputs.invocation).toBe(build(targetB, "--flag-a").externalInputs.invocation);
    expect(build(targetA, "--flag-a").externalInputs.invocation).not.toBe(build(targetA, "--flag-b").externalInputs.invocation);
    expect(build(targetA, "--flag-a").externalInputs.invocation).not.toContain(targetA);
  });

  it("binds external report/build artifacts named by the effective invocation", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-artifact-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-artifact-cache-"));
    dirs.push(targetDir, cacheDir);
    const artifact = join(targetDir, "bundle-stats.json");
    writeFileSync(artifact, '{"chunks":["a"]}\n');
    const build = () => buildCorpusScannerCache({
      repoRoot: process.cwd(), cacheDir, mode: "read-write", scanner: "detect-static", targetDir,
      targetRevision: "pin", targetTree: "tree", targetConfig: "root", invocationArgs: [targetDir, "--stats", artifact],
    });
    const before = build().externalInputs.invocationArtifacts;
    writeFileSync(artifact, '{"chunks":["b"]}\n');
    expect(build().externalInputs.invocationArtifacts).not.toBe(before);
  });

  it("follows literal dynamic helpers and rejects an unprovable dynamic implementation import", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-corpus-dynamic-closure-"));
    dirs.push(root);
    const helper = join(root, "helper.ts");
    const literal = join(root, "literal.ts");
    const unknown = join(root, "unknown.ts");
    writeFileSync(helper, "export const helper = true;\n");
    writeFileSync(literal, 'export async function load() { return import("./helper.js"); }\n');
    writeFileSync(unknown, 'export async function load(name: string) { return import(name); }\n');
    expect(discoverTransitiveImplementationFiles([literal])).toEqual([helper, literal].sort());
    expect(() => discoverTransitiveImplementationFiles([unknown])).toThrow(/identity cannot be proven/);
  });
});
