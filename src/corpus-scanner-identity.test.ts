import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CORPUS_CACHEABLE_SCANNERS } from "./corpus-scanner-cache.js";
import { buildCorpusScannerCache } from "./corpus-scanner-identity.js";

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
    });
    expect(JSON.parse(first.externalInputs.environment!)).toEqual({
      CI: "true", HOME: "/quality/home-a", NO_COLOR: "1", PATH: "/quality/bin-a", TMPDIR: "/quality/tmp-a",
    });
  });
});
