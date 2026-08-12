import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CORPUS_CACHEABLE_SCANNERS } from "./corpus-scanner-cache.js";
import { buildCorpusScannerCache } from "./corpus-scanner-identity.js";

describe("cacheable corpus scanner identity (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("admits only the two source-only scanners to content-addressed caching", () => {
    expect(CORPUS_CACHEABLE_SCANNERS).toEqual(["detect-static", "mutation-detect-only"]);
    expect(CORPUS_CACHEABLE_SCANNERS).not.toContain("quality-scan");
  });

  it("does not walk or key installed packages for either cacheable scanner", () => {
    const targetDir = mkdtempSync(join(tmpdir(), "harvey-corpus-source-identity-"));
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-corpus-source-cache-"));
    dirs.push(targetDir, cacheDir);
    const build = (scanner: (typeof CORPUS_CACHEABLE_SCANNERS)[number]) => buildCorpusScannerCache({
      repoRoot: process.cwd(),
      cacheDir,
      mode: "read-write",
      scanner,
      targetDir,
      targetRevision: "pin",
      targetTree: "tree",
      targetConfig: "root",
    });
    const before = Object.fromEntries(CORPUS_CACHEABLE_SCANNERS.map((scanner) => [scanner, build(scanner).externalInputs]));
    mkdirSync(join(targetDir, "node_modules", "provider"), { recursive: true });
    writeFileSync(join(targetDir, "node_modules", "provider", "config.js"), "module.exports = { changed: true };\n");
    const after = Object.fromEntries(CORPUS_CACHEABLE_SCANNERS.map((scanner) => [scanner, build(scanner).externalInputs]));

    expect(after).toEqual(before);
    expect(JSON.stringify(after)).not.toContain("config.js");
  });
});
