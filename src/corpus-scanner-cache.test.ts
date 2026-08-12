import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "./findings.js";
import {
  CORPUS_SCANNERS,
  assertCorpusScannerCacheVerification,
  executeCorpusScanner,
  type CorpusScanner,
  type CorpusScannerCacheOptions,
  type CorpusScannerRecord,
} from "./corpus-scanner-cache.js";

const finding = (id: string): Finding => ({
  id,
  title: id,
  severity: "Low",
  confidence: "Likely",
  category: "corpus-cache-test",
  taxonomy: "M5 — corpus cache test",
  location: `src/${id}.ts:1`,
  status: "Open",
  evidence: "complete normalized evidence",
  impact: "complete normalized impact",
  fix: "complete normalized fix",
  value: 1,
  ease: 1,
  safety: 1,
});

describe("content-addressed corpus scanner artifacts (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const options = (scanner: CorpusScanner, overrides: Partial<CorpusScannerCacheOptions> = {}): CorpusScannerCacheOptions => {
    const dir = overrides.dir ?? mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-cache-"));
    if (!overrides.dir) dirs.push(dir);
    return {
      dir,
      mode: "read-write",
      scanner,
      targetRevision: "pinned-commit",
      targetTree: "pinned-tree",
      implementation: `implementation:${scanner}:v1`,
      externalInputs: { node: "v24.18.0", tools: "pinned", targetConfig: "root", dependencyInstall: "lock-v1" },
      ...overrides,
    };
  };
  const execute = (ids: string[] = ["one"]) => ({
    findings: ids.map(finding),
    scope: { unitsExamined: 6_929, description: "faithful large pinned corpus fixture" },
    completed: true,
  });

  it("preserves normalized findings, categories, order, and examined scope on a warm hit", async () => {
    const cache = options("quality-scan");
    const cold = await executeCorpusScanner(cache, () => execute(["b", "a"]));
    const shouldNotRun = vi.fn(() => execute(["wrong"]));
    const warm = await executeCorpusScanner(cache, shouldNotRun);
    expect(cold.cache).toBe("miss");
    expect(warm.cache).toBe("hit");
    expect(shouldNotRun).not.toHaveBeenCalled();
    expect(warm.findings).toEqual(cold.findings);
    expect(warm.findings.map((row) => row.category)).toEqual(["corpus-cache-test", "corpus-cache-test"]);
    expect(warm.scope).toEqual(cold.scope);
  });

  it("rejects corrupt and wrong-schema artifacts visibly, then recomputes", async () => {
    const events: string[] = [];
    const cache = options("detect-static", { onEvent: (message) => events.push(message) });
    const cold = await executeCorpusScanner(cache, () => execute());
    const path = join(cache.dir, "corpus-scanners", cache.scanner, `${cold.key}.json`);
    writeFileSync(path, JSON.stringify({ schema: 0, scanner: cache.scanner, key: cold.key, findings: [] }));
    const fresh = await executeCorpusScanner(cache, () => execute(["fresh"]));
    expect(fresh.cache).toBe("miss");
    expect(fresh.findings[0]?.id).toBe("fresh");
    expect(events).toContainEqual(expect.stringContaining("CACHE REJECT detect-static"));
    expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ schema: 2, scanner: "detect-static" });
  });

  it("never stores an incomplete scanner output as a clean artifact", async () => {
    const events: string[] = [];
    const cache = options("mutation-detect-only", { onEvent: (message) => events.push(message) });
    const failed = await executeCorpusScanner(cache, () => ({ ...execute([]), completed: false, failure: "child exited 1" }));
    expect(failed.cache).toBe("non-cacheable");
    expect(events).toContainEqual(expect.stringContaining("incomplete output was not stored"));
    const retry = await executeCorpusScanner(cache, () => execute(["suite-absent"]));
    expect(retry.cache).toBe("miss");
    expect(retry.findings[0]?.id).toBe("suite-absent");
  });

  it("canonicalizes checkout roots in artifacts and materializes the current checkout on a hit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-portable-"));
    const rootA = mkdtempSync(join(tmpdir(), "harvey-corpus-target-a-"));
    const rootB = mkdtempSync(join(tmpdir(), "harvey-corpus-target-b-"));
    dirs.push(dir, rootA, rootB);
    const cacheA = options("quality-scan", { dir, pathRoot: rootA });
    const first = execute(["portable"]);
    first.findings[0]!.evidence = `scanner config failed under ${rootA}/packages/app`;
    await executeCorpusScanner(cacheA, () => first);
    const cacheB = { ...cacheA, pathRoot: rootB };
    const warm = await executeCorpusScanner(cacheB, () => execute(["must-not-run"]));
    expect(warm.cache).toBe("hit");
    expect(warm.findings[0]!.evidence).toContain(`${rootB}/packages/app`);
    const fresh = execute(["portable"]);
    fresh.findings[0]!.evidence = `scanner config failed under ${rootB}/packages/app`;
    expect((await executeCorpusScanner({ ...cacheB, mode: "verify" }, () => fresh)).cache).toBe("recomputed");
  });

  it("invalidates only the scanner whose implementation closure changed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-granular-"));
    dirs.push(dir);
    const seeded = Object.fromEntries(CORPUS_SCANNERS.map((scanner) => [scanner, options(scanner, { dir })])) as Record<CorpusScanner, CorpusScannerCacheOptions>;
    for (const scanner of CORPUS_SCANNERS) await executeCorpusScanner(seeded[scanner], () => execute([scanner]));
    for (const scanner of CORPUS_SCANNERS) {
      const cache = scanner === "quality-scan" ? { ...seeded[scanner], implementation: "quality-v2" } : seeded[scanner];
      expect((await executeCorpusScanner(cache, () => execute([`${scanner}-fresh`]))).cache).toBe(scanner === "quality-scan" ? "miss" : "hit");
    }
  });

  it("invalidates every affected scanner on target, runtime, or install identity changes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-global-"));
    dirs.push(dir);
    for (const scanner of CORPUS_SCANNERS) {
      const before = options(scanner, { dir });
      await executeCorpusScanner(before, () => execute([scanner]));
      const moved = { ...before, targetTree: "new-tree", externalInputs: { ...before.externalInputs, node: "v-next", dependencyInstall: "lock-v2" } };
      expect((await executeCorpusScanner(moved, () => execute([`${scanner}-moved`]))).cache).toBe("miss");
    }
  });

  it("forces cold parity in both directions: restored artifacts recompute; all misses fail", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-verify-"));
    dirs.push(dir);
    const records: CorpusScannerRecord[] = [];
    for (const scanner of CORPUS_SCANNERS) {
      const cache = options(scanner, { dir });
      await executeCorpusScanner(cache, () => execute([scanner]));
      records.push(await executeCorpusScanner({ ...cache, mode: "verify" }, () => execute([scanner])));
    }
    expect(() => assertCorpusScannerCacheVerification(records, "verify")).not.toThrow();
    expect(records.every((record) => record.cache === "recomputed")).toBe(true);

    const emptyDir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-empty-"));
    dirs.push(emptyDir);
    const misses: CorpusScannerRecord[] = [];
    for (const scanner of CORPUS_SCANNERS) misses.push(await executeCorpusScanner(options(scanner, { dir: emptyDir, mode: "verify" }), () => execute([scanner])));
    expect(() => assertCorpusScannerCacheVerification(misses, "verify")).toThrow("A miss may seed a later run but cannot claim equivalence");
  });
});
