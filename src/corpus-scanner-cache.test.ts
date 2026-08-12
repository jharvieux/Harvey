import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "./findings.js";
import {
  CORPUS_CACHEABLE_SCANNERS,
  assertCorpusScannerCacheVerification,
  executeCorpusScanner,
  type CorpusCacheableScanner,
  type CorpusScannerCacheOptions,
  type CorpusScannerObservation,
  type CorpusScannerRecord,
} from "./corpus-scanner-cache.js";
import { digestObservedPaths } from "./corpus-scanner-scope.js";

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

interface MutableQualityObservation {
  jscpd: { status: string };
  knip: { completed: string[] };
  divergedClones?: unknown;
}

describe("content-addressed corpus scanner artifacts (#1871)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const options = (scanner: CorpusCacheableScanner, overrides: Partial<CorpusScannerCacheOptions> = {}): CorpusScannerCacheOptions => {
    const dir = overrides.dir ?? mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-cache-"));
    if (!overrides.dir) dirs.push(dir);
    return {
      dir,
      mode: "read-write",
      scanner,
      targetRevision: "pinned-commit",
      targetTree: "pinned-tree",
      implementation: `implementation:${scanner}:v1`,
      externalInputs: { node: "v24.18.0", toolchain: "pinned", targetConfig: "root" },
      ...overrides,
    };
  };
  const observation = (scanner: CorpusCacheableScanner): CorpusScannerObservation => scanner === "detect-static"
    ? { scanner, loadedSources: { count: 6_929, pathsDigest: "a".repeat(64) }, ancillary: { productSources: 4_000, configSources: 10, testStorySources: 2_919 } }
    : scanner === "quality-scan"
      ? { scanner, productSources: { count: 4_000, pathsDigest: "b".repeat(64) }, jscpd: { status: "completed", comparedLines: 20_000 }, knip: { discovered: ["root"], completed: ["root"], reduced: [], incomplete: [] }, divergedClones: { securityPathSources: 4, wholeRepoEnabled: false, complementSources: 0 } }
      : { scanner, testSources: { count: 2_919, pathsDigest: "c".repeat(64) }, suiteSignals: { packageManifest: true, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] } };
  const execute = (ids: string[] = ["one"], scanner: CorpusCacheableScanner = "detect-static") => ({
    findings: ids.map(finding),
    scope: {
      unitsExamined: scanner === "detect-static" ? 6_929 : scanner === "quality-scan" ? 4_000 : 2_919,
      description: "faithful large pinned corpus fixture",
      observation: observation(scanner),
    },
    completed: true,
  });
  const zeroMutation = (ids: string[] = ["suite-absent"]) => ({
    findings: ids.map(finding),
    scope: {
      unitsExamined: 0,
      description: "package/config suite-presence signals examined; zero test sources found",
      observation: {
        scanner: "mutation-detect-only" as const,
        testSources: { count: 0, pathsDigest: digestObservedPaths([]) },
        suiteSignals: { packageManifest: false, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] as string[] },
        zeroTestDisposition: {
          status: "not-applicable" as const,
          reason: "No package manifest, test source, or runnable automated suite was present",
          provenance: "mutation-scan inspected package, configuration, workspace, and test-source signals",
          falsifier: "A discovered test source or runnable suite signal invalidates this zero-unit observation",
        },
      },
    },
    completed: true,
  });

  it("preserves normalized findings, categories, order, and examined scope on a warm hit", async () => {
    const cache = options("detect-static");
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

  it.each([
    ["missing divergence scope", (observation: MutableQualityObservation) => { delete observation.divergedClones; }],
    ["forged jscpd status", (observation: MutableQualityObservation) => { observation.jscpd.status = "forged"; }],
    ["completed Knip scope absent from discovery", (observation: MutableQualityObservation) => { observation.knip.completed = ["not-discovered"]; }],
  ])("rejects and recomputes an internally inconsistent quality artifact: %s", async (_name, mutate) => {
    const events: string[] = [];
    const cache = options("quality-scan", { onEvent: (message) => events.push(message) });
    const cold = await executeCorpusScanner(cache, () => execute(["cold"], "quality-scan"));
    const path = join(cache.dir, "corpus-scanners", cache.scanner, `${cold.key}.json`);
    const artifact = JSON.parse(readFileSync(path, "utf8")) as { scope: { observation: MutableQualityObservation } };
    mutate(artifact.scope.observation);
    writeFileSync(path, JSON.stringify(artifact));
    const recompute = vi.fn(() => execute(["fresh"], "quality-scan"));
    const result = await executeCorpusScanner(cache, recompute);
    expect(recompute).toHaveBeenCalledOnce();
    expect(result.cache).toBe("miss");
    expect(result.findings[0]?.id).toBe("fresh");
    expect(events).toContainEqual(expect.stringContaining("CACHE REJECT quality-scan"));
  });

  it("never stores an incomplete scanner output as a clean artifact", async () => {
    const events: string[] = [];
    const cache = options("mutation-detect-only", { onEvent: (message) => events.push(message) });
    const failed = await executeCorpusScanner(cache, () => ({ ...execute([], "mutation-detect-only"), completed: false, failure: "child exited 1" }));
    expect(failed.cache).toBe("non-cacheable");
    expect(events).toContainEqual(expect.stringContaining("incomplete output was not stored"));
    const retry = await executeCorpusScanner(cache, () => execute(["suite-absent"], "mutation-detect-only"));
    expect(retry.cache).toBe("miss");
    expect(retry.findings[0]?.id).toBe("suite-absent");
  });

  it("stores and reuses only a proven scanner-owned no-suite mutation zero", async () => {
    const cache = options("mutation-detect-only");
    const cold = await executeCorpusScanner(cache, () => zeroMutation());
    const shouldNotRun = vi.fn(() => zeroMutation(["wrong"]));
    const warm = await executeCorpusScanner(cache, shouldNotRun);
    expect([cold.cache, warm.cache]).toEqual(["miss", "hit"]);
    expect(shouldNotRun).not.toHaveBeenCalled();
    expect(warm.scope).toEqual(cold.scope);
    expect(warm.scope.observation).toMatchObject({
      scanner: "mutation-detect-only",
      zeroTestDisposition: {
        status: "not-applicable",
        reason: expect.stringContaining("No package manifest"),
        provenance: expect.stringContaining("mutation-scan inspected"),
        falsifier: expect.stringContaining("invalidates"),
      },
    });
  });

  it("rejects completed zero scopes that omit disposition, claim a suite, or come from another scanner", async () => {
    const completeZero = zeroMutation();
    const incompleteObservation = {
      scanner: completeZero.scope.observation.scanner,
      testSources: completeZero.scope.observation.testSources,
      suiteSignals: completeZero.scope.observation.suiteSignals,
    };
    const withoutDisposition = { ...completeZero, scope: { ...completeZero.scope, observation: incompleteObservation } };
    await expect(executeCorpusScanner(options("mutation-detect-only"), () => withoutDisposition)).rejects.toThrow(/complete scanner-owned observation/);

    const suiteClaim = zeroMutation();
    suiteClaim.scope.observation.suiteSignals.strykerConfig = true;
    await expect(executeCorpusScanner(options("mutation-detect-only"), () => suiteClaim)).rejects.toThrow(/complete scanner-owned observation/);

    for (const scanner of ["detect-static", "quality-scan"] as const) {
      const invalid = execute([], scanner);
      invalid.scope.unitsExamined = 0;
      if (invalid.scope.observation.scanner === "detect-static") invalid.scope.observation.loadedSources.count = 0;
      else if (invalid.scope.observation.scanner === "quality-scan") invalid.scope.observation.productSources.count = 0;
      else throw new Error(`unexpected ${invalid.scope.observation.scanner} observation`);
      await expect(executeCorpusScanner(options(scanner), () => invalid)).rejects.toThrow(/complete scanner-owned observation/);
    }
  });

  it("canonicalizes checkout roots in artifacts and materializes the current checkout on a hit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-portable-"));
    const rootA = mkdtempSync(join(tmpdir(), "harvey-corpus-target-a-"));
    const rootB = mkdtempSync(join(tmpdir(), "harvey-corpus-target-b-"));
    dirs.push(dir, rootA, rootB);
    const cacheA = options("mutation-detect-only", { dir, pathRoot: rootA });
    const first = execute(["portable"], "mutation-detect-only");
    first.findings[0]!.evidence = `scanner config failed under ${rootA}/packages/app`;
    await executeCorpusScanner(cacheA, () => first);
    const cacheB = { ...cacheA, pathRoot: rootB };
    const warm = await executeCorpusScanner(cacheB, () => execute(["must-not-run"], "mutation-detect-only"));
    expect(warm.cache).toBe("hit");
    expect(warm.findings[0]!.evidence).toContain(`${rootB}/packages/app`);
    const fresh = execute(["portable"], "mutation-detect-only");
    fresh.findings[0]!.evidence = `scanner config failed under ${rootB}/packages/app`;
    expect((await executeCorpusScanner({ ...cacheB, mode: "verify" }, () => fresh)).cache).toBe("recomputed");
  });

  it("invalidates only the scanner whose implementation closure changed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-granular-"));
    dirs.push(dir);
    const seeded = Object.fromEntries(CORPUS_CACHEABLE_SCANNERS.map((scanner) => [scanner, options(scanner, { dir })])) as Record<CorpusCacheableScanner, CorpusScannerCacheOptions>;
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) await executeCorpusScanner(seeded[scanner], () => execute([scanner], scanner));
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) {
      const cache = scanner === "detect-static" ? { ...seeded[scanner], implementation: "detect-static-v2" } : seeded[scanner];
      expect((await executeCorpusScanner(cache, () => execute([`${scanner}-fresh`], scanner))).cache).toBe(scanner === "detect-static" ? "miss" : "hit");
    }
  });

  it("invalidates only quality-scan when the dependency-preparation receipt changes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-preparation-"));
    dirs.push(dir);
    const seeded = Object.fromEntries(CORPUS_CACHEABLE_SCANNERS.map((scanner) => [scanner, options(scanner, {
      dir,
      externalInputs: {
        node: "v24.18.0",
        toolchain: "pinned",
        targetConfig: "root",
        ...(scanner === "quality-scan" ? { dependencyPreparation: "receipt-a" } : {}),
      },
    })])) as Record<CorpusCacheableScanner, CorpusScannerCacheOptions>;
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) await executeCorpusScanner(seeded[scanner], () => execute([scanner], scanner));
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) {
      const cache = scanner === "quality-scan"
        ? { ...seeded[scanner], externalInputs: { ...seeded[scanner].externalInputs, dependencyPreparation: "receipt-b" } }
        : seeded[scanner];
      expect((await executeCorpusScanner(cache, () => execute([`${scanner}-fresh`], scanner))).cache).toBe(scanner === "quality-scan" ? "miss" : "hit");
    }
  });

  it("invalidates every affected scanner on target or runtime identity changes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-global-"));
    dirs.push(dir);
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) {
      const before = options(scanner, { dir });
      await executeCorpusScanner(before, () => execute([scanner], scanner));
      const moved = { ...before, targetTree: "new-tree", externalInputs: { ...before.externalInputs, node: "v-next" } };
      expect((await executeCorpusScanner(moved, () => execute([`${scanner}-moved`], scanner))).cache).toBe("miss");
    }
  });

  it("forces cold parity in both directions: restored artifacts recompute; all misses fail", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-verify-"));
    dirs.push(dir);
    const records: CorpusScannerRecord[] = [];
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) {
      const cache = options(scanner, { dir });
      await executeCorpusScanner(cache, () => execute([scanner], scanner));
      records.push(await executeCorpusScanner({ ...cache, mode: "verify" }, () => execute([scanner], scanner)));
    }
    expect(() => assertCorpusScannerCacheVerification(records, "verify")).not.toThrow();
    expect(records.every((record) => record.cache === "recomputed")).toBe(true);

    const emptyDir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-empty-"));
    dirs.push(emptyDir);
    const misses: CorpusScannerRecord[] = [];
    for (const scanner of CORPUS_CACHEABLE_SCANNERS) misses.push(await executeCorpusScanner(options(scanner, { dir: emptyDir, mode: "verify" }), () => execute([scanner], scanner)));
    expect(() => assertCorpusScannerCacheVerification(misses, "verify")).toThrow("A miss may seed a later run but cannot claim equivalence");
  });
});
