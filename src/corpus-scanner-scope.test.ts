import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { digestObservedPaths, readCorpusScannerScope, writeCorpusScannerScope } from "./corpus-scanner-scope.js";
import type { CorpusScannerObservation } from "./corpus-scanner-cache.js";

interface MutableQualityObservation {
  scanner: "quality-scan";
  productSources: { count: number; pathsDigest: string };
  jscpd: { status: string; comparedLines: number };
  knip: { discovered: string[]; completed: string[]; reduced: string[]; incomplete: string[] };
  divergedClones?: { securityPathSources: number; wholeRepoEnabled: boolean; complementSources: number };
}

describe("scanner-owned examined-scope receipts", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const receiptPath = (): string => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-scanner-scope-"));
    dirs.push(dir);
    return join(dir, "scope.json");
  };

  it("round-trips the scanner identity and its own examined units", () => {
    const path = receiptPath();
    writeCorpusScannerScope(path, "detect-static", {
      unitsExamined: 6_131,
      description: "sources loaded by detect-static",
      observation: {
        scanner: "detect-static",
        loadedSources: { count: 6_131, pathsDigest: "a".repeat(64) },
        ancillary: { productSources: 3_066, configSources: 2, testStorySources: 3_063 },
      },
    });
    expect(readCorpusScannerScope(path, "detect-static")).toEqual({
      unitsExamined: 6_131,
      description: "sources loaded by detect-static",
      observation: {
        scanner: "detect-static",
        loadedSources: { count: 6_131, pathsDigest: "a".repeat(64) },
        ancillary: { productSources: 3_066, configSources: 2, testStorySources: 3_063 },
      },
    });
  });

  it("rejects a receipt from a different scanner instead of sharing a broad census", () => {
    const path = receiptPath();
    writeCorpusScannerScope(path, "quality-scan", {
      unitsExamined: 3_055,
      description: "quality source inputs",
      observation: {
        scanner: "quality-scan",
        productSources: { count: 3_055, pathsDigest: "b".repeat(64) },
        jscpd: { status: "completed", comparedLines: 8_000 },
        knip: { discovered: ["(repo root)"], completed: ["(repo root)"], reduced: [], incomplete: [] },
        divergedClones: { securityPathSources: 1, wholeRepoEnabled: false, complementSources: 0 },
      },
    });
    expect(() => readCorpusScannerScope(path, "mutation-detect-only")).toThrow(/mismatched/);
  });

  it.each([0, -1, 1.5])("rejects a non-positive or fractional unit claim (%s)", (unitsExamined) => {
    expect(() => writeCorpusScannerScope(receiptPath(), "quality-scan", {
      unitsExamined,
      description: "invalid",
      observation: {
        scanner: "quality-scan",
        productSources: { count: 0, pathsDigest: "none" },
        jscpd: { status: "completed", comparedLines: 0 },
        knip: { discovered: [], completed: [], reduced: [], incomplete: [] },
        divergedClones: { securityPathSources: 0, wholeRepoEnabled: false, complementSources: 0 },
      },
    })).toThrow(/incomplete or zero/);
  });

  it("allows mutation to report a proven no-suite zero while retaining its reason, provenance, and falsifier", () => {
    const path = receiptPath();
    writeCorpusScannerScope(path, "mutation-detect-only", {
      unitsExamined: 0,
      description: "zero test files; package/config signals consumed",
      observation: {
        scanner: "mutation-detect-only",
        testSources: { count: 0, pathsDigest: digestObservedPaths([]) },
        suiteSignals: { packageManifest: true, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
        zeroTestDisposition: {
          status: "no-suite",
          reason: "No runnable automated test suite was detected in this package",
          provenance: "mutation-scan inspected package, configuration, workspace, and test-source signals",
          falsifier: "A discovered test source or runnable suite signal invalidates this zero-unit observation",
        },
      },
    });
    const scope = readCorpusScannerScope(path, "mutation-detect-only");
    expect(scope.unitsExamined).toBe(0);
    if (scope.observation.scanner !== "mutation-detect-only") throw new Error("expected mutation observation");
    expect(scope.observation.zeroTestDisposition).toMatchObject({ status: "no-suite" });
  });

  it("rejects mutation zero without a complete disposition or with a signal claiming a suite", () => {
    const base = {
      unitsExamined: 0,
      description: "zero test files; package/config signals consumed",
      observation: {
        scanner: "mutation-detect-only" as const,
        testSources: { count: 0, pathsDigest: digestObservedPaths([]) },
        suiteSignals: { packageManifest: true, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] as string[] },
      },
    };
    expect(() => writeCorpusScannerScope(receiptPath(), "mutation-detect-only", base)).toThrow(/incomplete or zero/);
    expect(() => writeCorpusScannerScope(receiptPath(), "mutation-detect-only", {
      ...base,
      observation: {
        ...base.observation,
        suiteSignals: { ...base.observation.suiteSignals, strykerConfig: true },
        zeroTestDisposition: {
          status: "no-suite",
          reason: "No runnable automated test suite was detected in this package",
          provenance: "mutation-scan inspected package, configuration, workspace, and test-source signals",
          falsifier: "A discovered test source or runnable suite signal invalidates this zero-unit observation",
        },
      },
    })).toThrow(/incomplete or zero/);
  });

  it("rejects generic zero explanations and a zero disposition attached to positive mutation scope", () => {
    expect(() => writeCorpusScannerScope(receiptPath(), "mutation-detect-only", {
      unitsExamined: 0,
      description: "zero test files",
      observation: {
        scanner: "mutation-detect-only",
        testSources: { count: 0, pathsDigest: digestObservedPaths([]) },
        suiteSignals: { packageManifest: false, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
        zeroTestDisposition: { status: "not-applicable", reason: "none", provenance: "scanner", falsifier: "file" },
      },
    })).toThrow(/incomplete or zero/);
    expect(() => writeCorpusScannerScope(receiptPath(), "mutation-detect-only", {
      unitsExamined: 1,
      description: "one test source",
      observation: {
        scanner: "mutation-detect-only",
        testSources: { count: 1, pathsDigest: "c".repeat(64) },
        suiteSignals: { packageManifest: true, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
        zeroTestDisposition: {
          status: "no-suite",
          reason: "No runnable automated test suite was detected in this package",
          provenance: "mutation-scan inspected package, configuration, workspace, and test-source signals",
          falsifier: "A discovered test source or runnable suite signal invalidates this zero-unit observation",
        },
      },
    })).toThrow(/incomplete or zero/);
  });

  it("rejects malformed and forged generic receipts", () => {
    const path = receiptPath();
    writeFileSync(path, '{"schema":1,"unitsExamined":6133,"description":"generic target census"}\n');
    expect(() => readCorpusScannerScope(path, "detect-static")).toThrow(/mismatched/);
  });

  it.each([
    ["unknown jscpd status", (observation: MutableQualityObservation) => { observation.jscpd.status = "forged"; }],
    ["malformed source-path digest", (observation: MutableQualityObservation) => { observation.productSources.pathsDigest = "not-a-sha256"; }],
    ["missing divergence scope", (observation: MutableQualityObservation) => { delete observation.divergedClones; }],
    ["completed scope not discovered", (observation: MutableQualityObservation) => { observation.knip.completed = ["ghost"]; }],
    ["completed and incomplete overlap", (observation: MutableQualityObservation) => { observation.knip.incomplete = ["(repo root)"]; }],
    ["reduced scope not completed", (observation: MutableQualityObservation) => { observation.knip.reduced = ["ghost"]; }],
    ["non-canonical duplicate scope set", (observation: MutableQualityObservation) => { observation.knip.discovered = ["(repo root)", "(repo root)"]; }],
    ["negative divergence count", (observation: MutableQualityObservation) => { observation.divergedClones!.securityPathSources = -1; }],
    ["false whole-repo complement", (observation: MutableQualityObservation) => { observation.divergedClones!.complementSources = 1; }],
  ])("rejects a semantically inconsistent quality receipt: %s", (_name, mutate) => {
    const observation: MutableQualityObservation = {
      scanner: "quality-scan" as const,
      productSources: { count: 5, pathsDigest: "d".repeat(64) },
      jscpd: { status: "completed" as const, comparedLines: 100 },
      knip: { discovered: ["(repo root)"], completed: ["(repo root)"], reduced: [], incomplete: [] },
      divergedClones: { securityPathSources: 2, wholeRepoEnabled: false, complementSources: 0 },
    };
    mutate(observation);
    expect(() => writeCorpusScannerScope(receiptPath(), "quality-scan", {
      unitsExamined: 5,
      description: "five quality product sources examined",
      observation: observation as unknown as CorpusScannerObservation,
    })).toThrow(/incomplete or zero/);
  });
});
