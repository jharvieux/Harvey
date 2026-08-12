import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readCorpusScannerScope, writeCorpusScannerScope } from "./corpus-scanner-scope.js";

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
        loadedSources: { count: 6_131, pathsDigest: "static-paths" },
        ancillary: { productSources: 3_066, configSources: 2, testStorySources: 3_063 },
      },
    });
    expect(readCorpusScannerScope(path, "detect-static")).toEqual({
      unitsExamined: 6_131,
      description: "sources loaded by detect-static",
      observation: {
        scanner: "detect-static",
        loadedSources: { count: 6_131, pathsDigest: "static-paths" },
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
        productSources: { count: 3_055, pathsDigest: "quality-paths" },
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

  it("allows mutation to report zero test files while retaining the suite signals it consumed", () => {
    const path = receiptPath();
    writeCorpusScannerScope(path, "mutation-detect-only", {
      unitsExamined: 0,
      description: "zero test files; package/config signals consumed",
      observation: {
        scanner: "mutation-detect-only",
        testSources: { count: 0, pathsDigest: "empty" },
        suiteSignals: { packageManifest: true, strykerConfig: false, ancestorWorkspaceSuite: null, childWorkspaceSuites: [] },
      },
    });
    expect(readCorpusScannerScope(path, "mutation-detect-only").unitsExamined).toBe(0);
  });

  it("rejects malformed and forged generic receipts", () => {
    const path = receiptPath();
    writeFileSync(path, '{"schema":1,"unitsExamined":6133,"description":"generic target census"}\n');
    expect(() => readCorpusScannerScope(path, "detect-static")).toThrow(/mismatched/);
  });
});
