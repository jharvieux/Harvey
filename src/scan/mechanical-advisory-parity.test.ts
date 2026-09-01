import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./supply-chain.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./supply-chain.js")>();
  return { ...actual, checkSlopsquat: vi.fn(async () => []), checkLicenseCompliance: vi.fn(async () => []) };
});
vi.mock("./secrets.js", () => ({ scanSecrets: vi.fn(() => []), resolveBundleScan: vi.fn(() => ({})) }));
vi.mock("./semgrep.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./semgrep.js")>();
  return {
    ...actual,
    runSemgrep: vi.fn(() => ({
      result: { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } },
    })),
  };
});

const { runMechanicalScanDetailed } = await import("./mechanical.js");
const { CorpusAdvisoryFindingChangeError } = await import("../corpus-advisory-snapshot.js");

const parityInput = (extraReference: { type: string; url: string } | undefined = undefined, summary = "fixture advisory") => ({
  results: [{
    source: { path: "/tmp/package-lock.json" },
    packages: [{
      package: { name: "fixture-dep", version: "1.0.0", ecosystem: "npm" },
      groups: [{ ids: ["GHSA-fixture"], max_severity: "7.5" }],
      vulnerabilities: [{
        id: "GHSA-fixture",
        summary,
        details: "fixture impact",
        affected: [{ package: { name: "fixture-dep", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.1" }] }] }],
        references: [{ type: "ADVISORY", url: "https://example.test/advisory" }, ...(extraReference ? [extraReference] : [])],
        database_specific: { severity: "HIGH", cwe_ids: ["CWE-400"] },
      }],
    }],
  }],
});

describe("mechanical live advisory parity (#1883)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-advisory-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", dependencies: { "fixture-dep": "1.0.0" } }));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("continues when only unused OSV metadata changed", async () => {
    const observations: unknown[] = [];
    const scan = await runMechanicalScanDetailed({
      dir,
      skipNetworkChecks: true,
      advisorySnapshot: {
        result: parityInput({ type: "WEB", url: "https://access.redhat.com/errata/RHSA-2026:60520" }),
        digest: "a".repeat(64), capturedAt: "2026-08-28T00:00:00Z", expiresAt: "2026-09-04T00:00:00Z", osvScannerVersion: "2.3.8",
      },
      advisoryParitySnapshot: { result: parityInput(), digest: "b".repeat(64), capturedAt: "2026-08-27T00:00:00Z" },
      onAdvisoryObservation: (receipt) => observations.push(receipt),
    });
    expect(scan.advisoryObservation?.status).toBe("metadata-only");
    expect(observations).toEqual([scan.advisoryObservation]);
    expect(scan.findings.some((finding) => finding.id === "DEP-OSV-GHSA-fixture-fixture-dep@1.0.0")).toBe(true);
  });

  it("publishes the semantic receipt before a material failure", async () => {
    const observations: unknown[] = [];
    await expect(runMechanicalScanDetailed({
      dir,
      skipNetworkChecks: true,
      advisorySnapshot: {
        result: parityInput(undefined, "changed advisory"),
        digest: "a".repeat(64), capturedAt: "2026-08-28T00:00:00Z", expiresAt: "2026-09-04T00:00:00Z", osvScannerVersion: "2.3.8",
      },
      advisoryParitySnapshot: { result: parityInput(), digest: "b".repeat(64), capturedAt: "2026-08-27T00:00:00Z" },
      onAdvisoryObservation: (receipt) => observations.push(receipt),
    })).rejects.toBeInstanceOf(CorpusAdvisoryFindingChangeError);
    expect(observations).toMatchObject([{
      status: "finding-change",
      semantic: { equal: false, added: [], removed: [], changed: [{ fields: expect.arrayContaining(["title"]) }] },
    }]);
  });
});
