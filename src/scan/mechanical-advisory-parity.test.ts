import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, execFileSync: vi.fn((bin: string, args: string[], opts: unknown) => bin === "osv-scanner" ? JSON.stringify({ ...parityInput(), results: parityInput().results.map((row) => ({ ...row, source: { path: args.at(-1)! } })) }) : actual.execFileSync(bin as never, args as never, opts as never)) };
});

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

const { assembleEngagementDocument } = await import("../audit-report.js");
const { conservationLedger } = await import("../conservation-ledger.js");
const { renderFidelityBreaches } = await import("../render-fidelity.js");
const { buildHtml } = await import("../../report-template/render.mjs");
const { esc } = await import("../../report-template/sections.mjs");
const { runOsvScanner } = await import("./dependencies.js");
const { runMechanicalScanDetailed } = await import("./mechanical.js");
const { CorpusAdvisoryFindingChangeError } = await import("../corpus-advisory-snapshot.js");

const parityInput = (extraReference: { type: string; url: string } | undefined = undefined, summary = "fixture advisory") => ({
  results: [{
    source: { path: "package-lock.json" },
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
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/fixture-dep": { version: "1.0.0" } } }));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", dependencies: { "fixture-dep": "1.0.0" } }));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("continues when only unused OSV metadata changed", async () => {
    const observations: unknown[] = [];
    const scan = await runMechanicalScanDetailed({
      dir,
      skipNetworkChecks: true,
      advisorySnapshot: {
        assessment: runOsvScanner(dir).assessment,
        result: parityInput({ type: "WEB", url: "https://access.redhat.com/errata/RHSA-2026:60520" }),
        digest: "a".repeat(64), capturedAt: "2026-08-28T00:00:00Z", expiresAt: "2026-09-04T00:00:00Z", osvScannerVersion: "2.3.8",
      },
      advisoryParitySnapshot: { assessment: runOsvScanner(dir).assessment, result: parityInput(), digest: "b".repeat(64), capturedAt: "2026-08-27T00:00:00Z" },
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
        assessment: runOsvScanner(dir).assessment,
        result: parityInput(undefined, "changed advisory"),
        digest: "a".repeat(64), capturedAt: "2026-08-28T00:00:00Z", expiresAt: "2026-09-04T00:00:00Z", osvScannerVersion: "2.3.8",
      },
      advisoryParitySnapshot: { assessment: runOsvScanner(dir).assessment, result: parityInput(), digest: "b".repeat(64), capturedAt: "2026-08-27T00:00:00Z" },
      onAdvisoryObservation: (receipt) => observations.push(receipt),
    })).rejects.toBeInstanceOf(CorpusAdvisoryFindingChangeError);
    expect(observations).toMatchObject([{
      status: "finding-change",
      semantic: { equal: false, added: [], removed: [], changed: [{ fields: expect.arrayContaining(["title"]) }] },
    }]);
  });

  it("returns the live findings and receipt when the corpus caller records a complete population", async () => {
    const observations: unknown[] = [];
    const scan = await runMechanicalScanDetailed({
      dir,
      skipNetworkChecks: true,
      advisorySnapshot: {
        assessment: runOsvScanner(dir).assessment,
        result: parityInput(undefined, "changed advisory"),
        digest: "a".repeat(64), capturedAt: "2026-08-28T00:00:00Z", expiresAt: "2026-09-04T00:00:00Z", osvScannerVersion: "2.3.8",
      },
      advisoryParitySnapshot: { assessment: runOsvScanner(dir).assessment, result: parityInput(), digest: "b".repeat(64), capturedAt: "2026-08-27T00:00:00Z" },
      advisoryFindingChangeDisposition: "record",
      onAdvisoryObservation: (receipt) => observations.push(receipt),
    });
    expect(scan.advisoryObservation?.status).toBe("finding-change");
    expect(observations).toEqual([scan.advisoryObservation]);
    expect(scan.findings.some((finding) => finding.id === "DEP-OSV-GHSA-fixture-fixture-dep@1.0.0")).toBe(true);
  });

  it("conserves nested-source advisories and visible unsupported-input reasons through normalization, assembly and HTML", async () => {
    mkdirSync(join(dir, "nested"));
    writeFileSync(join(dir, "nested", "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/fixture-dep": { version: "1.0.0" } } }));
    writeFileSync(join(dir, "Cargo.lock"), "version = 4\n");
    const captured = runOsvScanner(dir);
    expect(captured.assessment.status).toBe("partial");
    const scan = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true, advisorySnapshot: {
      ...captured, digest: "a".repeat(64), capturedAt: "2026-09-09T00:00:00Z", expiresAt: "2026-09-16T00:00:00Z", osvScannerVersion: "2.3.8",
    } });
    const advisories = scan.findings.filter((finding) => finding.id.startsWith("DEP-OSV-GHSA-fixture"));
    expect(advisories).toHaveLength(2);
    expect(scan.detectors.find((row) => row.detector === "osv-advisories")?.examinedUnitIdentities.map((unit) => unit.identity)).toEqual([
      "nested/package-lock.json#npm:fixture-dep@1.0.0", "package-lock.json#npm:fixture-dep@1.0.0",
    ]);
    expect(new Set(advisories.map((finding) => finding.id)).size).toBe(2);
    expect(advisories.map((finding) => finding.location)).toEqual(expect.arrayContaining(["package-lock.json (fixture-dep@1.0.0)", "nested/package-lock.json (fixture-dep@1.0.0)"]));
    expect(advisories.every((finding) => finding.cwe?.includes("CWE-400") && finding.dependency === "fixture-dep")).toBe(true);
    const document = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, scan.findings, {
      client: "Fixture", subtitle: "Audit", date: "2026-09-09", commit: "fixture", auditor: "Harvey", confidential: true,
      overallHealth: 5, tenantIsolation: "Unmeasured", authModel: "Unmeasured", headline: "OSV input assessment", scope: "Fixture", methodology: "Mechanical", outOfScope: "Live application",
    });
    const html = buildHtml(document);
    writeFileSync(join(dir, "client-report.html"), html);
    expect(conservationLedger(scan.findings, document.findings).ok).toBe(true);
    expect(renderFidelityBreaches(document, html)).toEqual([]);
    const disclosure = document.findings.find((finding) => finding.id === "DEP-OSV-00")!;
    expect(disclosure.evidence).toContain("Cargo.lock");
    expect(html).toContain(esc(disclosure.evidence));
    expect(html).toContain("nested/package-lock.json");
    const withoutReason = html.replace(esc(disclosure.evidence), "");
    expect(renderFidelityBreaches(document, withoutReason).length).toBeGreaterThan(0);
  });

  it("reports zero resolved examination when no provider invocation occurred", async () => {
    unlinkSync(join(dir, "package-lock.json"));
    const captured = runOsvScanner(dir);
    const scan = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true, advisorySnapshot: {
      ...captured, digest: "a".repeat(64), capturedAt: "2026-09-09T00:00:00Z", expiresAt: "2026-09-16T00:00:00Z", osvScannerVersion: "2.3.8",
    } });
    const producer = scan.detectors.find((row) => row.detector === "osv-advisories");
    expect(producer).toMatchObject({ status: "not-assessed", unitsExamined: 0, examinedUnitIdentities: [] });
    expect(producer?.notAssessed?.reason).toContain("no selected supported lockfile");
    expect(scan.findings.find((finding) => finding.id === "SUP-SCOPE-00")?.evidence).not.toContain("walked the whole lockfile");
    expect(scan.findings.find((finding) => finding.id === "DEP-OSV-00")?.evidence).toContain("manifest ranges are not resolved versions");
  });


  it("does not substitute a different same-size SBOM lock tree for the OSV receipt", async () => {
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/sbom-only": { version: "9.0.0" } } }));
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages:\n  fixture-dep@1.0.0:\n    resolution: {integrity: sha512-fixture}\n");
    const captured = runOsvScanner(dir);
    const scan = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true, advisorySnapshot: {
      ...captured, digest: "a".repeat(64), capturedAt: "2026-09-09T00:00:00Z", expiresAt: "2026-09-16T00:00:00Z", osvScannerVersion: "2.3.8",
    } });
    expect(scan.detectors.find((row) => row.detector === "osv-advisories")?.examinedUnitIdentities).toEqual([
      { producer: "osv-advisories", kind: "resolved-dependency", identity: "pnpm-lock.yaml#npm:fixture-dep@1.0.0" },
    ]);
    expect(scan.findings.find((finding) => finding.id === "DEP-OSV-00")?.title).toContain("package-lock.json: alternate tree not assessed");
  });

});
