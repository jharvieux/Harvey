import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AUDIT_MODULES } from "../audit-coverage.js";
import { createAuditReplayBinding, writeAuditReplayBundle, type AuditEvidenceInput } from "../audit-replay.js";
import type { Finding, FindingsDocument, ReportMeta } from "../findings.js";
import { runGuardCommand, type GuardCommandResult } from "../guard-mutation-process.js";
import { contentIdentity } from "../../report-template/dispositions.mjs";

const repo = resolve(import.meta.dirname, "../..");
let root: string, target: string, bundle: string, preload: string;
let delivery: { code: number | null; stdout: string; stderr: string };
const children: Promise<GuardCommandResult>[] = [];
const teardown = new AbortController();
const meta: ReportMeta = { client: "CLI replay", subtitle: "evidence", date: "2026-09-24", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 5, tenantIsolation: "Unverified", authModel: "fixture", headline: "Scoped receipts", scope: "ten modules", methodology: "replay", outOfScope: "missing surfaces" };

async function run(extra: string[], env: Record<string, string> = {}, assemble = true): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = runGuardCommand({
    command: ["/usr/bin/env", ...Object.entries(env).map(([key, value]) => `${key}=${value}`), process.execPath, "--require", preload, "--import", "tsx", "src/cli/run-audit.ts", target, ...(assemble ? ["--assemble", bundle] : []), ...extra],
    cwd: repo, bundleDir: root, outputPrefix: `child-${children.length}`, timeoutMs: 20_000,
    killGraceMs: 1_000, signal: teardown.signal,
  });
  children.push(child);
  const receipt = await child;
  expect(receipt.state, JSON.stringify(receipt)).toBe("exited");
  expect(receipt.terminationAcknowledged).toBe(true);
  return { code: receipt.exitCode, stdout: readFileSync(join(root, receipt.stdout.path), "utf8"), stderr: readFileSync(join(root, receipt.stderr.path), "utf8") };
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), "harvey-replay-cli-")); target = join(root, "source"); bundle = join(root, "bundle"); preload = join(root, "tripwire.cjs");
  mkdirSync(target); writeFileSync(join(target, "sample.ts"), "export const value = 1;\n");
  writeFileSync(preload, `
const cp = require('node:child_process');
const trip = (kind) => () => { throw new Error('REPLAY TRIPWIRE: ' + kind); };
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) cp[name] = trip('child process ' + name);
for (const module of ['node:http', 'node:https']) for (const name of ['request', 'get']) require(module)[name] = trip('network ' + name);
for (const name of ['connect', 'createConnection']) require('node:net')[name] = trip('network ' + name);
require('node:tls').connect = trip('TLS');
globalThis.fetch = trip('model/network fetch');
require('node:module').syncBuiltinESMExports();
if (process.env.REPLAY_TRIP_CHILD) cp.spawnSync('mutation-scan', []);
if (process.env.REPLAY_TRIP_NETWORK) globalThis.fetch('https://example.invalid/model');
`);
  const raw = join(root, "raw.json"); writeFileSync(raw, '{"owningRun":"unchanged"}\n');
  const sbom = join(root, "sbom.json"); writeFileSync(sbom, '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}\n');
  const passes: AuditEvidenceInput[] = AUDIT_MODULES.map((module) => {
    const finding: Finding = { id: `${module}-CLI`, title: `${module} actual delivery`, severity: "Medium", confidence: "Confirmed", category: "Maintainability", taxonomy: `${module} — replay`, location: "sample.ts:1", status: "Open", evidence: "Retained producer evidence", impact: "Measured issue", fix: "Repair", value: 2, ease: 2, safety: 2 };
    return { scope: { module, workspace: ".", tier: "source", surface: "module", wholeModule: true }, generatedAt: new Date().toISOString(), producer: { name: module, version: "fixture" }, rawArtifacts: [raw], result: { kind: "examined", unitsExamined: 3, scope: "files", detail: "Actual retained scope", findings: [finding], ...(module === "M7" ? { reason: "HTTP 403: project.read denied [TRIED; falsifier: rerun permitted advisor command]" } : {}), ...(module === "M8" ? { reason: "15 configured files missing [MEASURED; falsifier: rerun full scope]", testQuality: { mutationScore: 39.7, mutationScoreBasedOnCoveredCode: 58.6, coveredScope: ["apps/main"], wholeRepo: false, scopeNote: "724 configured; 709 reported; 15 missing", rows: [], lineCoverage: { status: "partial", reason: "No summary" }, survivors: [], survivorTotal: 0 } } : {}), ...(module === "M10" ? { dataMap: {} } : {}) } };
  });
  const m3 = structuredClone(passes[2]!);
  m3.scope = { ...m3.scope, tier: "trend", surface: "history-window", wholeModule: false };
  if ("kind" in m3.result && m3.result.kind === "examined") m3.result.findings[0]!.id = "M3-TREND-00";
  passes.push(m3);
  for (const index of [6, 7]) {
    const prior = structuredClone(passes[index]!);
    prior.generatedAt = new Date(Date.now() - 5000).toISOString();
    if ("kind" in prior.result && prior.result.kind === "examined") {
      prior.result.reason = index === 6 ? "STALE_NO_CREDENTIALS" : "STALE_MUTATION_FAILED";
      if (prior.result.testQuality) prior.result.testQuality.mutationScore = 29.4;
    }
    passes.push(prior);
  }
  writeAuditReplayBundle(bundle, { binding: createAuditReplayBinding(target, { network: false, model: false }), scopes: passes.slice(0, 11).map((pass) => pass.scope), passes, meta, sbomPath: sbom });
  delivery = await run(["--findings-out", join(root, "findings.json"), "--sarif-out", join(root, "findings.sarif"), "--sbom-out", join(root, "inventory.json"), "--out", join(root, "coverage.json"), "--html-out", join(root, "report.html"), "--conservation-out", join(root, "ledger.json")]);
});
afterAll(async () => {
  teardown.abort();
  const receipts = await Promise.allSettled(children);
  expect(receipts.every((receipt) => receipt.status === "fulfilled" && receipt.value.terminationAcknowledged), "Every owned child must close before fixtures are removed").toBe(true);
  if (root) rmSync(root, { recursive: true, force: true });
});

describe("run-audit assembly capability boundary", () => {
  it("refuses to re-sign unbound legacy passes as fresh retained execution before invoking scanners", async () => {
    const result = await run(["--retain-artifacts", join(root, "laundered"), "--artifacts-dir", join(root, "legacy")], {}, false);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("legacy pass files lack original target tree/configuration/engine bindings");
    expect(result.stderr).not.toContain("REPLAY TRIPWIRE");
  });
  it("writes JSON/SARIF/SBOM/coverage/HTML and conservation with every external capability trapped", () => {
    expect(delivery, delivery.stderr).toMatchObject({ code: 0 });
    expect(delivery.stdout).toContain("ASSEMBLY PASS");
    const document = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
    const sarif = JSON.parse(readFileSync(join(root, "findings.sarif"), "utf8"));
    const html = readFileSync(join(root, "report.html"), "utf8");
    expect(document.findings.map((finding) => finding.id)).toContain("M3-TREND-00");
    expect(sarif.runs[0].results).toHaveLength(document.findings.length);
    expect(sarif.runs[0].results.find((row: { properties: { harveyId: string } }) => row.properties.harveyId === "M1-CLI")).toMatchObject({ kind: "review", level: "none", properties: { severity: "Medium", assessment: { disposition: "pending-review" } } });
    expect(sarif.runs[0].results.find((row: { properties: { harveyId: string } }) => row.properties.harveyId === "M4-CLI")).toMatchObject({ kind: "fail", level: "warning" });
    expect(sarif.runs[0].properties.harveyPopulations).toEqual(document.populations);
    expect(document.testQuality?.mutationScore).toBe(39.7);
    expect(html).toContain("M3-TREND-00"); expect(html).toContain("39.7"); expect(html).toContain("58.6");
    expect(html).toContain("724 configured; 709 reported; 15 missing");
    expect(html).toContain("HTTP 403: project.read denied"); expect(html).toContain("rerun permitted advisor command");
    expect(JSON.parse(readFileSync(join(root, "coverage.json"), "utf8"))).toHaveLength(10);
    expect(JSON.parse(readFileSync(join(root, "inventory.json"), "utf8")).bomFormat).toBe("CycloneDX");
    expect(JSON.parse(readFileSync(join(root, "ledger.json"), "utf8")).unaccounted).toBe(0);
  });
  it("M3 specialist survives beside a successful base pass in JSON and rendered HTML", () => {
    const document = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
    expect(document.findings.filter((row) => row.id === "M3-TREND-00")).toHaveLength(1);
    expect(document.findings.find((row) => row.id === "M3-CLI")).toBeDefined();
    expect(readFileSync(join(root, "report.html"), "utf8")).toContain("M3-TREND-00");
  });
  it("binds comparisons to verified receipts and keeps same-run checkpoints out of remediation counts", async () => {
    const prior = join(root, "findings.json");
    const output = join(root, "checkpoint-comparison.json");
    const htmlPath = join(root, "checkpoint-comparison.html");
    const sarifPath = join(root, "checkpoint-comparison.sarif");
    const result = await run(["--findings-out", output, "--baseline", prior, "--html-out", htmlPath, "--sarif-out", sarifPath]);
    expect(result.code, result.stderr).toBe(0);
    const doc = JSON.parse(readFileSync(output, "utf8")) as FindingsDocument;
    expect(doc.auditContext?.kind).toBe("same-run-checkpoint");
    expect(doc.auditContext?.target.revision).toMatch(/^unversioned:[a-f0-9]{64}$/);
    expect(doc.auditContext?.producerVersions.engine).toMatch(/^[a-f0-9]{64}$/);
    expect(doc.baseline?.counts).toMatchObject({ new: 0, resolved: 0 });
    expect(doc.baseline?.comparison?.kind).toBe("same-run-checkpoint");
    expect(doc.baseline?.comparison?.denominators.current).toBe(doc.findings.length);
    expect(readFileSync(htmlPath, "utf8")).toContain("not a prior client audit");
    const sarif = JSON.parse(readFileSync(sarifPath, "utf8"));
    expect(sarif.runs[0].properties.harveyBaseline).toEqual(doc.baseline);
    expect(sarif.runs[0].properties.harveyAuditContext).toEqual(doc.auditContext);
    expect(doc.findings.find((f) => f.id === "M1-CLI")?.assessment?.disposition).toBe("pending-review");
  });
  it("discloses an unbound legacy baseline and protects the baseline input from export overwrite", async () => {
    const prior = join(root, "legacy-baseline.json");
    const old = JSON.parse(readFileSync(join(root, "findings.json"), "utf8"));
    delete old.auditContext;
    writeFileSync(prior, JSON.stringify(old));
    const original = readFileSync(prior, "utf8");
    const output = join(root, "legacy-comparison.json");
    const result = await run(["--findings-out", output, "--baseline", prior]);
    expect(result.code, result.stderr).toBe(0);
    const doc = JSON.parse(readFileSync(output, "utf8")) as FindingsDocument;
    expect(doc.baseline?.comparison?.kind).toBe("incompatible");
    expect(doc.baseline?.counts).toMatchObject({ new: 0, resolved: 0 });
    const rejected = await run(["--findings-out", prior, "--baseline", prior]);
    expect(rejected.code).not.toBe(0);
    expect(rejected.stderr).toContain("must not overwrite");
    expect(readFileSync(prior, "utf8")).toBe(original);
  });
  it("consumes reviewed migration input without letting metadata replace measured producer/source provenance", async () => {
    const current = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
    const row = current.findings[0]!;
    const moved = { ...row, id: "historical-id", location: "renamed/prior.ts", evidence: "Prior wording requiring explicit reconciliation" };
    const baseline = join(root, "migration-prior.json");
    writeFileSync(baseline, JSON.stringify({ ...current, findings: [moved] }));
    const metadata = join(root, "migration-meta.json");
    writeFileSync(metadata, JSON.stringify({ ...meta, auditContext: { ...current.auditContext, target: { id: "forged", revision: "forged" }, producerVersions: { forged: "fake" }, scopeComplete: true }, identityMigrations: [{ priorContentKey: contentIdentity(moved), currentContentKey: contentIdentity(row), reason: "Reviewed source rename", reviewedBy: "fixture-reviewer" }] }));
    const output = join(root, "migration.json");
    const result = await run(["--findings-out", output, "--baseline", baseline, "--meta", metadata]);
    expect(result.code, result.stderr).toBe(0);
    const doc = JSON.parse(readFileSync(output, "utf8")) as FindingsDocument;
    expect(doc.auditContext?.target).toEqual(current.auditContext?.target);
    expect(doc.auditContext?.producerVersions).toEqual(current.auditContext?.producerVersions);
    expect(doc.auditContext?.scopeComplete).toBe(false);
    expect(doc.baseline?.comparison?.migrations).toHaveLength(1);
    expect(doc.baseline?.counts).toEqual({ persistent: 1, new: 0, resolved: 0 });
    expect(doc.findings[0]?.baselineReason).toContain("Reviewed source rename");
  });
  it("M8 current scores and complete missing-file denominator replace stale measurements", () => {
    const document = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
    expect(document.testQuality?.mutationScore).toBe(39.7);
    const html = readFileSync(join(root, "report.html"), "utf8");
    expect(html).toContain("39.7"); expect(html).toContain("58.6"); expect(html).toContain("724 configured; 709 reported; 15 missing");
  });
  it("contradictory credential and mutation reasons remain history only", () => {
    const document = JSON.parse(readFileSync(join(root, "findings.json"), "utf8"));
    expect(document.auditEvidence.history).toHaveLength(2);
    const current = JSON.stringify(document.coverage);
    const html = readFileSync(join(root, "report.html"), "utf8");
    for (const stale of ["STALE_NO_CREDENTIALS", "STALE_MUTATION_FAILED"]) { expect(current).not.toContain(stale); expect(html).not.toContain(stale); }
  });
  it("connected permission failure detail and rerun falsifier survive JSON and HTML", () => {
    const document = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
    const reason = document.coverage!.find((row) => row.module === "M7")!.reason;
    expect(reason).toContain("HTTP 403: project.read denied"); expect(reason).toContain("rerun permitted advisor command");
    const html = readFileSync(join(root, "report.html"), "utf8");
    expect(html).toContain("HTTP 403: project.read denied"); expect(html).toContain("rerun permitted advisor command");
  });
  it.each(["--llm", "--dynamic", "--connected", "--allow-target-install"])("rejects fresh execution intent %s", async (flag) => {
    const result = await run([flag, "--findings-out", join(root, "refused.json")]);
    expect(result.code).toBe(2); expect(result.stderr).toContain("execution/discovery flags");
  });
  it.each(["REPLAY_TRIP_CHILD", "REPLAY_TRIP_NETWORK"])("negative control proves %s fails before execution", async (variable) => {
    const result = await run(["--findings-out", join(root, "refused.json")], { [variable]: "1" });
    expect(result.code).not.toBe(0); expect(result.stderr).toContain("REPLAY TRIPWIRE");
  });
});
