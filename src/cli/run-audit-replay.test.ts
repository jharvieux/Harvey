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
const tripwirePreload = `
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
`;

async function run(extra: string[], env: Record<string, string> = {}, assemble = true, assemblyBundle = bundle): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = runGuardCommand({
    command: ["/usr/bin/env", ...Object.entries(env).map(([key, value]) => `${key}=${value}`), process.execPath, "--require", preload, "--import", "tsx", "src/cli/run-audit.ts", target, ...(assemble ? ["--assemble", assemblyBundle] : []), ...extra],
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
  writeFileSync(preload, tripwirePreload);
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

type ScopeMatrixMode = "same" | "expanded" | "reversed" | "new-version" | "two-versions" | "swapped" | "two-reversed" | "partial";

function createScopeMatrixFixture() {
  const caseRoot = mkdtempSync(join(tmpdir(), "harvey-replay-scope-"));
  const caseTarget = join(caseRoot, "source");
  const casePreload = join(caseRoot, "tripwire.cjs");
  const raw = join(caseRoot, "raw.json");
  const caseChildren: Promise<GuardCommandResult>[] = [];
  const caseTeardown = new AbortController();
  const initial = JSON.parse(readFileSync(join(root, "findings.json"), "utf8")) as FindingsDocument;
  mkdirSync(caseTarget);
  writeFileSync(join(caseTarget, "sample.ts"), "export const value = 1;\n");
  writeFileSync(casePreload, tripwirePreload);
  writeFileSync(raw, '{"owningRun":"scope-matrix"}\n');

  async function capture(name: string, mode: ScopeMatrixMode, prior?: string) {
    const passes: AuditEvidenceInput[] = AUDIT_MODULES.map((module) => ({
      scope: { module, workspace: ".", tier: "source", surface: "module", wholeModule: true },
      generatedAt: new Date().toISOString(), producer: { name: module, version: (mode === "new-version" || mode === "swapped") && module === "M7" ? "2" : "1" },
      rawArtifacts: [raw],
      result: { kind: "examined", unitsExamined: 1, scope: "owned files", detail: "Bound source scope",
        findings: [structuredClone(initial.findings.find((finding) => finding.id === `${module}-CLI`)!)],
        ...(module === "M10" ? { dataMap: {} } : {}),
      },
    }));
    if (mode === "expanded" || mode === "reversed" || mode === "two-versions" || mode === "swapped" || mode === "two-reversed") {
      const additional = structuredClone(passes[6]!);
      additional.scope.workspace = "another-workspace";
      if (mode === "two-versions" || mode === "two-reversed") additional.producer.version = "2";
      if (mode === "swapped") additional.producer.version = "1";
      if ("kind" in additional.result && additional.result.kind === "examined") {
        additional.result.findings[0]!.id = "M7-ANOTHER";
        additional.result.findings[0]!.location = "another-workspace/sample.ts:1";
      }
      passes.push(additional);
    }
    if (mode === "reversed" || mode === "two-reversed") passes.reverse();
    if (mode === "partial") passes[7]!.result = {
      kind: "not-assessed", reason: "Native mutation evidence unavailable", provenance: "TRIED",
      falsifier: "Run the native mutation producer", findings: [],
    };
    const retained = join(caseRoot, `${name}-bundle`);
    writeAuditReplayBundle(retained, {
      binding: createAuditReplayBinding(caseTarget, { fixture: "scope-classification" }),
      scopes: passes.map((pass) => pass.scope), passes,
      meta: { ...meta, auditContext: { ...initial.auditContext!, engagementId: name, kind: "client-audit" } },
    });
    const path = join(caseRoot, `${name}.json`), html = join(caseRoot, `${name}.html`), sarif = join(caseRoot, `${name}.sarif`);
    const child = runGuardCommand({
      command: ["/usr/bin/env", process.execPath, "--require", casePreload, "--import", "tsx", "src/cli/run-audit.ts", caseTarget, "--assemble", retained,
        "--findings-out", path, "--html-out", html, "--sarif-out", sarif, ...(prior ? ["--baseline", prior] : [])],
      cwd: repo, bundleDir: caseRoot, outputPrefix: `child-${caseChildren.length}`, timeoutMs: 20_000,
      killGraceMs: 1_000, signal: caseTeardown.signal,
    });
    caseChildren.push(child);
    const receipt = await child;
    expect(receipt.state, JSON.stringify(receipt)).toBe("exited");
    expect(receipt.terminationAcknowledged).toBe(true);
    const stderr = readFileSync(join(caseRoot, receipt.stderr.path), "utf8");
    expect(receipt.exitCode, stderr).toBe(0);
    const document = JSON.parse(readFileSync(path, "utf8")) as FindingsDocument;
    const exported = JSON.parse(readFileSync(sarif, "utf8"));
    expect(exported.runs[0].properties.harveyAuditContext).toEqual(document.auditContext);
    if (prior) {
      expect(exported.runs[0].properties.harveyBaseline).toEqual(document.baseline);
      for (const reason of document.baseline!.comparison!.limitations) expect(readFileSync(html, "utf8")).toContain(reason);
    }
    return { document, path };
  }

  async function close(): Promise<void> {
    caseTeardown.abort();
    const receipts = await Promise.allSettled(caseChildren);
    try {
      expect(receipts.every((receipt) => receipt.status === "fulfilled" && receipt.value.terminationAcknowledged), "Every scope-matrix child must close before its fixture is removed").toBe(true);
    } finally {
      rmSync(caseRoot, { recursive: true, force: true });
    }
  }

  return { capture, close, target: caseTarget };
}

describe("run-audit assembly capability boundary", () => {
  it("keeps identical source and producer receipts comparable in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const prior = await fixture.capture("scope-prior", "same");
      const same = await fixture.capture("scope-same", "same", prior.path);
      expect(same.document.baseline?.comparison?.kind).toBe("same-source");
    } finally { await fixture.close(); }
  });

  it("classifies scope expansion independently of receipt order in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const prior = await fixture.capture("scope-prior", "same");
      const expanded = await fixture.capture("scope-expanded", "expanded", prior.path);
      expect(expanded.document.baseline?.comparison?.kind).toBe("scope-change");
      expect(expanded.document.auditContext?.producerVersions).toEqual(prior.document.auditContext?.producerVersions);
      expect(expanded.document.auditContext!.assessedScope).toHaveLength(prior.document.auditContext!.assessedScope.length + 1);
      expect(expanded.document.baseline?.counts).toMatchObject({ new: 0, resolved: 0 });
      const reversed = await fixture.capture("scope-reversed", "reversed", prior.path);
      expect(JSON.stringify(reversed.document.auditContext?.producerVersions)).toBe(JSON.stringify(expanded.document.auditContext?.producerVersions));
      expect(reversed.document.baseline?.comparison?.kind).toBe("scope-change");
    } finally { await fixture.close(); }
  });

  it("classifies one or two changed producer versions in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const prior = await fixture.capture("scope-prior", "same");
      for (const mode of ["new-version", "two-versions"] as const) {
        const changed = await fixture.capture(`scope-${mode}`, mode, prior.path);
        expect(changed.document.baseline?.comparison?.kind).toBe("tool-change");
        expect(changed.document.auditContext?.producerVersions[JSON.stringify(["M7", "2"])]).toBe("2");
        if (mode === "two-versions") expect(changed.document.auditContext?.producerVersions[JSON.stringify(["M7", "1"])]).toBe("1");
      }
    } finally { await fixture.close(); }
  });

  it("binds producer assignments independently of assignment and receipt order", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const two = await fixture.capture("assignment-prior", "two-versions");
      const swapped = await fixture.capture("assignment-swapped", "swapped", two.path);
      expect(swapped.document.auditContext?.producerVersions).toEqual(two.document.auditContext?.producerVersions);
      expect(swapped.document.auditContext?.assessedScope).toEqual(two.document.auditContext?.assessedScope);
      expect(swapped.document.baseline?.comparison?.kind).toBe("tool-change");
      const reversed = await fixture.capture("assignment-reversed", "two-reversed", two.path);
      expect(reversed.document.baseline?.comparison?.kind).toBe("same-source");
      expect(reversed.document.auditContext?.producerAssignments).toEqual(two.document.auditContext?.producerAssignments);
    } finally { await fixture.close(); }
  });

  it("rejects a baseline without producer assignments in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const two = await fixture.capture("assignment-prior", "two-versions");
      const legacy = structuredClone(two.document);
      delete legacy.auditContext!.producerAssignments;
      const legacyPath = join(two.path, "..", "assignment-unknown.json");
      writeFileSync(legacyPath, JSON.stringify(legacy));
      expect((await fixture.capture("assignment-unknown-current", "two-versions", legacyPath)).document.baseline?.comparison?.kind).toBe("incompatible");
    } finally { await fixture.close(); }
  });

  it("distinguishes partial current scope and unbound prior scope in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const prior = await fixture.capture("scope-prior", "same");
      const partial = await fixture.capture("scope-partial", "partial", prior.path);
      expect(partial.document.baseline?.comparison?.kind).toBe("scope-change");
      expect(partial.document.auditContext?.scopeComplete).toBe(false);
      const unknown = structuredClone(prior.document);
      delete unknown.auditContext;
      const unknownPath = join(prior.path, "..", "scope-unknown.json");
      writeFileSync(unknownPath, JSON.stringify(unknown));
      expect((await fixture.capture("scope-unknown-current", "same", unknownPath)).document.baseline?.comparison?.kind).toBe("incompatible");
    } finally { await fixture.close(); }
  });

  it("binds source changes to an isolated target in every export", async () => {
    const fixture = createScopeMatrixFixture();
    try {
      const prior = await fixture.capture("scope-prior", "same");
      const source = join(fixture.target, "sample.ts");
      writeFileSync(source, `${readFileSync(source, "utf8")}export const changed = true;\n`);
      expect((await fixture.capture("scope-source-change", "same", prior.path)).document.baseline?.comparison?.kind).toBe("source-change");
    } finally { await fixture.close(); }
  });
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
