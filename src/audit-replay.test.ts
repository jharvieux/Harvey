import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_MODULES, type AuditModule } from "./audit-coverage.js";
import { createAuditReplayBinding, replayAuditBundle, writeAuditReplayBundle, type AuditEvidenceInput, type AuditEvidenceScope } from "./audit-replay.js";
import { deliverAuditReplay } from "./audit-replay-delivery.js";
import { runAudit, type Examined, type ModuleRunner } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import type { Finding, FindingsDocument, ReportMeta, TestQuality } from "./findings.js";

const scratch: string[] = [];
afterEach(() => { for (const dir of scratch.splice(0)) rmSync(dir, { recursive: true, force: true }); vi.restoreAllMocks(); });
const meta: ReportMeta = { client: "Replay specimen", subtitle: "ten module evidence", date: "2026-09-24", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 5, tenantIsolation: "PostgREST reconstruction only", authModel: "two local identities", headline: "Measured scopes", scope: "fixture", methodology: "retained passes", outOfScope: "application routes" };
const finding = (id: string, module: AuditModule): Finding => ({ id, title: id, severity: "Medium", confidence: "Confirmed", category: "Maintainability", taxonomy: `${module} — replay plant`, location: "src/a.ts:1", status: "Open", evidence: id, impact: "Measured defect", fix: "Repair the defect", value: 3, ease: 3, safety: 3 });
const quality = (mutationScore: number): TestQuality => ({ mutationScore, mutationScoreBasedOnCoveredCode: 58.6, coveredScope: ["apps/main/src/**/*.ts"], wholeRepo: false, scopeNote: "724 configured files; 709 reported; 15 missing. Falsifier: report all configured files.", rows: [], lineCoverage: { status: "partial", reason: "No coverage-summary.json produced" }, survivors: [], survivorTotal: 12 });

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "harvey-replay-test-")); scratch.push(root);
  const target = join(root, "target"); mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "export const measured = 1;\n");
  const raw = join(root, "owning-run.json"); writeFileSync(raw, JSON.stringify({ producer: "fixture", result: "original bytes" }));
  const sbom = join(root, "sbom.json"); writeFileSync(sbom, JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] }));
  const now = Date.now();
  const scopes: AuditEvidenceScope[] = AUDIT_MODULES.map((module) => ({ module, workspace: ".", tier: "source", surface: "module", wholeModule: true }));
  const passes: AuditEvidenceInput[] = scopes.map((scope) => ({ scope, generatedAt: new Date(now - 2000).toISOString(), producer: { name: scope.module, version: "test-v1" }, result: { kind: "examined", unitsExamined: 4, scope: "source files", detail: `original ${scope.module} command`, findings: [finding(`${scope.module}-BASE`, scope.module)], ...(scope.module === "M10" ? { dataMap: {} } : {}) }, rawArtifacts: [raw] }));
  const bundle = join(root, "bundle");
  const binding = createAuditReplayBinding(target, { consent: { model: false, network: false }, mutate: ["src/**/*.ts"] });
  const write = () => writeAuditReplayBundle(bundle, { binding, scopes, passes, sbomPath: sbom, meta, now });
  return { root, target, raw, bundle, binding, scopes, passes, now, write };
}

describe("bound audit replay", () => {
  it("conserves fresh producer findings and explicit scopes without invoking any runner", () => {
    const f = fixture();
    const env = { connected: false, dynamic: false, llm: false };
    const fresh = runAudit(f.passes.map((pass): ModuleRunner => ({ module: pass.scope.module, producers: [], typed: true, run: () => pass.result })), { targetDir: f.target, env, exists: () => true, exec: () => { throw new Error("fixture has no external capability"); } });
    f.write();
    const spies = AUDIT_RUNNERS.map((runner) => vi.spyOn(runner, "run").mockImplementation(() => { throw new Error("SCANNER TRIPWIRE"); }));
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(() => { throw new Error("NETWORK/MODEL TRIPWIRE"); });
    const replay = replayAuditBundle(f.bundle, f.target, { now: f.now });
    expect(replay.result.findings).toEqual(fresh.findings);
    expect(replay.result.recorded.map(({ module, status, instance }) => ({ module, status, instance }))).toEqual(fresh.recorded.map(({ module, status, instance }) => ({ module, status, instance })));
    expect(replay.evidence.current.map((row) => row.scope)).toEqual(f.scopes);
    expect(replay.result.recorded.every((row) => row.detail?.includes("examined 4 source files"))).toBe(true);
    expect(spies.every((spy) => spy.mock.calls.length === 0)).toBe(true); expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["target", "configuration", "raw", "missing", "manifest", "future", "stale"])("rejects %s evidence before delivery", (kind) => {
    const f = fixture(); f.write();
    if (kind === "target") writeFileSync(join(f.target, "source.ts"), "changed");
    const manifest = JSON.parse(readFileSync(join(f.bundle, "audit-replay.json"), "utf8"));
    if (kind === "raw" || kind === "missing") {
      const receipt = JSON.parse(readFileSync(join(f.bundle, manifest.receipts[0].path), "utf8"));
      const raw = join(f.bundle, receipt.rawArtifacts[0].path);
      if (kind === "raw") writeFileSync(raw, "tampered"); else rmSync(raw);
    }
    if (kind === "manifest") { manifest.scopes.pop(); writeFileSync(join(f.bundle, "audit-replay.json"), JSON.stringify(manifest)); }
    const now = kind === "future" ? f.now - 60 * 60_000 : kind === "stale" ? f.now + 31 * 24 * 60 * 60_000 : f.now;
    expect(() => replayAuditBundle(f.bundle, f.target, { now, ...(kind === "configuration" ? { effectiveConfig: { mutate: ["unrelated.ts"] } } : {}) })).toThrow(/mismatch|Tampered|tampered|Missing|Stale/);
  });

  it("keeps missing modules and application routes partial after a PostgREST-only pass", () => {
    const f = fixture();
    f.scopes[1] = { module: "M2", workspace: ".", tier: "dynamic", surface: "postgrest", wholeModule: false };
    f.passes[1]!.scope = f.scopes[1]!;
    f.scopes.push({ module: "M2", workspace: ".", tier: "dynamic", surface: "application-routes", wholeModule: false });
    f.passes.splice(4, 1); f.write();
    const replay = replayAuditBundle(f.bundle, f.target, { now: f.now });
    expect(replay.result.recorded.find((row) => row.module === "M2")).toMatchObject({ status: "partial", reason: expect.stringContaining("application-routes: no retained evidence") });
    expect(replay.result.recorded.find((row) => row.module === "M5")).toMatchObject({ status: "requires-live-run" });
    expect(replay.evidence.missing.map((scope) => scope.module)).toEqual(expect.arrayContaining(["M2", "M5"]));
  });

  it("reconciles M3, current M8 scores, credential history and 403 detail through JSON to HTML", async () => {
    const f = fixture();
    const m3 = { module: "M3" as const, workspace: ".", tier: "trend", surface: "history-window", wholeModule: false };
    f.scopes.push(m3);
    f.passes.push({ ...f.passes[2]!, scope: m3, result: { kind: "examined", unitsExamined: 26, scope: "degraded files", detail: "52-day trend window", findings: [finding("M3-TREND-00", "M3")] } });
    f.passes[6]!.result = { ...(f.passes[6]!.result as Examined), reason: "STALE_NO_CREDENTIALS" };
    f.passes.push({ ...f.passes[6]!, generatedAt: new Date(f.now - 1000).toISOString(), result: { kind: "examined", unitsExamined: 2, scope: "connected projects", detail: "Credentials supplied; authenticated advisor call attempted", reason: "HTTP 403 project abc permission denied [TRIED; raw receipt advisor.stderr; falsifier: rerun advisors with project.read permission]", findings: [finding("M7-CONNECTED-FAILURE", "M7")] } });
    f.passes[7]!.result = { ...(f.passes[7]!.result as Examined), testQuality: quality(29.4), reason: "STALE_MUTATION_FAILED" };
    f.passes.push({ ...f.passes[7]!, generatedAt: new Date(f.now - 1000).toISOString(), result: { kind: "examined", unitsExamined: 54022, scope: "valid mutants", detail: "Current mutation receipt", reason: "15 configured files missing; line coverage unavailable [MEASURED; falsifier: rerun complete configured scope]", findings: [finding("M8-CURRENT", "M8")], testQuality: quality(39.7) } });
    f.write();
    const json = join(f.root, "findings.json"), html = join(f.root, "report.html"), ledger = join(f.root, "conservation.json");
    await deliverAuditReplay({ target: f.target, bundle: f.bundle, findingsOut: json, htmlOut: html, conservationOut: ledger });
    const doc = JSON.parse(readFileSync(json, "utf8")) as FindingsDocument & { auditEvidence: { history: unknown[] } };
    const rendered = readFileSync(html, "utf8");
    expect(doc.findings.filter((row) => row.id === "M3-TREND-00")).toHaveLength(1);
    expect(rendered).toContain("M3-TREND-00");
    expect(doc.testQuality?.mutationScore).toBe(39.7);
    expect(rendered).toContain("39.7"); expect(rendered).toContain("58.6"); expect(rendered).toContain("724 configured files; 709 reported; 15 missing");
    expect(rendered).not.toContain("STALE_NO_CREDENTIALS"); expect(rendered).not.toContain("STALE_MUTATION_FAILED");
    expect(rendered).toContain("HTTP 403 project abc permission denied"); expect(rendered).toContain("rerun advisors with project.read permission");
    expect(doc.auditEvidence.history).toHaveLength(2);
    const conservation = JSON.parse(readFileSync(ledger, "utf8"));
    expect(conservation.ok).toBe(true); expect(conservation.produced).toBe(11); expect(conservation.delivered).toBe(11);
    expect(conservation.findingOwners.find((row: { id: string }) => row.id === "M3-TREND-00").rawArtifacts.length).toBeGreaterThan(0);
  });

  it("retains recorded M3 trend evidence when the base hotspot probe also succeeds", () => {
    const planted = finding("M3-TREND-00", "M3");
    const result = AUDIT_RUNNERS.find((runner) => runner.module === "M3")!.run({ targetDir: "/fixture", env: { connected: false, dynamic: false, llm: false }, captureDir: "/capture", artifactsDir: "/passes", exists: () => true, exec: () => ({ ok: true, output: "M3 hotspot table — /fixture (4 rows, worst first)" }), readArtifact: (path) => path.includes(".pass.") ? { module: "M3", target: "/fixture", pass: "trend", generatedAt: new Date().toISOString(), findings: [planted] } : { findings: [finding("M3-BASE", "M3")], topK: [] } });
    expect((result as Examined).unitsExamined).toBe(4);
    expect((result as Examined).findings.map((row) => row.id)).toContain("M3-BASE");
    expect((result as Examined).findings.map((row) => row.id)).toContain("M3-TREND-00");
  });
});
