import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { bundleAuditEvidenceRecipe, importLegacyAuditEvidence } from "./audit-evidence-import.js";
import { createAuditReplayBinding, replayAuditBundle, writeAuditReplayBundle, type AuditEvidenceInput } from "./audit-replay.js";
import { deliverAuditReplay } from "./audit-replay-delivery.js";
import { probeExec } from "./probe-exec.js";
import type { FindingsDocument } from "./findings.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function inputs() {
  const root = mkdtempSync(join(tmpdir(), "harvey-historical-test-")); roots.push(root);
  const revision = "a".repeat(40), engine = "b".repeat(40), tree = "c".repeat(40);
  const accepted = new Date(Date.now() - 1000).toISOString(), reconciled = new Date(Date.now() - 2000).toISOString();
  const document: FindingsDocument = {
    meta: { client: "Historical fixture", subtitle: "legacy", date: accepted.slice(0, 10), commit: revision, auditor: "Harvey", confidential: false, overallHealth: 5, tenantIsolation: "Holds", authModel: "fixture", headline: "Retained evidence", scope: "two workspaces", methodology: "legacy run", outOfScope: "unknown" },
    findings: ["apps/one", "apps/two"].map((workspace) => ({ id: `M4-CLONE@${workspace}`, title: "Duplication", severity: "Medium", confidence: "Confirmed", category: "Maintainability", taxonomy: "M4 — duplication", location: `${workspace}/file.ts:1`, status: "Open", evidence: "measured clone", impact: "drift", fix: "extract", value: 2, ease: 2, safety: 2 })),
    coverage: [
      { module: "M4", name: "Duplication", instance: "apps/one", status: "ran", detail: "10 compared lines" },
      { module: "M4", name: "Duplication", instance: "apps/two", status: "ran", detail: "20 compared lines" },
      { module: "M7", name: "Performance", status: "partial", detail: "source pass", reason: "OLD_NO_CREDENTIALS" },
    ],
  };
  const files: Record<string, unknown> = {
    document, snapshot: { captured_at: reconciled, target: { path: "/historical/original", head: revision, tree }, engine: { head: engine } },
    validation: { validated_at: accepted, target: { expected_head: revision, actual_head: revision, expected_tree: tree, actual_tree: tree }, engine: { expected_head: engine, actual_head: engine }, exports: { finding_count: 2 } },
    reconciliation: { generated_at: reconciled, target_commit: revision, reconciliations: [{ module: "M7", final_status: "partial", observed: ["Authenticated connected advisors ran"], superseded_base_probe_text: "OLD_NO_CREDENTIALS", unassessed: ["additional authenticated routes"] }] },
    sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [] },
  };
  for (const [name, body] of Object.entries(files)) writeFileSync(join(root, `${name}.json`), JSON.stringify(body));
  return { root, revision, engine, accepted, reconciled, options: { document: join(root, "document.json"), snapshot: join(root, "snapshot.json"), validation: join(root, "validation.json"), reconciliation: join(root, "reconciliation.json"), sbom: join(root, "sbom.json"), out: join(root, "bundle") } };
}

it("keeps original snapshot/engine/timestamps, per-workspace rows and explicit legacy partials", async () => {
  const f = inputs();
  const imported = importLegacyAuditEvidence(f.options);
  const replay = await replayAuditBundle(f.options.out, imported.target);
  expect(replay.result.findings.map((finding) => finding.id)).toEqual(["M4-CLONE@apps/one", "M4-CLONE@apps/two"]);
  expect(replay.result.recorded.filter((row) => row.module === "M4").map((row) => row.instance)).toEqual(["apps/one", "apps/two"]);
  expect(replay.result.recorded.every((row) => row.status !== "ran")).toBe(true);
  expect(replay.evidence.current.every((receipt) => receipt.historicalOrigin?.revision === f.revision && receipt.historicalOrigin.engine === f.engine)).toBe(true);
  expect(replay.evidence.current.find((receipt) => receipt.scope.module === "M7")?.generatedAt).toBe(f.reconciled);
  expect(replay.evidence.history[0]?.receipt.generatedAt).toBe(f.accepted);
  const html = join(f.root, "report.html");
  await deliverAuditReplay({ target: imported.target, bundle: f.options.out, htmlOut: html });
  const rendered = readFileSync(html, "utf8");
  expect(rendered).not.toContain("OLD_NO_CREDENTIALS");
  expect(rendered).toContain("additional authenticated routes");
  expect(rendered).toContain("not a new run or current target state");
  expect(rendered).toContain(f.revision); expect(rendered).toContain(f.engine);
});

it("refuses a historical acceptance receipt for another revision", () => {
  const f = inputs();
  const validation = JSON.parse(readFileSync(f.options.validation, "utf8")); validation.target.actual_head = "d".repeat(40);
  writeFileSync(f.options.validation, JSON.stringify(validation));
  expect(() => importLegacyAuditEvidence(f.options)).toThrow(/identities disagree/);
});

it.each(["valid", "valid-without-source", "unbound", "tree", "configuration", "raw"])("recipe preserves original execution provenance (%s)", async (kind) => {
  const f = inputs();
  const target = join(f.root, "source"); mkdirSync(target);
  const source = join(target, "source.ts"); writeFileSync(source, "original source");
  const raw = join(f.root, "producer.json"); writeFileSync(raw, "original output");
  const effectiveConfig = { mutate: ["src/**/*.ts"] };
  const binding = createAuditReplayBinding(target, effectiveConfig);
  const pass: AuditEvidenceInput = { scope: { module: "M3", workspace: ".", tier: "source", surface: "ranked-files", wholeModule: false }, generatedAt: new Date().toISOString(), producer: { name: "original", version: "1" }, rawArtifacts: [raw], result: { kind: "examined", unitsExamined: 4, scope: "ranked files", detail: "Original command", findings: [] } };
  if (kind === "valid-without-source") pass.rawArtifacts = [{ path: raw, sha256: createHash("sha256").update(readFileSync(raw)).digest("hex") }];
  const original = join(f.root, "original");
  writeAuditReplayBundle(original, { binding, scopes: [pass.scope], passes: [pass] });
  const originalReplay = await replayAuditBundle(original, target);
  if (kind === "valid-without-source") expect(originalReplay.evidence.current[0]!.rawArtifacts[0]!.sourcePath).toBeUndefined();
  const recipe = { target, expectedRevision: binding.target.revision, effectiveConfig, scopes: [pass.scope], passes: [kind === "unbound" ? { ...pass, resultFile: raw } : { bundle: original, receiptId: originalReplay.evidence.current[0]!.id }] };
  if (kind === "tree") writeFileSync(source, "changed source at the same revision");
  if (kind === "configuration") recipe.effectiveConfig = { mutate: ["different/**/*.ts"] };
  if (kind === "raw") writeFileSync(join(original, originalReplay.evidence.current[0]!.rawArtifacts[0]!.path), "tampered output");
  const path = join(f.root, "recipe.json"); writeFileSync(path, JSON.stringify(recipe));
  if (!kind.startsWith("valid")) await expect(bundleAuditEvidenceRecipe(path, join(f.root, "combined"))).rejects.toThrow(/original bound|mismatch|Tampered/);
  else {
    const combined = join(f.root, "combined"); await bundleAuditEvidenceRecipe(path, combined);
    const replay = await replayAuditBundle(combined, target);
    expect(replay.evidence.current[0]!.id).toBe(originalReplay.evidence.current[0]!.id);
    expect(replay.evidence.current[0]!.generatedAt).toBe(pass.generatedAt);
    expect(replay.evidence.binding.target).toEqual(binding.target);
  }
});


it("repackages command receipts twice without losing distinct identical-byte source identities", async () => {
  const f = inputs();
  const target = join(f.root, "source"); mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "export const value = 1;");
  const reports = [join(f.root, "first.json"), join(f.root, "second.json")];
  const executions = await Promise.all(reports.map((report) => probeExec(process.execPath, ["-e", "require('node:fs').writeFileSync(process.argv[1], '{}')", report], { receipt: { artifacts: [{ role: "report", path: report }] } })));
  expect(executions.every((execution) => execution.ok)).toBe(true);
  const result = { kind: "examined" as const, unitsExamined: 2, scope: "files", detail: "Two actual child commands", findings: [] };
  const scope = { module: "M8" as const, workspace: ".", tier: "orchestrated", surface: "module", wholeModule: true };
  const owner = join(f.root, "owner.json");
  writeFileSync(owner, JSON.stringify({ module: "M8", reports: [result], commandExecutionReceipts: executions.map((execution) => execution.receipt) }));
  const binding = createAuditReplayBinding(target, {});
  let bundle = join(f.root, "commands");
  writeAuditReplayBundle(bundle, { binding, scopes: [scope], passes: [{ scope, generatedAt: new Date().toISOString(), producer: { name: "audit-runner:M8", version: "fixture" }, result, rawArtifacts: [owner, ...reports] }] });
  const original = (await replayAuditBundle(bundle, target)).evidence.current[0]!;
  for (let round = 0; round < 2; round++) {
    const recipe = join(f.root, `command-recipe-${round}.json`);
    writeFileSync(recipe, JSON.stringify({ target, expectedRevision: binding.target.revision, effectiveConfig: {}, scopes: [scope], passes: [{ bundle, receiptId: original.id }] }));
    const next = join(f.root, `repacked-${round}`);
    await bundleAuditEvidenceRecipe(recipe, next);
    const replay = await replayAuditBundle(next, target);
    expect(replay.evidence.current[0]).toEqual(original);
    expect(replay.evidence.current[0]!.rawArtifacts.map((raw) => raw.sourcePath)).toEqual([owner, ...reports]);
    bundle = next;
  }
});

it("retains nested historical execution receipts without claiming current execution", async () => {
  const f = inputs();
  const execution = await probeExec(process.execPath, ["-e", "process.exit(0)"]);
  expect(execution.ok).toBe(true);
  const mutation = join(f.root, "mutation.json");
  writeFileSync(mutation, JSON.stringify({ summary: { overall: { mutationScore: 25, mutationScoreBasedOnCoveredCode: 50 }, coveredScope: ["a.ts"] }, reportRows: [], scope: { verified: true, scoped: true, note: "Historical bounded fixture" }, executionReceipt: execution.receipt }));
  const imported = importLegacyAuditEvidence({ ...f.options, mutation });
  const replay = await replayAuditBundle(f.options.out, imported.target);
  const receipt = replay.evidence.current.find((row) => row.scope.module === "M8" && row.producer.name === "mutation-scan");
  expect(receipt?.legacyReason).toContain("Historical acceptance");
  expect(replay.result.recorded.filter((row) => row.module === "M8").every((row) => row.status !== "ran")).toBe(true);
  const html = join(f.root, "historical-mutation.html");
  await deliverAuditReplay({ target: imported.target, bundle: f.options.out, htmlOut: html });
  expect(readFileSync(html, "utf8")).toContain("not a new run or current target state");
});
