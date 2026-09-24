import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { importLegacyAuditEvidence } from "./audit-evidence-import.js";
import { replayAuditBundle } from "./audit-replay.js";
import { deliverAuditReplay } from "./audit-replay-delivery.js";
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
  const replay = replayAuditBundle(f.options.out, imported.target);
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
