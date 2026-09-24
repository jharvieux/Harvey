import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildDryRunFamily, DETERMINISTIC_DRY_RUN_FILES, publishDryRunFamily } from "./dry-run-artifacts.js";
import { classifyDryRunChanges, compareDryRunFamilies, discoverDryRunDependencies } from "./dry-run-drift.js";
import type { Finding } from "./findings.js";

const ROOT = resolve(import.meta.dirname, "..");
const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("dry-run PR relevance", () => {
  it("discovers the real entrypoint's transitive imports, including the historically omitted producers", () => {
    const closure = discoverDryRunDependencies(ROOT);
    expect(closure.unresolved).toEqual([]);
    for (const path of ["tools/pii-classify.mjs", "src/definer-classifier.ts", "src/grant-classifier.ts", "src/migration-sql-parse.ts", "src/cwe-map.ts", "src/dry-run-artifacts.ts"]) {
      expect(closure.files.has(path), path).toBe(true);
      expect(classifyDryRunChanges(ROOT, [path])).toMatchObject({ relevant: true, reason: "producer-dependency" });
    }
  });

  it("selects literal executable/data inputs and fails closed on unknown paths", () => {
    expect(classifyDryRunChanges(ROOT, ["src/scan/rules/semgrep/auth.yml"])).toMatchObject({ relevant: true, reason: "producer-data" });
    expect(classifyDryRunChanges(ROOT, ["new-producer-shape.bin"])).toMatchObject({ relevant: true, reason: "unknown" });
  });

  it("selects regeneration when the discovered producer graph has an unresolved edge", () => {
    const repo = mkdtempSync(join(tmpdir(), "dry-run-unresolved-"));
    temporary.push(repo);
    mkdirSync(join(repo, "src/cli"), { recursive: true });
    writeFileSync(join(repo, "src/cli/dry-run.ts"), 'import "../missing-producer.js";\n');
    const result = classifyDryRunChanges(repo, ["docs/runbooks/example.md"]);
    expect(result).toMatchObject({ relevant: true, reason: "unknown" });
    expect(result.unresolved).toEqual(["src/cli/dry-run.ts -> ../missing-producer.js"]);
  });

  it("preserves a proved unrelated documentation no-op", () => {
    expect(classifyDryRunChanges(ROOT, ["docs/runbooks/example.md"])).toMatchObject({ relevant: false, reason: "proved-unrelated-docs" });
  });
});

function family(dir: string, id = "F-1"): void {
  const findings: Finding[] = [{ id, title: "finding", severity: "Low", confidence: "Confirmed", category: "test", taxonomy: "M1-TEST", location: "a.ts:1", evidence: "e", status: "Open", impact: "impact", fix: "f", value: 3, ease: 3, safety: 3 }];
  publishDryRunFamily(dir, buildDryRunFamily(findings, { public: ["email"] }, { target: "targets/calibration", targetTree: "a".repeat(40) }), [{ phase: "test", ms: Math.random() }]);
}

describe("complete deterministic dry-run family comparison", () => {
  it("derives membership from the owning contract and excludes timing observations", () => {
    const left = mkdtempSync(join(tmpdir(), "dry-run-left-"));
    const right = mkdtempSync(join(tmpdir(), "dry-run-right-"));
    temporary.push(left, right);
    family(left); family(right);
    const result = compareDryRunFamilies(left, right);
    expect(result.ok).toBe(true);
    expect(result.members).toBe(DETERMINISTIC_DRY_RUN_FILES);
    expect(result.members).not.toContain("timing.json");
    expect(readFileSync(join(left, "timing.json"), "utf8")).not.toBe(readFileSync(join(right, "timing.json"), "utf8"));
  });

  it("fails on derived-only drift even when raw findings and PII are unchanged", () => {
    const committed = mkdtempSync(join(tmpdir(), "dry-run-committed-"));
    const fresh = mkdtempSync(join(tmpdir(), "dry-run-fresh-"));
    temporary.push(committed, fresh);
    family(committed); family(fresh);
    const reportPath = join(fresh, "findings-report.json");
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { findings: unknown[] };
    report.findings = [];
    writeFileSync(reportPath, JSON.stringify(report));
    const result = compareDryRunFamilies(committed, fresh);
    expect(result.ok).toBe(false);
    expect(result.differences.join("\n")).toContain("fresh family violates its semantic/provenance contract");
    expect(result.differences).toContain("findings-report.json differs");
  });
});
