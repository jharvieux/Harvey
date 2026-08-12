import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readRecursiveSafe, statSafe } from "./fs-walk.js";

const root = process.cwd();
const path = join(root, ".github", "workflows", "corpus-drift.yml");
const workflow = readFileSync(path, "utf8");
const mechanical = readFileSync(join(root, "src", "scan", "mechanical.ts"), "utf8");

describe("#1864 corpus phase-cache workflow contract", () => {
  it("keeps the required context reporting on every PR and failing on any shard result", () => {
    expect(workflow).toMatch(/^\s{2}pull_request:\s*$/m);
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toMatch(/drift:\n\s+name: clone\s+pinned\s+commits\s+\+\s+score\s+baselines\n\s+needs: shard\n\s+if: always\(\)/);
    expect(workflow).toContain(`if [ "$result" != "success" ]`);
  });

  it("restores and saves the content-addressed directory without making a cache miss fatal or clean", () => {
    expect(workflow).toContain("uses: actions/cache/restore@v4");
    expect(workflow).toContain("uses: actions/cache/save@v4");
    expect(workflow.match(/path: \.harvey-corpus-phase-cache/g)).toHaveLength(2);
    expect(workflow).toContain("HARVEY_CORPUS_PHASE_CACHE_DIR: .harvey-corpus-phase-cache");
    expect(workflow).not.toMatch(/Restore content-addressed corpus phase results[\s\S]{0,300}continue-on-error/);
    expect(workflow.match(/corpus-phase-v3-/g)).toHaveLength(4);
    expect(workflow).toContain("Validate corpus phase-cache transport provenance");
    expect(workflow).toContain("Record corpus phase-cache transport provenance");
    expect(workflow).toContain("--matched-key '${{ steps.phase-cache.outputs.cache-matched-key }}'");
  });

  it("seeds the default-branch cache after merge while preserving unconditional PR reporting", () => {
    expect(workflow).toMatch(/push:\n\s+branches: \[main\]/);
    expect(workflow).toContain("--default-ref 'refs/heads/${{ github.event.repository.default_branch }}'");
    expect(workflow).toContain("--event '${{ github.event_name }}'");
    expect(workflow).toContain("--ref '${{ github.ref }}'");
  });

  it("refreshes registry bytes on attempt one and reuses the restored snapshot on retries", () => {
    expect(workflow).toContain("github.run_attempt > 1 && 1 || github.run_attempt");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: ${{ github.run_attempt == 1 && 'refresh' || (steps.phase-cache.outputs.cache-hit == 'true' && 'reuse' || 'unavailable') }}");
  });

  it("forces scheduled and dispatch runs cold so cache equivalence is re-earned", () => {
    expect(workflow).toContain('if [ "${{ github.event_name }}" = "schedule" ] || [ "${{ github.event_name }}" = "workflow_dispatch" ]');
    expect(workflow).toContain("cold_flag=(--force-cold-cache)");
    expect(workflow.match(/"\$\{cold_flag\[@\]\}"/g)).toHaveLength(2);
    expect(mechanical).toContain("assertMechanicalCacheVerification(phases, opts.phaseCache)");
  });

  it("declares test-only source edits unreachable while unknown production source remains fail-open", () => {
    const testCase = workflow.indexOf("src/*.test.ts) ;;");
    const failOpen = workflow.indexOf("*) relevant=true; manifest_only=false ;;", testCase);
    expect(testCase).toBeGreaterThan(0);
    expect(failOpen).toBeGreaterThan(testCase);
    const productionFiles = readRecursiveSafe(join(root, "src"))
      .filter((rel) => rel.endsWith(".ts") && !rel.endsWith(".test.ts") && statSafe(join(root, "src", rel))?.isFile());
    const importsTest = productionFiles.filter((rel) => /from\s+["'][^"']+\.test(?:\.js)?["']/.test(readFileSync(join(root, "src", rel), "utf8")));
    expect(importsTest, "a production module importing a test invalidates the workflow's test-only exclusion").toEqual([]);
  });
});
