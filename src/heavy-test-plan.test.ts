import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";
import { buildHeavyPlan, loadHeavyRegistry, selectHeavyWorkloads, shardSelectedWorkloads } from "./heavy-test-plan.mjs";

const registry = loadHeavyRegistry();
const allIds = registry.workloads.map((workload) => workload.id);

describe("heavy PR impact planner", () => {
  it("uses the same registry as Vitest's heavy exclusion — no second file list can drift", () => {
    expect(registry.workloads.map((workload) => workload.testFile)).toEqual(HEAVY_CLI_TESTS);
    expect(new Set(HEAVY_CLI_TESTS).size).toBe(HEAVY_CLI_TESTS.length);
  });

  it("scopes a mutation-only change to its CLI, cross-process cache seam, and orchestrator consumer", () => {
    expect(selectHeavyWorkloads(registry, ["src/mutation-scan.ts"])).toMatchObject({
      mode: "scoped",
      selected: ["run-audit", "mutation-scan", "corpus-scanner-cross-process"],
      unmatched: [],
    });
  });

  it("scopes independent module-local changes to their owned workloads", () => {
    expect(selectHeavyWorkloads(registry, ["src/lighthouse.ts"]).selected).toEqual(["lighthouse-scan"]);
    expect(selectHeavyWorkloads(registry, ["src/quality-scan.ts"]).selected).toEqual([
      "run-audit",
      "quick-scan",
      "quality-scan",
      "corpus-scanner-cross-process",
    ]);
    expect(selectHeavyWorkloads(registry, ["src/audit-report.ts"]).selected).toEqual(["run-audit"]);
    expect(selectHeavyWorkloads(registry, ["src/health-scorecard.ts"]).selected).toEqual(["run-audit", "quick-scan"]);
    expect(selectHeavyWorkloads(registry, ["src/fix/schedule.ts"]).selected).toEqual([
      "fix-calibration-acceptance",
      "fix-detector-rerun",
      "fix-execute",
    ]);
  });

  it("includes every child-process consumer of a shared corpus scanner contract", () => {
    expect(selectHeavyWorkloads(registry, ["src/corpus-scanner-scope.ts"]).selected).toEqual([
      "run-audit",
      "mutation-scan",
      "quality-scan",
      "corpus-scanner-cross-process",
    ]);
  });

  it("takes the union for a mixed but fully-owned PR", () => {
    const selection = selectHeavyWorkloads(registry, ["src/lighthouse.ts", "src/mutation-scan.ts"]);
    expect(selection.mode).toBe("scoped");
    expect(selection.selected).toEqual(["run-audit", "mutation-scan", "lighthouse-scan", "corpus-scanner-cross-process"]);
  });

  it("runs mapped owners and reports unmapped paths without upgrading the PR to full", () => {
    const selection = selectHeavyWorkloads(registry, ["src/lighthouse.ts", "src/new-shared-runtime.ts"]);
    expect(selection.mode).toBe("scoped");
    expect(selection.selected).toEqual(["lighthouse-scan"]);
    expect(selection.unmatched).toEqual(["src/new-shared-runtime.ts"]);
    expect(selection.reasons.join("\n")).toContain("full post-merge run remains the backstop");
  });

  it("skips empty, workflow-only, docs-only, planner-only, and otherwise unmapped PRs", () => {
    for (const paths of [
      [],
      [".github/workflows/conservation.yml"],
      [".github/workflows/ci.yml"],
      ["docs/design/heavy-routing.md"],
      ["src/heavy-test-plan.mjs"],
      ["src/unmapped-local-helper.ts"],
    ]) {
      expect(selectHeavyWorkloads(registry, paths)).toMatchObject({ mode: "skipped", selected: [] });
    }
    expect(buildHeavyPlan(registry, [".github/workflows/conservation.yml"])).toMatchObject({
      mode: "skipped",
      selected: [],
      matrix: { include: [] },
    });
  });

  it("runs ALL workloads when a PR changes a genuinely shared heavy runtime input", () => {
    expect(selectHeavyWorkloads(registry, ["package.json"])).toMatchObject({ mode: "full", selected: allIds });
    expect(selectHeavyWorkloads(registry, ["src/cli/sync-stdio.ts"])).toMatchObject({ mode: "full", selected: allIds });
  });

  it("runs ALL workloads on every non-PR event", () => {
    for (const reason of ["push", "merge_group", "schedule", "workflow_dispatch"]) {
      expect(selectHeavyWorkloads(registry, ["src/lighthouse.ts"], { forceFull: true, reason })).toMatchObject({
        mode: "full",
        selected: allIds,
        reasons: [reason],
      });
    }
  });

  it("partitions only the selected population, with no drop, duplicate, or empty runner", () => {
    const selected = ["mutation-scan", "quality-scan", "lighthouse-scan", "corpus-scanner-cross-process"];
    const matrix = shardSelectedWorkloads(registry, selected, 3);
    const flattened = matrix.include.flatMap((group) => group.workloadIds);
    expect([...flattened].sort()).toEqual([...selected].sort());
    expect(new Set(flattened).size).toBe(selected.length);
    expect(matrix.include).toHaveLength(3);
    for (const group of matrix.include) {
      expect(group.files.length).toBeGreaterThan(0);
      expect(group.files).toHaveLength(group.workloadIds.length);
      expect(group.total).toBe(3);
    }
    expect(matrix.include.map((group) => group.gates)).toEqual([
      ["calibration"],
      ["source-recall"],
      ["m2-coverage", "shared-source-match"],
    ]);
  });

  it("uses one runner for one selected workload and refuses an empty matrix", () => {
    expect(shardSelectedWorkloads(registry, ["lighthouse-scan"], 3).include).toEqual([
      {
        shard: 1,
        total: 1,
        files: ["src/cli/lighthouse-scan.test.ts"],
        workloadIds: ["lighthouse-scan"],
        gates: ["calibration", "source-recall", "m2-coverage", "shared-source-match"],
      },
    ]);
    expect(() => shardSelectedWorkloads(registry, [], 3)).toThrow(/empty heavy-test matrix/);
  });

  it("uses two runners for a scoped multi-workload plan instead of paying for the full three-runner setup", () => {
    const plan = buildHeavyPlan(registry, ["src/mutation-scan.ts"], { maxShards: 3 });
    expect(plan.mode).toBe("scoped");
    expect(plan.matrix.include).toHaveLength(2);
    expect(plan.matrix.include.flatMap((group) => group.workloadIds).sort()).toEqual([
      "corpus-scanner-cross-process",
      "mutation-scan",
      "run-audit",
    ]);
  });

  it("keeps run-audit alone in a three-runner full plan", () => {
    const plan = buildHeavyPlan(registry, ["package.json"], { maxShards: 3 });
    expect(plan.mode).toBe("full");
    expect(plan.matrix.include.find((group) => group.workloadIds.includes("run-audit"))?.workloadIds).toEqual(["run-audit"]);
  });

  it("produces a stable digest for the same exact plan", () => {
    const first = buildHeavyPlan(registry, ["src/lighthouse.ts"]);
    const second = buildHeavyPlan(registry, ["src/lighthouse.ts"]);
    expect(first.digest).toBe(second.digest);
  });

  it("the shipped CLI reads git's changed paths and writes the scoped matrix to GITHUB_OUTPUT", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-heavy-plan-cli-"));
    try {
      const git = join(dir, "git");
      const output = join(dir, "github-output");
      writeFileSync(git, "#!/bin/sh\nprintf '%s\\n' src/lighthouse.ts\n");
      chmodSync(git, 0o755);
      const result = spawnSync(
        process.execPath,
        ["src/heavy-test-plan.mjs", "--event", "pull_request", "--base", "base", "--head", "HEAD", "--max-shards", "3", "--github-output", output],
        { cwd: process.cwd(), encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` } },
      );
      expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
      const values = new Map(readFileSync(output, "utf8").trim().split("\n").map((line) => line.split("=", 2) as [string, string]));
      expect(values.get("mode")).toBe("scoped");
      expect(values.get("selected")).toBe("lighthouse-scan");
      expect(JSON.parse(values.get("matrix") ?? "null")).toMatchObject({
        include: [{ shard: 1, total: 1, workloadIds: ["lighthouse-scan"] }],
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the shipped CLI fails the routing job when git cannot provide a trustworthy diff", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-heavy-plan-diff-failure-"));
    try {
      const git = join(dir, "git");
      const output = join(dir, "github-output");
      writeFileSync(git, "#!/bin/sh\nprintf '%s\\n' 'fatal: missing base' >&2\nexit 42\n");
      chmodSync(git, 0o755);
      const result = spawnSync(
        process.execPath,
        ["src/heavy-test-plan.mjs", "--event", "pull_request", "--base", "missing-base", "--head", "HEAD", "--max-shards", "3", "--github-output", output],
        { cwd: process.cwd(), encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` } },
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("fatal: missing base");
      expect(() => readFileSync(output, "utf8")).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("heavy planner workflow contract", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");

  it("will be wired to the shipped planner and a dynamic matrix", () => {
    expect(workflow).toContain("node src/heavy-test-plan.mjs");
    expect(workflow).toContain("matrix: ${{ fromJSON(needs.changes.outputs.heavy_matrix) }}");
    expect(workflow).toContain("HARVEY_HEAVY_FILES_JSON: ${{ toJSON(matrix.files) }}");
  });

  it("assigns scored gates from the plan and keeps every non-PR run full", () => {
    expect(workflow).toContain("--event '${{ github.event_name }}'");
    for (const gate of ["calibration", "source-recall", "m2-coverage", "shared-source-match"]) {
      expect(workflow).toContain(`contains(matrix.gates, '${gate}')`);
    }
  });

  it("launches heavy runners only when the planner selected at least one workload", () => {
    const heavyJobCondition = "if: needs.changes.outputs.heavy_run == 'true'";
    expect(workflow).toMatch(new RegExp(`\\n  heavy-cli:[\\s\\S]*?\\n    ${heavyJobCondition.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\n`));
    expect(workflow).toMatch(/\n {2}build:[\s\S]*?\n {4}if: needs\.changes\.outputs\.code == 'true'\n/);
    expect(workflow).toContain("heavy_run: ${{ steps.heavy-plan.outputs.run }}");
  });
});
