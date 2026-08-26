import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";
import { buildHeavyPlan, loadHeavyRegistry, selectHeavyWorkloads, shardSelectedWorkloads } from "./heavy-test-plan.mjs";
import { MEASURED_OUTSIDE_DISCOVERY, SCORED_GATES } from "./scored-gates.js";

const registry = loadHeavyRegistry();
const allIds = registry.workloads.map((workload) => workload.id);
const censusOwners = ["effectiveness-registry", "effectiveness-delivery"];

function inventorySourceInputs(): string[] {
  const root = process.cwd();
  const manifest = JSON.parse(readFileSync("package.json", "utf8")) as { scripts: Record<string, string> };
  const pending = ["src/cli/detector-census.ts", "src/cli/run-audit.ts"];
  const bindings = ts.createSourceFile("src/audit-runners.ts", readFileSync("src/audit-runners.ts", "utf8"), ts.ScriptTarget.Latest, true);
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node) && /^(?:src|tools)\/[^#]+\.[cm]?[jt]sx?$/.test(node.text)
      && existsSync(node.text)) pending.push(node.text);
    ts.forEachChild(node, visit);
  };
  visit(bindings);
  pending.push(...SCORED_GATES.filter((gate) => gate.cadence.kind !== "none").map((gate) => `src/cli/${gate.id}.ts`));
  const inputs = new Set<string>();
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (inputs.has(file)) continue;
    inputs.add(file);
    const source = readFileSync(file, "utf8");
    const commands = (node: ts.Node): void => {
      if (ts.isStringLiteralLike(node) && (ts.isCallExpression(node.parent) || ts.isArrayLiteralExpression(node.parent))) {
        const command = manifest.scripts[node.text];
        for (const match of command?.matchAll(/(?:src|tools)\/[\w/.-]+\.[cm]?[jt]sx?\b/g) ?? []) {
          if (existsSync(match[0])) pending.push(match[0]);
        }
      }
      ts.forEachChild(node, commands);
    };
    commands(ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true));
    for (const imported of ts.preProcessFile(source, true, true).importedFiles) {
      if (!imported.fileName.startsWith(".")) continue;
      const path = resolve(dirname(file), imported.fileName);
      const stem = path.replace(/\.[cm]?jsx?$/, "");
      const candidates = [path, ...[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"].flatMap((extension) => [stem + extension, join(path, `index${extension}`)])];
      const found = candidates.find((candidate) => existsSync(candidate));
      expect(found, `${file} imports ${imported.fileName}`).toBeDefined();
      pending.push(relative(root, found!).split("\\").join("/"));
    }
  }
  for (const command of Object.values(manifest.scripts)) {
    const entry = /^(?:pnpm exec )?(?:node|tsx)\s+((?:src|tools)\/[\w/.-]+\.[cm]?[jt]sx?)(?:\s|$)/.exec(command)?.[1];
    if (entry && !/(?:&&|\|\||[|;])/.test(command)) inputs.add(entry);
  }
  return [...inputs].sort();
}

describe("heavy PR impact planner", () => {
  it("routes the census import, producer implementation, and scored-venue source closure to both owners", () => {
    const inputs = inventorySourceInputs();
    expect(inputs).toEqual(expect.arrayContaining(["src/sbom.ts", "src/scan/mechanical-dependency-registry.ts", "src/scan/calibration/b2-deps.entries.ts", "src/quick-scan.ts", "tools/pii-classify.mjs"]));
    for (const path of inputs) {
      expect(selectHeavyWorkloads(registry, [path]).selected, path).toEqual(expect.arrayContaining(censusOwners));
    }
  });

  it("routes discovered input classes and scored cadence files without selecting unrelated workloads", () => {
    const cadenceFiles = [...SCORED_GATES, ...MEASURED_OUTSIDE_DISCOVERY].flatMap((gate) =>
      gate.cadence.kind === "workflow" ? [gate.cadence.file]
        : gate.cadence.kind === "none" && gate.cadence.alarmedBy ? [gate.cadence.alarmedBy.file] : []);
    for (const path of [
      "src/scan/new-producer.ts", "src/scan/calibration/new-batch.entries.ts",
      "src/scan/rules/semgrep/new-family.yml", "src/detectors/new-detector.ts",
      "src/pentest/new-probe.ts", "src/cli/validate-new-venue.ts", ...cadenceFiles,
    ]) {
      const selection = selectHeavyWorkloads(registry, [path]);
      expect(selection.mode, path).toBe("scoped");
      expect(selection.selected, path).toEqual(expect.arrayContaining(censusOwners));
      expect(selection.selected, path).not.toContain("run-audit");
    }
  });

  it("uses the same registry as Vitest's heavy exclusion — no second file list can drift", () => {
    expect(registry.workloads.map((workload) => workload.testFile)).toEqual(HEAVY_CLI_TESTS);
    expect(new Set(HEAVY_CLI_TESTS).size).toBe(HEAVY_CLI_TESTS.length);
  });

  it("scopes a mutation change to its CLI, cache, orchestrator, and inventory consumers", () => {
    expect(selectHeavyWorkloads(registry, ["src/mutation-scan.ts"])).toMatchObject({
      mode: "scoped",
      selected: ["run-audit", "mutation-scan", "corpus-scanner-cross-process", ...censusOwners],
      unmatched: [],
    });
  });

  it("scopes independent module-local changes to their owned workloads", () => {
    expect(selectHeavyWorkloads(registry, ["src/lighthouse.ts"]).selected).toEqual(["lighthouse-scan", ...censusOwners]);
    expect(selectHeavyWorkloads(registry, ["src/quality-scan.ts"]).selected).toEqual([
      "run-audit",
      "quick-scan",
      "quality-scan",
      "corpus-scanner-cross-process",
      ...censusOwners,
    ]);
    expect(selectHeavyWorkloads(registry, ["src/audit-report.ts"]).selected).toEqual(["run-audit", ...censusOwners]);
    expect(selectHeavyWorkloads(registry, ["src/health-scorecard.ts"]).selected).toEqual(["run-audit", "quick-scan", ...censusOwners]);
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
      ...censusOwners,
    ]);
  });

  it("takes the union for a mixed but fully-owned PR", () => {
    const selection = selectHeavyWorkloads(registry, ["src/lighthouse.ts", "src/mutation-scan.ts"]);
    expect(selection.mode).toBe("scoped");
    expect(selection.selected).toEqual(["run-audit", "mutation-scan", "lighthouse-scan", "corpus-scanner-cross-process", ...censusOwners]);
  });

  it("runs mapped owners and reports unmapped paths without upgrading the PR to full", () => {
    const selection = selectHeavyWorkloads(registry, ["src/lighthouse.ts", "src/new-shared-runtime.ts"]);
    expect(selection.mode).toBe("scoped");
    expect(selection.selected).toEqual(["lighthouse-scan", ...censusOwners]);
    expect(selection.unmatched).toEqual(["src/new-shared-runtime.ts"]);
    expect(selection.reasons.join("\n")).toContain("full post-merge run remains the backstop");
  });

  it("skips empty, non-venue workflow, docs, planner, and otherwise unmapped PRs", () => {
    for (const paths of [
      [],
      [".github/workflows/conservation.yml"],
      [".github/workflows/acceptance-close.yml"],
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
    const plan = buildHeavyPlan(registry, ["src/mutation-scan.test.ts"], { maxShards: 3 });
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

  it.each([
    { name: "independent test", paths: ["src/lighthouse.test.ts"], selected: ["lighthouse-scan"] },
    { name: "SBOM producer input", paths: ["src/sbom.ts"], selected: censusOwners },
    { name: "new corpus batch", paths: ["src/scan/calibration/new-batch.entries.ts"], selected: ["validate-calibration", ...censusOwners] },
    { name: "scored workflow", paths: [".github/workflows/ci.yml"], selected: censusOwners },
    {
      name: "dependency-range PR",
      paths: [
        "dry-run/findings-report.json", "dry-run/findings.json", "src/findings.test.ts", "src/findings.ts",
        "src/render-fidelity.test.ts", "src/sbom.test.ts", "src/sbom.ts", "src/scan/calibration/b2-deps.entries.ts",
        "src/scan/mechanical-dependency-registry.ts", "src/scan/mechanical.test.ts", "src/scan/supply-chain.test.ts",
        "src/scan/supply-chain.ts", "src/unstructured-claims-baseline.ts", "targets/calibration/GROUND-TRUTH.md",
        "targets/calibration/package-lock.json",
      ],
      selected: ["validate-calibration", ...censusOwners],
    },
    { name: "unrelated documentation", paths: ["docs/design/operator-notes.md"], selected: [] },
  ])("the shipped CLI routes $name from git into GITHUB_OUTPUT", ({ paths, selected }) => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-heavy-plan-cli-"));
    try {
      const git = join(dir, "git");
      const output = join(dir, "github-output");
      writeFileSync(git, `#!/bin/sh\nprintf '%s\\n' ${paths.map((path) => `'${path}'`).join(" ")}\n`);
      chmodSync(git, 0o755);
      const result = spawnSync(
        process.execPath,
        ["src/heavy-test-plan.mjs", "--event", "pull_request", "--base", "base", "--head", "HEAD", "--max-shards", "3", "--github-output", output],
        { cwd: process.cwd(), encoding: "utf8", env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` } },
      );
      expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
      const values = new Map(readFileSync(output, "utf8").trim().split("\n").map((line) => line.split("=", 2) as [string, string]));
      expect(values.get("mode")).toBe(selected.length > 0 ? "scoped" : "skipped");
      expect(values.get("selected")).toBe(selected.join(","));
      const matrix = JSON.parse(values.get("matrix") ?? "null") as { include: { workloadIds: string[]; files: string[] }[] };
      expect(matrix.include.flatMap((group) => group.workloadIds).sort()).toEqual([...selected].sort());
      expect(matrix.include.flatMap((group) => group.files).sort()).toEqual(registry.workloads.filter((workload) => selected.includes(workload.id)).map((workload) => workload.testFile).sort());
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
