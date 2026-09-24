import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { CONSERVATION_INPUT_RULES, planConservationRun } from "./conservation-change-filter.mjs";

const script = resolve("src/conservation-change-filter.mjs");

function runShippingFilter(path: string): { stdout: string; outputs: string } {
  const repo = mkdtempSync(join(tmpdir(), "harvey-conservation-filter-"));
  const output = join(repo, "github-output");
  try {
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "conservation@example.invalid"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "Conservation Filter"], { cwd: repo });
    writeFileSync(join(repo, "seed.txt"), "seed\n");
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync("git", ["commit", "-qm", "seed"], { cwd: repo });
    const base = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
    const changed = join(repo, path);
    mkdirSync(dirname(changed), { recursive: true });
    writeFileSync(changed, "changed\n");
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync("git", ["commit", "-qm", "change"], { cwd: repo });
    const result = spawnSync(process.execPath, [script, "--event", "pull_request", "--base", base, "--head", "HEAD", "--github-output", output], { cwd: repo, encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    return { stdout: result.stdout, outputs: readFileSync(output, "utf8") };
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
}

describe("conservation change selection", () => {
  it.each([
    ["scanner source", "src/scan/semgrep.ts"],
    ["detector source", "src/detectors/hook-deps.ts"],
    ["effectiveness evidence", "src/effectiveness-registry.ts"],
    ["tool wrapper", "tools/pii-classify.mjs"],
    ["schema/registry source", "src/effectiveness-schema.ts"],
    ["package manager settings", "pnpm-workspace.yaml"],
    ["package manager configuration", ".npmrc"],
    ["package manager hook", ".pnpmfile.cjs"],
    ["dependency patch", "patches/tool.patch"],
    ["workspace dependency manifest", "site/package.json"],
    ["additional workspace manifest", "packages/new-workspace/package.json"],
    ["duplication tool configuration", ".jscpd.json"],
    ["dead-code tool configuration", "knip.json"],
    ["report template", "report-template/render.mjs"],
    ["liveness action", ".github/actions/gate-liveness/action.yml"],
    ["failure alert action", ".github/actions/alert-issue/action.yml"],
  ])("selects real execution for a %s-only change", (_label, path) => {
    const result = runShippingFilter(path);
    expect(result.outputs).toContain("relevant=true\n");
    expect(result.stdout).toContain("select real execution");
    expect(result.stdout).not.toContain("nothing was scored");
  });

  it("retains a declared no-op for a non-relevant change", () => {
    const result = runShippingFilter("docs/notes.md");
    expect(result.outputs).toContain("relevant=false\n");
    expect(result.outputs).toContain("drift=false\n");
    expect(result.stdout).toContain("nothing was scored");
  });

  it("keeps scheduled, dispatch, merge-queue, drift, and ordinary PR behavior distinct", () => {
    expect(planConservationRun("schedule", [])).toMatchObject({ relevant: true, drift: true });
    expect(planConservationRun("workflow_dispatch", [])).toMatchObject({ relevant: true, drift: true });
    expect(planConservationRun("merge_group", [])).toMatchObject({ relevant: true, drift: false });
    expect(planConservationRun("pull_request", ["src/scan/semgrep.ts"])).toMatchObject({ relevant: true, drift: false });
    expect(planConservationRun("pull_request", ["src/scan/__fixtures__/semgrep/result.json"])).toMatchObject({ relevant: true, drift: true });
  });

  it("uses a conservative population rule instead of leaf source allowlists", () => {
    expect(CONSERVATION_INPUT_RULES).toContainEqual({ kind: "prefix", value: "src/" });
    expect(planConservationRun("pull_request", ["src/scan/new-scanner.ts"]).relevant).toBe(true);
    expect(planConservationRun("pull_request", ["src/detectors/new-detector.ts"]).relevant).toBe(true);
    expect(planConservationRun("pull_request", ["src/effectiveness-new-evidence.ts"]).relevant).toBe(true);
  });

  it("the required workflow invokes this router in-job and has no outer paths filter", () => {
    const workflow = readFileSync(".github/workflows/conservation.yml", "utf8");
    expect(workflow).toContain("node src/conservation-change-filter.mjs");
    expect(workflow.match(/^\s+pull_request:\s*$/m)).not.toBeNull();
    expect(workflow.match(/^\s+merge_group:\s*$/m)).not.toBeNull();
    expect(workflow).not.toMatch(/^\s+paths(?:-ignore)?:/m);
    const localActions = [...workflow.matchAll(/uses:\s*\.\/(\.github\/actions\/[^\s]+)/g)]
      .map((match) => `${match[1]}/action.yml`);
    expect(localActions.length).toBeGreaterThan(0);
    for (const action of localActions) expect(planConservationRun("pull_request", [action]).relevant, action).toBe(true);
  });
});
