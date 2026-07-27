import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkWorkflowPermissions } from "./gha-permissions.js";
import { CI_PIPELINE_CATEGORY } from "./semgrep.js";

describe("checkWorkflowPermissions (#1212)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeWorkflows(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-gha-"));
    const dir = join(root, ".github", "workflows");
    mkdirSync(dir, { recursive: true });
    for (const [name, yaml] of Object.entries(files)) writeFileSync(join(dir, name), yaml);
    return root;
  }

  const JOB = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n";

  it("flags a workflow-level write-all at high tier — an exact fact in the file", () => {
    const dir = writeWorkflows({ "ci.yml": `on: [push]\npermissions: write-all\n${JOB}` });
    const f = checkWorkflowPermissions(dir);
    expect(f).toHaveLength(1);
    expect(f[0]!.precisionTier).toBe("high");
    expect(f[0]!.evidence).toContain("the whole workflow");
  });

  it("flags a JOB that re-widens a narrow workflow-level block", () => {
    // The shape a reviewer skims past: the top of the file is correct.
    const dir = writeWorkflows({
      "release.yml": "on: [push]\npermissions:\n  contents: read\njobs:\n  release:\n    permissions: write-all\n    steps:\n      - run: npm publish\n",
    });
    const f = checkWorkflowPermissions(dir);
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence).toContain("a job");
  });

  it("flags a workflow with NO permissions block at review tier — the default is a repo setting we cannot read", () => {
    const dir = writeWorkflows({ "ci.yml": `on: [push]\n${JOB}` });
    const f = checkWorkflowPermissions(dir);
    expect(f).toHaveLength(1);
    expect(f[0]!.id).toBe("CI-GHA-NO-PERMISSIONS-ci.yml");
    expect(f[0]!.precisionTier).toBe("review");
  });

  it("clears a workflow with an explicit narrow block, widened only on the job that writes", () => {
    const dir = writeWorkflows({
      "ci.yml": "on: [pull_request]\npermissions:\n  contents: read\njobs:\n  comment:\n    permissions:\n      pull-requests: write\n    steps:\n      - run: gh pr comment\n",
    });
    expect(checkWorkflowPermissions(dir)).toHaveLength(0);
  });

  it("clears a workflow whose ONLY permissions block is per-job — the token is scoped either way", () => {
    const dir = writeWorkflows({
      "ci.yml": "on: [push]\njobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n      - run: npm test\n",
    });
    expect(checkWorkflowPermissions(dir)).toHaveLength(0);
  });

  it("ignores a reusable fragment with no jobs — there is no token to scope", () => {
    const dir = writeWorkflows({ "fragment.yml": "name: shared inputs\non:\n  workflow_call:\n" });
    expect(checkWorkflowPermissions(dir)).toHaveLength(0);
  });

  it("routes to the non-grading CI/CD category, like the other GitHub Actions classes (#996)", () => {
    const dir = writeWorkflows({ "ci.yml": `on: [push]\npermissions: write-all\n${JOB}` });
    expect(checkWorkflowPermissions(dir)[0]!.category).toBe(CI_PIPELINE_CATEGORY);
  });

  it("reports nothing when the target has no .github/workflows at all", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-gha-"));
    expect(checkWorkflowPermissions(root)).toHaveLength(0);
  });
});
