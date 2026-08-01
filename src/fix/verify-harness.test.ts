import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { CommandRun, DetectorRun } from "./verify.js";
import { disposeCorpus, materialize } from "./materialize-calibration.js";
import {
  buildVerificationEvidence,
  detectRunner,
  discoverClientCommands,
  extractCiRunSteps,
  withBaselineWorktree,
  isPullRequestTriggered,
  runBaseline,
  type DiscoveredCommand,
} from "./verify-harness.js";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-vh-"));
  created.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

const cleanDetector: DetectorRun = { detectorId: "d", fired: false, output: "clean" };

describe("discoverClientCommands", () => {
  it("discovers the root verify command and records its provenance", () => {
    const dir = scratch({ "package.json": JSON.stringify({ scripts: { verify: "tsc && vitest" } }) });
    const cmds = discoverClientCommands(dir);
    expect(cmds).toEqual([{ command: "pnpm run verify", workspace: "", source: "package.json (root)" }]);
  });

  it("adds affected-workspace commands (monorepo rule) alongside the root", () => {
    const dir = scratch({
      "package.json": JSON.stringify({ scripts: { lint: "eslint ." } }),
      "apps/web/package.json": JSON.stringify({ scripts: { test: "vitest" } }),
    });
    const cmds = discoverClientCommands(dir, ["apps/web"]);
    expect(cmds).toContainEqual({ command: "pnpm run lint", workspace: "", source: "package.json (root)" });
    expect(cmds).toContainEqual({ command: "pnpm run test", workspace: "apps/web", source: "package.json (apps/web)" });
  });

  it("appends PR-triggered CI steps the scripts don't cover", () => {
    const dir = scratch({ "package.json": JSON.stringify({ scripts: { verify: "x" } }) });
    const ci: DiscoveredCommand[] = [{ command: "pnpm knip", workspace: "", source: "ci-workflow (ci.yml)" }];
    const cmds = discoverClientCommands(dir, [], "pnpm", ci);
    expect(cmds.map((c) => c.command)).toEqual(["pnpm run verify", "pnpm knip"]);
    expect(cmds[1]!.source).toContain("ci-workflow");
  });
});

describe("isPullRequestTriggered", () => {
  it("recognizes inline-array, bare, and block on: forms", () => {
    expect(isPullRequestTriggered("on: [push, pull_request]\n")).toBe(true);
    expect(isPullRequestTriggered("on: pull_request\n")).toBe(true);
    expect(isPullRequestTriggered("on:\n  pull_request:\n    branches: [main]\n")).toBe(true);
  });
  it("rejects a push-only workflow", () => {
    expect(isPullRequestTriggered("on:\n  push:\n    branches: [main]\n")).toBe(false);
  });
});

describe("extractCiRunSteps", () => {
  it("extracts inline and block run: steps from PR-triggered workflows only", () => {
    const dir = scratch({
      ".github/workflows/ci.yml": [
        "on: [pull_request]",
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: pnpm install",
        "      - run: |",
        "          pnpm knip",
        "          pnpm check:duplication",
      ].join("\n"),
      ".github/workflows/deploy.yml": ["on:", "  push:", "    branches: [main]", "jobs:", "  d:", "    steps:", "      - run: deploy"].join("\n"),
    });
    const steps = extractCiRunSteps(join(dir, ".github/workflows"));
    const cmds = steps.map((s) => s.command);
    expect(cmds).toContain("pnpm install");
    expect(cmds).toContain("pnpm knip\npnpm check:duplication");
    expect(cmds).not.toContain("deploy"); // push-only workflow is not a PR gate
  });
});

describe("buildVerificationEvidence", () => {
  const commands: DiscoveredCommand[] = [{ command: "pnpm run verify", workspace: "", source: "package.json (root)" }];
  const okRun = async (command: string, cwd: string): Promise<CommandRun> => ({ command, cwd, exitCode: 0, durationMs: 5, outputTail: "ok" });
  const failRun = async (command: string, cwd: string): Promise<CommandRun> => ({ command, cwd, exitCode: 1, durationMs: 5, outputTail: "boom" });

  it("is green when the detector is clean and the client check passes — green is decided, not asserted", async () => {
    const baseline = await runBaseline(commands, "/base", okRun);
    const ev = await buildVerificationEvidence(
      { findingId: "F", baselineCommit: "b", worktreeCommit: "w", detectorBefore: { detectorId: "d", fired: true, output: "" }, detectorAfter: cleanDetector, commands, baseline },
      "/fixed",
      okRun,
    );
    expect(ev.green).toBe(true);
    expect(ev.clientChecks[0]!.cwd).toBe("/fixed");
  });

  it("is not green when the detector did not run, even with the client check passing", async () => {
    const baseline = await runBaseline(commands, "/base", okRun);
    const ev = await buildVerificationEvidence(
      { findingId: "F", baselineCommit: "b", worktreeCommit: "w", detectorBefore: { detectorId: "d", fired: true, output: "" }, detectorAfter: { detectorId: "d", fired: false, output: "", notRun: "no resolver" }, commands, baseline },
      "/fixed",
      okRun,
    );
    expect(ev.green).toBe(false);
  });

  it("carries a pre-existing baseline failure as skipped, never attributing it to the fix", async () => {
    const baseline = await runBaseline(commands, "/base", failRun); // failed on the pinned commit
    const ev = await buildVerificationEvidence(
      { findingId: "F", baselineCommit: "b", worktreeCommit: "w", detectorBefore: { detectorId: "d", fired: true, output: "" }, detectorAfter: cleanDetector, commands, baseline },
      "/fixed",
      okRun,
    );
    expect(ev.clientChecks[0]!.skipped).toBe("pre-existing-failure-on-baseline");
    expect(ev.green).toBe(true); // ambient failure does not sink the fix
  });

  it("records a needs-ci command as skipped and does not count it against green", async () => {
    const baseline = new Map();
    const ev = await buildVerificationEvidence(
      { findingId: "F", baselineCommit: "b", worktreeCommit: "w", detectorBefore: { detectorId: "d", fired: true, output: "" }, detectorAfter: cleanDetector, commands, baseline, needsCi: () => true },
      "/fixed",
      failRun, // would fail if actually run — proves it is NOT run
    );
    expect(ev.clientChecks[0]!.skipped).toBe("needs-ci");
    expect(ev.green).toBe(true);
  });

  it("is not green when a runnable client check fails in the fixed worktree", async () => {
    const baseline = await runBaseline(commands, "/base", okRun);
    const ev = await buildVerificationEvidence(
      { findingId: "F", baselineCommit: "b", worktreeCommit: "w", detectorBefore: { detectorId: "d", fired: true, output: "" }, detectorAfter: cleanDetector, commands, baseline },
      "/fixed",
      failRun,
    );
    expect(ev.green).toBe(false);
  });
});

describe("detectRunner — the client's own runner, read off the lockfile (#1272)", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const withLockfile = (name?: string) => {
    const d = mkdtempSync(join(tmpdir(), "harvey-runner-"));
    dirs.push(d);
    if (name) writeFileSync(join(d, name), "");
    return d;
  };

  it("reads pnpm / yarn / bun / npm off their lockfiles", () => {
    expect(detectRunner(withLockfile("pnpm-lock.yaml"))).toBe("pnpm");
    expect(detectRunner(withLockfile("yarn.lock"))).toBe("yarn");
    expect(detectRunner(withLockfile("bun.lockb"))).toBe("bun");
    expect(detectRunner(withLockfile("package-lock.json"))).toBe("npm");
  });

  it("falls back to npm when there is no lockfile — pnpm's deps-status check would fail every command", () => {
    expect(detectRunner(withLockfile())).toBe("npm");
  });
});

describe("withBaselineWorktree — the §2.1 step-3 baseline root (#1272)", () => {
  it("hands the caller a real checkout of the PINNED commit, not the target's working tree, and disposes it", async () => {
    const c = materialize({ "a.txt": "baseline\n" });
    try {
      writeFileSync(join(c.dir, "a.txt"), "the operator moved on\n"); // a dirty client checkout
      let seen = "";
      let root = "";
      await withBaselineWorktree(c.dir, c.commit, async (r) => {
        root = r;
        seen = readFileSync(join(r, "a.txt"), "utf8");
      });
      expect(seen).toBe("baseline\n"); // the pinned commit, not the dirty tree
      expect(existsSync(root)).toBe(false); // and it is gone afterwards
    } finally {
      disposeCorpus(c);
    }
  });
});

describe("linkNodeModules — the client's installed tree is linked, never consumed", () => {
  it("survives the worktree's disposal: `git worktree remove --force` + rmSync take the LINK, not the target", async () => {
    // The destructive risk worth proving rather than assuming: the harness symlinks the client's own
    // node_modules into a disposable worktree, and that worktree is then force-removed. If either
    // removal followed the link, an engagement would end with the client's dependencies deleted.
    const c = materialize({ "a.txt": "baseline\n" });
    try {
      mkdirSync(join(c.dir, "node_modules"), { recursive: true });
      writeFileSync(join(c.dir, "node_modules", "keep.txt"), "installed\n");
      let linked = false;
      await withBaselineWorktree(c.dir, c.commit, async (root) => {
        linked = readFileSync(join(root, "node_modules", "keep.txt"), "utf8") === "installed\n";
      });
      expect(linked).toBe(true); // the commands really could have run against it
      expect(readFileSync(join(c.dir, "node_modules", "keep.txt"), "utf8")).toBe("installed\n");
    } finally {
      disposeCorpus(c);
    }
  });
});
