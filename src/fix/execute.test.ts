import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { executeFixDiff } from "./execute.js";

const created: string[] = [];

function git(cwd: string, args: string[]): string {
  return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" }).trim();
}

// A throwaway client repo with one committed file, so the fix path has a real baseline to cut a
// worktree from. Real git on purpose: the safety this module claims is git behavior, not a mock's.
function clientRepo(files: Record<string, string>): { dir: string; commit: string } {
  const dir = mkdtempSync(join(tmpdir(), "harvey-fix-client-"));
  created.push(dir);
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "t@example.com"]);
  git(dir, ["config", "user.name", "t"]);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-qm", "baseline"]);
  return { dir, commit: git(dir, ["rev-parse", "HEAD"]) };
}

function worktreeCount(dir: string): number {
  return git(dir, ["worktree", "list"]).split("\n").filter(Boolean).length;
}

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("executeFixDiff", () => {
  const allowlist = ["src/**"];

  function diffFor(file: string, from: string, to: string): string {
    return [`--- a/${file}`, `+++ b/${file}`, "@@ -1 +1 @@", `-${from}`, `+${to}`, ""].join("\n");
  }

  it("verifies a diff against a disposable worktree and leaves the client tree untouched", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = executeFixDiff("F-1", diffFor("src/a.ts", "export const a = 1;", "export const a = 2;"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("diff-verified");
    expect(result.files).toEqual(["src/a.ts"]);
    expect(git(dir, ["status", "--porcelain"])).toBe("");
    expect(worktreeCount(dir)).toBe(1); // the disposable worktree is gone
  });

  it("blocks a denylisted path before any worktree is created", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n", ".env": "SECRET=1\n" });
    const result = executeFixDiff("F-2", diffFor(".env", "SECRET=1", "SECRET=2"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist: ["**"],
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("denylisted path");
    expect(worktreeCount(dir)).toBe(1);
  });

  it("blocks a path outside the engagement allowlist", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n", "infra/deploy.ts": "x\n" });
    const result = executeFixDiff("F-3", diffFor("infra/deploy.ts", "x", "y"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("outside engagement path allowlist");
  });

  it("blocks a diff over the engagement diff cap", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n" });
    const body = ["--- a/src/a.ts", "+++ b/src/a.ts", "@@ -1,1 +1,5 @@", " a", "+1", "+2", "+3", "+4", ""].join("\n");
    const result = executeFixDiff("F-4", body, {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
      diffCap: { maxLines: 2, maxFiles: 10 },
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("cap is 2");
  });

  it("reports verify-failed — never verified — when the diff does not apply to the baseline", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = executeFixDiff("F-5", diffFor("src/a.ts", "something else entirely", "fixed"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("verify-failed");
    expect(result.verification).toContain("does not apply cleanly");
    expect(worktreeCount(dir)).toBe(1);
  });

  it("fails the fix when the effect command does not pass, and reverts the worktree", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = executeFixDiff("F-6", diffFor("src/a.ts", "export const a = 1;", "export const a = 2;"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
      effectCommand: ["node", "-e", "process.exit(3)"],
    });

    expect(result.outcome).toBe("verify-failed");
    expect(result.verification).toContain("effect check failed");
  });

  it("aborts when the pinned baseline commit is not in the target repo", () => {
    const { dir } = clientRepo({ "src/a.ts": "a\n" });
    const result = executeFixDiff("F-7", diffFor("src/a.ts", "a", "b"), {
      targetDir: dir,
      baselineCommit: "0".repeat(40),
      allowlist,
    });

    expect(result.outcome).toBe("aborted");
    expect(result.abortReason).toContain("not found");
  });

  it("refuses to fix Harvey's own repository", () => {
    const harvey = dirname(fileURLToPath(import.meta.url));
    const commit = git(harvey, ["rev-parse", "HEAD"]);
    expect(() =>
      executeFixDiff("F-8", diffFor("src/a.ts", "a", "b"), { targetDir: harvey, baselineCommit: commit, allowlist }),
    ).toThrow(/Harvey's own repository/);
  });

  it("aborts a diff that declares no file changes", () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n" });
    const result = executeFixDiff("F-9", "no diff headers here\n", { targetDir: dir, baselineCommit: commit, allowlist });
    expect(result.outcome).toBe("aborted");
    expect(result.abortReason).toContain("no file changes");
  });
});
