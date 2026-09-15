import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

function patchFromGit(dir: string, mutate: () => void): string {
  mutate();
  git(dir, ["add", "-A"]);
  const patch = `${git(dir, ["diff", "--cached", "--binary", "--find-renames=100%", "--find-copies-harder"])}\n`;
  git(dir, ["reset", "--hard", "-q", "HEAD"]);
  return patch;
}

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("executeFixDiff", () => {
  const allowlist = ["src/**"];

  function diffFor(file: string, from: string, to: string): string {
    return [`--- a/${file}`, `+++ b/${file}`, "@@ -1 +1 @@", `-${from}`, `+${to}`, ""].join("\n");
  }

  it("verifies a diff against a disposable worktree and leaves the client tree untouched", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = await executeFixDiff("F-1", diffFor("src/a.ts", "export const a = 1;", "export const a = 2;"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("diff-verified");
    expect(result.files).toEqual(["src/a.ts"]);
    expect(git(dir, ["status", "--porcelain"])).toBe("");
    expect(worktreeCount(dir)).toBe(1); // the disposable worktree is gone
  });

  it("blocks a denylisted path before any worktree is created", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n", ".env": "SECRET=1\n" });
    const result = await executeFixDiff("F-2", diffFor(".env", "SECRET=1", "SECRET=2"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist: ["**"],
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("denylisted path");
    expect(worktreeCount(dir)).toBe(1);
  });

  it("blocks both endpoints of a real Git rename before an unrelated passing effect can run", async () => {
    const { dir, commit } = clientRepo({
      "calc.js": "module.exports.add = (a, b) => a - b;\n",
      ".env": "SECRET=1\n",
    });
    const patch = patchFromGit(dir, () => {
      writeFileSync(join(dir, "calc.js"), "module.exports.add = (a, b) => a + b;\n");
      renameSync(join(dir, ".env"), join(dir, "renamed-secret.txt"));
    });
    expect(patch).toContain("rename from .env");
    expect(patch).toContain("rename to renamed-secret.txt");

    const result = await executeFixDiff("F-rename-env", patch, {
      targetDir: dir,
      baselineCommit: commit,
      allowlist: ["**"],
      effectCommand: ["node", "-e", "process.exit(require('./calc.js').add(2, 3) === 5 ? 0 : 1)"],
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.files).toContain(".env");
    expect(result.createdFiles).toContain("renamed-secret.txt");
    expect(result.railViolations.join(" ")).toContain("denylisted path");
    expect(worktreeCount(dir)).toBe(1);
  });

  it("blocks protected rename destinations and copy sources from real Git metadata", async () => {
    const renameRepo = clientRepo({ "src/source.ts": "export const value = 1;\n" });
    const renamePatch = patchFromGit(renameRepo.dir, () => renameSync(join(renameRepo.dir, "src/source.ts"), join(renameRepo.dir, ".env.local")));
    const renamed = await executeFixDiff("F-rename-destination", renamePatch, {
      targetDir: renameRepo.dir,
      baselineCommit: renameRepo.commit,
      allowlist: ["**"],
    });
    expect(renamed.outcome).toBe("rails-blocked");
    expect(renamed.createdFiles).toContain(".env.local");

    const copyRepo = clientRepo({ ".env": "SECRET=1\n" });
    const copyPatch = patchFromGit(copyRepo.dir, () => copyFileSync(join(copyRepo.dir, ".env"), join(copyRepo.dir, "copied-secret.txt")));
    expect(copyPatch).toContain("copy from .env");
    const copied = await executeFixDiff("F-copy-source", copyPatch, {
      targetDir: copyRepo.dir,
      baselineCommit: copyRepo.commit,
      allowlist: ["**"],
    });
    expect(copied.outcome).toBe("rails-blocked");
    expect(copied.files).toContain(".env");
    expect(copied.createdFiles).toContain("copied-secret.txt");
  });

  it("accepts real Git text rename, copy, and mode-only records inside the allowlist", async () => {
    const renameRepo = clientRepo({ "src/old.ts": "export const value = 1;\n" });
    const renamePatch = patchFromGit(renameRepo.dir, () => renameSync(join(renameRepo.dir, "src/old.ts"), join(renameRepo.dir, "src/new.ts")));
    const renamed = await executeFixDiff("F-rename", renamePatch, { targetDir: renameRepo.dir, baselineCommit: renameRepo.commit, allowlist });
    expect(renamed).toMatchObject({ outcome: "diff-verified", files: ["src/old.ts"], createdFiles: ["src/new.ts"] });

    const copyRepo = clientRepo({ "src/source.ts": "export const value = 1;\n" });
    const copyPatch = patchFromGit(copyRepo.dir, () => copyFileSync(join(copyRepo.dir, "src/source.ts"), join(copyRepo.dir, "src/copy.ts")));
    expect(copyPatch).toContain("copy from src/source.ts");
    expect(copyPatch).toContain("copy to src/copy.ts");
    const copied = await executeFixDiff("F-copy", copyPatch, { targetDir: copyRepo.dir, baselineCommit: copyRepo.commit, allowlist });
    expect(copied).toMatchObject({ outcome: "diff-verified", files: ["src/source.ts"], createdFiles: ["src/copy.ts"] });

    const modeRepo = clientRepo({ "src/script.sh": "#!/bin/sh\nexit 0\n" });
    const modePatch = patchFromGit(modeRepo.dir, () => chmodSync(join(modeRepo.dir, "src/script.sh"), 0o755));
    expect(modePatch).toContain("old mode 100644");
    expect(modePatch).toContain("new mode 100755");
    const mode = await executeFixDiff("F-mode", modePatch, { targetDir: modeRepo.dir, baselineCommit: modeRepo.commit, allowlist });
    expect(mode).toMatchObject({ outcome: "diff-verified", files: ["src/script.sh"], createdFiles: [] });
  });

  it("refuses real Git binary and symlink records explicitly before application", async () => {
    const binaryRepo = clientRepo({ "src/image.bin": "before\u0000bytes\n" });
    const binaryPatch = patchFromGit(binaryRepo.dir, () => writeFileSync(join(binaryRepo.dir, "src/image.bin"), "after\u0000bytes\n"));
    expect(binaryPatch).toContain("GIT binary patch");
    const binary = await executeFixDiff("F-binary", binaryPatch, { targetDir: binaryRepo.dir, baselineCommit: binaryRepo.commit, allowlist });
    expect(binary.outcome).toBe("rails-blocked");
    expect(binary.railViolations.join(" ")).toContain("binary patch metadata is unsupported");

    const symlinkRepo = clientRepo({ "src/target.ts": "export const value = 1;\n" });
    const symlinkPatch = patchFromGit(symlinkRepo.dir, () => symlinkSync("target.ts", join(symlinkRepo.dir, "src/link.ts")));
    expect(symlinkPatch).toContain("new file mode 120000");
    const symlink = await executeFixDiff("F-symlink", symlinkPatch, { targetDir: symlinkRepo.dir, baselineCommit: symlinkRepo.commit, allowlist });
    expect(symlink.outcome).toBe("rails-blocked");
    expect(symlink.railViolations.join(" ")).toContain("symlink patch metadata is unsupported");

    const changedSymlinkRepo = clientRepo({ "src/first.ts": "first\n", "src/second.ts": "second\n" });
    symlinkSync("first.ts", join(changedSymlinkRepo.dir, "src/existing-link.ts"));
    git(changedSymlinkRepo.dir, ["add", "-A"]);
    git(changedSymlinkRepo.dir, ["commit", "-qm", "add symlink"]);
    changedSymlinkRepo.commit = git(changedSymlinkRepo.dir, ["rev-parse", "HEAD"]);
    const changedSymlinkPatch = patchFromGit(changedSymlinkRepo.dir, () => {
      rmSync(join(changedSymlinkRepo.dir, "src/existing-link.ts"));
      symlinkSync("second.ts", join(changedSymlinkRepo.dir, "src/existing-link.ts"));
    });
    expect(changedSymlinkPatch).toMatch(/index \S+\.\.\S+ 120000/);
    const changedSymlink = await executeFixDiff("F-symlink-change", changedSymlinkPatch, {
      targetDir: changedSymlinkRepo.dir,
      baselineCommit: changedSymlinkRepo.commit,
      allowlist,
    });
    expect(changedSymlink.outcome).toBe("rails-blocked");
    expect(changedSymlink.railViolations.join(" ")).toContain("symlink patch metadata is unsupported");
  });

  it("blocks a path outside the engagement allowlist", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n", "infra/deploy.ts": "x\n" });
    const result = await executeFixDiff("F-3", diffFor("infra/deploy.ts", "x", "y"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("outside engagement path allowlist");
  });

  it("blocks a diff over the engagement diff cap", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n" });
    const body = ["--- a/src/a.ts", "+++ b/src/a.ts", "@@ -1,1 +1,5 @@", " a", "+1", "+2", "+3", "+4", ""].join("\n");
    const result = await executeFixDiff("F-4", body, {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
      diffCap: { maxLines: 2, maxFiles: 10 },
    });

    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("cap is 2");
  });

  it("reports verify-failed — never verified — when the diff does not apply to the baseline", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = await executeFixDiff("F-5", diffFor("src/a.ts", "something else entirely", "fixed"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
    });

    expect(result.outcome).toBe("verify-failed");
    expect(result.verification).toContain("does not apply cleanly");
    expect(worktreeCount(dir)).toBe(1);
  });

  it("fails the fix when the effect command does not pass, and reverts the worktree", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "export const a = 1;\n" });
    const result = await executeFixDiff("F-6", diffFor("src/a.ts", "export const a = 1;", "export const a = 2;"), {
      targetDir: dir,
      baselineCommit: commit,
      allowlist,
      effectCommand: ["node", "-e", "process.exit(3)"],
    });

    expect(result.outcome).toBe("verify-failed");
    expect(result.verification).toContain("effect check failed");
  });

  it("aborts when the pinned baseline commit is not in the target repo", async () => {
    const { dir } = clientRepo({ "src/a.ts": "a\n" });
    const result = await executeFixDiff("F-7", diffFor("src/a.ts", "a", "b"), {
      targetDir: dir,
      baselineCommit: "0".repeat(40),
      allowlist,
    });

    expect(result.outcome).toBe("aborted");
    expect(result.abortReason).toContain("not found");
  });

  it("refuses to fix Harvey's own repository", async () => {
    const harvey = dirname(fileURLToPath(import.meta.url));
    const commit = git(harvey, ["rev-parse", "HEAD"]);
    await expect(
      executeFixDiff("F-8", diffFor("src/a.ts", "a", "b"), { targetDir: harvey, baselineCommit: commit, allowlist }),
    ).rejects.toThrow(/Harvey's own repository/);
  });

  it("aborts a diff that declares no file changes", async () => {
    const { dir, commit } = clientRepo({ "src/a.ts": "a\n" });
    const result = await executeFixDiff("F-9", "no diff headers here\n", { targetDir: dir, baselineCommit: commit, allowlist });
    expect(result.outcome).toBe("aborted");
    expect(result.abortReason).toContain("no file changes");
  });
});
