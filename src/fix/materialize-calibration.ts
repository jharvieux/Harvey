// Materialize the calibration corpus into a STANDALONE throwaway git repo (design §8, blocker 3).
// executeFixDiff refuses any target that shares Harvey's --git-common-dir (assertNotHarveyItself), and
// targets/calibration is committed INSIDE Harvey's repo with no nested .git — so the §8 acceptance run
// cannot execute a fix against it in place. This copies the relevant planted files (verbatim, or a
// caller-supplied variant) into a fresh temp git repo the pipeline can branch/execute against. The
// caller disposes the returned dir.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const CALIBRATION_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../targets/calibration");

function git(cwd: string, args: string[]): string {
  return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" }).trim();
}

export function readCalibration(rel: string): string {
  return readFileSync(join(CALIBRATION_ROOT, rel), "utf8");
}

export interface MaterializedCorpus {
  dir: string;
  commit: string; // the baseline commit a fix is pinned + executed against
}

// Seed a fresh standalone git repo with the given repo-relative files and commit them as the baseline.
export function materialize(files: Record<string, string>): MaterializedCorpus {
  const dir = mkdtempSync(join(tmpdir(), "harvey-fixcal-"));
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "t@example.com"]);
  git(dir, ["config", "user.name", "t"]);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-qm", "calibration baseline"]);
  return { dir, commit: git(dir, ["rev-parse", "HEAD"]) };
}

// Capture a git-apply-compatible unified diff for a single-file mechanical fix: write the fixed
// content, diff it against the committed baseline, then revert so executeFixDiff applies the patch
// itself against a disposable worktree (the operator flow, not a dirty working tree). git's trim()
// drops the trailing newline git apply needs, so it is restored.
export function capturePatch(corpus: MaterializedCorpus, rel: string, fixedContent: string): string {
  writeFileSync(join(corpus.dir, rel), fixedContent);
  const patch = `${git(corpus.dir, ["diff", "--", rel])}\n`;
  git(corpus.dir, ["checkout", "--", rel]);
  return patch;
}

export function disposeCorpus(corpus: MaterializedCorpus): void {
  rmSync(corpus.dir, { recursive: true, force: true });
}
