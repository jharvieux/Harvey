// The first executing stage of the fix pipeline (#885): take an implementer-produced unified diff
// for a screened finding, put it through the §3 rails, and prove it applies against a DISPOSABLE
// worktree cut at the pinned engagement commit. See docs/design/fix-implementation.md §1.4/§2/§3.
//
// What this deliberately does NOT do: write to the client's working tree, create a branch, push a
// ref, or open a PR. The output is an inert, reviewable diff plus an execution record — the operator
// gate (§1.5) still sits between this and anything reaching the client. The branch/push/PR transport
// is tracked separately; nothing here can reach it.
//
// It routes through the existing pieces rather than restating them: rails.ts decides what may be
// touched, and src/trackers/fix-diff.ts verifySuggestedFix owns apply/effect/revert. The rails run
// BEFORE a worktree exists, so a denylisted or oversized diff never reaches git at all.

import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join } from "node:path";
import { verifySuggestedFix } from "../trackers/fix-diff.js";
import { blastRadiusOf, checkBlastRadius, parseDiffFacts, type DiffCap } from "./rails.js";

// "diff-verified" is the only success, and it still means an INERT diff on disk — never an applied
// fix. Everything else names why not, so a caller cannot mistake silence for success.
export type ExecutionOutcome = "diff-verified" | "rails-blocked" | "verify-failed" | "aborted";

export interface FixExecution {
  findingId: string;
  outcome: ExecutionOutcome;
  baselineCommit: string;
  files: string[];
  createdFiles: string[];
  changedLines: number;
  railViolations: string[];
  verification?: string; // how verifySuggestedFix decided, verbatim
  abortReason?: string;
}

interface ExecuteOptions {
  targetDir: string; // the client checkout — a git repo, never this one
  baselineCommit: string; // pinned engagement commit the diff was written against
  allowlist: string[]; // engagement path allowlist (§3.1 rule 3)
  diffCap?: DiffCap;
  // Optional ground-truth check run inside the worktree after the diff applies (§2.2). Absent ⇒
  // apply-clean is the only gate, and the record says so.
  effectCommand?: string[];
}

// stderr is piped, not inherited: the client repo's git chatter ("Preparing worktree…", a failed
// rev-parse) is this module's control flow, not the operator's report.
function git(cwd: string, args: string[]): string {
  return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
}

function gitCommonDir(dir: string): string {
  const out = git(dir, ["rev-parse", "--git-common-dir"]);
  return realpathSync(isAbsolute(out) ? out : join(dir, out));
}

// Harvey must never be its own fix target: a diff scoped to a client repo that lands here would be
// a self-modification with no operator gate in front of it. Worktrees share --git-common-dir with
// their primary checkout, so this also catches "target is a Harvey worktree".
function assertNotHarveyItself(targetDir: string): void {
  const self = gitCommonDir(dirname(fileURLToPath(import.meta.url)));
  if (gitCommonDir(targetDir) === self) {
    throw new Error(`refusing to execute a fix against Harvey's own repository (${targetDir})`);
  }
}

export function executeFixDiff(findingId: string, diff: string, opts: ExecuteOptions): FixExecution {
  const facts = parseDiffFacts(diff);
  const base: FixExecution = {
    findingId,
    outcome: "aborted",
    baselineCommit: opts.baselineCommit,
    files: facts.files,
    createdFiles: facts.createdFiles,
    changedLines: facts.changedLines,
    railViolations: [],
  };

  if (facts.files.length + facts.createdFiles.length === 0) {
    return { ...base, abortReason: "diff declares no file changes" };
  }

  const rails = checkBlastRadius(blastRadiusOf(facts), opts.allowlist, opts.diffCap);
  if (!rails.ok) {
    return { ...base, outcome: "rails-blocked", railViolations: (rails.violation ?? "").split("; ") };
  }

  assertNotHarveyItself(opts.targetDir);
  try {
    git(opts.targetDir, ["rev-parse", "--verify", `${opts.baselineCommit}^{commit}`]);
  } catch {
    return { ...base, abortReason: `baseline commit ${opts.baselineCommit} not found in ${opts.targetDir}` };
  }

  const worktree = mkdtempSync(join(tmpdir(), "harvey-fix-"));
  try {
    git(opts.targetDir, ["worktree", "add", "--detach", worktree, opts.baselineCommit]);
    const result = verifySuggestedFix(diff, { targetDir: worktree, effectCommand: opts.effectCommand });
    return { ...base, outcome: result.verified ? "diff-verified" : "verify-failed", verification: result.detail };
  } finally {
    disposeWorktree(opts.targetDir, worktree);
  }
}

function disposeWorktree(targetDir: string, worktree: string): void {
  try {
    git(targetDir, ["worktree", "remove", "--force", worktree]);
  } catch {
    // `worktree add` may have failed before registering the path; the rm + prune below still
    // clean up, and swallowing here keeps the original failure as the thrown error.
  }
  rmSync(worktree, { recursive: true, force: true });
  git(targetDir, ["worktree", "prune"]);
}
