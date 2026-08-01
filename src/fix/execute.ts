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

import { execFile } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join } from "node:path";
import { verifySuggestedFix } from "../trackers/fix-diff.js";
import { blastRadiusOf, checkBlastRadius, parseDiffFacts, type DiffCap } from "./rails.js";
import type { DetectorRun, VerificationEvidence } from "./verify.js";

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
  // Present only when `detectorAfter` was supplied AND the diff verified: the finding's own detector
  // re-run against the applied worktree (§2.3). Absent ⇒ the detector was never re-run here (no hook,
  // or the diff didn't clear the apply gate) — a caller must treat that as not-clean, never as green.
  detectorAfter?: DetectorRun;
  // Present only when the `evidence` hook was supplied and the detector re-ran: the full §2 evidence,
  // client checks included, assembled INSIDE the applied worktree (#1272). Absent ⇒ the client half
  // was never gathered here, which computeGreen refuses to score as green.
  evidence?: VerificationEvidence;
}

interface ExecuteOptions {
  targetDir: string; // the client checkout — a git repo, never this one
  baselineCommit: string; // pinned engagement commit the diff was written against
  allowlist: string[]; // engagement path allowlist (§3.1 rule 3)
  diffCap?: DiffCap;
  // Optional ground-truth check run inside the worktree after the diff applies (§2.2). Absent ⇒
  // apply-clean is the only gate, and the record says so.
  effectCommand?: string[];
  // Optional detector-after re-run (§2.3): once the diff applies clean, apply it into the worktree and
  // re-run the finding's own detector against the FIXED source. The interactive implementer (#1056)
  // uses this to score green from the same disposable worktree — the untrusted operator diff has to
  // make the detector stop firing, not just apply. Absent ⇒ apply-clean is the whole gate.
  detectorAfter?: (worktreeDir: string) => DetectorRun | Promise<DetectorRun>;
  // Optional §2.1/§2.2 client-verification pass (#1272): once the diff is applied into the worktree
  // and the detector has re-run, assemble the FULL verification evidence there — discovered client
  // commands actually executed against the fixed source, scored against a baseline. Runs only when
  // `detectorAfter` also ran, because green needs both halves and the assembler takes the detector
  // result as an input. Absent ⇒ the client half was not gathered and `evidence` is absent with it.
  evidence?: (worktreeDir: string, detectorAfter: DetectorRun) => VerificationEvidence | Promise<VerificationEvidence>;
}

const execFileAsync = promisify(execFile);

// stderr is piped, not inherited: the client repo's git chatter ("Preparing worktree…", a failed
// rev-parse) is this module's control flow, not the operator's report.
async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", ["-C", cwd, ...args], { encoding: "utf8" });
  return stdout.trim();
}

async function gitCommonDir(dir: string): Promise<string> {
  const out = await git(dir, ["rev-parse", "--git-common-dir"]);
  return realpathSync(isAbsolute(out) ? out : join(dir, out));
}

// Harvey must never be its own fix target: a diff scoped to a client repo that lands here would be
// a self-modification with no operator gate in front of it. Worktrees share --git-common-dir with
// their primary checkout, so this also catches "target is a Harvey worktree".
async function assertNotHarveyItself(targetDir: string): Promise<void> {
  const self = await gitCommonDir(dirname(fileURLToPath(import.meta.url)));
  if ((await gitCommonDir(targetDir)) === self) {
    throw new Error(`refusing to execute a fix against Harvey's own repository (${targetDir})`);
  }
}

// #1464: async end to end. Every child process this reaches — the git worktree calls here,
// verifySuggestedFix's `git apply`, and the client's own suite under the evidence hook — is now
// spawned rather than spawnSync'd, so an independent fix running in another slot makes progress
// while this one waits on the OS. The detector-after hook is awaited too, so a resolver that is
// itself async plugs in without changing this signature; today's resolvers are in-process AST
// engines plus an execFileSync semgrep replay (src/scan/semgrep.ts), so that ONE step still
// occupies the loop while it runs. Both facts are reported by the CLI, never assumed.
export async function executeFixDiff(findingId: string, diff: string, opts: ExecuteOptions): Promise<FixExecution> {
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

  await assertNotHarveyItself(opts.targetDir);
  try {
    await git(opts.targetDir, ["rev-parse", "--verify", `${opts.baselineCommit}^{commit}`]);
  } catch {
    return { ...base, abortReason: `baseline commit ${opts.baselineCommit} not found in ${opts.targetDir}` };
  }

  const worktree = mkdtempSync(join(tmpdir(), "harvey-fix-"));
  try {
    await git(opts.targetDir, ["worktree", "add", "--detach", worktree, opts.baselineCommit]);
    const result = await verifySuggestedFix(diff, { targetDir: worktree, effectCommand: opts.effectCommand });
    if (!result.verified) return { ...base, outcome: "verify-failed", verification: result.detail };
    // Detector-after (§2.3): verifySuggestedFix only `git apply --check`s, so the worktree is still at
    // baseline. Apply the diff for real, then re-run the detector against the fixed source. The worktree
    // is disposed in the finally, so no revert is needed.
    let detectorAfter: DetectorRun | undefined;
    if (opts.detectorAfter) {
      await applyDiff(worktree, diff);
      detectorAfter = await opts.detectorAfter(worktree);
    }
    const evidence = detectorAfter && opts.evidence ? await opts.evidence(worktree, detectorAfter) : undefined;
    return {
      ...base,
      outcome: "diff-verified",
      verification: result.detail,
      ...(detectorAfter ? { detectorAfter } : {}),
      ...(evidence ? { evidence } : {}),
    };
  } finally {
    await disposeWorktree(opts.targetDir, worktree);
  }
}

function applyDiff(worktree: string, diff: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = execFile("git", ["-C", worktree, "apply", "-"], { encoding: "utf8" }, (err) => (err ? reject(err) : resolve()));
    child.stdin?.end(diff);
  });
}

async function disposeWorktree(targetDir: string, worktree: string): Promise<void> {
  try {
    await git(targetDir, ["worktree", "remove", "--force", worktree]);
  } catch {
    // `worktree add` may have failed before registering the path; the rm + prune below still
    // clean up, and swallowing here keeps the original failure as the thrown error.
  }
  rmSync(worktree, { recursive: true, force: true });
  await git(targetDir, ["worktree", "prune"]);
}
