// Applicable-diff remediation (#825): the paid-tier upgrade of a Finding's prose `fix` into a
// mergeable unified diff, surfaced in the ticket body. This module owns two things — the mechanical
// verification gate that decides whether a proposed diff may be attached, and the pure markdown
// renderer that embeds a verified diff under the existing `**Fix:**` prose.
//
// Posture: diffs are INERT / for-review — nothing here applies a patch to the real target. The
// effect check runs against a DISPOSABLE worktree the caller (the paid-tier pass) hands in, and the
// diff is reverted afterwards so even that copy is left untouched. Only a diff that passes the gate
// is ever attached; an unverified proposal is dropped (fail loud — never file a patch we couldn't
// confirm applies).

import { execFile } from "node:child_process";
import type { SuggestedFix } from "../findings.js";
import { blastRadiusOf, checkDiffCap, isDenied, parseDiffFacts, type DiffCap } from "../fix/rails.js";

interface VerifyResult {
  verified: boolean;
  detail: string;
}

// A command run (exit 0 = pass) after the diff is applied, to confirm the fix achieves its stated
// effect. The cleanest case is M8: a diff that adds a mutant-killing test, whose effect command runs
// that test and confirms it passes against the fixed code. Absent ⇒ apply-clean is the only gate.
interface VerifyOptions {
  targetDir: string; // a disposable checkout of the target the diff is written against
  effectCommand?: string[]; // e.g. ["node", "-e", "..."] or ["pnpm", "vitest", "run", "kill-mutant.test.ts"]
  diffCap?: DiffCap; // engagement diff cap; defaults to the §3.1(4) 300-line/10-file rail
  run?: Runner; // injectable for tests; defaults to a child-process runner
}

type CmdResult = { ok: boolean; output: string };
type Runner = (file: string, args: string[], input: string | undefined, cwd: string) => Promise<CmdResult> | CmdResult;

// #1464: async so the whole ingest chain can yield — a caller running independent fixes under the §4
// concurrency caps needs every child process on this path off the event loop, not just the long ones.
const defaultRunner: Runner = (file, args, input, cwd) =>
  new Promise<CmdResult>((resolve) => {
    const child = execFile(file, args, { cwd, encoding: "utf8" }, (err, stdout, stderr) => {
      if (!err) return resolve({ ok: true, output: stdout });
      resolve({ ok: false, output: stderr || stdout || err.message || "" });
    });
    child.stdin?.end(input ?? "");
  });

// Mechanically verify a proposed diff: it must clear the §3 path/size rails, apply cleanly, and —
// where an effect command is given — achieve its stated effect. The rails run FIRST and delegate to
// the one rail implementation (src/fix/rails.ts), so a diff touching a denylisted path (.env, CI,
// keys) or exceeding the engagement diff cap can never be marked verified and thus never reaches a
// ticket body (renderFixSection is gated on `verified`). The diff is fed to git on stdin
// (`git apply -`), never written to the tree except transiently for the effect check, reverted in a
// finally.
export async function verifySuggestedFix(diff: string, opts: VerifyOptions): Promise<VerifyResult> {
  const facts = parseDiffFacts(diff);
  const denied = [...facts.files, ...facts.createdFiles].filter(isDenied);
  if (denied.length) return { verified: false, detail: `refuses denylisted path(s) (secrets/CI/keys/git): ${denied.join(", ")}` };
  const cap = checkDiffCap(blastRadiusOf(facts), opts.diffCap);
  if (!cap.ok) return { verified: false, detail: `exceeds engagement diff cap: ${cap.violation}` };

  const run = opts.run ?? defaultRunner;
  const git = (args: string[]) => run("git", args, diff, opts.targetDir);

  const check = await git(["apply", "--check", "-"]);
  if (!check.ok) return { verified: false, detail: `diff does not apply cleanly: ${check.output.trim() || "git apply --check failed"}` };
  if (!opts.effectCommand || opts.effectCommand.length === 0) {
    return { verified: true, detail: "applies cleanly (git apply --check)" };
  }

  const applied = await git(["apply", "-"]);
  if (!applied.ok) return { verified: false, detail: `apply failed: ${applied.output.trim()}` };
  try {
    const [file = "", ...args] = opts.effectCommand; // guaranteed non-empty by the guard above
    const effect = await run(file, args, undefined, opts.targetDir);
    const cmd = opts.effectCommand.join(" ");
    return effect.ok
      ? { verified: true, detail: `applies cleanly; effect confirmed via \`${cmd}\`` }
      : { verified: false, detail: `applies cleanly but effect check failed (\`${cmd}\` exited non-zero)` };
  } finally {
    await git(["apply", "-R", "-"]); // leave the disposable checkout as we found it
  }
}

// Pure markdown for the ticket body: the verified diff in a ```diff fence, under the prose fix. Only
// ever called with a verified fix (findings-to-tickets gates on suggestedFix.verified).
export function renderFixSection(fix: SuggestedFix): string[] {
  const lines = ["**Suggested fix** (inert — for review, not auto-applied):", "", "```diff", fix.diff.replace(/\n+$/, ""), "```", ""];
  if (fix.verification) lines.push(`_Mechanically verified: ${fix.verification}_`, "");
  return lines;
}
