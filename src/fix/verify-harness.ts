// Verification harness (design §2.1/§2.2/§2.4): the half of the verification contract that proves the
// CLIENT's own checks still pass. It reads a real checkout, discovers verify commands from its
// package.json(s) and its PR-triggered workflow run: steps (recording which came from where), runs a
// BASELINE on the pinned commit so pre-existing failures are never attributed to a fix, and assembles a
// VerificationEvidence whose `green` is DECIDED by computeGreen — no caller asserts it. Paired with the
// detector re-run (§2.3, src/fix/detector-rerun.ts): green needs both halves.

import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { readNamesSafe } from "../fs-walk.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { parse } from "yaml";
import {
  computeGreen,
  runCommand,
  type CommandRun,
  type DetectorRun,
  type VerificationEvidence,
} from "./verify.js";
import { discoverVerifyCommands } from "./verify.js";

// A command to run, with where it came from (§2.1: "records which came from where"). `workspace` is
// the repo-relative dir it runs in ("" = root); a monorepo runs each affected workspace plus the root.
export interface DiscoveredCommand {
  command: string;
  workspace: string;
  source: string; // e.g. "package.json (root)", "package.json (apps/web)", "ci-workflow (ci.yml)"
  notRunnableLocally?: string; // explicit workflow semantics that require the Actions runtime
}

type Runner = (command: string, cwd: string) => Promise<CommandRun>;

const execFileAsync = promisify(execFile);

function readScripts(dir: string): Record<string, string> | undefined {
  const p = join(dir, "package.json");
  if (!existsSync(p)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(p, "utf8")) as { scripts?: Record<string, string> };
    return parsed.scripts ?? {};
  } catch {
    return undefined;
  }
}

export const cmdKey = (c: Pick<DiscoveredCommand, "command" | "workspace" | "notRunnableLocally">) =>
  `${c.workspace}\u0000${c.command}\u0000${c.notRunnableLocally ?? ""}`;

/**
 * A baseline result is a property of `(targetDir, baselineCommit, workspace, command)` and nothing
 * else — the run happens in a worktree cut at that commit, in that workspace, so two findings in one
 * batch that discover the same command get the same answer (#1529). The commit and the checkout are
 * in the key so a cache reused across batches, or across two engagements in one process, keeps each
 * target's baseline to its own target.
 *
 * It holds the IN-FLIGHT PROMISE, not the finished run (#1464). Once the ingest is async, two
 * components genuinely overlap, and a map of finished runs is only populated after the first one
 * returns — so a second worker entering the same window would find it empty and run the client's
 * own suite a second time, silently undoing #1529's saving.
 */
export type BaselineCache = Map<string, Promise<CommandRun>>;

export const baselineCacheKey = (targetDir: string, baselineCommit: string, c: Pick<DiscoveredCommand, "command" | "workspace">): string =>
  `${targetDir}\u0000${baselineCommit}\u0000${cmdKey(c)}`;

// Which runner the client's own scripts are meant to be invoked with, read off the committed
// lockfile. It matters: `pnpm run <script>` performs a deps-status check that fails in a repo whose
// lockfile it does not find, which would report every discovered command as broken for a reason that
// has nothing to do with any fix. npm is the fallback because it runs a script without one.
const LOCKFILE_RUNNERS: readonly (readonly [string, string])[] = [
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lockb", "bun"],
  ["package-lock.json", "npm"],
];

export function detectRunner(targetDir: string): string {
  return LOCKFILE_RUNNERS.find(([file]) => existsSync(join(targetDir, file)))?.[1] ?? "npm";
}

// §2.1 step 1 + step 2. `affectedWorkspaces` are repo-relative dirs the fix touches (monorepo rule:
// per affected workspace plus the root). `ciSteps` are PR-triggered workflow run steps (extractCiRunSteps).
export function discoverClientCommands(
  targetDir: string,
  affectedWorkspaces: string[] = [],
  runner = "pnpm",
  ciSteps: DiscoveredCommand[] = [],
): DiscoveredCommand[] {
  const out: DiscoveredCommand[] = [];
  const seen = new Set<string>();
  const add = (command: string, workspace: string, source: string, notRunnableLocally?: string) => {
    const c: DiscoveredCommand = { command, workspace, source, ...(notRunnableLocally ? { notRunnableLocally } : {}) };
    if (seen.has(cmdKey(c))) return;
    seen.add(cmdKey(c));
    out.push(c);
  };
  for (const cmd of discoverVerifyCommands(readScripts(targetDir), runner)) add(cmd, "", "package.json (root)");
  for (const ws of affectedWorkspaces) {
    const scripts = readScripts(join(targetDir, ws));
    if (!scripts) continue;
    for (const cmd of discoverVerifyCommands(scripts, runner)) add(cmd, ws, `package.json (${ws})`);
  }
  for (const step of ciSteps) add(step.command, step.workspace, step.source, step.notRunnableLocally);
  return out;
}

// §2.1 step 2: PR-triggered workflow run: steps. Trigger admission stays a narrow textual check;
// admitted workflows are parsed as YAML so run blocks and their effective working-directory values
// remain attached to the same step instead of being reconstructed from unrelated lines.
export function isPullRequestTriggered(yaml: string): boolean {
  const lines = yaml.split("\n");
  const onIdx = lines.findIndex((l) => /^on:/.test(l));
  if (onIdx === -1) return false;
  // `on: [pull_request, push]` inline
  if (/^on:\s*\[.*pull_request.*\]/.test(lines[onIdx] as string)) return true;
  if (/^on:\s*pull_request\b/.test(lines[onIdx] as string)) return true;
  // block form: scan the indented lines under `on:` for a `pull_request:` (or `- pull_request`) key
  for (let i = onIdx + 1; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line.trim() === "") continue;
    if (/^\S/.test(line)) break; // dedented back to a top-level key — end of the on: block
    if (/^\s+(-\s*)?pull_request\b/.test(line)) return true;
  }
  return false;
}

export function extractCiRunSteps(workflowsDir: string): DiscoveredCommand[] {
  if (!existsSync(workflowsDir)) return [];
  const steps: DiscoveredCommand[] = [];
  const seen = new Set<string>();
  for (const file of readNamesSafe(workflowsDir).filter((f) => /\.ya?ml$/.test(f))) {
    const yaml = readFileSync(join(workflowsDir, file), "utf8");
    if (!isPullRequestTriggered(yaml)) continue;
    for (const step of extractRunCommands(yaml, file)) {
      const key = cmdKey(step);
      if (seen.has(key)) continue;
      seen.add(key);
      steps.push(step);
    }
  }
  return steps;
}

interface WorkflowRunDefaults { "working-directory"?: unknown }
interface WorkflowJob {
  defaults?: { run?: WorkflowRunDefaults };
  steps?: unknown[];
}

function ownWorkingDirectory(value: unknown): { present: boolean; value?: unknown } {
  if (!value || typeof value !== "object" || !("working-directory" in value)) return { present: false };
  return { present: true, value: (value as WorkflowRunDefaults)["working-directory"] };
}

function resolveWorkingDirectory(value: unknown): Pick<DiscoveredCommand, "workspace" | "notRunnableLocally"> {
  if (typeof value !== "string") {
    return { workspace: "", notRunnableLocally: "non-string workflow working-directory requires GitHub Actions" };
  }
  const raw = value.trim();
  if (raw.includes("${{")) {
    return { workspace: "", notRunnableLocally: `dynamic workflow working-directory \`${raw}\` requires GitHub Actions` };
  }
  if (raw === "" || raw.startsWith("/") || /^[A-Za-z]:[\\/]/.test(raw) || raw.includes("\\")) {
    return { workspace: "", notRunnableLocally: `unsupported workflow working-directory \`${raw}\` requires GitHub Actions` };
  }
  const parts = raw.replace(/^\.\//, "").split("/");
  if (parts.some((part) => part === "..")) {
    return { workspace: "", notRunnableLocally: `escaping workflow working-directory \`${raw}\` requires GitHub Actions` };
  }
  const workspace = parts.filter((part) => part !== "" && part !== ".").join("/");
  return { workspace };
}

function extractRunCommands(yaml: string, file: string): DiscoveredCommand[] {
  let document: unknown;
  try {
    document = parse(yaml);
  } catch {
    return [];
  }
  if (!document || typeof document !== "object") return [];
  const root = document as { defaults?: { run?: WorkflowRunDefaults }; jobs?: unknown };
  if (!root.jobs || typeof root.jobs !== "object" || Array.isArray(root.jobs)) return [];
  const workflowDefault = ownWorkingDirectory(root.defaults?.run);
  const commands: DiscoveredCommand[] = [];
  for (const rawJob of Object.values(root.jobs)) {
    if (!rawJob || typeof rawJob !== "object" || Array.isArray(rawJob)) continue;
    const job = rawJob as WorkflowJob;
    const jobDefault = ownWorkingDirectory(job.defaults?.run);
    if (!Array.isArray(job.steps)) continue;
    for (const rawStep of job.steps) {
      if (!rawStep || typeof rawStep !== "object" || Array.isArray(rawStep)) continue;
      const step = rawStep as Record<string, unknown>;
      if (typeof step.run !== "string" || step.run.trim() === "") continue;
      const stepDefault = ownWorkingDirectory(step);
      const effective = stepDefault.present ? stepDefault : jobDefault.present ? jobDefault : workflowDefault;
      const directory = effective.present ? resolveWorkingDirectory(effective.value) : { workspace: "" };
      commands.push({
        command: step.run.trim(),
        source: `ci-workflow (${file})`,
        ...directory,
      });
    }
  }
  return commands;
}

// Baseline run on the pinned commit (§2.1 step 3), keyed so the fixed run can look each command up.
// Serial WITHIN one baseline root on purpose: these commands share a single worktree (and its linked
// node_modules), so overlapping them would have two builds writing the same caches. Cross-component
// overlap is the scheduler's job (§4 maxClientChecks), not this loop's.
export async function runBaseline(commands: DiscoveredCommand[], baselineRoot: string, run: Runner = runCommand): Promise<Map<string, CommandRun>> {
  const m = new Map<string, CommandRun>();
  for (const c of commands) m.set(cmdKey(c), await run(c.command, join(baselineRoot, c.workspace)));
  return m;
}

// A freshly-cut worktree has no node_modules, so every discovered `pnpm run <script>` would fail
// there for a reason that has nothing to do with the fix. The baseline run would record the same
// failure and mark the check skipped — honest, but it would mean the client half never actually
// executes on any real Node repo. Linking the target checkout's installed tree in makes the
// commands genuinely runnable; when the target has no node_modules this is a silent no-op and the
// baseline mechanism handles the fallout, as designed.
export function linkNodeModules(fromDir: string, toDir: string): void {
  const src = join(fromDir, "node_modules");
  const dest = join(toDir, "node_modules");
  if (!existsSync(src) || existsSync(dest)) return;
  try {
    symlinkSync(src, dest, "dir");
  } catch {
    // A read-only or cross-device destination just means the checks run without it; the baseline
    // comparison still keeps the resulting failures off the fix's record.
  }
}

// Run `fn` against a disposable worktree of `targetDir` pinned at `commit` — the §2.1 step-3 baseline
// root. It is a real checkout of the pinned commit, never the operator's working tree, so a dirty or
// moved-on client checkout never leaks into the baseline the fix is measured against.
export async function withBaselineWorktree<T>(targetDir: string, commit: string, fn: (root: string) => Promise<T>): Promise<T> {
  const git = (args: string[]) => execFileAsync("git", ["-C", targetDir, ...args], { encoding: "utf8" });
  const root = mkdtempSync(join(tmpdir(), "harvey-baseline-"));
  try {
    await git(["worktree", "add", "--detach", root, commit]);
    linkNodeModules(targetDir, root);
    return await fn(root);
  } finally {
    try {
      await git(["worktree", "remove", "--force", root]);
    } catch {
      // `worktree add` may have failed before registering the path; the rm + prune still clean up.
    }
    rmSync(root, { recursive: true, force: true });
    await git(["worktree", "prune"]);
  }
}

interface EvidenceInputs {
  findingId: string;
  baselineCommit: string;
  worktreeCommit: string;
  detectorBefore: DetectorRun;
  detectorAfter: DetectorRun; // from rerunDetector against the fixed worktree (§2.3)
  commands: DiscoveredCommand[];
  baseline: Map<string, CommandRun>; // runBaseline output
  needsCi?: (c: DiscoveredCommand) => boolean; // steps that can't run locally (§2.2) → skipped needs-ci
  newTestAdded?: string;
  attempts?: number;
}

// Run the discovered commands in the FIXED worktree and assemble the evidence. A command that failed on
// the baseline is recorded once as skipped:"pre-existing-failure-on-baseline" and never re-attributed to
// the fix; a needs-ci command is recorded skipped:"needs-ci" and not run locally. `green` is DECIDED by
// computeGreen — every output is already secrets-scrubbed by runCommand.
export async function buildVerificationEvidence(inputs: EvidenceInputs, fixedRoot: string, run: Runner = runCommand): Promise<VerificationEvidence> {
  const clientChecks: CommandRun[] = [];
  for (const c of inputs.commands) {
    const cwd = join(fixedRoot, c.workspace);
    if (inputs.needsCi?.(c)) {
      clientChecks.push({
        command: c.command,
        cwd,
        exitCode: 0,
        durationMs: 0,
        outputTail: c.notRunnableLocally ?? "dynamic workflow command requires GitHub Actions",
        skipped: "needs-ci",
      });
      continue;
    }
    const baselineRun = inputs.baseline.get(cmdKey(c));
    if (baselineRun && baselineRun.exitCode !== 0) {
      clientChecks.push({ ...baselineRun, cwd, skipped: "pre-existing-failure-on-baseline" });
      continue;
    }
    clientChecks.push(await run(c.command, cwd));
  }

  const evidence: Omit<VerificationEvidence, "green"> = {
    findingId: inputs.findingId,
    worktreeCommit: inputs.worktreeCommit,
    baselineCommit: inputs.baselineCommit,
    detectorBefore: inputs.detectorBefore,
    detectorAfter: inputs.detectorAfter,
    clientChecks,
    newTestAdded: inputs.newTestAdded,
    attempts: inputs.attempts ?? 1,
  };
  return { ...evidence, green: computeGreen(evidence) };
}
