// Branch + push + draft-PR transport (design §1.4/§3.1/§6/§7). THIS IS THE FIRST PRIVILEGED,
// NETWORK-WRITING CODE PATH IN THE REPO. Every git push and every gh call goes through the one wrapped
// client below, where the push-ref and protected-branch rails are enforced at the WRAPPER, not left to
// a caller to remember (§3.1 rule 1). The only PR-affecting command the pipeline may issue is
// the fixed pull-request creation endpoint with draft=true; there is NO merge, ready-for-review,
// or repo-settings call anywhere in this
// module — absent, not merely unused (§6 Phase 1). Outbound operations run only when a caller invokes
// them explicitly; nothing here touches git or the network at import time. A draft PR is opened ONLY on
// a verified-green result, and `--dry-run` (the default) withholds every push.

import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { fixBranch, prTitle, renderPrBody, type FixResult } from "./result.js";
import { checkPushRef, isDenied, isProtectedBranch } from "./rails.js";
import type { VerificationEvidence } from "./verify.js";

// Injectable so tests never shell out to real git/gh, and so a refusal can be proven to happen BEFORE
// any command is issued (the fake records calls; the refusal tests assert it was never called).
export type CommandRunner = (file: "git" | "gh", args: string[], cwd: string, input?: string) => string;

const defaultRunner: CommandRunner = (file, args, cwd, input) => {
  // git is scoped with -C so it acts on the client checkout; gh reads the repo from cwd.
  const full = file === "git" ? ["-C", cwd, ...args] : args;
  try {
    return execFileSync(file, full, { cwd, encoding: "utf8", input, stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch (error) {
    if (file !== "gh") throw error;
    // The remote may echo the submitted body. Do not retain the original error or its streams.
    const status = error !== null && typeof error === "object" && "status" in error && typeof error.status === "number" ? `exit ${error.status}` : "spawn failure";
    throw new Error(`gh transport failed (${status}); output withheld (verify the remote before retrying)`);
  }
};

interface GitGhClient {
  targetDir: string;
  dryRun: boolean; // §3.1 rule 5 default — the first run of every engagement withholds all pushes
  protectedBranches: string[];
  run: CommandRunner;
}

export function createClient(opts: {
  targetDir: string;
  dryRun?: boolean;
  protectedBranches?: string[];
  run?: CommandRunner;
}): GitGhClient {
  return {
    targetDir: opts.targetDir,
    dryRun: opts.dryRun ?? true, // default DRY-RUN — a live push is an explicit opt-in
    protectedBranches: opts.protectedBranches ?? [],
    run: opts.run ?? defaultRunner,
  };
}

// A Harvey remote is a worse failure than a bad diff (§925 safety note): the push path gets the same
// self-protection as executeFixDiff. Worktrees share --git-common-dir with their primary checkout.
function gitCommonDir(client: GitGhClient, dir: string): string {
  const out = client.run("git", ["rev-parse", "--git-common-dir"], dir);
  return realpathSync(isAbsolute(out) ? out : join(dir, out));
}

function assertNotHarveyItself(client: GitGhClient): void {
  const self = gitCommonDir(client, dirname(fileURLToPath(import.meta.url)));
  if (gitCommonDir(client, client.targetDir) === self) {
    throw new Error(`refusing to push to Harvey's own repository (${client.targetDir})`);
  }
}

// Branch creation at the pinned baseline, ref-checked at the wrapper.
function createFixBranch(client: GitGhClient, findingId: string, baselineCommit: string): string {
  const ref = fixBranch(findingId);
  assertRefPushable(client, ref);
  client.run("git", ["checkout", "-b", ref, baselineCommit], client.targetDir);
  return ref;
}

// The wrapper-level rail (§3.1 rule 1): a non-harvey/fix ref or a protected-branch target is refused
// HERE, before any git command runs — a caller cannot bypass it by forgetting to ask.
function assertRefPushable(client: GitGhClient, ref: string): void {
  const refCheck = checkPushRef(ref);
  if (!refCheck.ok) throw new Error(refCheck.violation);
  const branch = ref.replace(/^refs\/heads\//, "");
  if (isProtectedBranch(branch, client.protectedBranches)) throw new Error(`refusing push to protected branch: ${branch}`);
}

export function pushFixBranch(client: GitGhClient, ref: string): { pushed: boolean; reason?: string } {
  assertRefPushable(client, ref);
  if (client.dryRun) return { pushed: false, reason: "--dry-run: push withheld" };
  assertNotHarveyItself(client);
  client.run("git", ["push", "-u", "origin", ref], client.targetDir);
  return { pushed: true };
}

interface DraftPrInput {
  base: string; // the client's default branch — the PR targets it, never stacks
  head: string; // harvey/fix/<id>
  title: string;
  body: string;
}

// The ONLY PR-affecting command the pipeline issues. Draft always; the operator flips to ready (§1.5).
export function openDraftPr(client: GitGhClient, input: DraftPrInput): { url?: string; opened: boolean; reason?: string } {
  assertRefPushable(client, input.head);
  if (client.dryRun) return { opened: false, reason: "--dry-run: draft PR withheld" };
  assertNotHarveyItself(client);
  // The CLI's --title flag has no stdin form. The fixed draft-create API accepts the complete
  // title/body as JSON stdin without placing either value in argv or another process environment.
  const reply = client.run(
    "gh",
    ["api", "--method", "POST", "repos/{owner}/{repo}/pulls", "--input", "-", "--jq", "{url: .html_url, draft: .draft}"],
    client.targetDir,
    JSON.stringify({ base: input.base, head: input.head, title: input.title, body: input.body, draft: true, maintainer_can_modify: true }),
  );
  try {
    const result: unknown = JSON.parse(reply);
    if (result !== null && typeof result === "object" && "draft" in result && result.draft === true && "url" in result && typeof result.url === "string") {
      const url = new URL(result.url);
      if (url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && /^\/[^/]+\/[^/]+\/pull\/[1-9]\d*$/.test(url.pathname)) {
        return { url: result.url, opened: true };
      }
    }
  } catch { /* An invalid reply is not proof that creation succeeded; never echo its payload. */ }
  throw new Error("gh draft PR creation returned an invalid draft response; output withheld (verify the remote before retrying)");
}

// §7 rollback paragraph must be TRUE for every PR opened (enforcement mirror of §3.1 rule 6): no
// migrations, no dependency changes, no config changes. Returns the offending path, if any.
const ROLLBACK_UNSAFE: readonly RegExp[] = [
  /(^|\/)migrations?\//i,
  /\.sql$/i,
  /(^|\/)package(-lock)?\.json$/,
  /(^|\/)pnpm-lock\.yaml$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)(next|vite|vercel|tsconfig|astro|svelte)\.config\.[cm]?[jt]s(on)?$/i,
];

export function violatesRollback(files: string[]): string | undefined {
  return files.find((f) => isDenied(f) || ROLLBACK_UNSAFE.some((re) => re.test(f.replace(/^\.\//, ""))));
}

interface DeliverInput {
  finding: Finding;
  plan: FixPlan;
  evidence: VerificationEvidence;
  operator: string;
  baseBranch: string; // client's default branch
  summary: string; // imperative PR-title summary
  tiersUsed: FixPlan["tier"][];
}

// Turn a verified fix into a draft PR (or an honest recommend-only). A PR is opened ONLY when the
// evidence computed green (§925 acceptance); a non-green fix is recommend-only with the failure
// evidence attached — the transport is never reached. A green fix whose diff would falsify the rollback
// paragraph aborts rather than opening a PR that lies.
export function deliverFix(client: GitGhClient, input: DeliverInput): FixResult {
  const { finding, plan, evidence } = input;
  const railEvents: string[] = [];
  const base: FixResult = { findingId: finding.id, outcome: "recommend-only", plan, evidence, tiersUsed: input.tiersUsed, railEvents };

  if (!evidence.green) {
    return { ...base, downgradeOrAbortReason: "verification not green — see attached evidence" };
  }

  const touched = [...plan.blastRadius.files, ...plan.blastRadius.createdFiles];
  const unsafe = violatesRollback(touched);
  if (unsafe) {
    railEvents.push(`rollback paragraph would be false (touches ${unsafe}) — aborting rather than opening a lying PR`);
    return { ...base, outcome: "aborted", downgradeOrAbortReason: `rollback-unsafe path in fix: ${unsafe}` };
  }

  const ref = createFixBranch(client, finding.id, evidence.baselineCommit);
  const body = renderPrBody({ ...base, outcome: "pr-opened", branch: ref }, finding, input.operator);
  const push = pushFixBranch(client, ref);
  if (!push.pushed) {
    railEvents.push(push.reason ?? "push withheld");
    return { ...base, branch: ref, downgradeOrAbortReason: `${push.reason} — draft PR withheld pending a live run` };
  }
  const pr = openDraftPr(client, { base: input.baseBranch, head: ref, title: prTitle(finding, input.summary), body });
  return { ...base, outcome: "pr-opened", branch: ref, prUrl: pr.url, railEvents };
}
