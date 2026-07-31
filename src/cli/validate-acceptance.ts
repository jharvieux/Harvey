// The acceptance-criteria conservation gate (#1315) and its remainder-liveness half (#1316).
//
//   pnpm exec tsx src/cli/validate-acceptance.ts --pr <number> [--repo <owner/repo>] [--json]
//   pnpm exec tsx src/cli/validate-acceptance.ts --body-file <path> [--json]
//   pnpm exec tsx src/cli/validate-acceptance.ts --closed-issue <number> [--act]
//   pnpm exec tsx src/cli/validate-acceptance.ts --selftest | --selftest-close
//
// Reads the PR body, finds every closing keyword, and asserts that each acceptance bullet of each
// issue it would close is mapped to `met` (with evidence), `split` (to a live remainder) or
// `relayed` (to a question recorded ON the issue). See src/acceptance-conservation.ts for why.
//
// --pr and --closed-issue evaluate THE SAME THING (#1562/#1581): the same venues — the body, every
// linked PR body (however many, minus the PR under test) and every comment on the issue, read
// cumulatively, one disposition per criterion across all of them — and, on --pr, the same close set,
// since `closingIssuesReferences` sees a Development-sidebar link that no keyword regex can. So a
// green --pr predicts the close verdict.
//
// PRE-FLIGHT, before the PR exists: write the body to a file and run
//   pnpm validate-acceptance --body-file <path> --repo <owner/repo>
// It reads the issues and their comments over `gh` exactly as --pr does, and names in its output the
// one thing it leaves unchecked without a PR number.
//
// Exit codes are three-valued ON PURPOSE, because the negative controls have to tell a gate that
// FAILED from a gate that could not RUN:
//   0  passed, or a green no-op (no closing keyword and no `remainder:` line)
//   1  the gate failed — a criterion is unaccounted for, or a remainder is dead
//   2  the gate could not run (no input, `gh` unavailable, a seed that could not be planted)
// A CI negative control that accepted "non-zero" would go green on exit 2, which is the shape
// #1246 found in five recorded falsifiers: an input-redirect error read as "the blocker holds".
//
// --closed-issue is #1341's half: a PR body is not the only way an issue closes. It reads every PR
// GitHub links to the issue (which covers the Development sidebar) PLUS the issue's own comments,
// and holds that union to the same rules. `--act` runs the failure action — comment, label, re-open
// once — and is what the acceptance-close workflow calls.
//
// --selftest runs the gate over the hermetic scenario in acceptance-conservation.ts: one healthy
// body that must PASS and eight seeded violations that must each FAIL, against a STUB checkout so
// the evidence-truth rules are exercised without depending on the working tree. It needs no network and no
// live issue state, so CI can prove the gate can still fail on a PR that closes nothing.
// --selftest-close does the same for the close path, one case per close path in both directions.
//
// --seed-drop-disposition / --seed-bare-evidence / --seed-remainder <n> plant the same violations
// into a REAL body (--pr / --body-file), mirroring validate-conservation.ts's --seed-* flags.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { readEntriesSafe, readNamesSafe } from "../fs-walk.js";
import { recordDeclaredNoOp, recordMeasured } from "../ci-liveness.js";
import { fileURLToPath } from "node:url";
import {
  checkAcceptance,
  checkClosedIssue,
  closeFailureComment,
  closeSelftestCases,
  formatAcceptance,
  formatClosedIssue,
  issueDoesNotExist,
  SELFTEST_LOOKUP,
  SELFTEST_WORLD,
  seedBareEvidence,
  seedDropDisposition,
  seedRemainder,
  selftestCases,
  type ClosingRef,
  type EvidenceWorld,
  type IssueRecord,
} from "../acceptance-conservation.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLOSE_LABEL = "acceptance-unaccounted";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(2);
}

if (args.includes("--selftest") || args.includes("--selftest-close")) {
  const closing = args.includes("--selftest-close");
  console.log(`Acceptance gate self-test (${closing ? "close path, #1341" : "PR body, #1315/#1316"}) — a hermetic scenario, so a green run proves the gate PASSES and CAN FAIL.\n`);
  const scored = closing
    ? closeSelftestCases().map((c) => ({ name: c.name, expect: c.expect, actual: checkClosedIssue(c.input, c.lookup, undefined, SELFTEST_WORLD).ok ? "pass" : "fail" }))
    : selftestCases().map((c) => ({ name: c.name, expect: c.expect, actual: checkAcceptance(c.body, SELFTEST_LOOKUP, undefined, SELFTEST_WORLD, c.extras).ok ? "pass" : "fail" }));
  let broken = 0;
  for (const c of scored) {
    const good = c.actual === c.expect;
    if (!good) broken++;
    console.log(`  ${good ? "✓" : "✗"} ${c.name} — expected ${c.expect}, got ${c.actual}`);
  }
  if (broken > 0) {
    console.error(`\n✗ ${broken} self-test case(s) wrong. A gate that cannot fail on a planted violation is not evidence of anything (#350/#1065).`);
    process.exit(1);
  }
  console.log("\n✓ every healthy case passes and every seeded violation fails.");
  // #1568: the self-test is this gate's negative control, and a workflow that skipped it would be
  // green having proved nothing. The count is what it actually scored, not what it intended to.
  // Two literal call sites rather than one with a computed id: the registry test greps for
  // `recordMeasured("<gate>"`, so an id assembled at runtime would read as produced by nothing.
  if (closing) recordMeasured("acceptance-close-selftest", scored.length, "hermetic close-path cases scored in both directions");
  else recordMeasured("acceptance-selftest", scored.length, "hermetic PR-body cases scored in both directions");
  process.exit(0);
}

/**
 * The checkout, so `met` evidence can be checked for TRUTH and not only for shape (#1320 bounds
 * audit). Built here rather than in the pure module, and only for a real run — the hermetic
 * self-test above must not depend on the working tree.
 *
 * This is UNCONDITIONAL, so THIS CLI never takes the shape-only branch: `src/` and `package.json`
 * are the files it is running out of, and their absence throws here rather than degrading to a
 * disclosure. The `NOT ASSESSED  no checkout supplied` row is a property of the LIBRARY API —
 * `checkAcceptance` called without an `EvidenceWorld` — and the design doc says so rather than
 * describing a CLI branch that cannot be reached.
 */
function evidenceWorld(): EvidenceWorld {
  const testNames = new Set<string>();
  const TITLE = /^\s*(?:it|test|describe)(?:\.\w+)?\(\s*"([^"]{8,})"/gm;
  const walk = (dir: string): void => {
    for (const e of readEntriesSafe(dir).entries) {
      const p = join(dir, e.name);
      if (e.isDirectory) walk(p);
      else if (e.name.endsWith(".test.ts")) for (const m of readFileSync(p, "utf8").matchAll(TITLE)) testNames.add(m[1]!);
    }
  };
  walk(join(REPO_ROOT, "src"));
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")) as { scripts?: Record<string, string> };
  return {
    topLevelEntries: new Set(readNamesSafe(REPO_ROOT).filter((n) => !n.startsWith("."))),
    pathExists: (p) => existsSync(resolve(REPO_ROOT, p)),
    scripts: new Set(Object.keys(pkg.scripts ?? {})),
    testNames,
  };
}

const gh = (ghArgs: string[]): { status: number; stdout: string; stderr: string } => {
  const r = spawnSync("gh", ghArgs, { encoding: "utf8" });
  if (r.error) die(`\`gh ${ghArgs.join(" ")}\` could not be run (${r.error.message}). This gate needs an authenticated gh; reporting a pass here would be the silent omission it exists to prevent.`);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

const repoFlag = flag("--repo");
const repoArgs = repoFlag ? ["--repo", repoFlag] : [];

/**
 * The repo whose name normalises `owner/repo#N` back to `#N`. Without it a body citing both `#1345`
 * and `jharvieux/Harvey#1345` fetches the same issue twice and reports it twice, so it is resolved
 * from the checkout rather than left to whether the caller happened to pass `--repo`. Resolution
 * failing is not fatal: the run is then exactly as un-normalised as it was before, which is a
 * duplicate row, not a wrong verdict.
 */
function currentRepo(): string | undefined {
  if (repoFlag) return repoFlag;
  const r = spawnSync("gh", ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], { encoding: "utf8" });
  return r.status === 0 ? (r.stdout ?? "").trim() || undefined : undefined;
}

// Resolved once, before anything can look an issue up: the lookup itself needs it to tell a
// cross-repo linked PR from a local one.
const self = currentRepo();

// `undefined` must mean "does not exist" and nothing else — a fetch that merely failed has to stop
// the run, never quietly become a nonexistent issue that fails the gate for the wrong reason.
const cache = new Map<string, IssueRecord | undefined>();
// `repo` is set when the closing reference named ANOTHER repository. `gh issue view N --repo
// owner/repo` resolves those (measured 2026-07-27 against OWASP/CheatSheetSeries#2196), so a
// cross-repo close is held to its own acceptance criteria instead of getting a NOT ASSESSED row.
/**
 * The bodies of the PRs GitHub links to an issue as closing it. Fetched here, into the lookup, so
 * the PR gate and the close gate read one venue list rather than two kept in step (#1581).
 * `closedByPullRequestsReferences` names the repository of each PR, so a cross-repo link resolves
 * instead of being fetched out of the wrong repo.
 */
function linkedPrBodies(refs: { number: number; repository?: { name: string; owner: { login: string } } }[]): { ref: string; body: string }[] {
  return refs.map((pr) => {
    const owner = pr.repository ? `${pr.repository.owner.login}/${pr.repository.name}` : undefined;
    const where = owner !== undefined && owner.toLowerCase() !== self?.toLowerCase() ? ["--repo", owner] : repoArgs;
    const p = gh(["pr", "view", String(pr.number), ...where, "--json", "body"]);
    if (p.status !== 0) die(`\`gh pr view ${pr.number}\` failed (exit ${p.status}): ${p.stderr.trim()}\n  A linked PR this gate cannot read is not a linked PR that carries no disposition.`);
    return { ref: `#${pr.number}`, body: (JSON.parse(p.stdout) as { body: string }).body ?? "" };
  });
}

function lookup(issue: number, repo?: string): IssueRecord | undefined {
  const key = `${repo ?? ""}#${issue}`;
  if (cache.has(key)) return cache.get(key);
  const where = repo ? ["--repo", repo] : repoArgs;
  const r = gh(["issue", "view", String(issue), ...where, "--json", "number,state,body,comments,closedByPullRequestsReferences"]);
  if (r.status !== 0) {
    if (issueDoesNotExist(r.stderr)) {
      cache.set(key, undefined);
      return undefined;
    }
    die(`\`gh issue view ${issue}${repo ? ` --repo ${repo}` : ""}\` failed (exit ${r.status}): ${r.stderr.trim()}\n  A repository that does not RESOLVE is not a repository that does not EXIST — a private repo this token cannot read fails identically — so this stops the run rather than reporting the reference as nonexistent.`);
  }
  const raw = JSON.parse(r.stdout) as { number: number; state: string; body: string; comments: { body: string }[]; closedByPullRequestsReferences?: { number: number; repository?: { name: string; owner: { login: string } } }[] };
  const record: IssueRecord = {
    number: raw.number,
    state: raw.state === "OPEN" ? "OPEN" : "CLOSED",
    body: raw.body ?? "",
    comments: (raw.comments ?? []).map((c) => c.body ?? ""),
    linkedPrs: linkedPrBodies(raw.closedByPullRequestsReferences ?? []),
  };
  cache.set(key, record);
  return record;
}

// #1341 — the close path. `closedByPullRequestsReferences` is the field that sees a Development-
// sidebar link: the sidebar records the same reference GitHub acts on at merge, and it is populated
// whether or not the PR body carries a keyword (measured 2026-07-28 against #1318 → PR #1343). A
// bare click leaves it empty, and the issue's own comments are then the whole surface.
const closedIssueFlag = flag("--closed-issue");
if (closedIssueFlag) {
  if (!/^\d+$/.test(closedIssueFlag)) die("--closed-issue needs an issue number");
  const issue = Number(closedIssueFlag);
  const r = gh(["issue", "view", String(issue), ...repoArgs, "--json", "number,state,body,comments,author,closedByPullRequestsReferences"]);
  if (r.status !== 0) die(`\`gh issue view ${issue}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  const raw = JSON.parse(r.stdout) as {
    number: number;
    state: string;
    body: string;
    comments: { body: string }[];
    author: { login: string; is_bot: boolean };
    closedByPullRequestsReferences: { number: number; repository?: { name: string; owner: { login: string } } }[];
  };
  cache.set(`#${issue}`, {
    number: raw.number,
    state: raw.state === "OPEN" ? "OPEN" : "CLOSED",
    body: raw.body ?? "",
    comments: (raw.comments ?? []).map((c) => c.body ?? ""),
    linkedPrs: linkedPrBodies(raw.closedByPullRequestsReferences ?? []),
  });

  const closeReport = checkClosedIssue(
    { issue, authorIsBot: raw.author?.is_bot === true },
    lookup,
    self,
    evidenceWorld(),
  );
  console.log(args.includes("--json") ? JSON.stringify(closeReport, null, 2) : formatClosedIssue(closeReport));

  // The failure ACTION, run here rather than in YAML so it is the same code the tests and the drill
  // exercise. Re-open ONCE: the label is the memory. Without it a human who closes the issue again
  // deliberately gets into a fight with a bot; with it, the second close stands and the label is the
  // standing record that a criterion was never accounted for.
  if (args.includes("--act")) {
    const labelled = gh(["issue", "view", String(issue), ...repoArgs, "--json", "labels", "--jq", "[.labels[].name] | join(\",\")"]).stdout.trim().split(",");
    const already = labelled.includes(CLOSE_LABEL);
    if (!closeReport.ok) {
      gh(["label", "create", CLOSE_LABEL, ...repoArgs, "--color", "B60205", "--description", "Closed with an acceptance criterion nothing accounted for (#1341)", "--force"]);
      gh(["issue", "edit", String(issue), ...repoArgs, "--add-label", CLOSE_LABEL]);
      gh(["issue", "comment", String(issue), ...repoArgs, "--body", closeFailureComment(closeReport)]);
      if (already) {
        console.log(`\nℹ ACTED: commented and re-labelled, and did NOT re-open — \`${CLOSE_LABEL}\` was already on this issue, so it has been through here once and the human's second close stands.`);
      } else {
        const reopen = gh(["issue", "reopen", String(issue), ...repoArgs]);
        console.log(reopen.status === 0 ? "\nℹ ACTED: commented, labelled and RE-OPENED. The gate holds the issue open until a disposition exists." : `\n✗ could not re-open #${issue}: ${reopen.stderr.trim()}`);
      }
    } else if (already) {
      gh(["issue", "edit", String(issue), ...repoArgs, "--remove-label", CLOSE_LABEL]);
      console.log(`\nℹ ACTED: removed \`${CLOSE_LABEL}\` — the dispositions are now on record, so the label would be a false statement about this issue.`);
    }
  }
  // #1568: this job answers to no PR and raises no alarm — it runs on `issues: [closed]`, so a run
  // that died in setup posts no comment and looks exactly like a close nobody had to object to.
  // The receipt is the only thing that tells those apart.
  if (closeReport.notAssessed) recordDeclaredNoOp("acceptance-close", closeReport.notAssessed);
  else recordMeasured("acceptance-close", 1, `closed issue #${issue} assessed over ${closeReport.surfacesRead.length} surface(s)`);
  process.exit(closeReport.ok ? 0 : 1);
}

const prFlag = flag("--pr");
const bodyFile = flag("--body-file");
if (!prFlag && !bodyFile) die("nothing to check — pass --pr <number>, --body-file <path>, --closed-issue <number>, --selftest or --selftest-close");

let body: string;
let source: string;
// `closingIssuesReferences` is the close set GITHUB will act on. It includes a Development-sidebar
// link, which carries no keyword the body regex could find — without it a PR that closes an issue
// on merge reads here as a PR that closes nothing, and the close gate then re-opens the issue.
let linkedCloses: ClosingRef[] = [];
let sidebarNote = "";
if (bodyFile) {
  body = readFileSync(bodyFile, "utf8");
  source = bodyFile;
  // Every clause here has to be true READ ALONE (#1573). The row used to open "reads the text
  // supplied and nothing else" and then correctly say two sentences later that issue comments WERE
  // read — and the opening clause is the part a skimmer keeps.
  sidebarNote = `ℹ NOT ASSESSED  --body-file takes the CLOSE SET from the supplied text alone, so GitHub's own \`closingIssuesReferences\` (which a Development-sidebar link populates with no keyword in the body) was NOT consulted. Issue comments and every LINKED PR body WERE read, over \`gh\`, so the one-disposition-per-criterion rule is checked in full. Re-run with \`--pr <n>\` once the PR exists for the sidebar half.${prFlag ? "" : " If this body already belongs to an open PR, pass `--pr <n>` alongside --body-file so that PR is not read as a linked venue AND as this body."}`;
} else {
  const r = gh(["pr", "view", prFlag!, ...repoArgs, "--json", "body,closingIssuesReferences"]);
  if (r.status !== 0) die(`\`gh pr view ${prFlag}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  const pr = JSON.parse(r.stdout) as { body: string; closingIssuesReferences?: { number: number; repository?: { name: string; owner: { login: string } } }[] };
  body = pr.body ?? "";
  source = `PR #${prFlag}`;
  linkedCloses = (pr.closingIssuesReferences ?? []).map((c) => {
    const owner = c.repository ? `${c.repository.owner.login}/${c.repository.name}` : undefined;
    return owner !== undefined && owner.toLowerCase() !== self?.toLowerCase()
      ? { repo: owner, number: c.number, ref: `${owner}#${c.number}` }
      : { number: c.number, ref: `#${c.number}` };
  });
}

const seeded: string[] = [];
try {
  if (args.includes("--seed-drop-disposition")) {
    const s = seedDropDisposition(body);
    body = s.body;
    seeded.push(`dropped the disposition line \`${s.dropped}\` — the bullet it mapped must now read UNMAPPED`);
  }
  if (args.includes("--seed-bare-evidence")) {
    const s = seedBareEvidence(body);
    body = s.body;
    seeded.push(`hollowed \`${s.replaced}\` out to a bare "done" — it must now fail the evidence check`);
  }
  const seedRemainderTarget = flag("--seed-remainder");
  if (args.includes("--seed-remainder")) {
    if (!seedRemainderTarget || !/^\d+$/.test(seedRemainderTarget)) die("--seed-remainder needs an issue number that is CLOSED or nonexistent");
    body = seedRemainder(body, Number(seedRemainderTarget));
    seeded.push(`appended \`remainder: #${seedRemainderTarget}\` — the liveness check must now fail naming which condition`);
  }
} catch (e) {
  die(`${(e as Error).message}. The negative control planted nothing, so a pass below would prove nothing.`);
}

console.log(`Acceptance conservation (#1315/#1316) — ${source}\n`);
if (sidebarNote) console.log(`${sidebarNote}\n`);
for (const s of seeded) console.log(`⚠ SEEDED VIOLATION: ${s}`);
if (seeded.length > 0) console.log("  The gate MUST exit 1 below. Exit 0 means it cannot fail; exit 2 means it could not run.\n");

// `selfPr` keeps this PR from being read twice: it is one of its issues' linked PRs as well as the
// body under test (#1581).
const report = checkAcceptance(body, lookup, self, evidenceWorld(), { linkedCloses, selfPr: prFlag ? `#${prFlag}` : undefined });
console.log(args.includes("--json") ? JSON.stringify(report, null, 2) : formatAcceptance(report));
// #1568. A PR that closes nothing is a legitimate green no-op, so it is DECLARED rather than left
// as an empty receipt — which is what a run that died before reading the PR would also leave.
if (report.noop) recordDeclaredNoOp("acceptance-pr", "this PR body carries no closing keyword, GitHub records no closing reference and there is no `remainder:` line, so there were no criteria to conserve");
else recordMeasured("acceptance-pr", report.issues.length + report.remainders.length, `issue(s) and remainder(s) held to their stated criteria from ${source}`);
process.exit(report.ok ? 0 : 1);
