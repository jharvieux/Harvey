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
    ? closeSelftestCases().map((c) => ({ name: c.name, expect: c.expect, actual: checkClosedIssue(c.input, SELFTEST_LOOKUP, undefined, SELFTEST_WORLD).ok ? "pass" : "fail" }))
    : selftestCases().map((c) => ({ name: c.name, expect: c.expect, actual: checkAcceptance(c.body, SELFTEST_LOOKUP, undefined, SELFTEST_WORLD).ok ? "pass" : "fail" }));
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

// `undefined` must mean "does not exist" and nothing else — a fetch that merely failed has to stop
// the run, never quietly become a nonexistent issue that fails the gate for the wrong reason.
const cache = new Map<string, IssueRecord | undefined>();
// `repo` is set when the closing reference named ANOTHER repository. `gh issue view N --repo
// owner/repo` resolves those (measured 2026-07-27 against OWASP/CheatSheetSeries#2196), so a
// cross-repo close is held to its own acceptance criteria instead of getting a NOT ASSESSED row.
function lookup(issue: number, repo?: string): IssueRecord | undefined {
  const key = `${repo ?? ""}#${issue}`;
  if (cache.has(key)) return cache.get(key);
  const where = repo ? ["--repo", repo] : repoArgs;
  const r = gh(["issue", "view", String(issue), ...where, "--json", "number,state,body,comments"]);
  if (r.status !== 0) {
    if (issueDoesNotExist(r.stderr)) {
      cache.set(key, undefined);
      return undefined;
    }
    die(`\`gh issue view ${issue}${repo ? ` --repo ${repo}` : ""}\` failed (exit ${r.status}): ${r.stderr.trim()}\n  A repository that does not RESOLVE is not a repository that does not EXIST — a private repo this token cannot read fails identically — so this stops the run rather than reporting the reference as nonexistent.`);
  }
  const raw = JSON.parse(r.stdout) as { number: number; state: string; body: string; comments: { body: string }[] };
  const record: IssueRecord = {
    number: raw.number,
    state: raw.state === "OPEN" ? "OPEN" : "CLOSED",
    body: raw.body ?? "",
    comments: (raw.comments ?? []).map((c) => c.body ?? ""),
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
    closedByPullRequestsReferences: { number: number }[];
  };
  cache.set(`#${issue}`, { number: raw.number, state: raw.state === "OPEN" ? "OPEN" : "CLOSED", body: raw.body ?? "", comments: (raw.comments ?? []).map((c) => c.body ?? "") });

  const linkedPrs = (raw.closedByPullRequestsReferences ?? []).map((pr) => {
    const p = gh(["pr", "view", String(pr.number), ...repoArgs, "--json", "body"]);
    if (p.status !== 0) die(`\`gh pr view ${pr.number}\` failed (exit ${p.status}): ${p.stderr.trim()}\n  A linked PR this gate cannot read is not a linked PR that carries no disposition.`);
    return { ref: `#${pr.number}`, body: (JSON.parse(p.stdout) as { body: string }).body ?? "" };
  });

  const closeReport = checkClosedIssue(
    { issue, linkedPrs, comments: (raw.comments ?? []).map((c) => c.body ?? ""), authorIsBot: raw.author?.is_bot === true },
    lookup,
    currentRepo(),
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
  process.exit(closeReport.ok ? 0 : 1);
}

const prFlag = flag("--pr");
const bodyFile = flag("--body-file");
if (!prFlag && !bodyFile) die("nothing to check — pass --pr <number>, --body-file <path>, --closed-issue <number>, --selftest or --selftest-close");

let body: string;
let source: string;
if (bodyFile) {
  body = readFileSync(bodyFile, "utf8");
  source = bodyFile;
} else {
  const r = gh(["pr", "view", prFlag!, ...repoArgs, "--json", "body"]);
  if (r.status !== 0) die(`\`gh pr view ${prFlag}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  body = (JSON.parse(r.stdout) as { body: string }).body ?? "";
  source = `PR #${prFlag}`;
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
for (const s of seeded) console.log(`⚠ SEEDED VIOLATION: ${s}`);
if (seeded.length > 0) console.log("  The gate MUST exit 1 below. Exit 0 means it cannot fail; exit 2 means it could not run.\n");

const report = checkAcceptance(body, lookup, currentRepo(), evidenceWorld());
console.log(args.includes("--json") ? JSON.stringify(report, null, 2) : formatAcceptance(report));
process.exit(report.ok ? 0 : 1);
