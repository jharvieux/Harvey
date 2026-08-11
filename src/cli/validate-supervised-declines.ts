// pnpm exec tsx src/cli/validate-supervised-declines.ts [--since-days N] [--pr N ...] [--all-history] [--selftest]
//
// #1545. Reads MERGED PR BODIES for the repo's densest false-decline family — "X is a supervised
// path", written in the same grammar as "X is impossible" — and reports every instance carrying no
// relay artifact. Why this is a scheduled scan and not a PR-blocking gate: the decline is prose, the
// prose is often EDITED after the merge, and the check has to read the issue it names as well, so
// there is no moment at merge time when the answer is stable. See src/supervised-declines.ts for
// the rule and for why a filed tracking issue is not a relay.
//
// Exit codes, three-valued like the other gates in this repo:
//   0  no unrelayed decline in the window (or --selftest passed)
//   1  at least one unrelayed decline — named, with the issues it did and did not ask
//   2  could not run (no gh, a bad flag, a fetch that failed)
// A control that accepted "non-zero" would go green on exit 2 (#1246).
//
// --since-days defaults to 1, matching the daily cadence: the scan is over what merged since the
// last run, so a standing backlog of historical instances never makes it permanently red. The
// historical population is in the issue and in the report's own footer, not in this exit code.

import "./sync-stdio.js";
import { spawnSync } from "node:child_process";
import { recordDeclaredNoOp, recordMeasured } from "../ci-liveness.js";
import {
  findSupervisedDeclines,
  judgeDecline,
  ROUTINELY_GRANTED,
  selftestCases,
  supervisedDeclineTriage,
  type IssueLike,
} from "../supervised-declines.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(2);
}

const gh = (ghArgs: string[]): { status: number; stdout: string; stderr: string } => {
  // maxBuffer, because the input IS the prose: 200 PR bodies from this repo overran the 1 MB
  // default and spawnSync returned ENOBUFS (MEASURED 2026-07-31 over a 4-day window). It exited 2
  // rather than 0, which is the three-valued design doing its job — but a scan that cannot read is
  // a scan that must not report a clean window.
  const r = spawnSync("gh", ghArgs, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) die(`\`gh ${ghArgs.join(" ")}\` could not be run (${r.error.message}). Reporting "no unrelayed declines" without having read anything is the silent omission this check exists to find.`);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

if (args.includes("--selftest")) {
  console.log("Supervised-decline scan self-test (#1545) — hermetic, so a green run proves the check FIRES and can stay SILENT.\n");
  let broken = 0;
  for (const c of selftestCases()) {
    const lookup = (n: number): IssueLike | undefined => c.issues.find((i) => i.number === n);
    const verdicts = findSupervisedDeclines(c.body).map((h) => judgeDecline(h, c.body, lookup));
    const actual = verdicts.some((v) => v.relay === "none") ? "flagged" : "clear";
    const good = actual === c.expect;
    if (!good) broken++;
    console.log(`  ${good ? "✓" : "✗"} ${c.name} — expected ${c.expect}, got ${actual}`);
  }
  if (broken > 0) {
    console.error(`\n✗ ${broken} self-test case(s) wrong. A check that cannot fire, or that fires on everything, measures nothing (#350/#1065).`);
    process.exit(1);
  }
  console.log("\n✓ every unrelayed decline is flagged and every relayed one is left alone.");
  recordMeasured("supervised-declines-selftest", selftestCases().length, "hermetic decline/relay cases scored in both directions");
  process.exit(0);
}

const issueCache = new Map<number, IssueLike | undefined>();
function lookupIssue(n: number): IssueLike | undefined {
  if (issueCache.has(n)) return issueCache.get(n);
  const r = gh(["issue", "view", String(n), "--json", "number,body,comments"]);
  // A PR number resolves through `gh issue view` too, which is what we want: a decline that names a
  // PR carrying the operator's own words is as good a relay as one naming an issue.
  const record = r.status === 0
    ? ((): IssueLike => {
        const raw = JSON.parse(r.stdout) as { number: number; body: string; comments: { body: string }[] };
        return { number: raw.number, body: raw.body ?? "", comments: (raw.comments ?? []).map((c) => c.body ?? "") };
      })()
    : undefined;
  issueCache.set(n, record);
  return record;
}

interface Pr {
  number: number;
  title: string;
  body: string;
  mergedAt: string;
}

const DEFAULT_SINCE_DAYS = 1;

function allMergedPrs(): Pr[] {
  const repo = gh(["repo", "view", "--json", "nameWithOwner"]);
  if (repo.status !== 0) die(`\`gh repo view\` failed (exit ${repo.status}): ${repo.stderr.trim()}`);
  const [owner, name] = (JSON.parse(repo.stdout) as { nameWithOwner: string }).nameWithOwner.split("/");
  if (!owner || !name) die("could not resolve owner/repo for the historical scan");
  const query = `query($owner:String!,$name:String!,$after:String){
    repository(owner:$owner,name:$name){
      pullRequests(first:50,states:MERGED,after:$after,orderBy:{field:CREATED_AT,direction:ASC}){
        pageInfo{hasNextPage endCursor}
        nodes{number title body mergedAt}
      }
    }
  }`;
  const prs: Pr[] = [];
  let after: string | undefined;
  for (;;) {
    const queryArgs = ["api", "graphql", "-f", `query=${query}`, "-F", `owner=${owner}`, "-F", `name=${name}`];
    if (after !== undefined) queryArgs.push("-F", `after=${after}`);
    const result = gh(queryArgs);
    if (result.status !== 0) die(`historical GraphQL page failed (exit ${result.status}): ${result.stderr.trim()}`);
    const page = (JSON.parse(result.stdout) as {
      data: { repository: { pullRequests: { pageInfo: { hasNextPage: boolean; endCursor: string }; nodes: Pr[] } } };
    }).data.repository.pullRequests;
    prs.push(...page.nodes);
    if (!page.pageInfo.hasNextPage) return prs;
    after = page.pageInfo.endCursor;
  }
}

function prsToScan(): Pr[] {
  const explicit = args.flatMap((a, i) => (a === "--pr" ? [args[i + 1]] : []));
  if (args.includes("--all-history") && explicit.length > 0) die("--all-history and --pr are mutually exclusive");
  if (explicit.length > 0) {
    return explicit.map((n) => {
      if (!n || !/^\d+$/.test(n)) die("--pr needs a PR number");
      const r = gh(["pr", "view", n, "--json", "number,title,body,mergedAt"]);
      if (r.status !== 0) die(`\`gh pr view ${n}\` failed (exit ${r.status}): ${r.stderr.trim()}`);
      return JSON.parse(r.stdout) as Pr;
    });
  }
  if (args.includes("--all-history")) return allMergedPrs();
  const days = Number(flag("--since-days") ?? DEFAULT_SINCE_DAYS);
  if (!Number.isFinite(days) || days <= 0) die("--since-days needs a positive number of days");
  const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
  const r = gh(["pr", "list", "--state", "merged", "--limit", "200", "--search", `merged:>=${since}`, "--json", "number,title,body,mergedAt"]);
  if (r.status !== 0) die(`\`gh pr list\` failed (exit ${r.status}): ${r.stderr.trim()}`);
  return JSON.parse(r.stdout) as Pr[];
}

const prs = prsToScan();
console.log(`Supervised-path declines (#1545) — ${prs.length} merged PR body(ies) read.\n`);

let unrelayed = 0;
let relayed = 0;
let notADecline = 0;
let triagedFalsePositive = 0;
const agedOutUnrelayed = new Set<number>();
const defaultCutoff = Date.now() - DEFAULT_SINCE_DAYS * 86_400_000;
for (const pr of prs) {
  for (const hit of findSupervisedDeclines(pr.body ?? "")) {
    const v = judgeDecline(hit, pr.body ?? "", lookupIssue);
    if (v.relay === "none") {
      const triage = supervisedDeclineTriage(pr.number, hit.line);
      if (triage) {
        triagedFalsePositive++;
        console.log(`○ PR #${pr.number} line ${hit.line} — TRIAGED FALSE POSITIVE (${triage.triagedBy}: ${triage.reason})`);
        continue;
      }
      unrelayed++;
      if (new Date(pr.mergedAt).getTime() < defaultCutoff) agedOutUnrelayed.add(pr.number);
      console.log(`✗ PR #${pr.number} line ${hit.line} — UNRELAYED DECLINE (${v.detail})`);
      console.log(`    ${hit.text.slice(0, 220)}`);
    } else if (v.relay === "nothing-owed" || v.relay === "met-criterion") {
      notADecline++;
      console.log(`ℹ PR #${pr.number} line ${hit.line} — not a decline (${v.detail})`);
    } else {
      relayed++;
      console.log(`✓ PR #${pr.number} line ${hit.line} — relayed (${v.relay}: ${v.detail})`);
    }
  }
}

// A window with no merged PRs is a legitimate nothing-to-read, and it must not leave the same empty
// receipt a run that died before `gh pr list` would leave.
if (prs.length === 0) recordDeclaredNoOp("supervised-declines", "no PR merged in this window, so there was no prose to read");
else recordMeasured("supervised-declines", prs.length, "merged PR body(ies) read for a supervised-path decline");

// Printed on EVERY run, pass or fail: this check's whole purpose is to put the counter-examples
// where the next person writing such a decline will read them.
console.log("\nRoutinely granted — a decline naming one of these is a permission ask, never a capability bound:");
for (const g of ROUTINELY_GRANTED) console.log(`  ${g.path}\n    ${g.evidence}`);
console.log(
  "\nA supervised path stops the EDIT, never the CRITERION: record the question ON THE ISSUE with the exact\n" +
    "wording you propose, and name it in the PR body. A filed tracker is not a relay: PR #1481 filed #1483,\n" +
    "#1483 asked the operator nothing, and the work sat undone for four days. It is the RIGHT answer that\n" +
    "clears this check, and #1483 has since been given one — so `--pr 1481` reads clean today. The check\n" +
    "reads an issue's CURRENT state by design; a decline is relayed the moment someone writes the question.",
);

// The bound, stated on every run rather than left for a reader to assume it away. It runs in BOTH
// directions on purpose: the first version disclosed only the recall floor, which reads as "anything
// it does flag is real" — and on this check's own first window that was the false half. MEASURED
// 2026-07-31, `--since-days 1` over 72 merged PRs: 4 flagged, at least 3 of them false (a heading
// whose relay sat one paragraph below, a verbatim quoted grant the word list could not read, and an
// `ACCEPTANCE … met` disposition). Those three causes are fixed; the residual precision bound below
// is the one that survives, and it is a live instance, not a hypothetical.
console.log(
  `\nBOUND — RECALL: ${unrelayed + relayed + notADecline + triagedFalsePositive} paragraph(s) matched a supervised-path signal AND a decline verb.` +
    ` A decline phrased outside that vocabulary is not counted here — this is a floor, not a census.` +
    `\nBOUND — PRECISION: a flag is a paragraph to READ, not a proven defect. The check cannot tell which of several` +
    `\n  files named in one paragraph a decline verb attaches to, so a sentence like "CLAUDE.md is not edited here;` +
    `\n  the falsified sentences are elsewhere and are corrected in place" is reported as a decline (live: PR #1683` +
    `\n  line 36, MEASURED 2026-07-31). Triage a flag before acting on it.` +
    `\nAND THE SAME BOUND RUNS THE OTHER WAY: a relay is credited from the whole markdown SECTION, so a decline in a` +
    `\n  section naming many issues is cleared if ANY ONE of them asks the operator something — about anything. The` +
    `\n  verdict names which issue cleared it for exactly this reason (live: PR #1481 line 162, cleared via #1319,` +
    `\n  MEASURED 2026-07-31). A "relayed" line is evidence to check, not a verdict to trust.`,
);
console.log(
  `BOUND — DURABILITY: the scheduled/default window is \`--since-days ${DEFAULT_SINCE_DAYS}\`. A flag ages out` +
    ` unfixed after that window, so a green scheduled run is evidence about one day, NOT evidence that no` +
    ` supervised-path decline ever went unrelayed. Run \`--all-history\` for the paginated aged-out population.`,
);

if (args.includes("--all-history")) {
  console.log(
    `\nHISTORICAL DURABILITY MEASUREMENT: ${agedOutUnrelayed.size} merged PR(s) older than` +
      ` \`--since-days ${DEFAULT_SINCE_DAYS}\` still carry an unrelayed decline with no current relay.` +
      ` Population: ${prs.length} merged PR(s), paginated in full; ${triagedFalsePositive} recorded false positive(s) excluded.`,
  );
}

if (unrelayed > 0) {
  console.error(`\n✗ ${unrelayed} unrelayed supervised-path decline(s) — ${relayed} correctly relayed, ${notADecline} not a decline, ${triagedFalsePositive} triaged false positive(s).`);
  process.exit(1);
}
console.log(`\n✓ no unrelayed supervised-path decline in this window (${relayed} relayed, ${notADecline} not a decline, ${triagedFalsePositive} triaged false positive(s)).`);
