// #1769 — a `relayed` disposition census that reads the GATE'S OWN venue set, not a superset of it.
//
//   pnpm exec tsx src/cli/relay-census.ts [--state open|closed|all] [--json]
//
// The census that sized #1753 (12 relayed dispositions, 3 completed-but-unsuperseded) was measured
// by grepping 48 PR bodies + 61 issue comments for the word "relayed" — a POPULATION of every venue
// that CONTAINS the word, not the population the gate actually reads for a given issue. The gate
// (`checkAcceptance`/`checkClosedIssue` in src/acceptance-conservation.ts, via `venuesOf`) reads only
// an issue's own comments plus its LINKED closing PRs (`closedByPullRequestsReferences`). A `relayed`
// line sitting in an UNLINKED PR is real text but is invisible to the gate — completing it there does
// nothing, and a census that counts it as "still stale" is wrong in the gate's own terms.
//
// MEASURED 2026-08-01: #1345.1 was reported stale on the strength of unlinked PR #1374 line 15, while
// linked PR #1346 line 97 already carried the disposition of record (`met`) — `checkAcceptance` never
// reads #1374 for #1345 at all, because it is not in `closedByPullRequestsReferences`. This tool
// reuses `checkAcceptance` itself (the same function both gates call) rather than a second venue
// definition, so its population is the gate's population BY CONSTRUCTION, not by two lists kept in
// step — the exact defect #1562/#1581 record for the gate's own two paths.
//
// It exits 0 whatever it finds; this reports a population, it does not gate anything.

import "./sync-stdio.js";
import { spawnSync } from "node:child_process";
import { checkAcceptance, type IssueLookup, type IssueRecord } from "../acceptance-conservation.js";

const args = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = args.indexOf(name);
  return i === -1 ? fallback : (args[i + 1] ?? fallback);
};

const state = flag("--state", "all").toUpperCase();
if (!["CLOSED", "OPEN", "ALL"].includes(state)) {
  console.error("✗ --state takes closed, open or all");
  process.exit(2);
}

interface Node {
  number: number;
  state: "OPEN" | "CLOSED";
  url: string;
  body: string;
  comments: { totalCount: number; nodes: { url: string; body: string }[] };
  closedByPullRequestsReferences: { totalCount: number; nodes: { number: number; body: string }[] };
}

const QUERY = `query($owner:String!,$name:String!,$states:[IssueState!],$after:String){
  repository(owner:$owner,name:$name){
    issues(first:50,states:$states,after:$after,orderBy:{field:CREATED_AT,direction:ASC}){
      pageInfo{hasNextPage endCursor}
      nodes{
        number state url body
        comments(first:100){ totalCount nodes{ url body } }
        closedByPullRequestsReferences(first:20){ totalCount nodes{ number body } }
      }
    }
  }
}`;

const [owner = "jharvieux", name = "Harvey"] = (flag("--repo", "jharvieux/Harvey")).split("/");

const nodes: Node[] = [];
let after: string | undefined;
for (;;) {
  const gqlArgs = ["api", "graphql", "-f", `query=${QUERY}`, "-F", `owner=${owner}`, "-F", `name=${name}`];
  if (state !== "ALL") gqlArgs.push("-F", `states=${state}`);
  if (after !== undefined) gqlArgs.push("-F", `after=${after}`);
  const r = spawnSync("gh", gqlArgs, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) {
    // Exit 2, never 1: "the census could not run" and "the census found nothing" must not share a
    // code, or a broken token reads as a clean population.
    console.error(`✗ gh api graphql failed (exit ${r.status ?? "no status"}): ${(r.stderr ?? "").trim() || r.error?.message}`);
    process.exit(2);
  }
  const page = (JSON.parse(r.stdout) as { data: { repository: { issues: { pageInfo: { hasNextPage: boolean; endCursor: string }; nodes: Node[] } } } }).data.repository.issues;
  nodes.push(...page.nodes);
  if (!page.pageInfo.hasNextPage) break;
  after = page.pageInfo.endCursor;
}

const truncatedComments = nodes.filter((n) => n.comments.totalCount > n.comments.nodes.length);
const truncatedPrs = nodes.filter((n) => n.closedByPullRequestsReferences.totalCount > n.closedByPullRequestsReferences.nodes.length);

const lookup: IssueLookup = (issue, repo) => {
  if (repo) return undefined; // this census reads one repo's own venues, same as the gate does for a local `#N` reference
  const n = nodes.find((x) => x.number === issue);
  if (!n) return undefined;
  const record: IssueRecord = {
    number: n.number,
    state: n.state,
    body: n.body ?? "",
    comments: n.comments.nodes.map((c) => ({ body: c.body ?? "", url: c.url })),
    linkedPrs: n.closedByPullRequestsReferences.nodes.map((pr) => ({ ref: `#${pr.number}`, body: pr.body ?? "" })),
  };
  return record;
};

interface Row {
  issue: number;
  index: number;
  text: string;
  status: "live" | "superseded";
  venue?: string;
  line?: number;
  detail?: string;
}

const rows: Row[] = [];
for (const n of nodes) {
  const report = checkAcceptance(`Closes #${n.number}`, lookup);
  for (const iv of report.issues) {
    if (iv.issue !== n.number) continue; // a self-referencing "Closes #N" only ever names this issue
    for (const c of iv.criteria) {
      // A resolved relay's `disposition` is the terminal met/split/ruled-unmet, not `relayed` — the retired
      // line is reported only in `superseded`. So "still live" and "already resolved" are told
      // apart by `superseded`, not by `disposition`, which the first cut of this tool got backwards.
      if (c.superseded) {
        rows.push({ issue: n.number, index: c.index, text: c.text, status: "superseded", venue: c.superseded.venue, line: c.superseded.line, detail: c.superseded.detail });
      } else if (c.disposition === "relayed") {
        rows.push({ issue: n.number, index: c.index, text: c.text, status: "live", detail: c.detail });
      }
    }
  }
}

const live = rows.filter((r) => r.status === "live");
const superseded = rows.filter((r) => r.status === "superseded");
const commentCount = nodes.reduce((a, n) => a + n.comments.nodes.length, 0);
const linkedPrCount = nodes.reduce((a, n) => a + n.closedByPullRequestsReferences.nodes.length, 0);

if (args.includes("--json")) {
  console.log(JSON.stringify({ issues: nodes.length, comments: commentCount, linkedPrs: linkedPrCount, live, superseded }, null, 2));
  process.exit(0);
}

console.log(`#1769 relay census — ${owner}/${name}, state=${state.toLowerCase()}`);
console.log("  venue set: EXACT match to the gate's own (checkAcceptance's venuesOf: each issue's own comments + its closedByPullRequestsReferences bodies) — not a superset, because this tool calls that function rather than re-defining the surface.");
console.log(`  population: ${nodes.length} issue(s), ${commentCount} comment(s), ${linkedPrCount} linked PR bodies read in full`);
if (truncatedComments.length > 0) console.log(`  ⚠ ${truncatedComments.length} issue(s) carry more than 100 comments and were read only that far: ${truncatedComments.map((t) => `#${t.number}`).join(", ")}`);
if (truncatedPrs.length > 0) console.log(`  ⚠ ${truncatedPrs.length} issue(s) carry more than 20 linked PRs and were read only that far: ${truncatedPrs.map((t) => `#${t.number}`).join(", ")}`);
console.log(`  relayed dispositions found: ${rows.length} — ${live.length} still live (no superseding met/split/ruled-unmet in the gate's own venues), ${superseded.length} already resolved (#1753/#1791)`);
for (const r of live) console.log(`    LIVE        #${r.issue}.${r.index} — ${r.detail?.slice(0, 90)}`);
for (const r of superseded) console.log(`    SUPERSEDED  #${r.issue}.${r.index} — retired by a ${r.detail} at ${r.venue}, line ${r.line}`);
console.log("\nA LIVE row is a `relayed` line the gate would still read as the disposition of record — it needs either a completing `met`/`split` or an attributed terminal `ruled-unmet` in a LINKED PR or issue comment (#1769/#1791).");
