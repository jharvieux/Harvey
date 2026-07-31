// #1603 — how often does an issue's acceptance bar get REVISED IN A COMMENT after the body was
// written? `validate-acceptance` grades the body and nothing else, so every one of these is an issue
// the gate can grade 3/3 against a bar that no longer applies (#1595, gate run 30598147578).
//
//   pnpm exec tsx src/cli/superseded-acceptance-census.ts [--state closed|open|all] [--json]
//
// This is the FALSIFIER for the convention the gate now prints (SUPERSEDING_CONVENTION): a new
// flagged comment on an issue closed after 2026-07-31 means the revision was not written back into
// the body. It reads the whole population — every issue and every comment, paged, not sampled — so
// the number it prints is a count and not an estimate.
//
// It exits 0 whatever it finds. The census REPORTS a population; the gate is `validate-acceptance`,
// which flags the same comments per-issue at the moment they could mislead a close.

import { spawnSync } from "node:child_process";
import { supersedingAcceptanceComments } from "../acceptance-conservation.js";

const args = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = args.indexOf(name);
  return i === -1 ? fallback : (args[i + 1] ?? fallback);
};

const state = flag("--state", "closed").toUpperCase();
if (!["CLOSED", "OPEN", "ALL"].includes(state)) {
  console.error("✗ --state takes closed, open or all");
  process.exit(2);
}

interface Node {
  number: number;
  url: string;
  body: string;
  comments: { totalCount: number; nodes: { url: string; body: string }[] };
}

const QUERY = `query($owner:String!,$name:String!,$states:[IssueState!],$after:String){
  repository(owner:$owner,name:$name){
    issues(first:50,states:$states,after:$after,orderBy:{field:CREATED_AT,direction:ASC}){
      pageInfo{hasNextPage endCursor}
      nodes{ number url body comments(first:100){ totalCount nodes{ url body } } }
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

const truncated = nodes.filter((n) => n.comments.totalCount > n.comments.nodes.length);
const hits = nodes.flatMap((n) => supersedingAcceptanceComments(n.comments.nodes).map((s) => ({ issue: n.number, ...s })));
const commentCount = nodes.reduce((a, n) => a + n.comments.nodes.length, 0);

if (args.includes("--json")) {
  console.log(JSON.stringify({ issues: nodes.length, comments: commentCount, truncated: truncated.map((t) => t.number), hits }, null, 2));
  process.exit(0);
}

console.log(`#1603 superseded-acceptance census — ${owner}/${name}, state=${state.toLowerCase()}`);
console.log(`  population: ${nodes.length} issue(s), ${commentCount} comment(s) read in full`);
// A truncated comment page is a comment nobody read, which would silently shrink the population.
if (truncated.length > 0) console.log(`  ⚠ ${truncated.length} issue(s) carry more than 100 comments and were read only that far: ${truncated.map((t) => `#${t.number}`).join(", ")}`);
console.log(`  flagged: ${hits.length} comment(s) across ${new Set(hits.map((h) => h.issue)).size} issue(s)`);
for (const h of hits) console.log(`    #${h.issue} — ${h.bullets} bullet(s) under "${h.heading}" — ${h.url}`);
console.log("\nThe flag is a WARNING, by decision: `validate-acceptance` still grades the issue BODY. Each row above is a comment a human should read before believing a green close.");
