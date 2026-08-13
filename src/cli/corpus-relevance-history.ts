import "./sync-stdio.js";
import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  evaluateCorpusRelevanceHistory,
  type CorpusHistoryJob,
  type CorpusHistoryPullRequest,
  type CorpusHistoryRun,
} from "../corpus-relevance-history.js";
import { discoverCorpusClosure, type CorpusChangedPath } from "../scan/corpus-relevance.js";

const args = process.argv.slice(2);
const value = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const repository = value("--repo") ?? "jharvieux/Harvey";
const repoRoot = resolve(value("--checkout") ?? process.cwd());
const out = value("--out");
const limit = Number(value("--limit") ?? "50");
if (!out || !Number.isInteger(limit) || limit < 1 || limit > 100) {
  console.error("usage: corpus-relevance-history --out <artifact.json> [--repo owner/name] [--checkout path] [--limit 1..100]");
  process.exit(2);
}
const [owner, name] = repository.split("/");
if (!owner || !name) {
  console.error(`--repo must be owner/name; got ${repository}`);
  process.exit(2);
}

function gh<T>(arguments_: string[]): T {
  const result = spawnSync("gh", arguments_, { encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  if (result.status !== 0) {
    console.error(`gh ${arguments_.slice(0, 2).join(" ")} failed (exit ${result.status ?? "no status"}): ${(result.stderr ?? "").trim() || result.error?.message}`);
    process.exit(2);
  }
  return JSON.parse(result.stdout) as T;
}

function git(arguments_: string[], encoding?: "utf8"): Buffer | string {
  return execFileSync("git", arguments_, { cwd: repoRoot, ...(encoding ? { encoding } : {}) });
}

function changedPaths(base: string, head: string): CorpusChangedPath[] {
  const fields = (git(["diff", "--name-status", "-z", "--find-renames", base, head]) as Buffer)
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  const changed: CorpusChangedPath[] = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++]!;
    if (status.startsWith("R") || status.startsWith("C")) {
      const oldPath = fields[index++]!;
      const path = fields[index++]!;
      changed.push({ status, oldPath, path });
    } else {
      changed.push({ status, path: fields[index++]! });
    }
  }
  return changed;
}

interface PullRequestNode {
  number: number;
  url: string;
  mergedAt: string;
  headRefOid: string | null;
  mergeCommit: { oid: string; parents: { nodes: Array<{ oid: string }> } } | null;
}

const pullRequestQuery = `query($owner:String!,$name:String!,$after:String){
  repository(owner:$owner,name:$name){
    pullRequests(first:100,states:MERGED,after:$after,orderBy:{field:UPDATED_AT,direction:DESC}){
      pageInfo{hasNextPage endCursor}
      nodes{number url mergedAt headRefOid mergeCommit{oid parents(first:1){nodes{oid}}}}
    }
  }
}`;

const allPullRequests: PullRequestNode[] = [];
let after: string | undefined;
for (;;) {
  const graphqlArgs = ["api", "graphql", "-f", `query=${pullRequestQuery}`, "-F", `owner=${owner}`, "-F", `name=${name}`];
  if (after) graphqlArgs.push("-F", `after=${after}`);
  const response = gh<{ data: { repository: { pullRequests: { pageInfo: { hasNextPage: boolean; endCursor: string | null }; nodes: PullRequestNode[] } } } }>(graphqlArgs);
  const page = response.data.repository.pullRequests;
  allPullRequests.push(...page.nodes);
  if (!page.pageInfo.hasNextPage) break;
  if (!page.pageInfo.endCursor) {
    console.error("merged-PR pagination claimed another page without an end cursor");
    process.exit(2);
  }
  after = page.pageInfo.endCursor;
}

const selected = allPullRequests
  .filter((pullRequest) => pullRequest.mergeCommit?.parents.nodes[0])
  .sort((left, right) => Date.parse(right.mergedAt) - Date.parse(left.mergedAt) || right.number - left.number)
  .slice(0, limit);
if (selected.length !== limit) {
  console.error(`GitHub returned only ${selected.length} merged PR(s) with a merge commit and first parent; expected ${limit}`);
  process.exit(2);
}

interface ApiRun {
  id: number;
  run_attempt: number;
  event: string;
  status: string;
  conclusion: string | null;
  head_sha: string;
  created_at: string;
  updated_at: string;
  html_url: string;
  pull_requests: Array<{ number: number }>;
}

interface ApiJob {
  id: number;
  run_id: number;
  run_attempt: number;
  name: string;
  status: string;
  conclusion: string | null;
  started_at: string | null;
  completed_at: string | null;
  runner_name: string | null;
  runner_group_name: string | null;
  labels: string[];
  html_url: string;
  steps?: Array<{
    number: number;
    name: string;
    status: string;
    conclusion: string | null;
    started_at: string | null;
    completed_at: string | null;
  }>;
}

function jobsFor(run: ApiRun): CorpusHistoryJob[] {
  const response = gh<{ jobs: ApiJob[] }>(["api", `repos/${owner}/${name}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`]);
  return response.jobs.map((job) => ({
    id: job.id,
    runId: job.run_id,
    runAttempt: job.run_attempt,
    name: job.name,
    status: job.status,
    conclusion: job.conclusion,
    startedAt: job.started_at,
    completedAt: job.completed_at,
    runnerName: job.runner_name,
    runnerGroupName: job.runner_group_name,
    labels: job.labels,
    htmlUrl: job.html_url,
    steps: (job.steps ?? []).map((step) => ({
      number: step.number,
      name: step.name,
      status: step.status,
      conclusion: step.conclusion,
      startedAt: step.started_at,
      completedAt: step.completed_at,
    })),
  }));
}

function runFor(pullRequest: PullRequestNode): CorpusHistoryRun | null {
  const revisions = [...new Set([pullRequest.headRefOid, pullRequest.mergeCommit?.oid].filter((revision): revision is string => Boolean(revision)))];
  const candidates: ApiRun[] = [];
  for (const revision of revisions) {
    const response = gh<{ workflow_runs: ApiRun[] }>([
      "api",
      `repos/${owner}/${name}/actions/workflows/corpus-drift.yml/runs?event=pull_request&head_sha=${encodeURIComponent(revision)}&per_page=100`,
    ]);
    // The workflow-runs endpoint returns an empty pull_requests array for this repository even
    // when the run is visible in the PR check rollup. The endpoint's exact head_sha filter is the
    // binding association; retaining pull_requests in the artifact makes that API quirk visible.
    candidates.push(...response.workflow_runs.filter((run) => run.head_sha === revision));
    if (candidates.length > 0) break;
  }
  const run = candidates.sort((left, right) => right.run_attempt - left.run_attempt || Date.parse(right.updated_at) - Date.parse(left.updated_at))[0];
  if (!run) return null;
  return {
    id: run.id,
    attempt: run.run_attempt,
    event: run.event,
    status: run.status,
    conclusion: run.conclusion,
    headSha: run.head_sha,
    createdAt: run.created_at,
    updatedAt: run.updated_at,
    htmlUrl: run.html_url,
    pullRequests: run.pull_requests.map((linked) => linked.number),
    jobs: jobsFor(run),
  };
}

const cutoff = new Date().toISOString();
const evaluatorRevision = (git(["rev-parse", "HEAD"], "utf8") as string).trim();
const evaluatorWorktree = (git(["status", "--porcelain=v1"], "utf8") as string).split("\n").filter(Boolean);
const closure = discoverCorpusClosure(repoRoot, evaluatorRevision);
const pullRequests: CorpusHistoryPullRequest[] = [];
for (const [index, pullRequest] of selected.entries()) {
  const mergeCommit = pullRequest.mergeCommit!;
  const firstParent = mergeCommit.parents.nodes[0]!.oid;
  console.error(`HISTORY ${index + 1}/${selected.length}: #${pullRequest.number} ${firstParent.slice(0, 8)}..${mergeCommit.oid.slice(0, 8)}`);
  pullRequests.push({
    number: pullRequest.number,
    url: pullRequest.url,
    mergedAt: pullRequest.mergedAt,
    mergeCommit: mergeCommit.oid,
    firstParent,
    headRevision: pullRequest.headRefOid,
    changed: changedPaths(firstParent, mergeCommit.oid),
    run: runFor(pullRequest),
  });
}

const artifact = evaluateCorpusRelevanceHistory({
  repository,
  cutoff,
  evaluatorRevision,
  evaluatorWorktree,
  closure,
  pullRequests,
  expectedPopulation: limit,
});
writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`);
console.error(
  `CORPUS RELEVANCE HISTORY PASS: ${artifact.population} latest merged PRs at ${artifact.cutoff}; `
  + `${artifact.totals.declaredNoOp} declared no-op; critical-path savings ${(artifact.totals.criticalPathSavingsMs / 60_000).toFixed(1)}m; `
  + `summed runner-time savings ${(artifact.totals.summedRunnerTimeSavingsMs / 60_000).toFixed(1)}m; ${artifact.totals.noOpWithMeasuredJobs} no-op(s) had measured corpus jobs.`,
);
