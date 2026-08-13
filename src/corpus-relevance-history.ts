import type {
  CorpusChangedPath,
  CorpusClosureReceipt,
} from "./scan/corpus-relevance.js";
import { decideCorpusRelevance } from "./scan/corpus-relevance.js";

export interface CorpusHistoryJobStep {
  number: number;
  name: string;
  status: string;
  conclusion: string | null;
  startedAt: string | null;
  completedAt: string | null;
}

export interface CorpusHistoryJob {
  id: number;
  runId: number;
  runAttempt: number;
  name: string;
  status: string;
  conclusion: string | null;
  startedAt: string | null;
  completedAt: string | null;
  runnerName: string | null;
  runnerGroupName: string | null;
  labels: string[];
  htmlUrl: string;
  steps: CorpusHistoryJobStep[];
}

export interface CorpusHistoryRun {
  id: number;
  attempt: number;
  event: string;
  status: string;
  conclusion: string | null;
  headSha: string;
  createdAt: string;
  updatedAt: string;
  htmlUrl: string;
  pullRequests: number[];
  jobs: CorpusHistoryJob[];
}

export interface CorpusHistoryPullRequest {
  number: number;
  url: string;
  mergedAt: string;
  mergeCommit: string;
  firstParent: string;
  headRevision: string | null;
  changed: CorpusChangedPath[];
  run: CorpusHistoryRun | null;
}

interface CorpusRelevanceHistoryOptions {
  repository: string;
  cutoff: string;
  evaluatorRevision: string;
  evaluatorWorktree: string[];
  closure: CorpusClosureReceipt;
  pullRequests: CorpusHistoryPullRequest[];
  expectedPopulation?: number;
}

interface CorpusRelevanceHistoryRow extends CorpusHistoryPullRequest {
  verdict: "full-scan" | "declared-no-op";
  reasons: string[];
  matched: ReturnType<typeof decideCorpusRelevance>["matched"];
  disjoint: string[];
  timedJobs: CorpusHistoryJob[];
  criticalPathSavingsMs: number;
  summedRunnerTimeSavingsMs: number;
}

interface CorpusRelevanceHistoryArtifact {
  schema: 1;
  repository: string;
  cutoff: string;
  selection: "latest-merged-at";
  population: number;
  evaluator: {
    revision: string;
    worktree: string[];
    closure: CorpusClosureReceipt;
  };
  mergeWindow: { newest: string; oldest: string };
  scheduledCoverage: "unconditional-full-scan-unchanged";
  rows: CorpusRelevanceHistoryRow[];
  totals: {
    declaredNoOp: number;
    fullScan: number;
    noOpWithMeasuredJobs: number;
    criticalPathSavingsMs: number;
    summedRunnerTimeSavingsMs: number;
  };
}

function epoch(value: string | null): number | undefined {
  if (!value) return undefined;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function elapsed(job: CorpusHistoryJob): number | undefined {
  const start = epoch(job.startedAt);
  const finish = epoch(job.completedAt);
  return start === undefined || finish === undefined || finish < start ? undefined : finish - start;
}

function isMeasuredCorpusWork(job: CorpusHistoryJob): boolean {
  const expectedJob = job.name.startsWith("corpus shard ") || job.name.startsWith("current independent replay ");
  if (!expectedJob) return false;
  return job.steps.some((step) =>
    (step.name === "Score the corpus against its baselines"
      || step.name === "Score pinned targets against every source-tier baseline"
      || step.name === "Execute the independent exact-head replay")
    && step.conclusion !== "skipped"
    && epoch(step.startedAt) !== undefined
    && epoch(step.completedAt) !== undefined);
}

function savings(jobs: readonly CorpusHistoryJob[]): { criticalPathMs: number; summedRunnerMs: number } {
  const intervals = jobs.flatMap((job) => {
    const start = epoch(job.startedAt);
    const finish = epoch(job.completedAt);
    return start === undefined || finish === undefined || finish < start ? [] : [{ start, finish, elapsed: finish - start }];
  });
  if (intervals.length === 0) return { criticalPathMs: 0, summedRunnerMs: 0 };
  return {
    criticalPathMs: Math.max(...intervals.map((row) => row.finish)) - Math.min(...intervals.map((row) => row.start)),
    summedRunnerMs: intervals.reduce((sum, row) => sum + row.elapsed, 0),
  };
}

/** Counterfactual replay: hold today's discovered closure fixed and feed it each historical merge diff. */
export function evaluateCorpusRelevanceHistory(options: CorpusRelevanceHistoryOptions): CorpusRelevanceHistoryArtifact {
  const expectedPopulation = options.expectedPopulation ?? 50;
  if (options.pullRequests.length !== expectedPopulation) {
    throw new Error(`historical relevance population is ${options.pullRequests.length}; expected exactly ${expectedPopulation}`);
  }
  const unique = new Set(options.pullRequests.map((pullRequest) => pullRequest.number));
  if (unique.size !== options.pullRequests.length) throw new Error("historical relevance population contains duplicate pull requests");
  if (options.closure.uncertainties.length > 0) {
    throw new Error(`the evaluator closure is uncertain; historical no-op claims are forbidden (${options.closure.uncertainties.length} uncertainty row(s))`);
  }

  const sorted = [...options.pullRequests].sort((left, right) =>
    Date.parse(right.mergedAt) - Date.parse(left.mergedAt) || right.number - left.number);
  const rows = sorted.map((pullRequest): CorpusRelevanceHistoryRow => {
    if (!pullRequest.mergeCommit || !pullRequest.firstParent) throw new Error(`#${pullRequest.number}: merge/first-parent revision is missing`);
    if (pullRequest.changed.length === 0) throw new Error(`#${pullRequest.number}: historical diff is empty or unreadable`);
    const decision = decideCorpusRelevance(options.closure, options.closure, pullRequest.changed);
    const timedJobs = pullRequest.run?.jobs.filter((job) => isMeasuredCorpusWork(job) && elapsed(job) !== undefined) ?? [];
    const measured = decision.verdict === "declared-no-op" ? savings(timedJobs) : { criticalPathMs: 0, summedRunnerMs: 0 };
    return {
      ...pullRequest,
      verdict: decision.verdict,
      reasons: decision.reasons,
      matched: decision.matched,
      disjoint: decision.disjoint,
      timedJobs,
      criticalPathSavingsMs: measured.criticalPathMs,
      summedRunnerTimeSavingsMs: measured.summedRunnerMs,
    };
  });
  const declared = rows.filter((row) => row.verdict === "declared-no-op");
  return {
    schema: 1,
    repository: options.repository,
    cutoff: options.cutoff,
    selection: "latest-merged-at",
    population: rows.length,
    evaluator: {
      revision: options.evaluatorRevision,
      worktree: [...options.evaluatorWorktree],
      closure: options.closure,
    },
    mergeWindow: { newest: rows[0]!.mergedAt, oldest: rows.at(-1)!.mergedAt },
    scheduledCoverage: "unconditional-full-scan-unchanged",
    rows,
    totals: {
      declaredNoOp: declared.length,
      fullScan: rows.length - declared.length,
      noOpWithMeasuredJobs: declared.filter((row) => row.timedJobs.length > 0).length,
      criticalPathSavingsMs: declared.reduce((sum, row) => sum + row.criticalPathSavingsMs, 0),
      summedRunnerTimeSavingsMs: declared.reduce((sum, row) => sum + row.summedRunnerTimeSavingsMs, 0),
    },
  };
}
