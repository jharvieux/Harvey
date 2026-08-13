import { describe, expect, it } from "vitest";
import { evaluateCorpusRelevanceHistory, type CorpusHistoryJob, type CorpusHistoryPullRequest } from "./corpus-relevance-history.js";
import type { CorpusClosureReceipt } from "./scan/corpus-relevance.js";

const closure: CorpusClosureReceipt = {
  schema: 1,
  revision: "head",
  roots: ["src/cli/corpus-drift.ts"],
  inputs: [{ category: "producer", path: "src/cli/corpus-drift.ts", digest: "a".repeat(64), consumer: "corpus executable entry point" }],
  edges: [],
  uncertainties: [],
  inventory: ["src/cli/corpus-drift.ts", "docs/report.md", "site/app/page.tsx"],
  digest: "b".repeat(64),
};

function job(id: number, start: string, finish: string): CorpusHistoryJob {
  return {
    id,
    runId: 90,
    runAttempt: 1,
    name: `corpus shard ${id}`,
    status: "completed",
    conclusion: "success",
    startedAt: start,
    completedAt: finish,
    runnerName: "GitHub Actions 1",
    runnerGroupName: "GitHub Actions",
    labels: ["ubuntu-latest"],
    htmlUrl: `https://example.test/jobs/${id}`,
    steps: [{
      number: 1,
      name: "Score the corpus against its baselines",
      status: "completed",
      conclusion: "success",
      startedAt: start,
      completedAt: finish,
    }],
  };
}

function pullRequest(number: number, path: string, jobs: CorpusHistoryJob[]): CorpusHistoryPullRequest {
  return {
    number,
    url: `https://example.test/pulls/${number}`,
    mergedAt: `2026-08-12T00:00:${number.toString().padStart(2, "0")}Z`,
    mergeCommit: `${number}`.repeat(40).slice(0, 40),
    firstParent: `${number + 1}`.repeat(40).slice(0, 40),
    headRevision: `${number + 2}`.repeat(40).slice(0, 40),
    changed: [{ status: "M", path }],
    run: {
      id: 90,
      attempt: 1,
      event: "pull_request",
      status: "completed",
      conclusion: "success",
      headSha: "d".repeat(40),
      createdAt: "2026-08-12T00:00:00Z",
      updatedAt: "2026-08-12T00:00:20Z",
      htmlUrl: "https://example.test/runs/90",
      pullRequests: [number],
      jobs,
    },
  };
}

describe("#1870 historical corpus relevance replay", () => {
  it("keeps a scanner PR relevant and a prose PR no-op while separating max critical path from summed runner time", () => {
    const jobs = [
      job(1, "2026-08-12T00:00:00Z", "2026-08-12T00:00:10Z"),
      job(2, "2026-08-12T00:00:02Z", "2026-08-12T00:00:12Z"),
    ];
    const artifact = evaluateCorpusRelevanceHistory({
      repository: "jharvieux/Harvey",
      cutoff: "2026-08-12T01:00:00Z",
      evaluatorRevision: "e".repeat(40),
      evaluatorWorktree: [],
      closure,
      pullRequests: [
        pullRequest(1, "src/cli/corpus-drift.ts", jobs),
        pullRequest(2, "docs/report.md", jobs),
      ],
      expectedPopulation: 2,
    });

    expect(artifact.rows.find((row) => row.number === 1)).toMatchObject({ verdict: "full-scan", criticalPathSavingsMs: 0, summedRunnerTimeSavingsMs: 0 });
    expect(artifact.rows.find((row) => row.number === 2)).toMatchObject({ verdict: "declared-no-op", criticalPathSavingsMs: 12_000, summedRunnerTimeSavingsMs: 20_000 });
    expect(artifact.totals).toMatchObject({ declaredNoOp: 1, fullScan: 1, criticalPathSavingsMs: 12_000, summedRunnerTimeSavingsMs: 20_000 });
  });

  it("fails when the latest-PR population, revisions, diffs, or closure are incomplete", () => {
    const complete = pullRequest(1, "docs/report.md", []);
    const options = {
      repository: "jharvieux/Harvey",
      cutoff: "2026-08-12T01:00:00Z",
      evaluatorRevision: "e".repeat(40),
      evaluatorWorktree: [],
      closure,
      pullRequests: [complete],
      expectedPopulation: 1,
    };
    expect(() => evaluateCorpusRelevanceHistory({ ...options, expectedPopulation: 2 })).toThrow(/expected exactly 2/);
    expect(() => evaluateCorpusRelevanceHistory({ ...options, pullRequests: [{ ...complete, firstParent: "" }] })).toThrow(/revision is missing/);
    expect(() => evaluateCorpusRelevanceHistory({ ...options, pullRequests: [{ ...complete, changed: [] }] })).toThrow(/diff is empty/);
    expect(() => evaluateCorpusRelevanceHistory({ ...options, closure: { ...closure, uncertainties: [{ kind: "dynamic", path: "src/x.ts", detail: "plant" }] } })).toThrow(/closure is uncertain/);
  });

  it("rejects duplicate PR rows instead of shrinking the measured population silently", () => {
    const row = pullRequest(1, "docs/report.md", []);
    expect(() => evaluateCorpusRelevanceHistory({
      repository: "jharvieux/Harvey",
      cutoff: "2026-08-12T01:00:00Z",
      evaluatorRevision: "e".repeat(40),
      evaluatorWorktree: [],
      closure,
      pullRequests: [row, row],
      expectedPopulation: 2,
    })).toThrow(/duplicate pull requests/);
  });
});
