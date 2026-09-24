import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";

import {
  assertPartitionCoversEveryTarget,
  compareUtf8Bytes,
  corpusCacheNamespaceForTarget,
  CORPUS_CACHE_PARTITION_POLICY,
  CORPUS_CACHE_SHARD_COUNT,
  CORPUS_SHARD_JOB_BUDGET_SECONDS,
  CORPUS_SHARD_OVERHEAD_SECONDS,
  DEFAULT_SCAN_SECONDS,
  partitionTargets,
  shardTargets,
  TARGET_SCAN_SECONDS,
  weightOf,
} from "./corpus-shards.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";

const SLUGS = EXTERNAL_CORPUS.map((t) => t.slug);
const load = (shard: string[]): number => shard.reduce((n, s) => n + weightOf(s), 0);
const WORKFLOW_TEXT = readFileSync(new URL("../../.github/workflows/corpus-drift.yml", import.meta.url), "utf8");
const FOUR_SHARD_ASSIGNMENT = [
  ["carbon", "mvp-boilerplate"],
  ["documenso", "ghostfolio", "saas-lite", "launch-mvp", "subscription-payments"],
  ["inbox-zero", "flori-web", "proposit", "multi-tenant-starter"],
  ["rallly", "tanstack-com", "cravab", "boxyhq", "effective", "supabase-security-labs"],
];
const FOUR_SHARD_LOADS = [2150, 1636, 1332, 1361];

const EXPECTED_WEIGHTS: Readonly<Record<string, number>> = {
  carbon: 2057, documenso: 898, "inbox-zero": 865, "tanstack-com": 390,
  ghostfolio: 356, rallly: 410, cravab: 235, "flori-web": 224, proposit: 149,
  boxyhq: 159, "saas-lite": 185, "mvp-boilerplate": 93, "multi-tenant-starter": 94,
  "launch-mvp": 105, "subscription-payments": 92, effective: 96, "supabase-security-labs": 71,
};

interface WorkflowStep {
  name?: string;
  env?: Record<string, unknown>;
}

interface CorpusWorkflow {
  jobs: {
    shard: { strategy: { matrix: { shard: unknown } }; "timeout-minutes": string | number; steps: WorkflowStep[] };
    "current-replay": { if: string; strategy: { matrix: { shard: unknown } }; steps: WorkflowStep[] };
  };
}

// These scalar expressions use the shared JS/Actions boolean operators. Evaluate the YAML,
// including fromJSON, rather than recognizing a spelling of the intended event predicate.
function eventExpression(value: unknown, event: string, shard = 1): unknown {
  if (typeof value !== "string") return value;
  return runInNewContext(value.replace(/^\$\{\{\s*|\s*\}\}$/g, "")
    .replaceAll("needs.prepare-current-inputs.result", "preparationResult")
    .replaceAll("needs.prepare-current-inputs.outputs.relevant", "relevant"), {
    github: { event_name: event }, matrix: { shard }, preparationResult: "success", relevant: "true", fromJSON: JSON.parse,
  });
}

function contractErrors(
  workflowText = WORKFLOW_TEXT,
  slugs: readonly string[] = SLUGS,
  weights: Readonly<Record<string, number>> = TARGET_SCAN_SECONDS,
): string[] {
  const errors: string[] = [];
  const workflow = parseYaml(workflowText) as CorpusWorkflow;
  const score = workflow.jobs.shard.steps.find((step) => step.name === "Score the corpus against its baselines");
  const replay = workflow.jobs["current-replay"].steps.find((step) => step.name === "Execute the independent exact-head replay");
  for (const event of ["push", "pull_request", "merge_group", "schedule", "workflow_dispatch"]) {
    const count = 4;
    const snapshot = ["push", "pull_request", "merge_group"].includes(event);
    const expected = Array.from({ length: count }, (_, index) => index + 1);
    if (JSON.stringify(eventExpression(workflow.jobs.shard.strategy.matrix.shard, event)) !== JSON.stringify(expected)) errors.push(`${event}: producer matrix`);
    if (eventExpression(score?.env?.SHARD_COUNT, event) !== count) errors.push(`${event}: producer count`);
    if (eventExpression(score?.env?.HARVEY_CURRENT_MECHANICAL_READINESS, event) !== (snapshot ? "1" : "0")) errors.push(`${event}: producer readiness`);
    if (eventExpression(workflow.jobs["current-replay"].if, event) !== snapshot) errors.push(`${event}: replay activation`);
    const expectedTimeouts = snapshot ? [45, 35, 30, 30] : [120, 120, 120, 120];
    for (const [index, expectedTimeout] of expectedTimeouts.entries()) {
      if (eventExpression(workflow.jobs.shard["timeout-minutes"], event, index + 1) !== expectedTimeout) errors.push(`${event}: shard ${index + 1} timeout`);
      if (snapshot && CORPUS_SHARD_JOB_BUDGET_SECONDS[index] !== expectedTimeout * 60) errors.push(`${event}: shard ${index + 1} planned budget`);
    }
  }
  if (JSON.stringify(workflow.jobs["current-replay"].strategy.matrix.shard) !== "[1,2,3,4]") errors.push("post-merge replay matrix is not fixed at four");
  if (replay?.env?.SHARD_COUNT !== 4) errors.push("post-merge replay count is not fixed at four");
  if (new Set(slugs).size !== slugs.length) errors.push("corpus contains a duplicate target");
  if ([...new Set([...slugs, ...Object.keys(weights)])].some((slug) => !slugs.includes(slug) || weights[slug] === undefined)) errors.push("weights and corpus differ");
  if (JSON.stringify(weights) !== JSON.stringify(EXPECTED_WEIGHTS)) errors.push("weights differ from hosted evidence");
  return errors;
}

describe("corpus shard partition (#1586)", () => {
  // The failure this guards is silent: a target dropped from the partition stops being scored, its
  // shard still exits 0, and the aggregate reads green while coverage shrank. So the property is
  // asserted over the REAL corpus, not a fixture, and at every shard count CI might plausibly use.
  it.each([1, 2, 3, 4, 5])("scores every corpus target exactly once at %i shard(s)", (count) => {
    const shards = partitionTargets(SLUGS, count);
    expect(shards).toHaveLength(count);
    expect([...shards.flat()].sort(compareUtf8Bytes)).toEqual([...SLUGS].sort(compareUtf8Bytes));
  });

  it("addresses shards 1-based, matching how the CI matrix names them", () => {
    const shards = partitionTargets(SLUGS, 4);
    expect(shardTargets(SLUGS, 1, 4)).toEqual(shards[0]);
    expect(shardTargets(SLUGS, 4, 4)).toEqual(shards[3]);
    expect(() => shardTargets(SLUGS, 0, 4)).toThrow(/within 1\.\.4/);
    expect(() => shardTargets(SLUGS, 5, 4)).toThrow(/within 1\.\.4/);
  });

  it("is deterministic, so shards need no coordination between runners", () => {
    expect(partitionTargets(SLUGS, 4)).toEqual(partitionTargets([...SLUGS].reverse(), 4));
  });

  it("uses explicit POSIX UTF-8 order, not locale or implicit UTF-16 order", () => {
    const traps = ["path/a.ts", "path/\u{10000}.ts", "path/\uE000.ts", "path/A.ts"];
    const expected = ["path/A.ts", "path/a.ts", "path/\uE000.ts", "path/\u{10000}.ts"];
    expect([...traps].sort(compareUtf8Bytes)).toEqual(expected);
    expect(partitionTargets(traps, 1)).toEqual([expected]);
  });

  it("gives every target one fixed four-way cache owner independent of execution shard count", () => {
    expect(CORPUS_CACHE_PARTITION_POLICY).toBe("corpus-capacity-lpt-four-owner-v2");
    expect(CORPUS_CACHE_SHARD_COUNT).toBe(4);
    const owners = FOUR_SHARD_ASSIGNMENT.flatMap((members, index) => members.map((slug) => [slug, index + 1] as const));
    expect(owners.map(([slug]) => [slug, corpusCacheNamespaceForTarget(SLUGS, slug)])).toEqual(owners);
    expect(() => corpusCacheNamespaceForTarget(SLUGS, "not-in-corpus")).toThrow("has no canonical owner");
  });

  it("fits a divisible workload into unequal deadlines while preserving publication time", () => {
    const slugs = Array.from({ length: 24 }, (_, index) => `target-${String(index).padStart(2, "0")}`);
    const weights = Object.fromEntries(slugs.map((slug) => [slug, 300]));
    const assigned = partitionTargets(slugs, 4, weights);
    expect(CORPUS_SHARD_OVERHEAD_SECONDS).toBe(300);
    expect(assigned.map((members) => members.length * 300)).toEqual([2400, 1800, 1500, 1500]);
    for (const [index, members] of assigned.entries()) {
      expect(members.length * 300 + CORPUS_SHARD_OVERHEAD_SECONDS).toBeLessThanOrEqual(CORPUS_SHARD_JOB_BUDGET_SECONDS[index]!);
    }
    // Equal deadlines outside the canonical hosted topology retain ordinary LPT.
    expect(partitionTargets(slugs, 3, weights).map((members) => members.length)).toEqual([8, 8, 8]);
  });

  it("beats the serial run it replaces", () => {
    const serial = load([...SLUGS]);
    const longest = Math.max(...partitionTargets(SLUGS, 4).map(load));
    expect(longest).toBeLessThan(serial / 2);
  });

  it("gives a target with no measured weight the heavier default rather than dropping it", () => {
    expect(weightOf("a-target-never-measured")).toBe(DEFAULT_SCAN_SECONDS);
    const withNew = [...SLUGS, "a-target-never-measured"];
    const shards = partitionTargets(withNew, 4);
    expect([...shards.flat()].sort(compareUtf8Bytes)).toEqual([...withNew].sort(compareUtf8Bytes));
  });

  it("rejects a nonsensical shard count instead of silently scoring nothing", () => {
    expect(() => partitionTargets(SLUGS, 0)).toThrow(/positive integer/);
    expect(() => partitionTargets(SLUGS, 1.5)).toThrow(/positive integer/);
  });
});

describe("the partition guard can actually fail (#1586)", () => {
  // Negative controls. Without these the exhaustiveness check is untested code asserting a property
  // nothing ever violates, which is indistinguishable from no check at all.
  it("catches a target that would never be scored", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b", "c"], [["a"], ["b"]])).toThrow(/never scored: c/);
  });

  it("catches a target scored twice", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b"], [["a", "b"], ["b"]])).toThrow(/scored more than once: b/);
  });

  it("catches a slug that is not in the corpus at all", () => {
    expect(() => assertPartitionCoversEveryTarget(["a"], [["a"], ["typo"]])).toThrow(/not in the corpus: typo/);
  });

  it("passes a true partition", () => {
    expect(() => assertPartitionCoversEveryTarget(["a", "b", "c"], [["c"], ["a"], ["b"]])).not.toThrow();
  });
});

describe("the weight table tracks the corpus (#1586)", () => {
  // A weight is only a partitioning hint, so a missing one is not an error — but a weight for a
  // target that no longer exists is a stale row that will quietly mis-skew the split, and nothing
  // else would ever surface it.
  it("has no weight for a target that has left the corpus", () => {
    expect(Object.keys(TARGET_SCAN_SECONDS).filter((s) => !SLUGS.includes(s))).toEqual([]);
  });

  it("matches every conservative hosted elapsed measurement and the exact four-shard plan", () => {
    expect(TARGET_SCAN_SECONDS).toEqual(EXPECTED_WEIGHTS);
    expect(partitionTargets(SLUGS, 4)).toEqual(FOUR_SHARD_ASSIGNMENT);
    expect(partitionTargets(SLUGS, 4).map(load)).toEqual(FOUR_SHARD_LOADS);
  });
});

describe("corpus workflow four-shard production contract", () => {
  it("keeps all producers four-way and live provider runs separate from snapshot replay", () => {
    expect(contractErrors()).toEqual([]);
  });

  it("keeps recorded shard weights below their event-scoped budgets (not a runtime forecast)", () => {
    const workflow = parseYaml(WORKFLOW_TEXT) as CorpusWorkflow;
    for (const event of ["push", "pull_request", "merge_group"]) {
      for (const [index, members] of partitionTargets(SLUGS, 4).entries()) {
        const minutes = Number(eventExpression(workflow.jobs.shard["timeout-minutes"], event, index + 1));
        expect(load(members) + CORPUS_SHARD_OVERHEAD_SECONDS).toBeLessThan(minutes * 60);
      }
    }
    for (const event of ["schedule", "workflow_dispatch"]) {
      const minutes = Number(eventExpression(workflow.jobs.shard["timeout-minutes"], event));
      expect(load(SLUGS) + 10 * 60).toBeLessThan(minutes * 60);
    }
  });

  it.each([
    ["old weights", WORKFLOW_TEXT, SLUGS, { ...EXPECTED_WEIGHTS, carbon: 564, documenso: 119, "inbox-zero": 95 }],
    ["producer 4→3", WORKFLOW_TEXT.replace("shard: [1, 2, 3, 4]", "shard: [1, 2, 3]").replace("SHARD_COUNT: 4", "SHARD_COUNT: 3"), SLUGS, EXPECTED_WEIGHTS],
    ["replay 4→3", WORKFLOW_TEXT.replaceAll("shard: [1, 2, 3, 4]", "shard: [1, 2, 3]").replaceAll("SHARD_COUNT: 4", "SHARD_COUNT: 3"), SLUGS, EXPECTED_WEIGHTS],
    ["producer/replay mismatch", WORKFLOW_TEXT.replace("SHARD_COUNT: 4", "SHARD_COUNT: 2"), SLUGS, EXPECTED_WEIGHTS],
    ["readiness restricted to push", WORKFLOW_TEXT.replace("(github.event_name == 'push' || github.event_name == 'pull_request' || github.event_name == 'merge_group') && '1' || '0'", "github.event_name == 'push' && '1' || '0'"), SLUGS, EXPECTED_WEIGHTS],
    ["replay restricted to push", WORKFLOW_TEXT.replace("needs.prepare-current-inputs.outputs.relevant == 'true' && (github.event_name == 'push' || github.event_name == 'pull_request' || github.event_name == 'merge_group')", "needs.prepare-current-inputs.outputs.relevant == 'true' && github.event_name == 'push'"), SLUGS, EXPECTED_WEIGHTS],
    ["schedule/manual timeout restored to 30m", WORKFLOW_TEXT.replace("&& 120 ||", "&& 30 ||"), SLUGS, EXPECTED_WEIGHTS],
    ["dropped target", WORKFLOW_TEXT, SLUGS.slice(1), EXPECTED_WEIGHTS],
    ["duplicated target", WORKFLOW_TEXT, [...SLUGS, SLUGS[0]!], EXPECTED_WEIGHTS],
    ["PR/queue matrix alone reverted", WORKFLOW_TEXT.replace("shard: [1, 2, 3, 4]", "shard: [1]"), SLUGS, EXPECTED_WEIGHTS],
    ["PR/queue count alone reverted", WORKFLOW_TEXT.replace("SHARD_COUNT: 4", "SHARD_COUNT: 1"), SLUGS, EXPECTED_WEIGHTS],
  ] as const)("turns red in a disposable %s reversion", (_name, workflow, slugs, weights) => {
    expect(contractErrors(workflow, slugs, weights)).not.toEqual([]);
  });
});
