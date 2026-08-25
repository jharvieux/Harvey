import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

const DEFAULT_REGISTRY = fileURLToPath(new URL("./heavy-test-workloads.json", import.meta.url));
const SAFE_TEST_FILE = /^src\/(?:[a-z0-9_.-]+\/)*[a-z0-9_.-]+\.test\.ts$/;
const SAFE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function matches(path, rule) {
  return rule.endsWith("/") || rule.endsWith("-") ? path.startsWith(rule) : path === rule;
}

export function loadHeavyRegistry(path = DEFAULT_REGISTRY) {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  if (parsed?.version !== 1 || !Array.isArray(parsed.globalPaths) || !Array.isArray(parsed.workloads) || parsed.workloads.length === 0) {
    throw new Error(`invalid heavy workload registry: ${path}`);
  }

  const ids = new Set();
  const files = new Set();
  for (const workload of parsed.workloads) {
    if (!SAFE_ID.test(workload.id ?? "") || ids.has(workload.id)) throw new Error(`invalid or duplicate heavy workload id: ${String(workload.id)}`);
    if (!SAFE_TEST_FILE.test(workload.testFile ?? "") || files.has(workload.testFile)) {
      throw new Error(`invalid or duplicate heavy test file: ${String(workload.testFile)}`);
    }
    if (!existsSync(workload.testFile)) throw new Error(`registered heavy test file does not exist: ${workload.testFile}`);
    if (!Number.isFinite(workload.weightSeconds) || workload.weightSeconds <= 0) {
      throw new Error(`heavy workload ${workload.id} has no positive weightSeconds`);
    }
    if (!Array.isArray(workload.paths) || workload.paths.length === 0 || workload.paths.some((entry) => typeof entry !== "string" || entry.length === 0)) {
      throw new Error(`heavy workload ${workload.id} has no valid path ownership rules`);
    }
    ids.add(workload.id);
    files.add(workload.testFile);
  }
  return parsed;
}

export function selectHeavyWorkloads(registry, changedPaths, { forceFull = false, reason = "non-pull-request event" } = {}) {
  const all = registry.workloads.map((workload) => workload.id);
  const paths = [...new Set(changedPaths.filter(Boolean))].sort();
  if (forceFull) return { mode: "full", selected: all, changedPaths: paths, reasons: [reason], unmatched: [] };
  if (paths.length === 0) {
    return { mode: "skipped", selected: [], changedPaths: [], reasons: ["no changed paths require a heavy workload"], unmatched: [] };
  }

  const global = paths.filter((path) => registry.globalPaths.some((rule) => matches(path, rule)));
  if (global.length > 0) {
    return {
      mode: "full",
      selected: all,
      changedPaths: paths,
      reasons: global.map((path) => `${path} controls the heavy-test planner or shared runtime`),
      unmatched: [],
    };
  }

  const selected = new Set();
  const reasons = [];
  const unmatched = [];
  for (const path of paths) {
    const owners = registry.workloads.filter((workload) => workload.testFile === path || workload.paths.some((rule) => matches(path, rule)));
    if (owners.length === 0) {
      unmatched.push(path);
      continue;
    }
    for (const owner of owners) {
      selected.add(owner.id);
      reasons.push(`${path} -> ${owner.id}`);
    }
  }

  if (unmatched.length > 0) {
    reasons.push(...unmatched.map((path) => `${path} has no mapped heavy workload; the full post-merge run remains the backstop`));
  }
  if (selected.size === 0) {
    return { mode: "skipped", selected: [], changedPaths: paths, reasons, unmatched };
  }
  return { mode: "scoped", selected: all.filter((id) => selected.has(id)), changedPaths: paths, reasons, unmatched };
}

export function shardSelectedWorkloads(registry, selectedIds, maxShards = 3) {
  if (!Number.isInteger(maxShards) || maxShards < 1) throw new Error(`maxShards must be a positive integer, got ${maxShards}`);
  const selected = selectedIds.map((id) => {
    const workload = registry.workloads.find((candidate) => candidate.id === id);
    if (!workload) throw new Error(`unknown selected workload: ${id}`);
    return workload;
  });
  if (selected.length === 0) throw new Error("refusing to create an empty heavy-test matrix");

  const count = Math.min(maxShards, selected.length);
  const bins = Array.from({ length: count }, (_, index) => ({ shard: index + 1, weight: 0, workloads: [] }));
  const ordered = [...selected].sort((a, b) => b.weightSeconds - a.weightSeconds || a.testFile.localeCompare(b.testFile));
  const reserved = count >= 3 ? ordered.find((workload) => workload.id === "run-audit") : undefined;
  if (reserved) {
    bins[0].workloads.push(reserved);
    bins[0].weight = Number.POSITIVE_INFINITY;
  }
  for (const workload of ordered) {
    if (workload === reserved) continue;
    let lightest = 0;
    for (let index = 1; index < bins.length; index += 1) {
      if (bins[index].weight < bins[lightest].weight) lightest = index;
    }
    bins[lightest].workloads.push(workload);
    bins[lightest].weight += workload.weightSeconds;
  }

  const gatesByShard =
    bins.length === 1
      ? [["calibration", "source-recall", "m2-coverage", "shared-source-match"]]
      : bins.length === 2
        ? [["calibration", "m2-coverage", "shared-source-match"], ["source-recall"]]
        : [["calibration"], ["source-recall"], ["m2-coverage", "shared-source-match"], ...bins.slice(3).map(() => [])];

  return {
    include: bins.map((bin, index) => ({
      shard: bin.shard,
      total: bins.length,
      files: bin.workloads.map((workload) => workload.testFile),
      workloadIds: bin.workloads.map((workload) => workload.id),
      gates: gatesByShard[index] ?? [],
    })),
  };
}

export function buildHeavyPlan(registry, changedPaths, options = {}) {
  const selection = selectHeavyWorkloads(registry, changedPaths, options);
  const maxShards = options.maxShards ?? 3;
  if (selection.selected.length === 0) {
    const matrix = { include: [] };
    const digest = createHash("sha256").update(JSON.stringify({ selection, matrix })).digest("hex");
    return { ...selection, matrix, digest };
  }
  // A scoped population pays one runner per useful parallel lane, not one runner per test file.
  // Four or fewer workloads fit in two serialized lanes without recreating the three-runner setup
  // cost this router exists to remove. Full plans retain the established three-way partition.
  const plannedShards = selection.mode === "full" ? maxShards : Math.min(maxShards, selection.selected.length === 1 ? 1 : selection.selected.length <= 4 ? 2 : 3);
  const matrix = shardSelectedWorkloads(registry, selection.selected, plannedShards);
  const digest = createHash("sha256").update(JSON.stringify({ selection, matrix })).digest("hex");
  return { ...selection, matrix, digest };
}

function value(args, flag, fallback) {
  const index = args.indexOf(flag);
  return index === -1 ? fallback : args[index + 1];
}

function main() {
  const args = process.argv.slice(2);
  const known = new Set(["--base", "--event", "--github-output", "--head", "--max-shards", "--registry"]);
  for (let index = 0; index < args.length; index += 2) {
    if (!known.has(args[index]) || args[index + 1] === undefined) throw new Error(`unknown or incomplete argument: ${args[index] ?? "<missing>"}`);
  }
  const event = value(args, "--event", "pull_request");
  const base = value(args, "--base", "");
  const head = value(args, "--head", "HEAD");
  const maxShards = Number(value(args, "--max-shards", "3"));
  const registry = loadHeavyRegistry(value(args, "--registry", DEFAULT_REGISTRY));
  const forceFull = event !== "pull_request";
  let paths = [];
  if (!forceFull && base) {
    paths = execFileSync("git", ["diff", "--name-only", base, head], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
      .split("\n")
      .filter(Boolean);
  }
  const plan = buildHeavyPlan(registry, paths, { forceFull, maxShards, reason: `${event} events run the full heavy suite` });
  const summary = `heavy plan: ${plan.mode}; ${plan.selected.length}/${registry.workloads.length} workload(s); ${plan.matrix.include.length} runner(s); digest ${plan.digest.slice(0, 12)}`;
  console.log(summary);
  for (const reason of plan.reasons) console.log(`  ${reason}`);
  for (const group of plan.matrix.include) console.log(`  shard ${group.shard}/${group.total}: ${group.workloadIds.join(", ")}`);

  const githubOutput = value(args, "--github-output", "");
  if (githubOutput) {
    appendFileSync(
      githubOutput,
      [
        `matrix=${JSON.stringify(plan.matrix)}`,
        `mode=${plan.mode}`,
        `run=${plan.selected.length > 0}`,
        `digest=${plan.digest}`,
        `selected=${plan.selected.join(",")}`,
        `summary=${summary}`,
      ].join("\n") + "\n",
    );
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
