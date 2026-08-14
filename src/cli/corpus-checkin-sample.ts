import "./sync-stdio.js";
import { writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import { sealCorpusCheckinSample, verifyCorpusCheckinSample } from "../corpus-checkin-sample.js";

const USAGE = "usage: corpus-checkin-sample --scorecard <corpus-drift.json> --relevance <corpus-relevance.json> --jobs <corpus-checkin-jobs.json> --evidence-dir <parts> --producer <current-hosted-producer.json> --replay <current-independent-replay.json> --out <corpus-checkin-performance-sample.json> --run-id <id> --run-attempt <attempt> --actions-head-sha <sha> --execution-head-sha <sha> --event pull_request --ref <refs/pull/N/merge> --requested-runner <label>";

const NAMES = [
  "--scorecard",
  "--relevance",
  "--jobs",
  "--evidence-dir",
  "--producer",
  "--replay",
  "--out",
  "--run-id",
  "--run-attempt",
  "--actions-head-sha",
  "--execution-head-sha",
  "--event",
  "--ref",
  "--requested-runner",
] as const;

function parse(): Map<string, string> {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === "--help") {
    console.log(USAGE);
    process.exit(0);
  }
  const known = new Set<string>(NAMES);
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name || !known.has(name)) throw new Error(`unknown argument ${name ?? "<missing>"}`);
    if (values.has(name)) throw new Error(`duplicate argument ${name}`);
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${name}`);
    values.set(name, value);
  }
  for (const name of NAMES) if (!values.has(name)) throw new Error(`missing ${name}`);
  return values;
}

function positiveInteger(value: string, name: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function within(parent: string, child: string): boolean {
  const path = relative(parent, child).replaceAll("\\", "/");
  return path === "" || (!path.startsWith("../") && path !== "..");
}

try {
  const args = parse();
  const value = (name: (typeof NAMES)[number]): string => args.get(name)!;
  const scorecardPath = resolve(value("--scorecard"));
  const relevancePath = resolve(value("--relevance"));
  const jobsPath = resolve(value("--jobs"));
  const evidenceDir = resolve(value("--evidence-dir"));
  const producerPath = resolve(value("--producer"));
  const replayPath = resolve(value("--replay"));
  const out = resolve(value("--out"));
  const rawInputs = [scorecardPath, relevancePath, jobsPath, producerPath, replayPath];
  if (rawInputs.includes(out) || within(evidenceDir, out)) {
    throw new Error("--out must be distinct from every raw input and outside --evidence-dir; self-reseal is forbidden");
  }
  const options = {
    scorecardPath,
    relevancePath,
    jobsPath,
    evidenceDir,
    producerPath,
    replayPath,
    repoRoot: process.cwd(),
    runId: positiveInteger(value("--run-id"), "--run-id"),
    runAttempt: positiveInteger(value("--run-attempt"), "--run-attempt"),
    actionsHeadSha: value("--actions-head-sha"),
    executionHeadSha: value("--execution-head-sha"),
    event: value("--event"),
    ref: value("--ref"),
    requestedRunner: value("--requested-runner"),
  };
  const sample = sealCorpusCheckinSample(options);
  verifyCorpusCheckinSample(sample, options);
  writeFileSync(out, `${JSON.stringify(sample, null, 2)}\n`);
  console.error(
    `CORPUS CHECK-IN SAMPLE PASS: correctness=${sample.validity.correctnessValid}; performanceComparable=${sample.validity.performanceComparable}; `
    + `targets=${sample.population.targetCount}; shards=${sample.population.shardSizes.join("/")}; comparison=${sample.comparison.key}`,
  );
} catch (error) {
  console.error(`CORPUS CHECK-IN SAMPLE REJECT: ${error instanceof Error ? error.message : String(error)}`);
  console.error(USAGE);
  process.exit(1);
}
