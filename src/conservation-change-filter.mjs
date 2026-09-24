import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// validate-conservation reaches the whole M1-M10 runner graph, the mechanical scanner,
// detector registries, effectiveness evidence, and several package-script wrappers. Keeping a
// leaf allowlist here recreated the exact omission this gate exists to catch. The source/input
// population is therefore conservative by design: all production source plus every runtime input
// family the shipping command consumes. A new file inside one of these families is selected
// without needing a second routing edit.
export const CONSERVATION_INPUT_RULES = Object.freeze([
  { kind: "prefix", value: "src/" },
  { kind: "prefix", value: "targets/calibration/" },
  { kind: "prefix", value: "briefs/" },
  { kind: "prefix", value: "tools/" },
  { kind: "prefix", value: ".github/actions/mechanical-binaries/" },
  { kind: "exact", value: ".github/workflows/conservation.yml" },
  { kind: "exact", value: ".nvmrc" },
  { kind: "exact", value: ".semgrepignore" },
  { kind: "exact", value: "package.json" },
  { kind: "exact", value: "pnpm-lock.yaml" },
  { kind: "exact", value: "tsconfig.json" },
  { kind: "exact", value: "vitest.config.ts" },
]);

const DRIFT_INPUT_RULES = Object.freeze([
  { kind: "prefix", value: "src/scan/__fixtures__/" },
  { kind: "prefix", value: "src/__fixtures__/" },
  { kind: "prefix", value: ".github/actions/mechanical-binaries/" },
  { kind: "exact", value: "src/cli/fixture-drift.ts" },
  { kind: "exact", value: "src/cli/osv-fixture-drift.ts" },
  { kind: "exact", value: "src/scan/fixture-drift-contracts.ts" },
  { kind: "exact", value: ".github/workflows/conservation.yml" },
]);

function matches(path, rule) {
  return rule.kind === "prefix" ? path.startsWith(rule.value) : path === rule.value;
}

function matchingPaths(paths, rules) {
  return paths.filter((path) => rules.some((rule) => matches(path, rule)));
}

export function planConservationRun(event, changedPaths) {
  const paths = [...new Set(changedPaths.filter(Boolean))].sort();
  if (event === "merge_group") {
    return { relevant: true, drift: false, paths, relevantPaths: [], driftPaths: [], reason: "merge queue entries run the conservation gate" };
  }
  if (event !== "pull_request") {
    return { relevant: true, drift: true, paths, relevantPaths: [], driftPaths: [], reason: `${event} events run the gate and captured-fixture drift tier` };
  }
  const relevantPaths = matchingPaths(paths, CONSERVATION_INPUT_RULES);
  const driftPaths = matchingPaths(paths, DRIFT_INPUT_RULES);
  return {
    relevant: relevantPaths.length > 0,
    drift: driftPaths.length > 0,
    paths,
    relevantPaths,
    driftPaths,
    reason: relevantPaths.length > 0
      ? `${relevantPaths.length} changed conservation input(s) select real execution`
      : "no changed conservation source or runtime input; declare an explicit no-op",
  };
}

function value(args, flag, fallback = "") {
  const index = args.indexOf(flag);
  return index === -1 ? fallback : args[index + 1];
}

function main() {
  const args = process.argv.slice(2);
  const known = new Set(["--base", "--event", "--github-output", "--head"]);
  for (let index = 0; index < args.length; index += 2) {
    if (!known.has(args[index]) || args[index + 1] === undefined) throw new Error(`unknown or incomplete argument: ${args[index] ?? "<missing>"}`);
  }
  const event = value(args, "--event", "pull_request");
  const base = value(args, "--base");
  const head = value(args, "--head", "HEAD");
  const paths = event === "pull_request"
    ? execFileSync("git", ["diff", "--name-only", base, head], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).split("\n").filter(Boolean)
    : [];
  const plan = planConservationRun(event, paths);
  if (plan.paths.length > 0) console.log(`Changed files:\n${plan.paths.join("\n")}`);
  console.log(`conservation selection: relevant=${plan.relevant}; drift=${plan.drift}; ${plan.reason}`);
  if (!plan.relevant) {
    console.log("No change to the conservation source or runtime-input population — nothing was scored. The daily scheduled run covers the tree regardless.");
  } else if (!plan.drift) {
    console.log("Running the gate but skipping captured-fixture drift checks: those measure upstream tool output over time, and the daily scheduled run executes all of them.");
  }
  const githubOutput = value(args, "--github-output");
  if (githubOutput) appendFileSync(githubOutput, `relevant=${plan.relevant}\ndrift=${plan.drift}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
