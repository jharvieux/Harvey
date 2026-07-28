// pnpm validate-scored-gates [--seed-missing-script | --seed-broken-cadence | --seed-unclassified]
//
// #1288: prints where every SCORED gate runs, and fails when one of them runs nowhere.
//
// Offline and sub-second — its logic is locked into `pnpm verify` by src/scored-gates.test.ts, so
// this CLI is the human-readable view plus the negative controls. Each --seed flag corrupts one
// input and the run MUST go red, so the failing direction is exercised rather than assumed.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { assertKnownFlags } from "./args.js";
import {
  NOT_SCORED,
  SCORED_GATES,
  checkScoredGates,
  describeCadence,
  discoverValidateClis,
  type GateInputs,
} from "../scored-gates.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function loadGateInputs(root = REPO_ROOT): GateInputs {
  const workflowDir = join(root, ".github", "workflows");
  const workflows: Record<string, string> = {};
  for (const f of readNamesSafe(workflowDir).filter((f) => f.endsWith(".yml"))) {
    workflows[`.github/workflows/${f}`] = readFileSync(join(workflowDir, f), "utf8");
  }
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { scripts?: Record<string, string> };
  return {
    discovered: discoverValidateClis(join(root, "src", "cli")),
    scripts: pkg.scripts ?? {},
    workflows,
  };
}

const SEEDS = ["--seed-missing-script", "--seed-broken-cadence", "--seed-unclassified"] as const;
assertKnownFlags(SEEDS);

let inputs = loadGateInputs();
const gates = SCORED_GATES;

// Negative control 1: the state #1288 found — a scored gate with no package.json script, so nobody
// could discover it, let alone run it.
if (process.argv.includes("--seed-missing-script")) {
  const scripts = { ...inputs.scripts };
  delete scripts["validate:precision"];
  inputs = { ...inputs, scripts };
}

// Negative control 2: the cadence silently removed again — the calibration step deleted from ci.yml.
if (process.argv.includes("--seed-broken-cadence")) {
  const workflows = { ...inputs.workflows };
  workflows[".github/workflows/ci.yml"] = (workflows[".github/workflows/ci.yml"] ?? "").replaceAll("src/cli/validate-calibration.ts", "");
  inputs = { ...inputs, workflows };
}

// Negative control 3: a sixth scored gate lands in src/cli and is classified nowhere.
if (process.argv.includes("--seed-unclassified")) {
  inputs = { ...inputs, discovered: [...inputs.discovered, "validate-brand-new-recall"] };
}

const violations = checkScoredGates(inputs, gates);

console.log(`Scored gates — where each recall/precision number is re-measured:\n`);
for (const gate of gates) {
  console.log(`  ${gate.id.padEnd(24)} ${gate.measures}`);
  console.log(`  ${" ".repeat(24)} ${describeCadence(gate.cadence)}  [pnpm ${gate.script}]`);
}
console.log(`\nClassified as not scored (structural or schema checks, no recall/precision number): ${NOT_SCORED.length}`);

const noCadence = gates.filter((g) => g.cadence.kind === "none");
if (noCadence.length) {
  console.log(
    `\nDISCLOSED GAP — ${noCadence.length} of ${gates.length} scored gates run on no cadence: ` +
      noCadence.map((g) => `${g.id} (#${g.cadence.kind === "none" ? g.cadence.issue : ""})`).join(", ") +
      `\nThe reason each one gives is a recorded REASON block in src/scored-gates.ts, re-tested by \`pnpm validate-reasons --revalidate\`.`,
  );
}

if (violations.length) {
  console.log(`\nGATE FAIL — ${violations.length} violation(s):`);
  for (const v of violations) console.log(`  - ${v}`);
  process.exit(1);
}
console.log(`\nGATE PASS — every scored gate is discoverable by a script, and every declared cadence venue still invokes it.`);
