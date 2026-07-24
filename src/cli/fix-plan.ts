// The FixPlan producer stage (design §1.2), as an operator CLI:
//
//   pnpm exec tsx src/cli/fix-plan.ts <findings.json> <manifest.json> --target <client-checkout> [--out <dir>]
//
// Screens the client-approved findings via intake(), drafts a FixPlan per auto/manual finding with a
// grep-derived blast radius over the real checkout, runs each plan through the SAME rails that gate
// execution (checkPlanRails), and writes fix-plans.json. Side-effect-free: no worktree, no git, no
// diff — the plan is what the implementer pass (and the operator) read before any code changes. A plan
// whose blast radius already fails the rails is emitted as rails-blocked so it is downgraded cheaply,
// before a worktree ever spins up.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { validateFindings, type FindingsDocument } from "../findings.js";
import { checkPlanRails, intake, type EngagementManifest } from "../fix/pipeline.js";
import { producePlan } from "../fix/produce-plan.js";
import type { FixPlan } from "../fix/plan.js";

const args = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--target", "--out"]);
const positional: string[] = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i] as string;
  if (VALUE_FLAGS.has(a)) i++;
  else if (!a.startsWith("--")) positional.push(a);
}
const [findingsPath, manifestPath] = positional;
const flag = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const targetArg = flag("--target");
const outDir = resolve(flag("--out") ?? "fix-out");

if (!findingsPath || !manifestPath || !targetArg) {
  console.error("usage: pnpm exec tsx src/cli/fix-plan.ts <findings.json> <manifest.json> --target <client-checkout> [--out <dir>]");
  process.exit(2);
}

const doc = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
const { ok, errors } = validateFindings(doc);
if (!ok) {
  console.error(`✗ ${findingsPath} is not a valid findings document:`);
  for (const e of errors) console.error(`  ${e}`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as EngagementManifest;
const result = intake(doc, manifest);
if (!result.baselineMatches) {
  console.error(
    `✗ baseline mismatch: findings meta.commit=${doc.meta.commit} ≠ manifest.baselineCommit=${manifest.baselineCommit}. Re-baseline before planning.`,
  );
  process.exit(1);
}

const targetDir = resolve(targetArg);
mkdirSync(outDir, { recursive: true });

interface PlannedRow {
  plan: FixPlan;
  railsOk: boolean;
  railViolation?: string;
}

const rows: PlannedRow[] = [];
for (const { finding, screen } of [...result.auto, ...result.manual]) {
  const plan = producePlan(finding, { screen, targetDir });
  const rails = checkPlanRails(plan, manifest);
  rows.push({ plan, railsOk: rails.ok, railViolation: rails.violation });
}

writeFileSync(
  join(outDir, "fix-plans.json"),
  `${JSON.stringify({ client: manifest.client, baselineCommit: manifest.baselineCommit, plans: rows }, null, 2)}\n`,
);

console.log(`Fix plans — ${manifest.client} @ ${manifest.baselineCommit} (target ${targetDir})`);
console.log(`Artifacts: ${outDir}  ·  plans only — no worktree, no diff, no push.\n`);
for (const { plan, railsOk, railViolation } of rows) {
  const tag = railsOk ? `[${plan.mode}/${plan.tier}]` : "[rails-blocked]";
  const detail = railsOk ? `${plan.blastRadius.callers.length} caller(s)` : railViolation;
  console.log(`  ${railsOk ? "✓" : "✗"} ${plan.findingId}  ${tag}  ${plan.blastRadius.files.join(", ")} — ${detail}`);
}
console.log(`\nRECOMMEND-ONLY: ${result.recommendOnly.length} · not client-approved: ${result.notApproved.length}`);
