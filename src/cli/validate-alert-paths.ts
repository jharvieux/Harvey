// pnpm exec tsx src/cli/validate-alert-paths.ts [--labels] [--seed-unprovable | --seed-missing-label]
//
// Gate 5 of epic #1320 (#1287). Two passes:
//
//   • STRUCTURAL (always, offline) — every alert path is dispatch-provable, carries a recorded proof
//     run, and agrees with .github/alert-paths.json in both directions; every scheduled workflow
//     either alerts on failure or is disclosed as not doing so. Locked into `pnpm verify` by
//     src/alert-paths.test.ts.
//   • --labels (needs an authenticated `gh`) — THE standing invariant #1287 asks for: every alert
//     step self-heals its marker label with `gh label create`, so a marker label that does not exist
//     is machine-checkable proof that the path has never executed. This is the half no diff can
//     speak to — a label deleted by hand in the GitHub UI leaves every file in this repo unchanged —
//     so it runs on a schedule as well as on PRs.
//
// A `gh` that cannot run exits 127 = UNVERIFIABLE, never 1: "I could not check" must not be
// reported in the same channel as "I checked and the label is gone" (#1246's rule for falsifiers).
//
// The two --seed flags are the negative controls. A gate only ever seen passing is indistinguishable
// from one that cannot fail — which is the exact defect this gate exists to catch.

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkAlertPaths, expectedLabels, workflowFacts, type AlertPathRegistry } from "../alert-paths.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WORKFLOWS = join(REPO_ROOT, ".github", "workflows");
const REGISTRY = join(REPO_ROOT, ".github", "alert-paths.json");

export function loadFacts(root = REPO_ROOT): ReturnType<typeof workflowFacts>[] {
  const dir = join(root, ".github", "workflows");
  return readdirSync(dir)
    .filter((f) => f.endsWith(".yml"))
    .sort()
    .map((f) => workflowFacts(`.github/workflows/${f}`, readFileSync(join(dir, f), "utf8")));
}

export function loadRegistry(root = REPO_ROOT): AlertPathRegistry {
  return JSON.parse(readFileSync(join(root, ".github", "alert-paths.json"), "utf8")) as AlertPathRegistry;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const registry = loadRegistry();
  let facts = loadFacts();

  // Negative control 1: strip workflow_dispatch out of every alert condition. That is precisely the
  // state main was in before #1287 — four paths nobody could fire — so the gate MUST reject it.
  if (process.argv.includes("--seed-unprovable")) {
    facts = facts.map((f) => ({ ...f, alertSteps: f.alertSteps.map((s) => ({ ...s, condition: "failure() && github.event_name == 'schedule'" })) }));
  }

  const violations = checkAlertPaths(facts, registry);
  const alerting = facts.filter((f) => f.alertSteps.length > 0);

  console.log(`Alert paths, derived from ${facts.length} workflow file(s) in ${WORKFLOWS.replace(REPO_ROOT + "/", "")}:`);
  for (const f of alerting) {
    for (const s of f.alertSteps) {
      const proof = registry.paths.find((p) => p.marker === s.marker)?.provenBy;
      console.log(`  ${s.marker.padEnd(24)} ${f.workflow}\n${" ".repeat(28)}proved by ${proof?.run ?? "(nothing)"} → issue #${proof?.issue ?? "?"}`);
    }
  }
  for (const u of registry.unconverted) console.log(`  ${u.marker.padEnd(24)} ${u.workflow} (inlined, not drilled — proved by issue #${u.provenBy.issue})`);

  // Disclosed, never silent: a scheduled workflow with no alarm is still a hole, and an absent row
  // never appears in a tally.
  for (const w of registry.scheduledWithoutAlertPath) {
    console.log(`  (no alert path)          ${w.workflow} — scheduled failure raises nothing; tracked by #${w.tracking}`);
  }

  if (process.argv.includes("--labels")) {
    const gh = spawnSync("gh", ["label", "list", "--limit", "200", "--json", "name", "--jq", ".[].name"], { encoding: "utf8", cwd: REPO_ROOT });
    if (gh.status !== 0) {
      console.error(`✗ UNVERIFIABLE — \`gh label list\` could not run (${(gh.stderr || gh.error?.message || "").trim().slice(0, 200)}). This is not "the labels are fine" and not "the labels are gone"; it is no measurement at all.`);
      process.exit(127);
    }
    const present = new Set(gh.stdout.split("\n").map((l) => l.trim()).filter(Boolean));
    // Negative control 2: pretend a marker label vanished. #1287's whole finding rests on a missing
    // label being detectable, so this must fail.
    if (process.argv.includes("--seed-missing-label")) present.delete(expectedLabels(registry)[0] as string);

    const missing = expectedLabels(registry).filter((l) => !present.has(l));
    for (const l of missing) {
      violations.push({ workflow: "(labels)", detail: `marker label '${l}' does not exist. Every alert step creates its own label, so this is proof the path has not run — or that someone deleted the label, which breaks find-or-update and turns every future alarm into a duplicate issue.` });
    }
    if (missing.length === 0) console.log(`\n✓ all ${expectedLabels(registry).length} marker label(s) exist`);
  } else {
    console.log("\nℹ marker-label existence NOT checked (pass --labels with an authenticated gh). Structure alone cannot tell a path that has run from one that never has.");
  }

  if (violations.length > 0) {
    console.error(`\n✗ ${violations.length} alert-path violation(s):`);
    for (const v of violations) console.error(`  ${v.workflow} — ${v.detail}`);
    process.exit(1);
  }
  console.log(`\n✓ ${alerting.reduce((n, f) => n + f.alertSteps.length, 0)} alert path(s): every one dispatch-provable and carrying a recorded proof run`);
}
