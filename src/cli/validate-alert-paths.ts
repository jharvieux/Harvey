// pnpm exec tsx src/cli/validate-alert-paths.ts [--labels]
//     [--seed-unprovable | --seed-missing-label | --seed-closed-tracking]
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
//     so it runs on a schedule as well as on PRs. It also re-reads the tracking issue behind every
//     `scheduledWithoutAlertPath` disclosure: that hatch fails OPEN the day the tracker closes.
//
// A `gh` that cannot run exits 127 = UNVERIFIABLE, never 1: "I could not check" must not be
// reported in the same channel as "I checked and the label is gone" (#1246's rule for falsifiers).
//
// The two --seed flags are the negative controls. A gate only ever seen passing is indistinguishable
// from one that cannot fail — which is the exact defect this gate exists to catch.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { recordMeasured } from "../ci-liveness.js";
import { checkAlertPaths, checkDisclosureTracking, expectedLabels, retrying, seedClosedTrackingPopulation, staleProofs, workflowFacts, type AlertPathRegistry } from "../alert-paths.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const WORKFLOWS = join(REPO_ROOT, ".github", "workflows");

export function loadFacts(root = REPO_ROOT): ReturnType<typeof workflowFacts>[] {
  const dir = join(root, ".github", "workflows");
  return readNamesSafe(dir)
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
      const entry = registry.paths.find((p) => p.marker === s.marker);
      // An unproven path prints louder than a proven one, not quieter. The hatch is legitimate and
      // it is still a path nobody has watched fire, which is the state this gate exists to name.
      const line = entry?.pendingProof
        ? `UNPROVEN — landed ${entry.pendingProof.since}, proof run outstanding, tracked by #${entry.pendingProof.tracking}`
        : `proved by ${entry?.provenBy?.run ?? "(nothing)"} → issue #${entry?.provenBy?.issue ?? "?"}`;
      console.log(`  ${s.marker.padEnd(24)} ${f.workflow}\n${" ".repeat(28)}${line}`);
    }
  }
  for (const u of registry.unconverted) console.log(`  ${u.marker.padEnd(24)} ${u.workflow} (inlined, not drilled — proved by issue #${u.provenBy.issue})`);

  // Disclosed, never silent: a scheduled workflow with no alarm is still a hole, and an absent row
  // never appears in a tally.
  for (const w of registry.scheduledWithoutAlertPath) {
    console.log(`  (no alert path)          ${w.workflow} — scheduled failure raises nothing; tracked by #${w.tracking}`);
  }

  // #1604: every converted path's alert step runs through the ONE shared find-or-update.sh, so a
  // change to it is a claim-invalidating event for every OTHER marker's provenBy, not just the one
  // PR that touched it. Informational, not a violation — see staleProofs' own doc comment.
  const sharedActionSha = spawnSync("git", ["rev-parse", "HEAD:.github/actions/alert-issue/find-or-update.sh"], { encoding: "utf8", cwd: REPO_ROOT });
  if (sharedActionSha.status === 0) {
    const stale = staleProofs(registry, sharedActionSha.stdout.trim());
    if (stale.length > 0) {
      console.log(`\n⚠ ${stale.length} proof(s) predate the current find-or-update.sh (${sharedActionSha.stdout.trim().slice(0, 12)}):`);
      for (const s of stale) console.log(`  ${s.marker} — recorded against ${s.recordedSha.slice(0, 12)}; re-drill to refresh`);
    }
  }

  if (process.argv.includes("--labels")) {
    const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    const runGh = (args: string[]) => retrying(() => spawnSync("gh", args, { encoding: "utf8", cwd: REPO_ROOT }), 3, sleep);
    const unverifiable = (what: string, detail: string): never => {
      console.error(`✗ UNVERIFIABLE — ${what} could not run after 3 attempts (${detail.trim().slice(0, 200)}). This is not "the labels are fine" and not "the labels are gone"; it is no measurement at all.`);
      process.exit(127);
    };

    const gh = runGh(["label", "list", "--limit", "200", "--json", "name", "--jq", ".[].name"]);
    if (gh.status !== 0) unverifiable("`gh label list`", gh.stderr || gh.error?.message || "");
    const present = new Set(gh.stdout.split("\n").map((l) => l.trim()).filter(Boolean));
    // Negative control 2: pretend a marker label vanished. #1287's whole finding rests on a missing
    // label being detectable, so this must fail.
    if (process.argv.includes("--seed-missing-label")) present.delete(expectedLabels(registry)[0] as string);

    const missing = expectedLabels(registry).filter((l) => !present.has(l));
    for (const l of missing) {
      violations.push({ workflow: "(labels)", detail: `marker label '${l}' does not exist. Every alert step creates its own label, so this is proof the path has not run — or that someone deleted the label, which breaks find-or-update and turns every future alarm into a duplicate issue.` });
    }
    if (missing.length === 0) console.log(`\n✓ all ${expectedLabels(registry).length} marker label(s) exist`);

    // The disclosure hatch, checked rather than trusted. --seed-closed-tracking is its negative
    // control: a hatch nobody has watched fail is one nobody knows can fail.
    const seedClosed = process.argv.includes("--seed-closed-tracking");
    const trackingState = (issue: number): string | undefined => {
      if (seedClosed) return "CLOSED";
      const r = runGh(["issue", "view", String(issue), "--json", "state", "--jq", ".state"]);
      if (r.status !== 0) unverifiable(`\`gh issue view ${issue}\``, r.stderr || r.error?.message || "");
      return r.stdout.trim();
    };
    // #1333: the control has to have a population — see seedClosedTrackingPopulation for why zero
    // hatches would otherwise turn this control into a green light nobody can read.
    const seeded = seedClosed ? seedClosedTrackingPopulation(registry) : registry;
    if (seeded !== registry) {
      console.log("\nℹ --seed-closed-tracking: no live hatch exists, so the control ran against a synthetic disclosure row. It still proves checkDisclosureTracking rejects a CLOSED tracker; it proves nothing about today's registry, which has nothing to check.");
    }
    const stale = checkDisclosureTracking(seeded, trackingState);
    violations.push(...stale);
    // Counted over BOTH hatches this function now covers — the no-alarm disclosures and the
    // unproven paths. Reporting only the first would understate what was checked, in the one line a
    // reader takes as the summary of what was checked.
    const hatches = registry.scheduledWithoutAlertPath.length + registry.paths.filter((p) => p.pendingProof).length;
    if (stale.length === 0 && hatches > 0) {
      console.log(`✓ all ${hatches} hatch(es) — ${registry.scheduledWithoutAlertPath.length} no-alert-path disclosure(s), ${hatches - registry.scheduledWithoutAlertPath.length} unproven path(s) — still point at an OPEN tracking issue`);
    }
  } else {
    console.log("\nℹ marker-label existence NOT checked (pass --labels with an authenticated gh). Structure alone cannot tell a path that has run from one that never has.");
  }

  if (violations.length > 0) {
    console.error(`\n✗ ${violations.length} alert-path violation(s):`);
    for (const v of violations) console.error(`  ${v.workflow} — ${v.detail}`);
    process.exit(1);
  }
  // The pass line states the exemption count in the same breath as the pass. A summary that says
  // "every one carrying a recorded proof run" while one of them does not is the shape of sentence
  // this gate was written to stop believing.
  const pending = registry.paths.filter((p) => p.pendingProof);
  const total = alerting.reduce((n, f) => n + f.alertSteps.length, 0);
  // #1568: this gate's own liveness receipt. The label half is the one assertion in this repo that
  // no diff can speak to, so a run that died before reaching it reports an absence that reads like
  // "every label is there". Recorded only on the passing path, and only when the label pass ran —
  // a structure-only run scored a strictly smaller thing and must not claim the larger one.
  if (process.argv.includes("--labels")) recordMeasured("alert-paths", total, `alert path(s) checked for structure and marker-label existence across ${facts.length} workflow(s)`);
  console.log(
    pending.length === 0
      ? `\n✓ ${total} alert path(s): every one dispatch-provable and carrying a recorded proof run`
      : `\n✓ ${total} alert path(s) dispatch-provable; ${total - pending.length} carry a recorded proof run and ${pending.length} do NOT: ` +
          pending.map((p) => `${p.marker} (tracked by #${p.pendingProof?.tracking})`).join(", ") +
          `\n  Take the drill and record it: gh workflow run "<workflow name>" -f alert_drill=true`,
  );
}
