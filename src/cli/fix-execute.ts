// Execute the screened, client-approved fix diffs against a disposable worktree of the client
// checkout and emit inert, reviewable artifacts (#885). This is the executing half of
// docs/design/fix-implementation.md §1.4 — MINUS the transport: it never writes to the client's
// working tree, never creates a branch, never pushes, never opens a PR.
//
//   pnpm exec tsx src/cli/fix-execute.ts <findings.json> <manifest.json> --target <client-checkout> [--out <dir>]
//
// A finding enters here only if intake() screened it `auto` (client-approved, Confirmed/Likely,
// ease+safety ≥ 4, enabled category) AND it carries a `suggestedFix.diff` from an implementer pass.
// An `auto` finding with no diff is reported as AWAITING IMPLEMENTER, never omitted — the implementer
// stage is not built yet, and a silently short list would read as "nothing to fix".
//
// #1272 remainder: this path used to call executeFixDiff with NEITHER the detector-after hook nor the
// §2.1 client-check hook, so "diff-verified" here meant `git apply --check` and nothing else — and it
// still reached the client handoff as `verified-inert` with a merge rank. MEASURED 2026-07-30: a
// purely cosmetic diff over a planted M5 class was reported "✓ F-COSMETIC [diff-verified]", exit 0,
// merge rank 1. The batch path now runs the SAME two-halves gate the interactive path runs, by going
// through ingestFixDiff — one contract, one implementation, no second definition of "verified".

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { validateFindings, type Finding, type FindingsDocument } from "../findings.js";
import type { FixExecution } from "../fix/execute.js";
import { assembleHandoff, type FixOutcomeSummary, type HandoffStatus } from "../fix/handoff.js";
import { ingestFixDiff } from "../fix/interactive.js";
import { intake, type EngagementManifest } from "../fix/pipeline.js";
import { fileOfLocation } from "../fix/produce-plan.js";
import { DEFAULT_CAPS, detectLateConflict, runScheduled, scheduleFixes, type ScheduleNode } from "../fix/schedule.js";

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
  console.error("usage: pnpm exec tsx src/cli/fix-execute.ts <findings.json> <manifest.json> --target <client-checkout> [--out <dir>]");
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
    `✗ baseline mismatch: findings meta.commit=${doc.meta.commit} ≠ manifest.baselineCommit=${manifest.baselineCommit}.` +
      ` Re-baseline before executing — a fix written against a stale commit fixes stale evidence.`,
  );
  process.exit(1);
}

const targetDir = resolve(targetArg);
mkdirSync(outDir, { recursive: true });

// The execution record plus the half of the §2 verdict FixExecution does not carry: whether the two
// halves actually cleared, and — when they did not — the named reason.
type ScoredExecution = FixExecution & { green: boolean; rejectReason?: string };

const executions: ScoredExecution[] = [];
const awaitingImplementer: string[] = [];
const bftb = (f: Finding) => f.value * f.ease * f.safety;
// A diff that applies but does not clear both halves has not earned verified-inert — that status
// carries a merge rank into the client handoff. It is verify-failed, with ingestFixDiff's reason.
const EXECUTION_STATUS: Record<FixExecution["outcome"], HandoffStatus> = {
  "diff-verified": "verified-inert",
  "rails-blocked": "rails-blocked",
  "verify-failed": "verify-failed",
  aborted: "aborted",
};
const statusOf = (e: ScoredExecution): HandoffStatus =>
  e.outcome === "diff-verified" && !e.green ? "verify-failed" : EXECUTION_STATUS[e.outcome];
const outcomes: FixOutcomeSummary[] = [];

const withDiff = new Map<string, string>();
for (const { finding } of result.auto) {
  const diff = finding.suggestedFix?.diff;
  if (!diff || diff.trim() === "") {
    awaitingImplementer.push(finding.id);
    // A screened-auto finding with no diff is still an APPROVED deliverable — it lands in the handoff
    // as awaiting-implementer against its own file, never silently dropped.
    outcomes.push({ findingId: finding.id, severity: finding.severity, bftb: bftb(finding), files: [finding.location.split(":")[0] as string], status: "awaiting-implementer" });
    continue;
  }
  withDiff.set(finding.id, diff);
}

// §1.3/§4 scheduling (#926/#1272). The nodes carry the BATCH-TIME view of what each fix touches — the
// finding's own file, which is all the plan knows before a diff exists. That is deliberate: the
// late-conflict check below compares it against what the diff ACTUALLY changed, and a fix that grew a
// file mid-implementation is an overlap that does not exist until the diff is written.
const findingById = new Map(result.auto.map((e) => [e.finding.id, e.finding]));
const nodes: ScheduleNode[] = [...withDiff.keys()].map((id) => {
  const f = findingById.get(id) as Finding;
  return { findingId: id, severity: f.severity, bftb: bftb(f), files: [fileOfLocation(f.location)] };
});
const components = scheduleFixes(nodes);

// Concurrency is MEASURED here, not asserted: the worker records how many slots and how many
// client-check runs were ever live at once, and those numbers are written into fix-execution.json.
// See CONCURRENCY_NOTE below for what they mean today.
let liveSlots = 0;
let peakSlots = 0;
let liveChecks = 0;
let peakClientChecks = 0;
let clientCheckMs = 0;
await runScheduled(
  components,
  async (component, clientCheck) => {
    liveSlots++;
    peakSlots = Math.max(peakSlots, liveSlots);
    try {
      // Serialized WITHIN the component: these fixes touch the same files, so their execution order
      // is the merge order the client is advised to follow.
      for (const findingId of component.findingIds) {
        const finding = findingById.get(findingId) as Finding;
        const diff = withDiff.get(findingId) as string;
        // The whole ingest sits inside the client-check gate: it is the phase that baselines and
        // re-runs the client's own suite, which is the scarce resource maxClientChecks bounds.
        const ingest = await clientCheck(async () => {
          liveChecks++;
          peakClientChecks = Math.max(peakClientChecks, liveChecks);
          try {
            return ingestFixDiff({
              finding,
              diff,
              targetDir,
              baselineCommit: manifest.baselineCommit,
              allowlist: manifest.allowlist,
              diffCap: manifest.diffCap,
            });
          } finally {
            liveChecks--;
          }
        });
        const execution: ScoredExecution = { ...ingest.execution, green: ingest.green, rejectReason: ingest.rejectReason };
        for (const c of ingest.evidence.clientChecks) clientCheckMs += c.durationMs;
        executions.push(execution);
        outcomes.push({
          findingId,
          severity: finding.severity,
          bftb: bftb(finding),
          files: [...execution.files, ...execution.createdFiles],
          status: statusOf(execution),
          verification: execution.verification,
          reason: ingest.rejectReason ?? execution.abortReason ?? (execution.railViolations.length ? execution.railViolations.join("; ") : undefined),
        });
        // A rail-blocked diff is never written out: the rails say it may not touch those paths, and a
        // .diff sitting in the artifacts dir is one `git apply` away from doing exactly that. Its file
        // list and violations are in fix-execution.json, which is what the operator needs to see.
        if (execution.outcome !== "rails-blocked") {
          writeFileSync(join(outDir, `${findingId}.diff`), diff.endsWith("\n") ? diff : `${diff}\n`);
        }
      }
    } finally {
      liveSlots--;
    }
    return null;
  },
  DEFAULT_CAPS,
);

// §4 pre-push late-conflict check: each verified fix's ACTUAL changed-file set against every fix
// already cleared in this run. Batch time saw only the finding's own file, so this is where an
// overlap introduced by the diff itself surfaces — before anything is pushed.
const lateConflicts: { findingId: string; conflictsWith: { findingId: string; files: string[] }[] }[] = [];
const cleared: { findingId: string; changedFiles: string[] }[] = [];
for (const e of executions) {
  if (!e.green) continue; // only a fix that cleared BOTH halves is on its way to a push
  const changedFiles = [...e.files, ...e.createdFiles];
  const conflictsWith = detectLateConflict(changedFiles, cleared);
  if (conflictsWith.length) lateConflicts.push({ findingId: e.findingId, conflictsWith });
  cleared.push({ findingId: e.findingId, changedFiles });
}

for (const { finding, screen } of result.manual) {
  outcomes.push({ findingId: finding.id, severity: finding.severity, bftb: bftb(finding), files: [], status: "manual", reason: screen.reason });
}
for (const { finding, screen } of result.recommendOnly) {
  outcomes.push({ findingId: finding.id, severity: finding.severity, bftb: bftb(finding), files: [], status: "recommend-only", reason: screen.reason });
}

const handoff = assembleHandoff({ client: manifest.client, baselineCommit: manifest.baselineCommit, outcomes, notApproved: result.notApproved });

// MEASURED 2026-07-30, and it CORRECTS what #1463 recorded here. That note read "peakSlots is 1 on
// every run … the semaphore has nothing to hold back yet". Wiring the client-check gate below put a
// real await inside the worker, so components are now genuinely in flight together: 2 components →
// peakSlots 2, and 6 disjoint components → peakSlots 4, i.e. the cap is OBSERVED AT ITS LIMIT rather
// than merely configured. The 4-slot cap binds.
//
// What is still bounded is the CLIENT-CHECK cap: ingestFixDiff never yields while holding that
// semaphore (execFileSync git + verifySuggestedFix + the sync detector re-run + spawnSync client
// checks), so no two client-check phases overlap in wall-clock and peakClientChecks is 1 whatever the
// component count. Both numbers are REPORTED, never assumed, so a change in either is visible.
//
// REASON: the 2-client-check cap is enforced but not yet binding — the ingest holds it without ever yielding, so no two client-check phases overlap.
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-30 — six disjoint components through this CLI reported peakSlots 4 (the cap) and peakClientChecks 1; ingestFixDiff is execFileSync/spawnSync throughout.
// FALSIFIER: test -f src/fix/execute.ts || exit 127; grep -q 'export async function executeFixDiff' src/fix/execute.ts
// TOUCHES: src/fix/schedule.ts, src/fix/execute.ts, src/cli/fix-execute.ts
// Tracked as #1464 — the async-executor conversion is a scanner-core change, not a fix-pipeline one.
const CONCURRENCY_NOTE =
  "caps enforced by the runScheduled semaphores; peakSlots reaches maxSlots once there are enough components, peakClientChecks stays 1 while the ingest is synchronous end to end (an async executor is the falsifier)";

writeFileSync(
  join(outDir, "fix-execution.json"),
  `${JSON.stringify(
    {
      client: manifest.client,
      baselineCommit: manifest.baselineCommit,
      targetDir,
      concurrency: { ...DEFAULT_CAPS, componentsScheduled: components.length, peakSlots, peakClientChecks, clientCheckMs, note: CONCURRENCY_NOTE },
      lateConflicts,
      executions,
      awaitingImplementer,
    },
    null,
    2,
  )}\n`,
);
// The client-handoff artifact (§1.5): every approved finding with its status + the merge-order advisory.
// An operator folds fixHandoff into findings.<client>.json; report-template renders it (render.mjs).
writeFileSync(join(outDir, "fix-handoff.json"), `${JSON.stringify(handoff, null, 2)}\n`);

console.log(`Fix execution — ${manifest.client} @ ${manifest.baselineCommit} (target ${targetDir})`);
console.log(`Artifacts: ${outDir}  ·  inert diffs only — nothing was applied to ${targetDir}, no branch, no push, no PR.\n`);

// The ✓ tracks GREEN, not apply-clean. A diff that applies and leaves the detector firing (or breaks
// the client's own suite) is a ✗ here and a verify-failed row in the handoff — the outcome word alone
// used to read "diff-verified" and carry a merge rank (#1272).
for (const e of executions) {
  const detail = e.rejectReason ?? e.verification ?? e.abortReason ?? e.railViolations.join("; ");
  const checks = e.evidence?.clientChecks ?? [];
  const ran = checks.filter((c) => c.skipped === undefined).length;
  console.log(`  ${e.green ? "✓" : "✗"} ${e.findingId}  [${statusOf(e)}]  ${e.files.length + e.createdFiles.length} file(s), ~${e.changedLines} lines — ${detail}`);
  console.log(
    `      detector ${e.detectorAfter ? (e.detectorAfter.notRun ? `not-run (${e.detectorAfter.notRun})` : e.detectorAfter.fired ? "STILL FIRING" : "clean") : "not re-run"}` +
      `  ·  client checks: ${checks.length === 0 ? "NONE DISCOVERED — the client half cannot be evidenced, so this fix cannot be green" : `${ran} run, ${checks.length - ran} skipped`}`,
  );
}

if (awaitingImplementer.length) {
  console.log(`\nAWAITING IMPLEMENTER (${awaitingImplementer.length}) — screened auto but no suggestedFix.diff supplied: ${awaitingImplementer.join(", ")}`);
}
console.log(
  `\nScheduling: ${components.length} independent component(s), caps ${DEFAULT_CAPS.maxSlots} slot(s)/${DEFAULT_CAPS.maxClientChecks} client-check(s),` +
    ` peak slots observed ${peakSlots}, peak client checks observed ${peakClientChecks}, ${clientCheckMs}ms spent in the client's own suite — ${CONCURRENCY_NOTE}.`,
);
for (const lc of lateConflicts) {
  console.log(
    `  ⚠ late conflict: ${lc.findingId}'s diff also touches ${lc.conflictsWith.map((c) => `${c.files.join(", ")} (with ${c.findingId})`).join("; ")} — batch time did not see this; merge the earlier fix first.`,
  );
}
console.log(`\nMANUAL: ${result.manual.length} · RECOMMEND-ONLY: ${result.recommendOnly.length} · not client-approved: ${result.notApproved.length}`);

if (handoff.mergeOrder.order.length) {
  console.log(`\nRecommended merge order: ${handoff.mergeOrder.order.join(" → ")}`);
  for (const note of handoff.mergeOrder.notes) console.log(`  · ${note}`);
}
console.log(`Handoff: ${join(outDir, "fix-handoff.json")} — every approved finding as a row (PR'd / inert / downgraded / blocked), never a silent drop.`);

const blocked = executions.filter((e) => e.outcome === "rails-blocked" || e.outcome === "aborted");
const failed = executions.filter((e) => statusOf(e) === "verify-failed");
if (blocked.length || failed.length) {
  console.error(`\n✗ ${blocked.length} blocked by rails/aborted, ${failed.length} failed verification. None of these is a fix — do not present them as applied.`);
  process.exit(1);
}
