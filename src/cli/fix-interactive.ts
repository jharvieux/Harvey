// The INTERACTIVE fix-implementer CLI (#1056). Two modes bracket the operator's own Claude session —
// there is NO automated LLM call anywhere in this path (operator ruling 2026-07-26: no SDK, no key):
//
//   emit:   ... --target <checkout> --finding <id> --interactive
//           writes <out>/<id>.fix-prompt.md — a self-contained spec the operator pastes into their
//           interactive session to author a diff.
//   ingest: ... --target <checkout> --finding <id> --apply-diff <diff-file> [--apply-diff <next>] [--live]
//           runs that diff through the EXISTING rails (executeFixDiff + detector-after + the §2.1
//           client-check half) and scores it with computeGreen.
//           Green ⇒ a DRAFT PR via deliverFix (withheld under the default dry-run; --live pushes).
//           Not green ⇒ REJECTED with a named reason and a non-zero exit. Never shipped.
//
// --apply-diff may be given MORE THAN ONCE, in the order the operator authored the attempts, and that
// is what makes the §5 escalation ladder (#922) real here rather than documented: planningTriggers +
// initialTier decide which model tier attempt 1 should have been authored at, runEscalation walks the
// supplied attempts (at most MAX_ATTEMPTS_PER_TIER per tier), and `tiersUsed` on the delivered result
// is the walk that actually happened — never a hardcoded single tier. A ladder that runs out of tiers
// DOWNGRADES the fix to recommend-only with the reason named, instead of shipping attempt N.
//
// A finding is eligible only if intake() screened it `auto` — same gate as fix-execute. The finding's
// FixPlan is produced here (producePlan), so emit and ingest agree on scope and approach.

import "./sync-stdio.js";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { validateFindings, type FindingsDocument } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { deliverFix, createClient } from "../fix/transport.js";
import { MAX_ATTEMPTS_PER_TIER, initialTier, planningTriggers, runEscalation } from "../fix/escalation.js";
import { emitFixPrompt, ingestFixDiff } from "../fix/interactive.js";
import { intake, type EngagementManifest } from "../fix/pipeline.js";
import { attachAll, type AttachInput } from "../fix/attach.js";
import { producePlan } from "../fix/produce-plan.js";
import { screenFinding, type EscalationTier } from "../fix/plan.js";

const args = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--target", "--finding", "--apply-diff", "--out", "--base", "--findings-out"]);
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
// Repeatable: each --apply-diff is one escalation attempt, in the order the operator authored them.
const flagAll = (name: string) => args.flatMap((a, i) => (a === name && args[i + 1] !== undefined ? [args[i + 1] as string] : []));
const has = (name: string) => args.includes(name);

const targetArg = flag("--target");
const findingId = flag("--finding");
const applyDiffPaths = flagAll("--apply-diff");
const interactive = has("--interactive");
const live = has("--live");
const outDir = resolve(flag("--out") ?? "fix-out");
const baseBranch = flag("--base") ?? "main";
// #825: where to write the findings document with the VERIFIED diff attached as `suggestedFix`, so
// it reaches the ticket body. --paid is the engagement tier signal, default FALSE for the same
// fail-closed reason findings-to-tickets defaults it false: an unasserted tier attaches nothing.
const findingsOut = flag("--findings-out");
const paid = has("--paid");

const USAGE =
  "usage:\n" +
  "  emit:   pnpm exec tsx src/cli/fix-interactive.ts <findings.json> <manifest.json> --target <checkout> --finding <id> --interactive [--out <dir>]\n" +
  "  ingest: pnpm exec tsx src/cli/fix-interactive.ts <findings.json> <manifest.json> --target <checkout> --finding <id> --apply-diff <diff> [--apply-diff <next-attempt>]… [--base <branch>] [--live] [--out <dir>] [--findings-out <file> --paid]";

if (!findingsPath || !manifestPath || !targetArg || !findingId || (!interactive && applyDiffPaths.length === 0)) {
  console.error(USAGE);
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
      ` Re-baseline before running — a fix written against a stale commit fixes stale evidence.`,
  );
  process.exit(1);
}

const targetDir = resolve(targetArg);
const auto = result.auto.find((e) => e.finding.id === findingId);
if (!auto) {
  // Fail loud: say WHY this id can't take the automated interactive path, never a silent no-op.
  const finding = doc.findings.find((f) => f.id === findingId);
  if (!finding) console.error(`✗ finding ${findingId} is not in ${findingsPath}`);
  else if (!manifest.approvedFindingIds.includes(findingId)) console.error(`✗ finding ${findingId} is not client-approved for this engagement`);
  else {
    const screen = screenFinding(finding, { enabledCategories: manifest.enabledCategories, sensitivePaths: manifest.sensitivePaths });
    console.error(`✗ finding ${findingId} is screened "${screen.mode}", not "auto": ${screen.reason ?? ""}`);
  }
  process.exit(1);
}

const finding = auto.finding;
const plan = producePlan(finding, { screen: auto.screen, targetDir });

function readSources(files: string[]): SourceInput[] {
  const out: SourceInput[] = [];
  for (const f of files) {
    try {
      out.push({ path: f, text: readFileSync(join(targetDir, f), "utf8") });
    } catch {
      // A file the plan names but that isn't readable is disclosed in the prompt as missing, not dropped.
      out.push({ path: f, text: `// (could not read ${f} under the target checkout)` });
    }
  }
  return out;
}

if (interactive) {
  mkdirSync(outDir, { recursive: true });
  const prompt = emitFixPrompt({
    finding,
    plan,
    baselineCommit: manifest.baselineCommit,
    allowlist: manifest.allowlist,
    diffCap: manifest.diffCap,
    sources: readSources(plan.blastRadius.files),
  });
  const promptPath = join(outDir, `${finding.id}.fix-prompt.md`);
  writeFileSync(promptPath, prompt);
  console.log(`Fix prompt for ${finding.id} — ${finding.title}`);
  console.log(`Written: ${promptPath}`);
  console.log(`\nOpen it in an interactive Claude session, author the diff, then re-run this CLI with:`);
  console.log(`  --finding ${finding.id} --apply-diff <your-diff-file>`);
  console.log(`\nNo LLM was called, no worktree created, no branch pushed (emit only).`);
  process.exit(0);
}

// ingest — the §5 escalation walk over the operator's ordered attempts (#922/#1272).
// planningTriggers is fed the SAME ScreenOptions intake screened with, so the tier decision here and
// the screen agree. plansDisagreed is threaded false with a recorded reason: it compares two
// INDEPENDENTLY-DRAFTED plans, and this path drafts exactly one (producePlan is deterministic, so
// drafting it twice compares a plan to itself and can only ever agree).
//
// REASON: §5 trigger 4 (plan self-disagreement) is not evaluated on the interactive path.
// KIND: decisional
// PROVENANCE: TRIED 2026-07-28 — ran producePlan twice on one screened finding against targets/calibration and fed both to plansDisagree: identical plans, disagreement false. Two LOCAL drafts can only ever agree.
// OWNER: operator
// DECISION: the 2026-07-26 no-SDK/no-key ruling recorded on issue #1056 removes the second independent draft the trigger compares; relayed again on #1272.
// TOUCHES: src/fix/escalation.ts, src/fix/produce-plan.ts
//
// plansDisagree stays a PARAMETER of planningTriggers, so an implementer that does draft twice
// supplies the flag without touching this file.
const triggers = planningTriggers(finding, { enabledCategories: manifest.enabledCategories, sensitivePaths: manifest.sensitivePaths }, false);
const startTier = initialTier(plan.tier, triggers);

interface Attempt {
  tier: EscalationTier;
  diffPath: string;
  green: boolean;
  reason?: string;
  ingest: ReturnType<typeof ingestFixDiff>;
}
const attempts: Attempt[] = [];
let next = 0;
const walk = runEscalation(plan.tier, triggers, (tier) => {
  const diffPath = applyDiffPaths[next];
  if (diffPath === undefined) return false; // out of operator attempts — the ladder ends here
  next++;
  const result = ingestFixDiff({
    finding,
    diff: readFileSync(resolve(diffPath), "utf8"),
    targetDir,
    baselineCommit: manifest.baselineCommit,
    allowlist: manifest.allowlist,
    diffCap: manifest.diffCap,
    attempts: next,
  });
  attempts.push({ tier, diffPath, green: result.green, reason: result.rejectReason, ingest: result });
  return result.green;
});

// Only tiers an attempt actually RAN at are recorded. runEscalation keeps walking when the operator's
// diffs run out, and writing a tier nobody attempted into tiersUsed would be exactly the false-record
// defect this wiring exists to remove.
const tiersUsed = walk.tiersUsed.filter((t) => attempts.some((a) => a.tier === t));
const ranOutOfDiffs = next >= applyDiffPaths.length && walk.outcome === "downgrade";
const last = attempts[attempts.length - 1];

console.log(`Interactive fix ingest — ${finding.id} @ ${manifest.baselineCommit} (target ${targetDir})`);
console.log(`  escalation: screened "${plan.tier}" → start "${startTier}"  ·  triggers: ${triggers.length ? triggers.join(", ") : "none"}  ·  ≤${MAX_ATTEMPTS_PER_TIER} attempts/tier`);
for (const [i, a] of attempts.entries()) {
  const ev = a.ingest.evidence;
  console.log(`\n  attempt ${i + 1} @ tier "${a.tier}" — ${a.diffPath}`);
  console.log(`    apply/rails: ${a.ingest.execution.outcome}${a.ingest.execution.verification ? ` — ${a.ingest.execution.verification}` : ""}`);
  console.log(
    `    detector ${ev.detectorBefore.detectorId}: before=FIRED  after=${ev.detectorAfter.notRun ? `not-run (${ev.detectorAfter.notRun})` : ev.detectorAfter.fired ? "STILL FIRING" : "clean"}`,
  );
  // The §2.1 half, printed per command: an empty list is the loudest line here, because it is the
  // one state in which green is unreachable no matter what the detector says (#1272).
  if (ev.clientChecks.length === 0) console.log(`    client checks: NONE DISCOVERED — the client half cannot be evidenced, so this attempt cannot be green`);
  for (const c of ev.clientChecks) {
    console.log(`    client check: ${c.skipped ? `SKIPPED (${c.skipped})` : c.exitCode === 0 ? "pass" : `FAIL (exit ${c.exitCode})`}  ${c.command}  [${c.durationMs}ms]`);
  }
  if (!a.green) console.log(`    ✗ ${a.reason}`);
}

// #825 — the producer→deliverable seam. Runs on BOTH paths on purpose: the interesting half of the
// proof is that a REJECTED diff writes a findings document with NO suggestedFix, so the ticket body
// falls back to prose. A seam that only ever runs on success leaves its fail-closed half unproven.
function writeFindingsWithDiff(green: boolean, diff: string, evidence: (typeof attempts)[number]["ingest"]["evidence"], rejectReason?: string): void {
  if (!findingsOut) return;
  const proposal: AttachInput = { finding, diff, green, evidence, ...(rejectReason ? { rejectReason } : {}) };
  const ledger = attachAll(doc.findings, new Map([[finding.id, proposal]]), { paid });
  writeFileSync(findingsOut, `${JSON.stringify({ ...doc, findings: ledger.findings }, null, 2)}\n`);
  for (const row of ledger.attached) console.log(`  suggestedFix ATTACHED to ${row.findingId} → ${findingsOut}`);
  for (const row of ledger.refused) console.log(`  suggestedFix REFUSED for ${row.findingId}: ${row.reason}`);
}

if (walk.outcome === "downgrade" || last === undefined || !last.green) {
  if (last) writeFindingsWithDiff(false, readFileSync(resolve(last.diffPath), "utf8"), last.ingest.evidence, last.reason);
  console.error(`\n✗ REJECTED after ${attempts.length} attempt(s) — ${last?.reason ?? "no attempt ran"}`);
  if (walk.outcome === "downgrade") {
    console.error(`  escalation: ${ranOutOfDiffs ? "no further attempt was supplied" : walk.downgradeReason} ⇒ DOWNGRADE to recommend-only.`);
    console.error(`  Tiers actually attempted: ${tiersUsed.length ? tiersUsed.join(" → ") : "none"}.`);
  }
  console.error(`  No branch, no push, no PR. The diff is not a fix until the detector stops firing AND the client's own checks pass.`);
  process.exit(1);
}

// Green: only now is the transport reached. Draft PR only, withheld under the default dry-run.
const ingest = last.ingest;
const client = createClient({ targetDir, dryRun: !live });
const delivered = deliverFix(client, {
  finding,
  plan,
  evidence: ingest.evidence,
  operator: manifest.operator,
  baseBranch,
  summary: finding.title,
  tiersUsed,
});

mkdirSync(outDir, { recursive: true });
writeFileSync(
  join(outDir, `${finding.id}.fix-ingest.json`),
  `${JSON.stringify({ ...delivered, evidence: ingest.evidence, escalation: { screenedTier: plan.tier, startTier, triggers, tiersUsed, attempts: attempts.length } }, null, 2)}\n`,
);

writeFindingsWithDiff(true, readFileSync(resolve(last.diffPath), "utf8"), ingest.evidence);

console.log(`\n✓ GREEN — detector cleared and the client's own checks pass. Transport outcome: ${delivered.outcome}`);
console.log(`  tiers used: ${tiersUsed.join(" → ")} (attempt ${attempts.length} of ${applyDiffPaths.length} supplied)`);
if (delivered.branch) console.log(`  branch: ${delivered.branch}`);
if (delivered.prUrl) console.log(`  draft PR: ${delivered.prUrl}`);
if (delivered.downgradeOrAbortReason) console.log(`  note: ${delivered.downgradeOrAbortReason}`);
if (!live) console.log(`  (dry-run — draft PR withheld; re-run with --live to push and open the DRAFT PR)`);
