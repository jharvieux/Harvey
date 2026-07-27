// The INTERACTIVE fix-implementer CLI (#1056). Two modes bracket the operator's own Claude session —
// there is NO automated LLM call anywhere in this path (operator ruling 2026-07-26: no SDK, no key):
//
//   emit:   ... --target <checkout> --finding <id> --interactive
//           writes <out>/<id>.fix-prompt.md — a self-contained spec the operator pastes into their
//           interactive session to author a diff.
//   ingest: ... --target <checkout> --finding <id> --apply-diff <diff-file> [--live]
//           runs that diff through the EXISTING rails (executeFixDiff + detector-after + computeGreen).
//           Green ⇒ a DRAFT PR via deliverFix (withheld under the default dry-run; --live pushes).
//           Not green ⇒ REJECTED with a named reason and a non-zero exit. Never shipped.
//
// A finding is eligible only if intake() screened it `auto` — same gate as fix-execute. The finding's
// FixPlan is produced here (producePlan), so emit and ingest agree on scope and approach.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { validateFindings, type FindingsDocument } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { deliverFix, createClient } from "../fix/transport.js";
import { emitFixPrompt, ingestFixDiff } from "../fix/interactive.js";
import { intake, type EngagementManifest } from "../fix/pipeline.js";
import { producePlan } from "../fix/produce-plan.js";
import { screenFinding } from "../fix/plan.js";

const args = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--target", "--finding", "--apply-diff", "--out", "--base"]);
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
const has = (name: string) => args.includes(name);

const targetArg = flag("--target");
const findingId = flag("--finding");
const applyDiffPath = flag("--apply-diff");
const interactive = has("--interactive");
const live = has("--live");
const outDir = resolve(flag("--out") ?? "fix-out");
const baseBranch = flag("--base") ?? "main";

const USAGE =
  "usage:\n" +
  "  emit:   pnpm exec tsx src/cli/fix-interactive.ts <findings.json> <manifest.json> --target <checkout> --finding <id> --interactive [--out <dir>]\n" +
  "  ingest: pnpm exec tsx src/cli/fix-interactive.ts <findings.json> <manifest.json> --target <checkout> --finding <id> --apply-diff <diff> [--base <branch>] [--live] [--out <dir>]";

if (!findingsPath || !manifestPath || !targetArg || !findingId || (!interactive && !applyDiffPath)) {
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

// ingest
const diff = readFileSync(resolve(applyDiffPath as string), "utf8");
const ingest = ingestFixDiff({
  finding,
  diff,
  targetDir,
  baselineCommit: manifest.baselineCommit,
  allowlist: manifest.allowlist,
  diffCap: manifest.diffCap,
});

const before = ingest.evidence.detectorBefore;
const after = ingest.evidence.detectorAfter;
console.log(`Interactive fix ingest — ${finding.id} @ ${manifest.baselineCommit} (target ${targetDir})`);
console.log(`  apply/rails: ${ingest.execution.outcome}${ingest.execution.verification ? ` — ${ingest.execution.verification}` : ""}`);
console.log(`  detector ${before.detectorId}: before=FIRED  after=${after.notRun ? `not-run (${after.notRun})` : after.fired ? "STILL FIRING" : "clean"}`);

if (ingest.rejected) {
  console.error(`\n✗ REJECTED — ${ingest.rejectReason}`);
  console.error(`  No branch, no push, no PR. The diff is not a fix until the detector stops firing.`);
  process.exit(1);
}

// Green: only now is the transport reached. Draft PR only, withheld under the default dry-run.
const client = createClient({ targetDir, dryRun: !live });
const delivered = deliverFix(client, {
  finding,
  plan,
  evidence: ingest.evidence,
  operator: manifest.operator,
  baseBranch,
  summary: finding.title,
  tiersUsed: [plan.tier],
});

mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, `${finding.id}.fix-ingest.json`), `${JSON.stringify({ ...delivered, evidence: ingest.evidence }, null, 2)}\n`);

console.log(`\n✓ GREEN — detector cleared. Transport outcome: ${delivered.outcome}`);
if (delivered.branch) console.log(`  branch: ${delivered.branch}`);
if (delivered.prUrl) console.log(`  draft PR: ${delivered.prUrl}`);
if (delivered.downgradeOrAbortReason) console.log(`  note: ${delivered.downgradeOrAbortReason}`);
if (!live) console.log(`  (dry-run — draft PR withheld; re-run with --live to push and open the DRAFT PR)`);
