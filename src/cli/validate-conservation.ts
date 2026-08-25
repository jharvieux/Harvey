// The conservation gate (#1064, invariants 4 and 5).
//
//   pnpm exec tsx src/cli/validate-conservation.ts [--target <dir>] [--json]
//                                                  [--require <Mn>]... [--seed-loss <Mn>]...
//
// Runs the REAL ten-module orchestrator against a fixture with planted defects, assembles the REAL
// deliverable, and asserts each module's planted finding survived the trip. Exit 1 on any module
// that produced nothing for its plant, or produced it and did not deliver it.
//
// PREREQUISITES, same as `pnpm validate:calibration`: the mechanical binaries (semgrep, trufflehog,
// gitleaks, osv-scanner) on PATH and a full git history for the target — PLUS the `vitals` plugin,
// because M3's plant is a truck-factor-1 row and knowledge-risk analysis exists only in vitals' full
// tier: without it hotspot-scan drops to the reduced churn×complexity tier (#807) and M3 correctly
// reports GONE. `.github/workflows/conservation.yml` installs it from source at a pinned commit.
// Deliberately NOT part of `pnpm verify` for exactly the reason dry-run-drift and corpus-drift are
// not — `pnpm verify` runs in a CI job with none of those. What IS in `pnpm verify` is
// src/audit-conservation.test.ts, which seeds each violation into the gate's logic and proves it
// fails; this CLI proves the wiring.
//
// --require <Mn>  hold a module recorded in UNEXERCISED to the full standard anyway — the falsifier
//                 path for its recorded reason (#1033). UNEXERCISED is currently EMPTY: M2, its last
//                 member, gained an offline plant in #1155 (the injected #416 dynamic-pass artifact),
//                 so `--require` is retained for a future genuinely-live-only module, not M2.
// --seed-loss <Mn>  SEED A VIOLATION: discard everything module Mn's probe produced, before
//                 assembly, reproducing the #1040/#1061 break in which results were produced and
//                 then dropped. The gate must fail naming Mn. It exists because a gate nobody has
//                 watched fail is not evidence that it can (#350). It reads each module's OWN probe
//                 attribution (findingsByModule), not the merged document, so it catches the loss
//                 even if another probe or a synthesizer contributes the same taxonomy. (Before #1084
//                 M9 captured detect-static UNFILTERED and re-collected M7's rows, so a seeded M7 loss
//                 stayed visible in the deliverable while M7 produced nothing — the #1062 shape. #1084
//                 makes M9 collect only the complement of M6/M7/M8, so that masking is gone; reading
//                 findingsByModule is why the gate never depended on it.)
// --seed-unaccounted  SEED THE OTHER VIOLATION (#1096): drop one finding out of the ASSEMBLED
//                 deliverable with no disposition — what an undeclared filter at a consumer
//                 boundary does. The plant-and-assert above can miss it (it watches ten rows); the
//                 conservation ledger's arithmetic cannot.
// --seed-baseline-loss  SEED THE #1146 BASELINE VIOLATION: after applyBaseline tags the current set,
//                 drop one finding from the result — a baseline-application bug silently deleting a
//                 NEW finding. The baseline ledger across applyBaseline must fail naming it.
// --seed-misdeclared  SEED THE #1146 DISPOSITION VIOLATION: declare a finding `suppressed` that is
//                 in fact still delivered. A disposition column credited against a fiction must fail.

import "./sync-stdio.js";
import { probeExec } from "../probe-exec.js";
import { recordMeasured } from "../ci-liveness.js";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkConservation, formatConservation, writeM2ConservationPlant } from "../audit-conservation.js";
import { baselineLedger, conservationLedger, type DeclaredDrop, formatBaselineLedger, formatLedger } from "../conservation-ledger.js";
import { assembleEngagementDocument } from "../audit-report.js";
import { applyBaseline } from "../audit-diff.js";
import type { AuditModule } from "../audit-coverage.js";
import { formatFailures, runAudit, type RunContext } from "../audit-runner.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { discoverSchemaFiles } from "../dynamic-validate.js";
import { discoverTargets } from "../pentest/targets.js";
import { isGitRepoRoot } from "../scan/secrets.js";
import { type Finding, type ReportMeta, validateFindings } from "../findings.js";
import { buildEffectivenessInventory, validateEffectivenessDelivery, validateEffectivenessInventory } from "../effectiveness-registry.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flagValues = (flag: string): string[] => args.flatMap((a, i) => (a === flag && args[i + 1] ? [args[i + 1]!] : []));
const targetDir = resolve(flagValues("--target")[0] ?? join(REPO_ROOT, "targets", "calibration"));
const required = flagValues("--require") as AuditModule[];
const seedLoss = new Set(flagValues("--seed-loss") as AuditModule[]);

const captureDir = mkdtempSync(join(tmpdir(), "harvey-conservation-"));

// #1155 — the M2 plant. M2 has no offline detector: its findings reach the deliverable through the
// #416 dynamic-pass artifact a live pen-test writes, which run-audit's m2 probe reads via
// findFreshPass. Injecting that artifact (fresh, target-matched) makes the gate span the offline
// consume→assemble half of the M2 delivery path — the seam #1042 silently dropped. The LIVE
// pentest→artifact half needs a stood-up stack and stays out of this offline gate (#1155).
const artifactsDir = mkdtempSync(join(tmpdir(), "harvey-conservation-artifacts-"));
writeM2ConservationPlant(artifactsDir, targetDir, new Date().toISOString());

const ctx: RunContext = {
  targetDir,
  artifactsDir,
  env: { connected: false, dynamic: false, llm: false },
  // #1109: shared with run-audit rather than copied. A gate that shells out differently from the
  // orchestrator it is gating measures the copy, not the thing.
  exec: probeExec,
  exists: existsSync,
  captureDir,
  readFindings: (p) => (existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Finding[]) : []),
  readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
  now: Date.now(),
  apps: discoverTargets(targetDir).apps.map((a) => ({ name: a.name, path: a.path })),
  discoverSchemaFiles,
  isGitRepoRoot,
};

// The gate is about findings surviving assembly, not about engagement metadata, so meta is blank
// rather than invented — the same placeholder run-audit writes when no --meta is supplied.
const meta: ReportMeta = {
  client: "", subtitle: "", date: new Date().toISOString().slice(0, 10), commit: "", auditor: "",
  confidential: true, overallHealth: 0, tenantIsolation: "", authModel: "", headline: "",
  scope: targetDir, methodology: "", outOfScope: "",
};

console.log(`Conservation gate — ${targetDir}\n`);
const run = runAudit(AUDIT_RUNNERS, ctx);
if (run.failures.length) {
  console.error(formatFailures(run.failures));
  process.exit(1);
}

const findingsByModule = { ...run.findingsByModule };
let findings = run.findings;
for (const module of seedLoss) {
  const dropped = findingsByModule[module] ?? [];
  findingsByModule[module] = [];
  findings = findings.filter((f) => !dropped.includes(f));
  console.log(`⚠ SEEDED LOSS: discarded ${dropped.length} finding(s) produced by ${module} — the gate must fail naming it.`);
}

const doc = assembleEngagementDocument(run.recorded, ctx.env, findings, meta, run.hotspots, run.dataMap, run.testQuality);
// #1096 invariant (1): the arithmetic, before the schema check — a document that lost findings is
// wrong whether or not it validates, and the plant-and-assert below only watches ten rows.
// --seed-unaccounted drops one delivered finding with no disposition, which is what an undeclared
// filter at a consumer boundary looks like; the ledger must fail on it.
if (args.includes("--seed-unaccounted") && doc.findings.length) {
  const [victim, ...rest] = doc.findings;
  doc.findings = rest;
  console.log(`⚠ SEEDED UNACCOUNTED LOSS: dropped ${victim!.id} from the assembled deliverable with no disposition — the ledger must fail naming it.`);
}
// #1146: a disposition declared against a finding that is STILL delivered — a column credited
// against a fiction. The ledger's misdeclared check must fail on it.
const declared: DeclaredDrop[] = [];
if (args.includes("--seed-misdeclared") && doc.findings.length) {
  const victim = doc.findings[0]!;
  declared.push({ id: victim.id, disposition: "suppressed", reason: "seeded false suppression", by: "validate-conservation --seed-misdeclared" });
  console.log(`⚠ SEEDED MISDECLARED DISPOSITION: declared ${victim.id} suppressed while it is still in the deliverable — the ledger must fail naming it.`);
}
const ledger = conservationLedger(findings, doc.findings, findingsByModule, declared);
console.log(`${formatLedger(ledger)}\n`);

// #1146: the baseline seam (#457). applyBaseline runs AFTER assembly and was unmeasured — ledger it
// on an EMPTY baseline (every finding tagged `new`, nothing dropped) so the arithmetic is exercised
// on the real deliverable every run. --seed-baseline-loss drops one finding after the tag to prove
// a baseline-application bug that deletes a NEW finding fails loud.
const preBaseline = doc.findings;
const baselined = applyBaseline({ ...doc, findings: [...doc.findings] }, []);
let baselinedFindings = baselined.findings;
if (args.includes("--seed-baseline-loss") && baselinedFindings.length) {
  const [victim, ...rest] = baselinedFindings;
  baselinedFindings = rest;
  console.log(`⚠ SEEDED BASELINE LOSS: dropped ${victim!.id} while applying the baseline — the baseline ledger must fail naming it.`);
}
const bLedger = baselineLedger(preBaseline, baselinedFindings, findingsByModule);
console.log(`${formatBaselineLedger(bLedger)}\n`);
// An assembled document that fails the report schema is not a deliverable, so "it reached the
// deliverable" would be a claim about a file that could never ship.
const { ok: schemaOk, errors } = validateFindings(doc);
if (!schemaOk) {
  console.error("Assembled findings document is invalid — the deliverable this gate asserts against does not exist:");
  for (const e of errors) console.error(`  ✗ ${e}`);
  process.exit(1);
}

const report = checkConservation({ findingsByModule, recorded: run.recorded, delivered: doc.findings, required });
const effectiveness = buildEffectivenessInventory({ root: REPO_ROOT, producerExecutionReceipts: report.producerExecutionReceipts });
const effectivenessProblems = validateEffectivenessInventory(effectiveness, { root: REPO_ROOT });
effectivenessProblems.push(...validateEffectivenessDelivery(effectiveness, report.producerExecutionReceipts.flatMap((receipt) => receipt.edges.some((edge) => edge.kind === "client-delivery")
  ? receipt.findingIds.map((findingId) => ({ findingId, producerId: receipt.producerId, familyId: receipt.findingFamilyIds[0]!, venueId: "run-audit" }))
  : [])));
if (effectivenessProblems.length) {
  console.error(`Conservation producer receipts are invalid:\n${effectivenessProblems.join("\n")}`);
  process.exit(1);
}

if (args.includes("--json")) console.log(JSON.stringify({ ledger, baselineLedger: bLedger, plants: report }, null, 2));
else console.log(formatConservation(report));

// #1509's second-order defect. Emitted after the plants are scored and BEFORE the verdict, because
// the claim is "this job reached its measuring phase", which is true of a failing gate too — the
// negative-control runs below in .github/workflows/conservation.yml are supposed to end non-zero.
// A run that died in setup writes nothing here and the workflow's assert step names it.
recordMeasured("conservation-plants", report.rows.length, `module plants asserted probe → deliverable over ${targetDir}`);

process.exit(report.ok && ledger.ok && bLedger.ok ? 0 : 1);
