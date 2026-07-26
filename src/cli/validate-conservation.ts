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
// --require <Mn>  hold a module recorded in UNEXERCISED to the full standard anyway. This is the
//                 falsifier path for its recorded reason (#1033): `--require M2` exits 0 the day M2
//                 delivers findings from this fixture, i.e. the day "cannot be exercised offline"
//                 stops being true.
// --seed-loss <Mn>  SEED A VIOLATION: discard everything module Mn's probe produced, before
//                 assembly, reproducing the #1040/#1061 break in which results were produced and
//                 then dropped. The gate must fail naming Mn. It exists because a gate nobody has
//                 watched fail is not evidence that it can (#350) — and note it still fails for a
//                 module whose rows another probe re-collects (M9 captures detect-static unfiltered,
//                 so M7's rows survive in the deliverable while M7 itself produced nothing: the
//                 #1062 shape).
// --seed-unaccounted  SEED THE OTHER VIOLATION (#1096): drop one finding out of the ASSEMBLED
//                 deliverable with no disposition — what an undeclared filter at a consumer
//                 boundary does. The plant-and-assert above can miss it (it watches ten rows); the
//                 conservation ledger's arithmetic cannot.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkConservation, formatConservation } from "../audit-conservation.js";
import { conservationLedger, formatLedger } from "../conservation-ledger.js";
import { assembleEngagementDocument } from "../audit-report.js";
import type { AuditModule } from "../audit-coverage.js";
import { formatFailures, runAudit, type RunContext } from "../audit-runner.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { discoverSchemaFiles } from "../dynamic-validate.js";
import { discoverTargets } from "../pentest/targets.js";
import { isGitRepoRoot } from "../scan/secrets.js";
import { type Finding, type ReportMeta, validateFindings } from "../findings.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = process.argv.slice(2);
const flagValues = (flag: string): string[] => args.flatMap((a, i) => (a === flag && args[i + 1] ? [args[i + 1]!] : []));
const targetDir = resolve(flagValues("--target")[0] ?? join(REPO_ROOT, "targets", "calibration"));
const required = flagValues("--require") as AuditModule[];
const seedLoss = new Set(flagValues("--seed-loss") as AuditModule[]);

const captureDir = mkdtempSync(join(tmpdir(), "harvey-conservation-"));
const ctx: RunContext = {
  targetDir,
  env: { connected: false, dynamic: false, llm: false },
  exec: (command, argv, opts) => {
    try {
      const output = execFileSync(command, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...(opts?.env ? { env: { ...process.env, ...opts.env } } : {}) });
      return { ok: true, output };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message?: string };
      return { ok: false, output: e.stderr || e.stdout || e.message || "" };
    }
  },
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
const ledger = conservationLedger(findings, doc.findings, findingsByModule);
console.log(`${formatLedger(ledger)}\n`);
// An assembled document that fails the report schema is not a deliverable, so "it reached the
// deliverable" would be a claim about a file that could never ship.
const { ok: schemaOk, errors } = validateFindings(doc);
if (!schemaOk) {
  console.error("Assembled findings document is invalid — the deliverable this gate asserts against does not exist:");
  for (const e of errors) console.error(`  ✗ ${e}`);
  process.exit(1);
}

const report = checkConservation({ findingsByModule, recorded: run.recorded, delivered: doc.findings, required });

if (args.includes("--json")) console.log(JSON.stringify({ ledger, plants: report }, null, 2));
else console.log(formatConservation(report));

process.exit(report.ok && ledger.ok ? 0 : 1);
