// Dry-run harness for the calibration target (issue #34). Runs every scan module that is
// genuinely executable in a sandbox with no Docker/live DB against a target directory, timing
// each phase and emitting a combined Finding[] + timing report + PII data map.
//
//   pnpm exec tsx src/cli/dry-run.ts --target targets/calibration --out dry-run
//
// Wires: the mechanical scan (M1 secrets/deps/semgrep/supply-chain/leftover-auth,
// src/scan/mechanical.ts), the M1 detect-deeper grant/definer classifiers fed from parsed
// migration SQL instead of a live DB (src/migration-sql-parse.ts + src/*-classifier.ts), and
// the M10 PII data map (tools/pii-classify.mjs) over the same parsed migration columns.
//
// Explicitly NOT run here — see docs/runbooks/dry-run-calibration.md "requires live environment":
// Supabase Advisor lints (needs `supabase start`/Docker), the LLM-driven /threat-model,
// /vuln-scan, /triage pass (needs the anthropics/defending-code-reference-harness skills),
// and M2/M7/M8 (quality-scan, perf-scan, mutation-scan — need a live DB and/or a running app).

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { classifyMigrationSql } from "../../tools/pii-classify.mjs";
import { classifyDefinerFunctions, definerFindings, type DefinerFunction } from "../definer-classifier.js";
import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { classifyNoPolicyTables, grantFindings, type NoPolicyTable } from "../grant-classifier.js";
import { parseDefinerFunctions, parseRlsState } from "../migration-sql-parse.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { relativizeScanScope } from "../scan/scan-scope.js";

interface PhaseResult {
  phase: string;
  module: string;
  ms: number;
  findingCount: number;
  notes: string;
}

async function timePhase<T>(phase: string, module: string, fn: () => T | Promise<T>): Promise<{ result: T; report: PhaseResult; findings: Finding[] }> {
  const start = performance.now();
  const result = await fn();
  const ms = Math.round((performance.now() - start) * 10) / 10;
  const findings = Array.isArray(result) ? (result as unknown as Finding[]) : [];
  return { result, findings, report: { phase, module, ms, findingCount: findings.length, notes: "" } };
}

// Recursive (#355, matching the #299 fix already applied to corpus-drift.ts's readMigrationSql
// and pii-classify.mjs's readSchemaSql): a Prisma schemaPath (prisma/migrations/<name>/migration.sql)
// is one directory deeper than Supabase's flat supabase/migrations/<timestamp>.sql — a
// non-recursive readdir silently finds nothing there, reading as "no schema input".
function readMigrations(targetDir: string): string {
  const dir = join(targetDir, "supabase", "migrations");
  if (!existsSync(dir)) return "";
  return readdirSync(dir, { recursive: true, encoding: "utf8" })
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(dir, f), "utf8"))
    .join("\n\n");
}

// #343 — targets/calibration/.gitignore excludes .env/.env.local so a stray `npm install` or
// `next build` run inside the target never lands real-looking artifacts in THIS repo's own
// index, but those two files also hold the planted secret fixtures gitleaks/trufflehog must see.
// runMechanicalScan's scope guard (src/scan/scan-scope.ts, #101) walks git-TRACKED files only —
// correct for a real client repo, but here it silently drops any fixture a contributor forgot to
// `git add -f` into this repo's own index; a plain `git add -A` never stages them and the dry run
// exits clean with the findings simply missing. Build a disposable git repo around a COPY of the
// target and force-add everything its .gitignore would otherwise skip except genuine build
// output (node_modules/.next/*.log), so the scope guard always sees the fixtures regardless of
// what got committed upstream — there is nothing left to forget.
//
// Nested one level inside its own repo root (targetDir's real relationship to the Harvey repo is
// mirrored: a subdirectory, not the root) so secrets.ts's isGitRepoRoot still sees a
// SUBDIRECTORY and the git-history trufflehog pass stays skipped, exactly as it is today for the
// real targets/calibration path — this only changes which files the TRACKED-file walk finds.
// Since #528, "skipped" means the SEC-TH-GH-00 disclosure finding fires instead of a silent []
// — that finding is expected to appear in this harness's committed findings.json.
const BUILD_ARTIFACT_IGNORE = /(^|\/)(node_modules|\.next)\/|\.log$/;

function findEnvFixtures(dir: string, base = dir): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".next" || entry.name === ".git") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...findEnvFixtures(full, base));
    else if (entry.name === ".env" || entry.name === ".env.local") found.push(relative(base, full));
  }
  return found;
}

function buildScratchTarget(targetDir: string): { scanDir: string; cleanup: () => void } {
  const scratchRoot = mkdtempSync(join(tmpdir(), "harvey-dry-run-scratch-"));
  const repoRoot = join(scratchRoot, "repo");
  const scanDir = join(repoRoot, "target");
  cpSync(targetDir, scanDir, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: repoRoot });
  execFileSync("git", ["-C", repoRoot, "add", "-A"]);

  const ignored = execFileSync("git", ["-C", repoRoot, "status", "--porcelain", "--ignored=matching"], { encoding: "utf8" })
    .split("\n")
    .filter((l) => l.startsWith("!! "))
    .map((l) => l.slice(3));
  const fixtures = ignored.filter((p) => !BUILD_ARTIFACT_IGNORE.test(p));
  if (fixtures.length > 0) execFileSync("git", ["-C", repoRoot, "add", "-f", "--", ...fixtures]);

  // Fail loud (#343's minimum bar, kept as a safety net alongside the force-add above): if the
  // source tree has planted .env fixtures but the scratch repo's index doesn't have every one of
  // them, the force-add pass above regressed — a quietly-wrong dry run is worse than a crash that
  // names exactly which fixture went missing.
  const expected = findEnvFixtures(targetDir);
  if (expected.length > 0) {
    const tracked = new Set(execFileSync("git", ["-C", scanDir, "ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean));
    const missing = expected.filter((rel) => !tracked.has(rel));
    if (missing.length > 0) {
      throw new Error(`dry-run scratch repo dropped planted secret fixture(s): ${missing.join(", ")} — buildScratchTarget's force-add did not include them.`);
    }
  }

  return { scanDir, cleanup: () => rmSync(scratchRoot, { recursive: true, force: true }) };
}

// Postgres grants EXECUTE on a function to PUBLIC by default unless explicitly REVOKEd — every
// role (including Supabase's anon/authenticated) is implicitly a PUBLIC member for privilege
// purposes. None of the calibration migrations contain a REVOKE, so this is the correct default
// per Postgres's own privilege model — but it is an INFERRED assumption, not a live grant read.
// The live path (src/cli/detect-deeper.ts) queries pg_proc.proacl via aclexplode() for the real
// answer; a migration-SQL-only feed cannot distinguish "default, never touched" from "explicitly
// re-granted after a revoke elsewhere" (e.g. a Supabase platform system migration this repo
// doesn't have access to).
const ASSUMED_DEFAULT_FUNCTION_EXPOSURE = ["anon", "authenticated"];

function arg(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
}

async function main(): Promise<void> {
  const targetDir = arg("--target", join(import.meta.dirname, "..", "..", "targets", "calibration"));
  const outDir = arg("--out", join(import.meta.dirname, "..", "..", "dry-run"));
  mkdirSync(outDir, { recursive: true });

  const phases: PhaseResult[] = [];
  const allFindings: Finding[] = [];

  // --- M1 (+ dependency CVE / supply-chain / leftover-auth): mechanical scan ---
  // Scan a scratch copy (#343) rather than targetDir directly, so the scope guard's
  // git-tracked-only walk can't silently drop a planted .env fixture nobody force-added upstream.
  const scratch = buildScratchTarget(targetDir);
  let mech: Awaited<ReturnType<typeof timePhase<Finding[]>>>;
  try {
    mech = await timePhase("M1 + supply chain", "mechanical scan (secrets, deps, semgrep, supply-chain, leftover-auth)", () =>
      // skipNetworkChecks: findings.json is committed and contractually deterministic across
      // machines (#285) — the live npm-registry calls (checkLicenseCompliance, checkSlopsquat)
      // would let it drift on registry reachability, not just the target/scanner. Real engagement
      // scans are unaffected: this flag is opt-in and only the dry-run harness sets it.
      runMechanicalScan({ dir: scratch.scanDir, skipNetworkChecks: true }),
    );
  } finally {
    scratch.cleanup();
  }
  mech.report.notes = "secrets (trufflehog+gitleaks), dependency CVEs (osv-scanner + curated Next.js ranges), semgrep, supply-chain, leftover-auth grep — all ran live against the target, except the two live npm-registry checks (license compliance, slopsquat) which are skipped to keep this artifact network-independent.";
  phases.push(mech.report);
  allFindings.push(...mech.findings);

  // --- M1 detect-deeper: grant/definer classifiers fed from parsed migration SQL ---
  const migrationSql = readMigrations(targetDir);
  const m1Deeper = await timePhase("M1 detect-deeper", "grant/definer classifiers (static migration-SQL feed, no live DB)", () => {
    const definerFns: DefinerFunction[] = parseDefinerFunctions(migrationSql).map((fn) => ({
      ...fn,
      exposedTo: ASSUMED_DEFAULT_FUNCTION_EXPOSURE,
    }));
    const definerVerdicts = classifyDefinerFunctions(definerFns);

    const rlsState = parseRlsState(migrationSql, migrationSql);
    const noPolicyCandidates: NoPolicyTable[] = rlsState
      .filter((t) => t.rlsEnabled && !t.hasPolicy)
      .map((t) => ({ schema: t.schema, table: t.table, grants: [], queriedByClientCode: false }));
    const grantVerdicts = classifyNoPolicyTables(noPolicyCandidates);

    return [...definerFindings(definerVerdicts), ...grantFindings(grantVerdicts)];
  });
  m1Deeper.report.notes = "exposedTo for SECURITY DEFINER functions is an assumed default (Postgres grants EXECUTE to PUBLIC unless revoked; no REVOKE found) — see ASSUMED_DEFAULT_FUNCTION_EXPOSURE. No-policy-table candidates require only structural RLS/policy presence, no live grants.";
  phases.push(m1Deeper.report);
  allFindings.push(...m1Deeper.findings);

  // --- M10: PII data map over parsed migration columns ---
  const piiPhase = await timePhase("M10", "PII/PHI/PCI data map (tools/pii-classify.mjs, static migration-SQL feed)", () => {
    const { columns, dataMap, unknownType } = classifyMigrationSql(migrationSql);
    return { columns, dataMap, unknownType };
  });
  const dataMap = piiPhase.result.dataMap;
  const unknownTypeNote = piiPhase.result.unknownType.length
    ? ` ${piiPhase.result.unknownType.length} column(s) had an unrecognized SQL type, classified by name only (#851).`
    : "";
  phases.push({
    phase: "M10",
    module: piiPhase.report.module,
    ms: piiPhase.report.ms,
    findingCount: Object.keys(dataMap).length,
    notes: `${piiPhase.result.columns.length} columns classified across ${Object.keys(dataMap).length} tables with PII/PHI/PCI hits.${unknownTypeNote}`,
  });

  // #975 — declare CWEs for the out-of-mechanical-scan classifier findings too (definer/grant);
  // mech.findings are already enriched, and the pass is idempotent.
  enrichFindingsCwe(allFindings);
  // findings.json is committed, so it must be diffable across runs and machines (issue #285).
  const portableFindings = allFindings.map((f) => ({ ...f, location: relativizeScanScope(f.location) }));
  writeFileSync(join(outDir, "findings.json"), JSON.stringify(portableFindings, null, 2));
  writeFileSync(join(outDir, "pii-data-map.json"), JSON.stringify(dataMap, null, 2));
  writeFileSync(join(outDir, "timing.json"), JSON.stringify(phases, null, 2));

  console.log(`dry-run complete: ${allFindings.length} findings, ${Object.keys(dataMap).length} PII-bearing tables`);
  for (const p of phases) console.log(`  ${p.phase.padEnd(20)} ${String(p.ms).padStart(8)}ms  ${p.module}`);
  console.log(`\nWrote ${outDir}/{findings.json,pii-data-map.json,timing.json}`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
