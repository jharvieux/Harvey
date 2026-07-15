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

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildDataMap } from "../../tools/pii-classify.mjs";
import { classifyDefinerFunctions, definerFindings, type DefinerFunction } from "../definer-classifier.js";
import type { Finding } from "../findings.js";
import { classifyNoPolicyTables, grantFindings, type NoPolicyTable } from "../grant-classifier.js";
import { parseColumns, parseDefinerFunctions, parseRlsState } from "../migration-sql-parse.js";
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

function readMigrations(targetDir: string): string {
  const dir = join(targetDir, "supabase", "migrations");
  if (!existsSync(dir)) return "";
  return readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => readFileSync(join(dir, f), "utf8"))
    .join("\n\n");
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
  const mech = await timePhase("M1 + supply chain", "mechanical scan (secrets, deps, semgrep, supply-chain, leftover-auth)", () =>
    runMechanicalScan({ dir: targetDir }),
  );
  mech.report.notes = "secrets (trufflehog+gitleaks), dependency CVEs (osv-scanner + curated Next.js ranges), semgrep, supply-chain, leftover-auth grep — all ran live against the target.";
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
    const columns = parseColumns(migrationSql);
    const dataMap = buildDataMap(columns);
    return { columns, dataMap };
  });
  const dataMap = piiPhase.result.dataMap;
  phases.push({
    phase: "M10",
    module: piiPhase.report.module,
    ms: piiPhase.report.ms,
    findingCount: Object.keys(dataMap).length,
    notes: `${piiPhase.result.columns.length} columns classified across ${Object.keys(dataMap).length} tables with PII/PHI/PCI hits.`,
  });

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
