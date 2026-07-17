// #450 — dynamic validation: stand up a public repo LOCALLY and pen-test it (M2), so validation
// includes the tier that proves exploitability instead of only flagging shapes. Dynamic needs
// nothing from the repo owner — we bring our own local Supabase — so it belongs in validation.
//
// This module is the TESTABLE core: the "can we even stand this up?" assessment, the orchestration,
// and the M2 pass-artifact emission (#448). The actual Docker/supabase/build execution is behind the
// injected StandUpRunner seam (like RunContext.exec) so the decision logic runs offline; the live
// runner is operator-run (the same live-stack work tracked in #159/#161).

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { buildPassArtifact, writePassArtifact } from "./audit-pass-artifact.js";
import type { Finding } from "./findings.js";

// The facts about a repo that decide whether — and how fully — we can stand it up for M2.
export interface RepoLayout {
  hasSupabaseMigrations: boolean; // supabase/migrations with at least one .sql — the RLS surface to probe
  scripts: Record<string, string>; // package.json scripts (dev/build/start let us run the app)
  externalSeamDeps: string[]; // deps naming a separate backend we can't stand up locally
}

// Deps that imply a SEPARATE backend service the app calls — cross-service seam probes need it, and
// we can't stand it up from this repo. Not a hard blocker (core RLS still works); a disclosed limit.
// Extend per engagement — kept small and explicit rather than guessing.
const EXTERNAL_SEAM_DEP = /^(@aws-sdk\/|@pinecone-database\/|@qdrant\/|weaviate-|@elastic\/)/;

export type Coverage = "full" | "postgrest-only" | "none";

interface StandUpVerdict {
  canStandUp: boolean; // can we stand up the DB at all? (false ⇒ no migrations, nothing to probe)
  coverage: Coverage; // full = app + DB; postgrest-only = DB but app not runnable; none = can't stand up
  reason: string;
  limitations: string[]; // reduced-coverage disclosures — never a silent drop (the repo's fail-loud rule)
}

// The decision: given a repo's layout, can we stand it up, and how fully?
export function assessStandUpAbility(layout: RepoLayout): StandUpVerdict {
  if (!layout.hasSupabaseMigrations) {
    return { canStandUp: false, coverage: "none", reason: "no supabase/migrations — no schema to apply to a local stack, so there is no RLS surface to probe", limitations: [] };
  }
  const limitations: string[] = [];
  const canRunApp = Boolean(layout.scripts.dev || layout.scripts.build || layout.scripts.start);
  if (!canRunApp) {
    limitations.push("no dev/build/start script — the app can't be run, so custom API-route and seam probes are skipped; the PostgREST RLS matrix still runs against the local DB");
  }
  if (layout.externalSeamDeps.length) {
    limitations.push(`depends on external backend(s) we can't stand up locally (${layout.externalSeamDeps.join(", ")}) — cross-service seam probes are skipped`);
  }
  return {
    canStandUp: true,
    coverage: canRunApp ? "full" : "postgrest-only",
    reason: canRunApp ? "stand-up-able: local Supabase + app run" : "stand-up-able for PostgREST RLS probing (the app is not runnable)",
    limitations,
  };
}

// Read the layout facts off a target directory.
export function readRepoLayout(targetDir: string): RepoLayout {
  const migrationsDir = join(targetDir, "supabase", "migrations");
  const hasSupabaseMigrations = existsSync(migrationsDir) && readdirSync(migrationsDir).some((f) => f.endsWith(".sql"));
  let scripts: Record<string, string> = {};
  let deps: string[] = [];
  const pkgPath = join(targetDir, "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string>; dependencies?: Record<string, string> };
    scripts = pkg.scripts ?? {};
    deps = Object.keys(pkg.dependencies ?? {});
  }
  return { hasSupabaseMigrations, scripts, externalSeamDeps: deps.filter((d) => EXTERNAL_SEAM_DEP.test(d)) };
}

// The live-execution seam. The real runner shells out to `supabase start`, applies migrations, seeds
// two tenants, runs the app, and drives pentest.ts; a test injects a fake. `pentest` returns the M2
// findings so the harness can bank them into the artifact.
export interface StandUpRunner {
  standUpDb: (targetDir: string) => { ok: boolean; output: string };
  runApp: (targetDir: string) => { ok: boolean; output: string };
  pentest: (targetDir: string, coverage: Coverage) => { ok: boolean; findings: Finding[]; output: string };
}

interface DynamicValidationResult {
  target: string;
  standUp: boolean;
  coverage: Coverage;
  reason: string;
  limitations: string[];
  artifactPath: string | null; // null whenever we produced no evidence — a no-go never writes a pass
  findings: Finding[];
}

// Orchestrate one target: assess → stand up DB → (run app) → pen-test → emit M2.pass.json. Any step
// that can't complete returns a reasoned failure and writes NO artifact — a target we couldn't stand
// up must never read as a clean `ran` (the guard the whole coverage system exists to enforce).
export function runDynamicValidation(opts: {
  targetDir: string;
  layout: RepoLayout;
  artifactsDir: string;
  now: () => string; // injected clock (ISO string) so the result is deterministic under test
  runner: StandUpRunner;
}): DynamicValidationResult {
  const { targetDir, layout, artifactsDir, now, runner } = opts;
  const base = { target: targetDir, artifactPath: null, findings: [] as Finding[] };

  const verdict = assessStandUpAbility(layout);
  if (!verdict.canStandUp) {
    return { ...base, standUp: false, coverage: "none", reason: `could not stand up ${targetDir}: ${verdict.reason}`, limitations: verdict.limitations };
  }

  const db = runner.standUpDb(targetDir);
  if (!db.ok) {
    return { ...base, standUp: false, coverage: "none", reason: `stand-up failed for ${targetDir}: ${db.output}`, limitations: verdict.limitations };
  }

  let coverage = verdict.coverage;
  const limitations = [...verdict.limitations];
  if (coverage === "full") {
    const app = runner.runApp(targetDir);
    if (!app.ok) {
      coverage = "postgrest-only";
      limitations.push(`the app failed to run (${app.output}) — degraded to PostgREST-only probing`);
    }
  }

  const pt = runner.pentest(targetDir, coverage);
  if (!pt.ok) {
    return { ...base, standUp: false, coverage, reason: `pen-test failed against the local stack: ${pt.output}`, limitations };
  }

  const artifact = buildPassArtifact({
    module: "M2",
    target: targetDir,
    pass: "dynamic",
    generatedAt: now(),
    summary: `dynamic validation (${coverage} coverage); ${pt.findings.length} finding(s)`,
    findings: pt.findings,
  });
  const artifactPath = writePassArtifact(artifactsDir, artifact);
  return { target: targetDir, standUp: true, coverage, reason: `dynamic validation ran (${coverage})`, limitations, artifactPath, findings: pt.findings };
}
