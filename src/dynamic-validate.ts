// #450 — dynamic validation: stand up a public repo LOCALLY and pen-test it (M2), so validation
// includes the tier that proves exploitability instead of only flagging shapes. Dynamic needs
// nothing from the repo owner — we bring our own local Supabase — so it belongs in validation.
//
// #508/#514 extend this to a COLD client that ships none of ATC's assets: migration discovery now
// finds nested `apps/*/supabase/migrations` (a monorepo's real schema, #508), Harvey provisions its
// OWN local stack and applies the CLIENT's migrations, seeds two tenants with a Harvey-owned generic
// seed (two-tenant-seed.ts), and runs Harvey's own pentest.ts. The client's own security suite is a
// BONUS signal, gated on proof it actually exercised the DB (never counted if it skipped, #508). If
// the client's migrations don't apply cleanly to a fresh stack, that is itself an M2 finding, never
// a silent skip (#514).
//
// This module is the TESTABLE core: the "can we even stand this up?" assessment, the provisioning
// plan, the seed derivation, the orchestration, and the M2 pass-artifact emission (#448). The actual
// Docker/supabase/build execution is behind the injected StandUpRunner seam (like RunContext.exec)
// so the decision logic runs offline. The live runner is now AUTONOMOUS — src/pentest/live-standup.ts
// (createLiveStandUp) really does `supabase start`, applies the client migrations, creates two auth
// users, seeds two tenants, and runs the PostgREST matrix with no operator step (#159/#161).

import { type Dirent, existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { buildPassArtifact, writePassArtifact } from "./audit-pass-artifact.js";
import type { Finding } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";
import { buildTwoTenantSeed, type TwoTenantSeed } from "./pentest/two-tenant-seed.js";

// The facts about a repo that decide whether — and how fully — we can stand it up for M2.
export interface RepoLayout {
  migrationDirs: string[]; // every supabase/migrations dir with ≥1 .sql (top-level AND nested apps/*) — the RLS surface to apply
  scripts: Record<string, string>; // package.json scripts (dev/build/start let us run the app)
  externalSeamDeps: string[]; // deps naming a separate backend we can't stand up locally
}

// Deps that imply a SEPARATE backend service the app calls — cross-service seam probes need it, and
// we can't stand it up from this repo. Not a hard blocker (core RLS still works); a disclosed limit.
// Extend per engagement — kept small and explicit rather than guessing.
const EXTERNAL_SEAM_DEP = /^(@aws-sdk\/|@pinecone-database\/|@qdrant\/|weaviate-|@elastic\/)/;

// Dirs a bounded migration walk never descends into — build output, deps, VCS internals.
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", ".turbo", ".vercel"]);

export type Coverage = "full" | "postgrest-only" | "none";

interface StandUpVerdict {
  canStandUp: boolean; // can we stand up the DB at all? (false ⇒ no migrations, nothing to probe)
  coverage: Coverage; // full = app + DB; postgrest-only = DB but app not runnable; none = can't stand up
  reason: string;
  limitations: string[]; // reduced-coverage disclosures — never a silent drop (the repo's fail-loud rule)
}

// #508 — a monorepo's real migrations live under apps/*/supabase/migrations, not the (empty)
// top-level supabase/migrations. Bounded recursive walk finding every `supabase/migrations` dir
// holding ≥1 .sql, skipping build/dep/VCS dirs so the scan is cheap and can't wander. Depth is
// capped because a Supabase project's migrations are near the app root, never buried deep.
export function discoverMigrationDirs(targetDir: string, maxDepth = 5): string[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable dir — nothing to discover here
    }
    if (basename(dir) === "migrations" && basename(join(dir, "..")) === "supabase") {
      if (entries.some((e) => e.isFile() && e.name.endsWith(".sql"))) found.push(dir);
      return; // a migrations dir has no nested migrations dirs to find
    }
    if (depth >= maxDepth) return;
    for (const e of entries) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) walk(join(dir, e.name), depth + 1);
    }
  };
  walk(targetDir, 0);
  return found.sort();
}

// The decision: given a repo's layout, can we stand it up, and how fully?
export function assessStandUpAbility(layout: RepoLayout): StandUpVerdict {
  if (layout.migrationDirs.length === 0) {
    return { canStandUp: false, coverage: "none", reason: "no supabase/migrations (top-level or nested apps/*) — no schema to apply to a local stack, so there is no RLS surface to probe", limitations: [] };
  }
  const limitations: string[] = [];
  const canRunApp = Boolean(layout.scripts.dev || layout.scripts.build || layout.scripts.start);
  if (!canRunApp) {
    limitations.push("no dev/build/start script — the app can't be run, so custom API-route and seam probes are skipped; the PostgREST RLS matrix still runs against the local DB");
  }
  if (layout.externalSeamDeps.length) {
    limitations.push(`depends on external backend(s) we can't stand up locally (${layout.externalSeamDeps.join(", ")}) — cross-service seam probes are skipped`);
  }
  if (layout.migrationDirs.length > 1) {
    limitations.push(`${layout.migrationDirs.length} separate Supabase projects discovered (${layout.migrationDirs.map((d) => basename(join(d, "..", ".."))).join(", ")}) — each is a distinct backend; stand up and probe each in turn`);
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
  let scripts: Record<string, string> = {};
  let deps: string[] = [];
  const pkgPath = join(targetDir, "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string>; dependencies?: Record<string, string> };
    scripts = pkg.scripts ?? {};
    deps = Object.keys(pkg.dependencies ?? {});
  }
  return { migrationDirs: discoverMigrationDirs(targetDir), scripts, externalSeamDeps: deps.filter((d) => EXTERNAL_SEAM_DEP.test(d)) };
}

// Concatenate every discovered migration dir's SQL, in dir + filename order, so the seed derivation
// (buildTwoTenantSeed) sees the whole schema. Deterministic ordering keeps the seed stable.
export function readMigrationSql(migrationDirs: string[]): string {
  const parts: string[] = [];
  for (const dir of migrationDirs) {
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) {
      parts.push(readFileSync(join(dir, f), "utf8"));
    }
  }
  return parts.join("\n");
}

// ---- provisioning plan (#514) ----------------------------------------------

export interface ProvisioningStep {
  kind: "start" | "apply-migrations" | "seed" | "pentest";
  detail: string;
}

export interface ProvisioningPlan {
  migrationDirs: string[]; // the client migrations the live runner applies to the fresh stack
  seed: TwoTenantSeed; // the Harvey-owned two-tenant seed derived from those migrations
  steps: ProvisioningStep[];
  tables: string; // HARVEY_TABLES spec for pentest.ts (name:tenantKey list) — the pentest wiring
}

// Build the ordered plan that stands up a Harvey-owned stack for a cold client: start → apply the
// client's own migrations → seed two tenants generically → run Harvey's pentest.ts. Pure: the live
// runner executes each step; this just assembles what to do and the seed to do it with.
export function buildProvisioningPlan(layout: RepoLayout, migrationSql: string): ProvisioningPlan {
  const seed = buildTwoTenantSeed(migrationSql);
  const steps: ProvisioningStep[] = [
    { kind: "start", detail: "supabase start — a Harvey-owned local stack (the client provides no DB)" },
    { kind: "apply-migrations", detail: `apply the client's ${layout.migrationDirs.length} migration dir(s): ${layout.migrationDirs.join(", ")}` },
    { kind: "seed", detail: `seed two tenants across ${seed.scopedTables.length} tenant-scoped table(s)${seed.warnings.length ? ` (warnings: ${seed.warnings.length})` : ""}` },
    { kind: "pentest", detail: "run Harvey's own pentest.ts against the stood-up stack (the mechanism; the client's suite is only a bonus)" },
  ];
  return { migrationDirs: layout.migrationDirs, seed, steps, tables: seed.tablesSpec };
}

// ---- the client's OWN security suite: a bonus signal, gated on it not skipping (#508) ------------

export interface ClientSecuritySuite {
  present: boolean;
  command: string[]; // how the live runner invokes it
  detail: string; // human note of what/where it is
  envGate?: string; // an env var the suite gates its DB-backed tests behind (e.g. CROSS_TENANT_FIXTURES)
}

const SECURITY_SCRIPT = /(cross.?tenant|isolation|security|pentest|rls)/i;
const SECURITY_TEST_DIRS = [join("tests", "security"), join("test", "security"), join("e2e", "security")];

// Detect whether the client ships its own cross-tenant/security suite. Presence only — the live DB
// creds and the decision to run it are the operator's; this just tells the runner there's a bonus
// signal to try. Returns present:false with no command when nothing matches.
export function detectClientSecuritySuite(targetDir: string): ClientSecuritySuite {
  const pkgPath = join(targetDir, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string> };
      const script = Object.keys(pkg.scripts ?? {}).find((s) => SECURITY_SCRIPT.test(s));
      if (script) return { present: true, command: ["npm", "run", script], detail: `package.json script "${script}"` };
    } catch { /* not JSON — fall through to dir probe */ }
  }
  const dir = SECURITY_TEST_DIRS.find((d) => existsSync(join(targetDir, d)));
  if (dir) return { present: true, command: ["npx", "vitest", "run", dir], detail: `test directory ${dir}` };
  return { present: false, command: [], detail: "no client security/cross-tenant suite found" };
}

// Did the client's suite actually EXERCISE the DB, or did its DB-backed tests skip (the ATC failure:
// the meaningful assertion is it.skip unless CROSS_TENANT_FIXTURES=true with seeded creds)? Parse the
// runner's pass/skip/fail counts. Anything that executed (passed OR failed) proves it exercised; only
// skips (or nothing) proves it did not. A suite that skipped is NEVER counted as M2 evidence (#508).
export function interpretClientSuiteRun(output: string): { exercised: boolean; reason: string } {
  const num = (re: RegExp): number => {
    const m = output.match(re);
    return m ? Number(m[1]) : 0;
  };
  const passed = num(/(\d+) passed/);
  const failed = num(/(\d+) failed/);
  const skipped = num(/(\d+) skipped/);
  const executed = passed + failed;
  if (executed > 0) return { exercised: true, reason: `${passed} passed, ${failed} failed — the suite ran against the DB` };
  if (skipped > 0) return { exercised: false, reason: `${skipped} skipped, 0 executed — the DB-backed tests were gated off (likely a fixtures/creds env gate); not counted as evidence` };
  return { exercised: false, reason: "no tests executed and none reported skipped — could not confirm the suite exercised the DB; not counted as evidence" };
}

// ---- findings synthesized by the provisioning path -------------------------

// #514 — the client's migrations not applying to a fresh local stack is a real M2 finding (the app
// is not reproducibly provisionable), captured with the failure, not swallowed as an environment gap.
function migrationApplyFinding(targetDir: string, output: string): Finding {
  return mechanicalFinding({
    id: "M2-PROVISION-MIGRATE",
    title: "Client migrations do not apply cleanly to a fresh local stack",
    severity: "Medium",
    category: "Dynamic pen-test (M2)",
    taxonomy: "M2 — Provisioning / reproducibility",
    location: targetDir,
    evidence: `Applying the discovered migrations to a fresh \`supabase start\` stack failed:\n${output.slice(0, 500)}`,
    impact: "The schema is not reproducibly provisionable from its own migrations, so a from-scratch environment (CI, a new engineer, disaster recovery, or this pen-test) cannot be stood up. It also blocks dynamic isolation probing.",
    fix: "Make the migration set apply cleanly to an empty database (ordering, missing extensions, or environment-specific objects). Verify with `supabase db reset` on a clean stack.",
    precisionTier: "high",
  });
}

// A client's OWN cross-tenant/security test failing against the seeded stack is direct dynamic
// evidence — surfaced as an M2 finding, distinct from Harvey's independent pentest.ts findings.
function clientSuiteFailureFinding(targetDir: string, output: string): Finding {
  return mechanicalFinding({
    id: "M2-CLIENT-SUITE",
    title: "Client's own cross-tenant/security suite failed against the seeded two-tenant stack",
    severity: "High",
    category: "Dynamic pen-test (M2)",
    taxonomy: "M2 — Tenant isolation",
    location: targetDir,
    evidence: `The client's own security suite executed (did not skip) and reported failures:\n${output.slice(0, 500)}`,
    impact: "The client's own isolation assertions fail on a clean seeded stack — a cross-tenant leak the client's tests already encode but that is not holding.",
    fix: "Investigate the failing assertions; they encode the client's own tenancy invariants.",
    precisionTier: "high",
  });
}

// The live-execution seam. The real runner shells out to `supabase start`, applies the client
// migrations, seeds two tenants, runs the app, drives pentest.ts, and (bonus) the client's own
// suite; a test injects a fake. `pentest` returns the M2 findings so the harness can bank them.
export interface StandUpResult {
  ok: boolean;
  output: string;
  // true ⇒ the DB engine came up but the CLIENT's migrations failed to apply. Distinguishes a real
  // M2 finding (schema won't provision) from an operator/env gap (Docker/CLI missing ⇒ ok:false,
  // this false) so the former emits evidence and the latter honestly records requires-live-run.
  migrationApplyFailed?: boolean;
}

export interface StandUpRunner {
  standUpDb: (targetDir: string, plan: ProvisioningPlan) => StandUpResult;
  runApp: (targetDir: string) => { ok: boolean; output: string };
  pentest: (targetDir: string, coverage: Coverage) => { ok: boolean; findings: Finding[]; output: string };
  clientSuite?: (targetDir: string, suite: ClientSecuritySuite) => { ok: boolean; output: string };
}

interface DynamicValidationResult {
  target: string;
  standUp: boolean;
  coverage: Coverage;
  reason: string;
  limitations: string[];
  notes: string[]; // operator-facing, non-limitation disclosures (e.g. the bonus client-suite outcome)
  artifactPath: string | null; // null whenever we produced no evidence — a no-go never writes a pass
  findings: Finding[];
}

// Orchestrate one target: assess → stand up DB (apply client migrations + seed two tenants) →
// (run app) → pen-test → (bonus: the client's own suite) → emit M2.pass.json. A step that can't
// complete returns a reasoned failure and writes NO artifact — a target we couldn't stand up must
// never read as a clean `ran` (the guard the whole coverage system exists to enforce) — EXCEPT a
// clean-migration failure, which IS an M2 finding and so DOES emit an artifact carrying it (#514).
export function runDynamicValidation(opts: {
  targetDir: string;
  layout: RepoLayout;
  plan: ProvisioningPlan;
  artifactsDir: string;
  now: () => string; // injected clock (ISO string) so the result is deterministic under test
  runner: StandUpRunner;
  clientSuite?: ClientSecuritySuite; // detected client suite to try as a bonus signal
}): DynamicValidationResult {
  const { targetDir, layout, plan, artifactsDir, now, runner, clientSuite } = opts;
  const base = { target: targetDir, artifactPath: null, findings: [] as Finding[], notes: [] as string[] };

  const verdict = assessStandUpAbility(layout);
  if (!verdict.canStandUp) {
    return { ...base, standUp: false, coverage: "none", reason: `could not stand up ${targetDir}: ${verdict.reason}`, limitations: verdict.limitations };
  }

  const db = runner.standUpDb(targetDir, plan);
  if (!db.ok) {
    if (db.migrationApplyFailed) {
      const finding = migrationApplyFinding(targetDir, db.output);
      const artifact = buildPassArtifact({
        module: "M2", target: targetDir, pass: "dynamic", generatedAt: now(),
        summary: "client migrations did not apply cleanly to a fresh local stack — recorded as an M2 finding",
        findings: [finding],
      });
      const artifactPath = writePassArtifact(artifactsDir, artifact);
      return { ...base, standUp: false, coverage: "none", reason: `client migrations failed to apply (recorded as an M2 finding, not skipped): ${db.output}`, limitations: verdict.limitations, artifactPath, findings: [finding] };
    }
    return { ...base, standUp: false, coverage: "none", reason: `stand-up failed for ${targetDir}: ${db.output}`, limitations: verdict.limitations };
  }

  let coverage = verdict.coverage;
  const limitations = [...verdict.limitations];
  const notes: string[] = [];
  for (const w of plan.seed.warnings) limitations.push(`seed: ${w}`);

  if (coverage === "full") {
    const app = runner.runApp(targetDir);
    if (!app.ok) {
      coverage = "postgrest-only";
      limitations.push(`the app failed to run (${app.output}) — degraded to PostgREST-only probing`);
    }
  }

  const pt = runner.pentest(targetDir, coverage);
  if (!pt.ok) {
    return { ...base, standUp: false, coverage, reason: `pen-test failed against the local stack: ${pt.output}`, limitations, notes };
  }

  const findings = [...pt.findings];

  // Bonus signal only (#514: the client's suite is never the mechanism). Counted as evidence ONLY
  // if it proved it exercised the DB; a skipped suite is disclosed, never trusted (#508).
  if (clientSuite?.present && runner.clientSuite) {
    const res = runner.clientSuite(targetDir, clientSuite);
    const outcome = interpretClientSuiteRun(res.output);
    if (!outcome.exercised) {
      limitations.push(`client's own security suite (${clientSuite.detail}) was present but did not exercise the DB — ${outcome.reason}; not counted as M2 evidence (Harvey's own pentest.ts is the mechanism)`);
    } else if (!res.ok) {
      findings.push(clientSuiteFailureFinding(targetDir, res.output));
      notes.push(`client's own security suite ran and FAILED — captured as an M2 finding (${outcome.reason})`);
    } else {
      notes.push(`client's own security suite ran and passed against the seeded stack (bonus signal: ${outcome.reason})`);
    }
  }

  const artifact = buildPassArtifact({
    module: "M2",
    target: targetDir,
    pass: "dynamic",
    generatedAt: now(),
    summary: `dynamic validation (${coverage} coverage); ${findings.length} finding(s)`,
    findings,
  });
  const artifactPath = writePassArtifact(artifactsDir, artifact);
  return { target: targetDir, standUp: true, coverage, reason: `dynamic validation ran (${coverage})`, limitations, notes, artifactPath, findings };
}
