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

import { existsSync, readFileSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { readEntriesSafe, readNamesSafe, type SafeDirEntry } from "./fs-walk.js";
import { buildPassArtifact, writePassArtifact } from "./audit-pass-artifact.js";
import type { Finding } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";
import { buildScopeLedger, type ScopeRow } from "./pentest/scope-ledger.js";
import { buildTwoTenantSeed, type SeedSkip, type TwoTenantSeed } from "./pentest/two-tenant-seed.js";

// The facts about a repo that decide whether — and how fully — we can stand it up for M2.
export interface RepoLayout {
  migrationDirs: string[]; // every supabase/migrations dir with ≥1 .sql (top-level AND nested apps/*) — the RLS surface to apply
  schemaFiles: string[]; // #574 — standalone schema .sql files (root schema.sql / conventional) used when there is NO migrations dir (Vite/no-code exports ship one committed schema)
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
    let entries: SafeDirEntry[];
    try {
      entries = readEntriesSafe(dir).entries;
    } catch {
      return; // unreadable dir — nothing to discover here
    }
    if (basename(dir) === "migrations" && basename(join(dir, "..")) === "supabase") {
      if (entries.some((e) => !e.isDirectory && e.name.endsWith(".sql"))) found.push(dir);
      return; // a migrations dir has no nested migrations dirs to find
    }
    if (depth >= maxDepth) return;
    for (const e of entries) {
      if (e.isDirectory && !SKIP_DIRS.has(e.name)) walk(join(dir, e.name), depth + 1);
    }
  };
  walk(targetDir, 0);
  return found.sort();
}

// #574 — conventional locations a single committed schema lives in when a target has no
// supabase/migrations dir (Vite / v0 / Lovable / Bolt exports commit one root schema.sql). Probed in
// order; the first that exists AND declares a table is the schema fed to the local stack.
const SCHEMA_FILE_CANDIDATES = [
  "schema.sql",
  "db/schema.sql",
  "sql/schema.sql",
  "database/schema.sql",
  "supabase/schema.sql",
  "prisma/schema.sql",
];

function declaresTable(file: string): boolean {
  try {
    return /create\s+table/i.test(readFileSync(file, "utf8"));
  } catch {
    return false;
  }
}

// Find the standalone schema .sql file(s) to apply when there is NO migrations dir. Tries the
// conventional paths first; failing that, a bounded shallow scan for any *.sql (not a seed file,
// not inside a migrations dir) that declares a table. Returns [] for a genuinely schema-less repo —
// the caller then records an honest NO-GO listing what it probed. `probed` reports the locations
// checked so a NO-GO can name them.
export function discoverSchemaFiles(targetDir: string, maxDepth = 3): { files: string[]; probed: string[] } {
  const probed: string[] = [...SCHEMA_FILE_CANDIDATES];
  const conventional = SCHEMA_FILE_CANDIDATES.map((rel) => join(targetDir, rel)).filter((p) => existsSync(p) && declaresTable(p));
  if (conventional.length) return { files: conventional.sort(), probed };
  const found: string[] = [];
  const walk = (dir: string, depth: number): void => {
    let entries: SafeDirEntry[];
    try {
      entries = readEntriesSafe(dir).entries;
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory) {
        if (!SKIP_DIRS.has(e.name) && e.name !== "migrations" && depth < maxDepth) walk(p, depth + 1);
      } else if (e.name.endsWith(".sql") && !/seed/i.test(e.name) && declaresTable(p)) {
        found.push(p);
      }
    }
  };
  walk(targetDir, 0);
  probed.push(`shallow *.sql scan (depth ≤ ${maxDepth}, excluding migrations/ and seed files)`);
  return { files: found.sort(), probed };
}

// The decision: given a repo's layout, can we stand it up, and how fully?
export function assessStandUpAbility(layout: RepoLayout): StandUpVerdict {
  if (layout.migrationDirs.length === 0 && layout.schemaFiles.length === 0) {
    return {
      canStandUp: false,
      coverage: "none",
      reason: `no schema to apply to a local stack (no supabase/migrations top-level or nested apps/*, and no standalone schema .sql) — nothing to provision, so there is no RLS surface to probe. Probed: supabase/migrations, ${SCHEMA_FILE_CANDIDATES.join(", ")}, and a shallow *.sql scan`,
      limitations: [],
    };
  }
  const limitations: string[] = [];
  if (layout.migrationDirs.length === 0 && layout.schemaFiles.length > 0) {
    limitations.push(`no supabase/migrations dir — applying the standalone schema file(s) directly to the local stack: ${layout.schemaFiles.join(", ")} (#574)`);
  }
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
  // Migrations take precedence; only a target with NO migrations dir falls back to a standalone
  // schema file (#574), so the two are never both applied.
  const migrationDirs = discoverMigrationDirs(targetDir);
  const schemaFiles = migrationDirs.length === 0 ? discoverSchemaFiles(targetDir).files : [];
  return { migrationDirs, schemaFiles, scripts, externalSeamDeps: deps.filter((d) => EXTERNAL_SEAM_DEP.test(d)) };
}

// Concatenate every discovered migration dir's SQL, in dir + filename order, so the seed derivation
// (buildTwoTenantSeed) sees the whole schema. Deterministic ordering keeps the seed stable.
function readMigrationSql(migrationDirs: string[]): string {
  const parts: string[] = [];
  for (const dir of migrationDirs) {
    for (const f of readNamesSafe(dir).filter((n) => n.endsWith(".sql")).sort()) {
      parts.push(readFileSync(join(dir, f), "utf8"));
    }
  }
  return parts.join("\n");
}

// The concatenated schema for a layout: its migrations if it has them, else its standalone schema
// file(s) (#574). This is what the seed derivation sees and what the live runner applies.
export function readSchemaSql(layout: RepoLayout): string {
  if (layout.migrationDirs.length) return readMigrationSql(layout.migrationDirs);
  return layout.schemaFiles.map((f) => readFileSync(f, "utf8")).join("\n");
}

// ---- provisioning plan (#514) ----------------------------------------------

export interface ProvisioningStep {
  kind: "start" | "apply-migrations" | "seed" | "pentest";
  detail: string;
}

export interface ProvisioningPlan {
  projectRoot: string; // #574 — the target dir; the live runner's workdir when there is no supabase/migrations to derive it from
  migrationDirs: string[]; // the client migrations the live runner applies to the fresh stack
  schemaFiles: string[]; // #574 — standalone schema files applied via psql when there is no migrations dir
  seed: TwoTenantSeed; // the Harvey-owned two-tenant seed derived from those migrations
  steps: ProvisioningStep[];
  tables: string; // HARVEY_TABLES spec for pentest.ts (name:tenantKey list) — the pentest wiring
}

// Build the ordered plan that stands up a Harvey-owned stack for a cold client: start → apply the
// client's own migrations → seed two tenants generically → run Harvey's pentest.ts. Pure: the live
// runner executes each step; this just assembles what to do and the seed to do it with.
export function buildProvisioningPlan(layout: RepoLayout, migrationSql: string, projectRoot: string): ProvisioningPlan {
  const seed = buildTwoTenantSeed(migrationSql);
  const applyDetail = layout.migrationDirs.length
    ? `apply the client's ${layout.migrationDirs.length} migration dir(s): ${layout.migrationDirs.join(", ")}`
    : `apply the standalone schema file(s) via psql (no migrations dir): ${layout.schemaFiles.join(", ")}`;
  const steps: ProvisioningStep[] = [
    { kind: "start", detail: "supabase start — a Harvey-owned local stack (the client provides no DB)" },
    { kind: "apply-migrations", detail: applyDetail },
    { kind: "seed", detail: `seed two ${seed.dataModel === "user" ? "users" : "tenants"} across ${seed.scopedTables.length} scoped table(s)${seed.warnings.length ? ` (warnings: ${seed.warnings.length})` : ""}` },
    { kind: "pentest", detail: "run Harvey's own pentest.ts against the stood-up stack (the mechanism; the client's suite is only a bonus)" },
  ];
  return { projectRoot, migrationDirs: layout.migrationDirs, schemaFiles: layout.schemaFiles, seed, steps, tables: seed.tablesSpec };
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
  // true ⇒ the client's migrations applied cleanly but HARVEY'S OWN two-tenant seed.sql failed. A
  // harness/seed issue (#598), NOT a client schema defect — must never surface as M2-PROVISION-
  // MIGRATE. Recorded as a distinct, honest reason (requires-live-run), never a false client finding.
  seedApplyFailed?: boolean;
  // #649 — tables the per-table SAVEPOINT seed had to skip (a bespoke cross-column CHECK a generic
  // seed can't satisfy). The rest seeded and were probed; these are disclosed (fail-loud) and were
  // NOT probed for cross-tenant isolation. Never a silent narrowing of the surface.
  seedSkips?: SeedSkip[];
  // #875 — the target checkout's commit, so the scope disclosure names WHICH schema was replayed.
  // Absent ⇒ the disclosure says the revision was not captured, never that it does not matter.
  revision?: string;
  // #876/#877 — surface + identity-class rows the runner observed (which access paths and which API
  // surfaces this stand-up could exercise, and which it could not). Folded into the scope ledger.
  scopeRows?: ScopeRow[];
  // #907 — scoped tables with a soft-delete column the data-residue probe received; when present the
  // scope ledger's DATA_RESIDUE_ROW flips from "not probed" to "probed" for the soft-delete class.
  softDeleteTables?: string[];
}

export interface StandUpRunner {
  standUpDb: (targetDir: string, plan: ProvisioningPlan) => StandUpResult;
  runApp: (targetDir: string) => { ok: boolean; output: string };
  pentest: (targetDir: string, coverage: Coverage) => { ok: boolean; findings: Finding[]; output: string };
  clientSuite?: (targetDir: string, suite: ClientSecuritySuite) => { ok: boolean; output: string };
}

export interface DynamicValidationResult {
  target: string;
  standUp: boolean;
  coverage: Coverage;
  reason: string;
  limitations: string[];
  notes: string[]; // operator-facing, non-limitation disclosures (e.g. the bonus client-suite outcome)
  artifactPath: string | null; // null whenever we produced no evidence — a no-go never writes a pass
  findings: Finding[];
}

// The outcome of probing ONE Supabase project (one stood-up DB). The artifact-writing decision lives
// in the caller so the same probe body serves the single-project path and the per-DB monorepo loop.
interface ProbeResult {
  standUp: boolean;
  coverage: Coverage;
  reason: string;
  limitations: string[];
  notes: string[];
  findings: Finding[];
  producedEvidence: boolean; // stood up + probed, OR a migration-apply M2 finding — warrants an artifact
  artifactSummary?: string; // the summary to use when this project's evidence is the whole artifact
}

// Probe one Supabase project: assess → stand up its DB (apply its migrations + seed two tenants) →
// (run its app) → pen-test → (bonus: the client's own suite). Pure over the injected runner; the
// caller (single-project or per-DB loop) decides what artifact to write. `appDir` is the project's
// own app root (== targetDir for a single-project repo; the app dir beside `supabase/` in a monorepo).
function probeOneProject(opts: {
  targetDir: string;
  appDir: string;
  layout: RepoLayout;
  plan: ProvisioningPlan;
  runner: StandUpRunner;
  clientSuite?: ClientSecuritySuite;
}): ProbeResult {
  const { targetDir, appDir, layout, plan, runner, clientSuite } = opts;

  const verdict = assessStandUpAbility(layout);
  if (!verdict.canStandUp) {
    return { standUp: false, coverage: "none", reason: `could not stand up ${targetDir}: ${verdict.reason}`, limitations: verdict.limitations, notes: [], findings: [], producedEvidence: false };
  }

  const db = runner.standUpDb(appDir, plan);
  if (!db.ok) {
    if (db.seedApplyFailed) {
      // Harvey's OWN two-tenant seed failed to apply — the client's migrations DID apply, so this is
      // NOT M2-PROVISION-MIGRATE and carries no client finding. Fail loud with the real seed error so
      // M2 reads as requires-live-run for a harness reason, not a false "schema won't provision" (#598).
      return { standUp: false, coverage: "none", reason: `Harvey's two-tenant seed failed to apply (a harness/seed issue, not a client migration defect): ${db.output}`, limitations: verdict.limitations, notes: [], findings: [], producedEvidence: false };
    }
    if (db.migrationApplyFailed) {
      const finding = migrationApplyFinding(appDir, db.output);
      return { standUp: false, coverage: "none", reason: `client migrations failed to apply (recorded as an M2 finding, not skipped): ${db.output}`, limitations: verdict.limitations, notes: [], findings: [finding], producedEvidence: true, artifactSummary: "client migrations did not apply cleanly to a fresh local stack — recorded as an M2 finding" };
    }
    return { standUp: false, coverage: "none", reason: `stand-up failed for ${targetDir}: ${db.output}`, limitations: verdict.limitations, notes: [], findings: [], producedEvidence: false };
  }

  let coverage = verdict.coverage;
  const limitations = [...verdict.limitations];
  const notes: string[] = [];
  for (const w of plan.seed.warnings) limitations.push(`seed: ${w}`);
  // #649 — every table the per-table SAVEPOINT seed skipped is disclosed as a limitation (fail-loud):
  // its cross-tenant isolation was NOT probed, so it can't read as a clean pass. The rest DID seed and
  // were probed — a partial isolation proof over the seeded surface, never zero.
  for (const s of db.seedSkips ?? []) {
    limitations.push(`seed: table "${s.table}" was SKIPPED — its INSERT violated ${s.constraint || "a constraint"} (${s.reason}); a generic two-tenant seed can't satisfy this table's bespoke invariant, so its cross-tenant isolation was NOT probed`);
  }
  if (db.seedSkips?.length) {
    const scopedSkipped = db.seedSkips.filter((s) => plan.seed.scopedTables.some((t) => t.toLowerCase() === s.table.toLowerCase())).length;
    notes.push(`seed: ${plan.seed.scopedTables.length - scopedSkipped}/${plan.seed.scopedTables.length} scoped table(s) seeded and probed; ${db.seedSkips.length} table(s) skipped-and-disclosed (per-table SAVEPOINT, #649)`);
  }

  if (coverage === "full") {
    const app = runner.runApp(appDir);
    if (!app.ok) {
      coverage = "postgrest-only";
      limitations.push(`the app failed to run (${app.output}) — degraded to PostgREST-only probing`);
    }
  }

  const pt = runner.pentest(appDir, coverage);
  if (!pt.ok) {
    return { standUp: false, coverage, reason: `pen-test failed against the local stack: ${pt.output}`, limitations, notes, findings: [], producedEvidence: false };
  }

  const findings = [...pt.findings];

  // #875 — every M2 run that actually probed ships the scope statement WITH its results: what was
  // stood up, from which schema at which commit, which surfaces/identities were exercised, and that
  // production configuration was not observed. Without it a clean matrix reads as a clean production.
  const scope = buildScopeLedger({
    targetDir,
    stack: "a Harvey-owned local Supabase stack (`supabase start`)",
    sources: [...plan.migrationDirs, ...plan.schemaFiles],
    revision: db.revision ?? null,
    coverage,
    rows: db.scopeRows ?? [],
    softDeleteProbed: db.softDeleteTables,
  });
  findings.push(scope.finding);
  limitations.push(...scope.limitations);

  // Bonus signal only (#514: the client's suite is never the mechanism). Counted as evidence ONLY
  // if it proved it exercised the DB; a skipped suite is disclosed, never trusted (#508).
  if (clientSuite?.present && runner.clientSuite) {
    const res = runner.clientSuite(appDir, clientSuite);
    const outcome = interpretClientSuiteRun(res.output);
    if (!outcome.exercised) {
      limitations.push(`client's own security suite (${clientSuite.detail}) was present but did not exercise the DB — ${outcome.reason}; not counted as M2 evidence (Harvey's own pentest.ts is the mechanism)`);
    } else if (!res.ok) {
      findings.push(clientSuiteFailureFinding(appDir, res.output));
      notes.push(`client's own security suite ran and FAILED — captured as an M2 finding (${outcome.reason})`);
    } else {
      notes.push(`client's own security suite ran and passed against the seeded stack (bonus signal: ${outcome.reason})`);
    }
  }

  return { standUp: true, coverage, reason: `dynamic validation ran (${coverage})`, limitations, notes, findings, producedEvidence: true };
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
  const r = probeOneProject({ targetDir, appDir: targetDir, layout, plan, runner, clientSuite });
  let artifactPath: string | null = null;
  if (r.producedEvidence) {
    const artifact = buildPassArtifact({
      module: "M2", target: targetDir, pass: "dynamic", generatedAt: now(),
      summary: r.artifactSummary ?? `dynamic validation (${r.coverage} coverage); ${r.findings.length} finding(s)`,
      findings: r.findings,
    });
    artifactPath = writePassArtifact(artifactsDir, artifact);
  }
  return { target: targetDir, standUp: r.standUp, coverage: r.coverage, reason: r.reason, limitations: r.limitations, notes: r.notes, artifactPath, findings: r.findings };
}

// ---- monorepo: stand up + probe EVERY Supabase project (#610) ---------------

// A single Supabase project inside a (possibly mono-) repo: its own migrations/schema, its own app
// dir, and a stable label for the per-DB coverage rows.
interface ProjectLayout {
  label: string; // path relative to the repo root, or the repo basename for a single-project target
  appDir: string; // the app root beside this project's supabase/ dir (the dir we build/boot + probe)
  layout: RepoLayout; // scoped to THIS project's migrations only — so its seed matches its applied schema
}

// Split a repo's layout into one entry per Supabase project. A monorepo (>1 migrations dir) yields one
// project per `apps/*/supabase/migrations`, each scoped to its OWN migrations so the derived seed
// matches the DB that is actually stood up (the concatenated-seed-vs-single-DB mismatch, #610). A
// single-project or schema-file target yields exactly one project covering the whole repo.
export function splitLayoutByProject(targetDir: string, layout: RepoLayout): ProjectLayout[] {
  if (layout.migrationDirs.length <= 1) {
    return [{ label: basename(targetDir) || targetDir, appDir: targetDir, layout }];
  }
  return layout.migrationDirs.map((dir) => {
    const appDir = join(dir, "..", ".."); // <app>/supabase/migrations → <app>
    return {
      label: relative(targetDir, appDir) || basename(appDir),
      appDir,
      layout: { migrationDirs: [dir], schemaFiles: [], scripts: layout.scripts, externalSeamDeps: layout.externalSeamDeps },
    };
  });
}

// Prefix a rolled-up finding with its DB label so two projects that emit the same finding id (e.g. each
// failing to provision → M2-PROVISION-MIGRATE) stay distinct and the location names which DB.
function tagFindingWithProject(f: Finding, label: string): Finding {
  const slug = label.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "db";
  return { ...f, id: `${f.id}-${slug}`, location: `${label}: ${f.location}` };
}

// Overall coverage across the per-DB rows: full only when EVERY project stood up at full coverage,
// none when NONE stood up, else the honest middle (postgrest-only) — never rounded up.
function rollUpCoverage(results: ProbeResult[]): Coverage {
  if (results.every((r) => !r.standUp)) return "none";
  if (results.every((r) => r.standUp && r.coverage === "full")) return "full";
  return "postgrest-only";
}

// Stand up and probe EVERY Supabase project in a (mono-)repo, one isolated stack at a time, and roll
// the per-DB outcomes into a single M2 deliverable (#610). Each project gets its own runner + teardown
// from `makeProject` (the CLI hands back a fresh createLiveStandUp per plan, on its own project-id/
// ports); a project that can't stand up is recorded as an honest per-DB partial, never dropped, and
// the others still run. One rolled-up M2.pass.json carries the union of findings so run-audit derives
// a single `ran` for the whole engagement. For a single-project repo this is exactly one project.
export function runMultiProjectDynamicValidation(opts: {
  targetDir: string;
  layout: RepoLayout;
  artifactsDir: string;
  now: () => string;
  makeProject: (project: ProjectLayout, plan: ProvisioningPlan) => { runner: StandUpRunner; clientSuite?: ClientSecuritySuite; stop: () => void };
}): DynamicValidationResult {
  const { targetDir, layout, artifactsDir, now, makeProject } = opts;
  const projects = splitLayoutByProject(targetDir, layout);

  const results: ProbeResult[] = [];
  const findings: Finding[] = [];
  const limitations: string[] = [];
  const notes: string[] = [];

  for (const project of projects) {
    const sql = readSchemaSql(project.layout);
    const plan = buildProvisioningPlan(project.layout, sql, project.appDir);
    const made = makeProject(project, plan);
    let r: ProbeResult;
    try {
      r = probeOneProject({ targetDir: project.appDir, appDir: project.appDir, layout: project.layout, plan, runner: made.runner, clientSuite: made.clientSuite });
    } finally {
      made.stop(); // tear this project's stack down before the next binds its ports
    }
    results.push(r);
    // Only tag/prefix in the multi-project case; a single-project repo keeps its findings verbatim.
    for (const f of r.findings) findings.push(projects.length > 1 ? tagFindingWithProject(f, project.label) : f);
    const prefix = projects.length > 1 ? `DB "${project.label}": ` : "";
    limitations.push(`${prefix}coverage=${r.coverage}${r.standUp ? "" : " (not stood up)"} — ${r.reason}`);
    for (const l of r.limitations) limitations.push(`${prefix}${l}`);
    for (const n of r.notes) notes.push(`${prefix}${n}`);
  }

  const producedEvidence = results.some((r) => r.producedEvidence);
  const coverage = rollUpCoverage(results);
  const standUp = results.some((r) => r.standUp);

  let artifactPath: string | null = null;
  if (producedEvidence) {
    const perDb = projects.map((p, i) => `${p.label}=${results[i]!.coverage}`).join(", ");
    const artifact = buildPassArtifact({
      module: "M2", target: targetDir, pass: "dynamic", generatedAt: now(),
      summary: projects.length > 1
        ? `dynamic validation across ${projects.length} Supabase project(s) [${perDb}]; ${findings.length} finding(s)`
        : `dynamic validation (${coverage} coverage); ${findings.length} finding(s)`,
      findings,
    });
    artifactPath = writePassArtifact(artifactsDir, artifact);
  }

  const reason = projects.length > 1
    ? `dynamic validation across ${projects.length} Supabase project(s): ${projects.map((p, i) => `${p.label} (${results[i]!.coverage})`).join(", ")}`
    : results[0]!.reason;
  return { target: targetDir, standUp, coverage, reason, limitations, notes, artifactPath, findings };
}
