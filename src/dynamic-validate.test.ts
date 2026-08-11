import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass } from "./audit-pass-artifact.js";
import type { RunContext } from "./audit-runner.js";
import {
  assessStandUpAbility,
  buildProvisioningPlan,
  detectClientSecuritySuite,
  discoverMigrationDirs,
  discoverSchemaFiles,
  interpretClientSuiteRun,
  type ClientSecuritySuite,
  type ProvisioningPlan,
  readRepoLayout,
  readSchemaSql,
  type RepoLayout,
  runDynamicValidation,
  runMultiProjectDynamicValidation,
  splitLayoutByProject,
  type StandUpRunner,
} from "./dynamic-validate.js";
import type { Finding } from "./findings.js";
import { driveAppBehaviorSuite } from "./pentest/live-standup.js";
import type { AppBehaviorProbed } from "./pentest/scope-ledger.js";

const layout = (over: Partial<RepoLayout> = {}): RepoLayout => ({
  migrationDirs: ["/repo/supabase/migrations"],
  schemaFiles: [],
  scripts: { dev: "next dev", build: "next build" },
  externalSeamDeps: [],
  ...over,
});

const MIGRATION_SQL = `
create table tenants (
  id uuid primary key,
  name text not null
);
create table documents (
  id uuid primary key,
  tenant_id uuid not null,
  body text
);
`;
const plan = (l: RepoLayout = layout()): ProvisioningPlan => buildProvisioningPlan(l, MIGRATION_SQL, "/repo");

describe("assessStandUpAbility (#450 — can we stand this up, and how fully?)", () => {
  it("is a hard no-go with no migrations — there is no RLS surface to probe", () => {
    const v = assessStandUpAbility(layout({ migrationDirs: [] }));
    expect(v.canStandUp).toBe(false);
    expect(v.coverage).toBe("none");
    expect(v.reason).toMatch(/no supabase\/migrations/);
  });

  it("is full coverage with migrations + a runnable app", () => {
    const v = assessStandUpAbility(layout());
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("full");
    expect(v.limitations).toEqual([]);
  });

  it("degrades to postgrest-only when the app can't be run — and SAYS so, never silently", () => {
    const v = assessStandUpAbility(layout({ scripts: {} }));
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("postgrest-only");
    expect(v.limitations.join(" ")).toMatch(/no dev\/build\/start script/);
  });

  it("discloses an external backend it can't stand up as a limitation, not a silent gap", () => {
    const v = assessStandUpAbility(layout({ externalSeamDeps: ["@pinecone-database/pinecone"] }));
    expect(v.canStandUp).toBe(true);
    expect(v.limitations.join(" ")).toMatch(/external backend/);
  });

  it("discloses multiple discovered Supabase projects as distinct backends (#508 monorepo)", () => {
    const v = assessStandUpAbility(layout({ migrationDirs: ["/repo/apps/main/supabase/migrations", "/repo/apps/rag/supabase/migrations"] }));
    expect(v.canStandUp).toBe(true);
    expect(v.limitations.join(" ")).toMatch(/2 separate Supabase projects/);
  });
});

// #508 acceptance: migration discovery must find nested apps/*/supabase/migrations, not only the
// (empty) top-level supabase/migrations that made ATC read NO-GO for the wrong reason.
describe("discoverMigrationDirs (#508 — monorepo nested migrations)", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-migdisc-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const withMigration = (rel: string): string => {
    const dir = join(root, rel, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "0001_init.sql"), "create table t (id uuid);\n");
    return dir;
  };

  it("finds apps/*/supabase/migrations that the old top-level-only check missed", () => {
    const main = withMigration("apps/main");
    const rag = withMigration("apps/rag");
    const found = discoverMigrationDirs(root);
    expect(found).toContain(main);
    expect(found).toContain(rag);
  });

  it("requires ≥1 .sql — an empty migrations dir is not a schema surface", () => {
    const empty = mkdtempSync(join(tmpdir(), "harvey-empty-"));
    mkdirSync(join(empty, "supabase", "migrations"), { recursive: true });
    expect(discoverMigrationDirs(empty)).toEqual([]);
    rmSync(empty, { recursive: true, force: true });
  });

  it("never descends into node_modules (a dep's own supabase/migrations is not the client's)", () => {
    const nm = join(root, "node_modules", "some-pkg", "supabase", "migrations");
    mkdirSync(nm, { recursive: true });
    writeFileSync(join(nm, "0001.sql"), "create table x (id uuid);\n");
    expect(discoverMigrationDirs(root)).not.toContain(nm);
  });
});

// #450 acceptance: the go/no-go decision is exercised against real fixture repo LAYOUTS on disk.
describe("readRepoLayout → assessStandUpAbility over fixture repo directories (#450/#508)", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-dynval-fixtures-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const fixture = (name: string, files: { migrations?: { rel?: string; files: string[] }; pkg?: object }): string => {
    const dir = join(root, name);
    mkdirSync(dir, { recursive: true });
    if (files.migrations) {
      const mig = join(dir, files.migrations.rel ?? "", "supabase", "migrations");
      mkdirSync(mig, { recursive: true });
      for (const f of files.migrations.files) writeFileSync(join(mig, f), "-- sql\n");
    }
    if (files.pkg) writeFileSync(join(dir, "package.json"), JSON.stringify(files.pkg));
    return dir;
  };

  it("stand-up-able fixture (top-level migrations + build script) reads as a full GO", () => {
    const dir = fixture("standupable", { migrations: { files: ["0001_init.sql"] }, pkg: { scripts: { build: "next build" } } });
    const v = assessStandUpAbility(readRepoLayout(dir));
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("full");
  });

  it("monorepo fixture (migrations only under apps/main) reads as a GO — #508 regression", () => {
    const dir = fixture("monorepo", { migrations: { rel: "apps/main", files: ["0001_init.sql"] }, pkg: { scripts: { build: "next build" } } });
    const l = readRepoLayout(dir);
    expect(l.migrationDirs.some((d) => d.includes(join("apps", "main")))).toBe(true);
    expect(assessStandUpAbility(l).canStandUp).toBe(true);
  });

  it("missing-migrations fixture is a hard NO-GO — nothing to probe", () => {
    const dir = fixture("no-migrations", { pkg: { scripts: { build: "next build" } } });
    const v = assessStandUpAbility(readRepoLayout(dir));
    expect(v.canStandUp).toBe(false);
    expect(v.coverage).toBe("none");
  });

  it("external-dep-blocked fixture stands up but discloses the seam it can't fake", () => {
    const dir = fixture("external-dep", {
      migrations: { files: ["0001_init.sql"] },
      pkg: { scripts: { build: "next build" }, dependencies: { "@pinecone-database/pinecone": "^1.0.0" } },
    });
    const l = readRepoLayout(dir);
    expect(l.externalSeamDeps).toContain("@pinecone-database/pinecone");
    expect(assessStandUpAbility(l).limitations.join(" ")).toMatch(/external backend/);
  });
});

// #508 part 2: a client's own security suite is only evidence if it PROVED it exercised the DB.
describe("interpretClientSuiteRun (#508 — a skipped suite is never evidence)", () => {
  it("counts a suite that executed tests as having exercised the DB", () => {
    const r = interpretClientSuiteRun("Tests  3 passed | 1 skipped (4)");
    expect(r.exercised).toBe(true);
  });

  it("a suite whose DB-backed tests all skipped did NOT exercise the DB (the ATC it.skip case)", () => {
    const r = interpretClientSuiteRun("Tests  2 skipped (2)");
    expect(r.exercised).toBe(false);
    expect(r.reason).toMatch(/skipped/);
  });

  it("failures still count as having exercised the DB (a failing isolation test IS a result)", () => {
    const r = interpretClientSuiteRun("Tests  1 failed | 2 passed (3)");
    expect(r.exercised).toBe(true);
  });

  it("no executed and none skipped is not confirmed evidence", () => {
    expect(interpretClientSuiteRun("no tests found").exercised).toBe(false);
  });
});

describe("detectClientSecuritySuite (#508 — presence only, the run is the operator's)", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-suite-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("finds a matching package.json script", () => {
    const dir = join(root, "with-script");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { "test:cross-tenant": "vitest run" } }));
    const s = detectClientSecuritySuite(dir);
    expect(s.present).toBe(true);
    expect(s.command).toContain("test:cross-tenant");
  });

  it("finds a tests/security directory when there is no matching script", () => {
    const dir = join(root, "with-dir");
    mkdirSync(join(dir, "tests", "security"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { build: "next build" } }));
    expect(detectClientSecuritySuite(dir).present).toBe(true);
  });

  it("reports absent when the client ships no such suite", () => {
    const dir = join(root, "none");
    mkdirSync(dir, { recursive: true });
    expect(detectClientSecuritySuite(dir).present).toBe(false);
  });
});

describe("buildProvisioningPlan (#514 — own stack, client migrations, generic seed, pentest)", () => {
  it("orders start → apply-migrations → seed → pentest and carries the seeded table surface", () => {
    const p = buildProvisioningPlan(layout(), MIGRATION_SQL, "/repo");
    expect(p.steps.map((s) => s.kind)).toEqual(["start", "apply-migrations", "seed", "pentest"]);
    expect(p.seed.scopedTables).toContain("documents");
    expect(p.tables).toContain("documents:tenant_id");
  });
});

const FINDING = { id: "M2-IDOR-1", title: "cross-tenant read", category: "security", taxonomy: "M2 — Tenant isolation", location: "orders/[id]", status: "open", evidence: "e", impact: "i", fix: "f" } as unknown as Finding;

// A fake runner: each step's success is configurable, so the orchestration's decisions are tested
// without Docker/supabase.
const runner = (over: Partial<StandUpRunner> = {}): StandUpRunner => ({
  standUpDb: () => ({ ok: true, output: "" }),
  runApp: () => ({ ok: true, output: "" }),
  pentest: () => ({ ok: true, findings: [FINDING], output: "" }),
  ...over,
});

// #875 — every probed run now also carries the M2 scope disclosure. The assertions below are about
// the PROBE findings, so the disclosure is filtered out of them and asserted on its own.
const probeFindings = (findings: Finding[]): Finding[] => findings.filter((f) => !f.id.startsWith("M2-SCOPE-RECONSTRUCTION"));

describe("runDynamicValidation (#450 orchestration + #448 emit + #508/#514)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-dynval-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const now = () => "2026-07-17T12:00:00.000Z";
  const run = (o: Partial<Parameters<typeof runDynamicValidation>[0]> = {}) =>
    runDynamicValidation({ targetDir: "/repo", layout: layout(), plan: plan(), artifactsDir: dir, now, runner: runner(), ...o });

  it("stands up, pen-tests, and writes an M2.pass.json carrying the findings", () => {
    const r = run();
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("full");
    expect(r.artifactPath).toBe(join(dir, "M2.pass.json"));
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(written.module).toBe("M2");
    expect(written.target).toBe("/repo");
    expect(probeFindings(written.findings)).toHaveLength(1);
  });

  // #875 — the deliverable must say it probed a RECONSTRUCTION, not the deployed system; an
  // undisclosed scope reads as a clean bill of health for production.
  it("carries the scope disclosure into the emitted artifact", () => {
    const r = run();
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8")) as { findings: Finding[] };
    const scope = written.findings.find((f) => f.id === "M2-SCOPE-RECONSTRUCTION");
    expect(scope, "M2 artifact must carry the scope disclosure").toBeDefined();
    expect(scope!.evidence).toContain("PRODUCTION CONFIGURATION WAS NOT OBSERVED");
    expect(scope!.evidence).toContain("/repo/supabase/migrations");
    expect(r.limitations.join("\n")).toMatch(/RECONSTRUCTION/);
  });

  it("a no-go target writes NO artifact and says why — never a silent clean ran", () => {
    const r = run({ layout: layout({ migrationDirs: [] }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/could not stand up.*no supabase\/migrations/);
  });

  it("a failed stand-up (env/operator gap) writes no artifact and reports the failure", () => {
    const r = run({ runner: runner({ standUpDb: () => ({ ok: false, output: "supabase start: port in use" }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/stand-up failed.*port in use/);
  });

  // #514: migrations that won't apply to a fresh stack are an M2 FINDING with evidence, not an
  // environment gap to swallow — so this path DOES emit an artifact carrying that finding.
  it("client migrations that fail to apply are recorded as an M2 finding, WITH an artifact", () => {
    const r = run({ runner: runner({ standUpDb: () => ({ ok: false, migrationApplyFailed: true, output: "ERROR: relation already exists" }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).not.toBeNull();
    expect(r.findings[0]?.id).toBe("M2-PROVISION-MIGRATE");
    expect(r.reason).toMatch(/failed to apply.*not skipped/);
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(written.findings[0].evidence).toMatch(/relation already exists/);
  });

  // #598: the client's migrations applied, but HARVEY'S OWN seed failed (e.g. a signup-trigger
  // dup-key). This is a harness/seed issue — it must NOT surface as an M2-PROVISION-MIGRATE client
  // finding, and it must fail loud with the real seed error, never a silent clean ran.
  it("a harness seed failure is a distinct status, not a client migration defect", () => {
    const r = run({ runner: runner({ standUpDb: () => ({ ok: false, seedApplyFailed: true, output: 'ERROR: duplicate key value violates unique constraint "profiles_pkey"' }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.findings).toHaveLength(0);
    expect(r.findings.map((f) => f.id)).not.toContain("M2-PROVISION-MIGRATE");
    expect(r.reason).toMatch(/harness\/seed issue, not a client migration defect/);
    expect(r.reason).toMatch(/profiles_pkey/);
  });

  it("degrades to postgrest-only when the app won't run, discloses it, and still emits", () => {
    const r = run({ runner: runner({ runApp: () => ({ ok: false, output: "build error" }) }) });
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("postgrest-only");
    expect(r.limitations.join(" ")).toMatch(/app failed to run/);
    expect(r.artifactPath).not.toBeNull();
  });

  it("a failed pen-test writes no artifact — no evidence, no ran", () => {
    const r = run({ runner: runner({ pentest: () => ({ ok: false, findings: [], output: "probe crashed" }) }) });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/pen-test failed/);
  });

  // #508: a client suite that SKIPPED is disclosed and never counted as evidence; one that ran and
  // FAILED becomes an M2 finding on top of Harvey's own pentest findings.
  const suite: ClientSecuritySuite = { present: true, command: ["npm", "run", "test:sec"], detail: 'script "test:sec"' };

  it("a skipped client suite is disclosed as a limitation, not counted as evidence", () => {
    const r = run({ clientSuite: suite, runner: runner({ clientSuite: () => ({ ok: true, output: "Tests  2 skipped (2)" }) }) });
    expect(r.limitations.join(" ")).toMatch(/did not exercise the DB/);
    expect(probeFindings(r.findings)).toHaveLength(1); // only Harvey's own finding
  });

  it("a client suite that ran and failed adds an M2 finding (real dynamic evidence)", () => {
    const r = run({ clientSuite: suite, runner: runner({ clientSuite: () => ({ ok: false, output: "Tests  1 failed | 3 passed (4)" }) }) });
    expect(r.findings.map((f) => f.id)).toContain("M2-CLIENT-SUITE");
    expect(r.notes.join(" ")).toMatch(/ran and FAILED/);
  });

  it("a client suite that ran and passed is a bonus note, not a finding", () => {
    const r = run({ clientSuite: suite, runner: runner({ clientSuite: () => ({ ok: true, output: "Tests  4 passed (4)" }) }) });
    expect(probeFindings(r.findings)).toHaveLength(1);
    expect(r.notes.join(" ")).toMatch(/passed against the seeded stack/);
  });

  it("surfaces seed warnings (no scoped tables ⇒ nothing to leak) as limitations", () => {
    const noScope = buildProvisioningPlan(layout(), "create table settings (\n  id uuid primary key,\n  k text\n);", "/repo");
    const r = run({ plan: noScope });
    expect(r.limitations.join(" ")).toMatch(/no scoped tables/);
  });

  // #450 acceptance: the emitted M2.pass.json must round-trip through findFreshPass → ran.
  it("the emitted M2.pass.json is read back by findFreshPass as fresh and derives ran", () => {
    const target = "/engagement/repo";
    const r = run({ targetDir: target });
    expect(r.artifactPath).not.toBeNull();

    const ctx: RunContext = {
      targetDir: target,
      env: { connected: false, dynamic: true, llm: false },
      exec: () => ({ ok: true, output: "" }),
      exists: (p) => existsSync(p),
      artifactsDir: dir,
      readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
      now: Date.parse(now()),
    };
    const pass = findFreshPass(ctx, "M2");
    expect(pass.fresh).toBe(true);
    if (pass.fresh) {
      expect(pass.artifact.pass).toBe("dynamic");
      expect(ranFromPass(pass.artifact, "dynamic pen-test").status).toBe("ran");
      expect(probeFindings(pass.artifact.findings ?? [])).toHaveLength(1);
    }
  });
});

describe("#574 — standalone root schema.sql discovery + stand-up ability", () => {
  const root = mkdtempSync(join(tmpdir(), "harvey-schemafile-"));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("discovers a root schema.sql that declares a table (no supabase/migrations)", () => {
    const dir = join(root, "vite-export");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "schema.sql"), "create table notes (id uuid primary key, owner_id uuid not null);");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { build: "vite build" } }));
    const { files } = discoverSchemaFiles(dir);
    expect(files).toEqual([join(dir, "schema.sql")]);
    const layout = readRepoLayout(dir);
    expect(layout.migrationDirs).toEqual([]);
    expect(layout.schemaFiles).toEqual([join(dir, "schema.sql")]);
  });

  it("stands up a schema-file target (GO) and applies it as the schema", () => {
    const layout: RepoLayout = { migrationDirs: [], schemaFiles: [join(root, "vite-export", "schema.sql")], scripts: { build: "vite build" }, externalSeamDeps: [] };
    const v = assessStandUpAbility(layout);
    expect(v.canStandUp).toBe(true);
    expect(v.limitations.join(" ")).toMatch(/standalone schema file/);
    expect(readSchemaSql(layout)).toContain("create table notes");
    const plan = buildProvisioningPlan(layout, readSchemaSql(layout), join(root, "vite-export"));
    expect(plan.schemaFiles).toHaveLength(1);
    expect(plan.projectRoot).toBe(join(root, "vite-export"));
    expect(plan.steps.find((s) => s.kind === "apply-migrations")?.detail).toMatch(/standalone schema file/);
  });

  it("a genuinely schema-less target is an honest NO-GO listing the probed locations", () => {
    const bare = join(root, "bare");
    mkdirSync(bare, { recursive: true });
    writeFileSync(join(bare, "package.json"), "{}");
    const v = assessStandUpAbility(readRepoLayout(bare));
    expect(v.canStandUp).toBe(false);
    expect(v.reason).toMatch(/Probed: supabase\/migrations/);
    expect(v.reason).toMatch(/schema\.sql/);
  });

  // #770: the shallow scan's shape (any *.sql, not "migrations"-named, not a seed file, declaring a
  // table) already covers these — reused by M10's schema-tier probe (src/audit-runners.ts) — but
  // neither exact real-world shape had a test naming it until the M10 gap surfaced them.
  it("discovers a root-level schema file under an unconventional name (launch-mvp shape)", () => {
    const dir = join(root, "launch-mvp-shape");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "initial_supabase_table_schema.sql"), "create table customers (id uuid primary key, email text);");
    const { files } = discoverSchemaFiles(dir);
    expect(files).toEqual([join(dir, "initial_supabase_table_schema.sql")]);
  });

  it("discovers a conventionally-NAMED schema.sql nested under a non-conventional directory (nocode-rescue shape)", () => {
    const dir = join(root, "nocode-rescue-shape");
    mkdirSync(join(dir, "before"), { recursive: true });
    writeFileSync(join(dir, "before", "schema.sql"), "create table applicants (id uuid primary key, customer_ssn text);");
    const { files } = discoverSchemaFiles(dir);
    expect(files).toEqual([join(dir, "before", "schema.sql")]);
  });
});

describe("splitLayoutByProject (#610 — one entry per Supabase project)", () => {
  it("a single-migration repo is one project covering the whole target", () => {
    const projects = splitLayoutByProject("/repo", layout());
    expect(projects).toHaveLength(1);
    expect(projects[0]!.appDir).toBe("/repo");
    expect(projects[0]!.layout.migrationDirs).toEqual(["/repo/supabase/migrations"]);
  });

  it("a monorepo yields one project per apps/*/supabase/migrations, each scoped to its own dir", () => {
    const mono = layout({ migrationDirs: ["/repo/apps/main/supabase/migrations", "/repo/apps/rag/supabase/migrations"] });
    const projects = splitLayoutByProject("/repo", mono);
    expect(projects.map((p) => p.label)).toEqual(["apps/main", "apps/rag"]);
    expect(projects.map((p) => p.appDir)).toEqual(["/repo/apps/main", "/repo/apps/rag"]);
    // each project's layout carries ONLY its own migrations — so its derived seed matches the DB
    // that is actually stood up (never the concatenation of every project's schema, #610).
    expect(projects[0]!.layout.migrationDirs).toEqual(["/repo/apps/main/supabase/migrations"]);
    expect(projects[1]!.layout.migrationDirs).toEqual(["/repo/apps/rag/supabase/migrations"]);
  });

  it("a schema-file target (no migrations dir) is a single project", () => {
    const projects = splitLayoutByProject("/repo", layout({ migrationDirs: [], schemaFiles: ["/repo/schema.sql"] }));
    expect(projects).toHaveLength(1);
    expect(projects[0]!.appDir).toBe("/repo");
  });
});

describe("runMultiProjectDynamicValidation (#610 — stand up + probe EVERY project)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-dynval-multi-"));
  // A real monorepo fixture on disk: each app ships its OWN supabase/migrations (the orchestrator
  // reads each project's SQL to derive its offline seed preview).
  const repo = mkdtempSync(join(tmpdir(), "harvey-monorepo-"));
  for (const app of ["main", "rag"]) {
    const mig = join(repo, "apps", app, "supabase", "migrations");
    mkdirSync(mig, { recursive: true });
    writeFileSync(join(mig, "0001_init.sql"), `create table tenants (id uuid primary key, name text not null);\ncreate table ${app}_docs (id uuid primary key, tenant_id uuid not null, body text);`);
  }
  afterAll(() => { rmSync(dir, { recursive: true, force: true }); rmSync(repo, { recursive: true, force: true }); });
  const now = () => "2026-07-21T12:00:00.000Z";
  const mono = layout({ migrationDirs: [join(repo, "apps/main/supabase/migrations"), join(repo, "apps/rag/supabase/migrations")] });

  it("stands up + probes BOTH DBs, tears each stack down, and rolls up per-DB coverage rows", () => {
    const stops: string[] = [];
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: mono, artifactsDir: dir, now,
      makeProject: (project) => ({ runner: runner(), stop: () => stops.push(project.label) }),
    });
    expect(stops).toEqual(["apps/main", "apps/rag"]); // every stack torn down
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("full");
    // one rolled-up artifact carrying BOTH DBs' findings, id-tagged so they don't collide
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(written.target).toBe(repo);
    expect(probeFindings(written.findings)).toHaveLength(2);
    expect(probeFindings(written.findings).map((f: Finding) => f.id).sort()).toEqual(["M2-IDOR-1-apps-main", "M2-IDOR-1-apps-rag"]);
    expect(written.summary).toMatch(/across 2 Supabase project\(s\)/);
    // per-DB rows, both named — never a single blended verdict
    expect(r.limitations.join("\n")).toMatch(/DB "apps\/main": coverage=full/);
    expect(r.limitations.join("\n")).toMatch(/DB "apps\/rag": coverage=full/);
  });

  it("an honest per-DB partial: one DB can't stand up, the other still probes and emits", () => {
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: mono, artifactsDir: dir, now,
      makeProject: (project) => ({
        runner: project.label === "apps/rag"
          ? runner({ standUpDb: () => ({ ok: false, output: "supabase start: docker not running" }) })
          : runner(),
        stop: () => undefined,
      }),
    });
    // the failed DB is disclosed by name (fail-loud), the healthy one still produced evidence
    expect(r.limitations.join("\n")).toMatch(/DB "apps\/rag":.*not stood up.*docker not running/);
    expect(r.coverage).toBe("postgrest-only"); // not rounded up to full — one DB was not probed
    expect(r.artifactPath).not.toBeNull();
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(probeFindings(written.findings)).toHaveLength(1); // only the DB that stood up
  });

  it("when NO project stands up, writes no artifact and says so per DB — never a silent clean ran", () => {
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: mono, artifactsDir: dir, now,
      makeProject: () => ({ runner: runner({ standUpDb: () => ({ ok: false, output: "docker not running" }) }), stop: () => undefined }),
    });
    expect(r.standUp).toBe(false);
    expect(r.coverage).toBe("none");
    expect(r.artifactPath).toBeNull();
  });

  it("a single-project target keeps its findings verbatim (no DB-label id suffix)", () => {
    const single = mkdtempSync(join(tmpdir(), "harvey-single-"));
    const mig = join(single, "supabase", "migrations");
    mkdirSync(mig, { recursive: true });
    writeFileSync(join(mig, "0001.sql"), "create table tenants (id uuid primary key);\ncreate table docs (id uuid primary key, tenant_id uuid not null);");
    const r = runMultiProjectDynamicValidation({
      targetDir: single, layout: layout({ migrationDirs: [mig] }), artifactsDir: dir, now,
      makeProject: () => ({ runner: runner(), stop: () => undefined }),
    });
    expect(probeFindings(r.findings).map((f) => f.id)).toEqual(["M2-IDOR-1"]);
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(written.summary).toMatch(/dynamic validation \(full coverage\)/);
    rmSync(single, { recursive: true, force: true });
  });
});

// #1280 — the seam, not the library. The reader and the ledger are unit-tested in their own files;
// what is unguarded without this is the WIRING (#1407's lesson: three round-trips proven at library
// level had their CLI wiring reverted and every test still passed). This asserts the connected
// pass's artifact reaches the M2 scope statement that ships in M2.pass.json.
describe("the connected drift pass reaches M2's scope statement (#1280)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-dynval-drift-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const now = () => "2026-07-17T12:00:00.000Z";

  const scopeOf = (findings: Finding[]): Finding => findings.find((f) => f.id === "M2-SCOPE-RECONSTRUCTION")!;

  it("says drift WAS observed on this engagement when a connected pass is recorded for it", () => {
    writeFileSync(
      join(dir, "M1.pass.json"),
      JSON.stringify({
        module: "M1",
        target: "/repo",
        pass: "connected",
        generatedAt: "2026-07-17T09:00:00.000Z",
        findings: [
          { id: "SB-DRIFT-00", evidence: "The deployed database was compared against the end state of 3 committed migration files." },
          { id: "SB-DRIFT-RLS-public-quotes", evidence: "rls off live" },
        ],
      }),
    );
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), plan: plan(), artifactsDir: dir, now, runner: runner() });
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(scopeOf(written.findings).evidence).toMatch(/PROD-VS-MIGRATION DRIFT WAS OBSERVED ON THIS ENGAGEMENT/);
    expect(scopeOf(written.findings).evidence).toMatch(/1 drift finding\(s\)/);
  });

  it("keeps the honest not-observed wording when no connected pass was recorded", () => {
    const clean = mkdtempSync(join(tmpdir(), "harvey-dynval-nodrift-"));
    const r = runDynamicValidation({ targetDir: "/repo", layout: layout(), plan: plan(), artifactsDir: clean, now, runner: runner() });
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(scopeOf(written.findings).evidence).not.toMatch(/WAS OBSERVED ON THIS ENGAGEMENT/);
    expect(scopeOf(written.findings).evidence).toMatch(/dashboard after the last committed migration/);
    rmSync(clean, { recursive: true, force: true });
  });

  // `runDynamicValidation` now has a production caller: `runMultiProjectDynamicValidation` uses it
  // for the single-project path. The multi-project path still calls `probeOneProject` directly, so
  // that separate wiring needs its own case: deleting `driftPass` there left the suite fully green
  // with the cases above alone (verified against feature/sweep-drift-1070 before this test existed).
  it("also reaches the scope statement through runMultiProjectDynamicValidation, the path the CLI actually calls", () => {
    const multiDir = mkdtempSync(join(tmpdir(), "harvey-dynval-drift-multi-artifacts-"));
    const repo = mkdtempSync(join(tmpdir(), "harvey-dynval-drift-multi-repo-"));
    const mig = join(repo, "supabase", "migrations");
    mkdirSync(mig, { recursive: true });
    writeFileSync(join(mig, "0001_init.sql"), "create table tenants (id uuid primary key, name text not null);\ncreate table docs (id uuid primary key, tenant_id uuid not null, body text);");
    writeFileSync(
      join(multiDir, "M1.pass.json"),
      JSON.stringify({
        module: "M1",
        target: repo,
        pass: "connected",
        generatedAt: "2026-07-17T09:00:00.000Z",
        findings: [
          { id: "SB-DRIFT-00", evidence: "The deployed database was compared against the end state of 1 committed migration file." },
          { id: "SB-DRIFT-RLS-public-docs", evidence: "rls off live" },
        ],
      }),
    );
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: layout({ migrationDirs: [mig] }), artifactsDir: multiDir, now,
      makeProject: () => ({ runner: runner(), stop: () => undefined }),
    });
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    expect(scopeOf(written.findings).evidence).toMatch(/PROD-VS-MIGRATION DRIFT WAS OBSERVED ON THIS ENGAGEMENT/);
    expect(scopeOf(written.findings).evidence).toMatch(/1 drift finding\(s\)/);
    rmSync(multiDir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });
});

// #1686 follow-up — the SAME shape as the drift seam above, for the app-behaviour ledger rows.
// Deleting `appBehaviorProbed: pt.appBehaviorProbed` from probeOneProject left 49 files / 771 tests
// green (MEASURED on this branch before this describe existed): the property is optional on the
// ledger input, so tsc accepts the omission and scope-ledger.test.ts only exercises the pure
// function. Without the wiring the three rows silently fall back to the not-invoked wording — a run
// that DID probe them reads exactly like one that never ran them.
describe("the stand-up's app-behaviour states reach M2's scope statement (#1686)", () => {
  const now = () => "2026-07-17T12:00:00.000Z";
  const scopeOf = (findings: Finding[]): Finding => findings.find((f) => f.id === "M2-SCOPE-RECONSTRUCTION")!;

  const runWithStates = (appBehaviorProbed: AppBehaviorProbed): Finding => {
    const artifacts = mkdtempSync(join(tmpdir(), "harvey-dynval-appbehavior-"));
    const repo = mkdtempSync(join(tmpdir(), "harvey-dynval-appbehavior-repo-"));
    const mig = join(repo, "supabase", "migrations");
    mkdirSync(mig, { recursive: true });
    writeFileSync(join(mig, "0001_init.sql"), "create table tenants (id uuid primary key, name text not null);\ncreate table docs (id uuid primary key, tenant_id uuid not null, body text);");
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: layout({ migrationDirs: [mig] }), artifactsDir: artifacts, now,
      makeProject: () => ({
        runner: runner({ pentest: () => ({ ok: true, findings: [FINDING], output: "", appBehaviorProbed }) }),
        stop: () => undefined,
      }),
    });
    const written = JSON.parse(readFileSync(r.artifactPath as string, "utf8"));
    rmSync(artifacts, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
    return scopeOf(written.findings);
  };

  it("flips the three rows to [probed] in the WRITTEN artifact when the stand-up probed them", () => {
    const scope = runWithStates({ concurrency: "probed", businessLogic: "probed", upload: "probed" });
    expect(scope.evidence).toMatch(/\[probed] concurrency \/ TOCTOU/);
    expect(scope.evidence).toMatch(/\[probed] business-logic abuse/);
    expect(scope.evidence).toMatch(/\[probed] file-upload validation/);
    // and it must NOT still be claiming the derivation was never invoked on this path
    expect(scope.evidence).not.toMatch(/never invokes it/);
  });

  it("carries a CRASHED suite through to the artifact rather than as an absent target", () => {
    const scope = runWithStates({ concurrency: "crashed", businessLogic: "derived-none", upload: "not-reached" });
    const line = (prefix: string): string => scope.evidence.split("\n").find((l) => l.includes(prefix))!;
    expect(line("race-toctou.ts")).toMatch(/subprocess FAILED before producing a verdict/);
    expect(line("business-logic.ts")).toMatch(/derived NO case/);
    expect(line("upload-attack.ts")).toMatch(/did not run because the app did not boot/);
  });
});

// #1686 follow-up — the producer→deliverable seam for the three app-behaviour suites. MEASURED
// against the executor's own delivered artifact (/tmp/m2-vsa2/M2.pass.json, 28 findings): only each
// suite's PROVEN probes were there, and BIZLOGIC-VALUE / BIZLOGIC-WORKFLOW / BIZLOGIC-AUTHZ /
// UPLOAD-SIZE-LIMIT / UPLOAD-STORED-XSS and the probed-and-cleared controls upload/safe,
// api-upload-safe, RACE-TOCTOU:api-checkout each occurred 0 times — a cleared control read exactly
// like one nobody ran. This drives the real suite reader over a real suite output file and asserts
// every one of them lands in the WRITTEN M2.pass.json.
describe("a suite's non-proven verdicts and cleared controls reach the written artifact (#1686)", () => {
  const now = () => "2026-07-17T12:00:00.000Z";

  it("carries requires-live-run classes and probed-clean controls all the way into M2.pass.json", () => {
    const suiteDir = mkdtempSync(join(tmpdir(), "harvey-suite-out-"));
    const out = join(suiteDir, "upload.json");
    // The shape pentest.ts --mode=upload-attack emits: proven probes in `findings`, EVERY probe's
    // verdict in `results`. The gap between the two is what used to be dropped.
    writeFileSync(out, JSON.stringify({
      mode: "upload-attack",
      findings: [FINDING],
      results: [
        { id: "UPLOAD-DISGUISED-TYPE:route-api-upload", status: "vulnerable", reason: "a PHP payload was accepted as image/png" },
        { id: "UPLOAD-SIZE-LIMIT", status: "requires-live-run", reason: "no target reported a size limit to test against" },
        { id: "UPLOAD-STORED-XSS", status: "requires-live-run", reason: "no served URL was returned, so re-service could not be checked" },
        { id: "UPLOAD-DISGUISED-TYPE:upload/safe", status: "not-vulnerable", reason: "the control route rejected the disguised type" },
        { id: "UPLOAD-PATH-TRAVERSAL:api-upload-safe", status: "not-vulnerable", reason: "the control route sanitized the filename to a basename" },
      ],
      coverage: { status: "partial", reason: "2/5 file-upload probe(s) need a live step" },
    }));
    const suite = driveAppBehaviorSuite({
      id: "M2-UPLOAD-COVERAGE", suite: "file-upload (upload-attack.ts, #635)",
      derivation: "3 upload target(s) derived", appUrl: "http://127.0.0.1:3000",
      run: { ok: true, output: "" }, out, derivedCases: 3,
    });
    expect(suite.state).toBe("probed");

    const artifacts = mkdtempSync(join(tmpdir(), "harvey-dynval-suite-artifacts-"));
    const repo = mkdtempSync(join(tmpdir(), "harvey-dynval-suite-repo-"));
    const mig = join(repo, "supabase", "migrations");
    mkdirSync(mig, { recursive: true });
    writeFileSync(join(mig, "0001_init.sql"), "create table tenants (id uuid primary key, name text not null);\ncreate table docs (id uuid primary key, tenant_id uuid not null, body text);");
    const r = runMultiProjectDynamicValidation({
      targetDir: repo, layout: layout({ migrationDirs: [mig] }), artifactsDir: artifacts, now,
      makeProject: () => ({
        runner: runner({ pentest: () => ({ ok: true, findings: suite.findings, output: "", appBehaviorProbed: { concurrency: "derived-none", businessLogic: "derived-none", upload: suite.state } }) }),
        stop: () => undefined,
      }),
    });
    const written = readFileSync(r.artifactPath as string, "utf8");
    // the two blocked classes, WITH their reasons — an unstated limit reads as a clean pass
    expect(written).toContain("UPLOAD-SIZE-LIMIT");
    expect(written).toContain("UPLOAD-STORED-XSS");
    expect(written).toContain("no served URL was returned");
    // and both negative controls, so probed-and-cleared is distinguishable from never-run
    expect(written).toContain("upload/safe");
    expect(written).toContain("api-upload-safe");
    rmSync(suiteDir, { recursive: true, force: true });
    rmSync(artifacts, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });
});
