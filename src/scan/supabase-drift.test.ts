import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkMigrationDrift, expectedRlsEnabled, loadMigrations, readDriftPassEvidence, type DriftLivePolicy, type DriftLiveTable } from "./supabase-drift.js";

const table = (name: string, rlsEnabled: boolean, extensionOwned = false): DriftLiveTable => ({ schema: "public", name, rlsEnabled, extensionOwned });
const policy = (table: string, name: string): DriftLivePolicy => ({ schema: "public", table, name });
const migration = (sql: string, file = "20260101000000_init.sql") => [{ file, sql }];

// The shape the detector exists for: the migrations protect the table, the deployed database does not.
const PROTECTED = `
create table quotes (
  id uuid primary key,
  tenant_id uuid not null
);
alter table quotes enable row level security;
create policy "tenant reads own quotes" on quotes for select using (tenant_id = auth.uid());
`;

const ids = (fs: { id: string }[]): string[] => fs.map((f) => f.id);

describe("checkMigrationDrift", () => {
  it("flags a table the migrations protect and the deployed database does not", () => {
    const findings = checkMigrationDrift([table("quotes", false)], [policy("quotes", "tenant reads own quotes")], migration(PROTECTED));
    const rls = findings.find((f) => f.id === "SB-DRIFT-RLS-public-quotes");
    expect(rls).toBeDefined();
    expect(rls!.severity).toBe("Critical");
    // Each half's source is named in the evidence — that is what makes the row actionable.
    expect(rls!.evidence).toMatch(/committed migrations end with row-level security ENABLED/i);
    expect(rls!.evidence).toMatch(/deployed database reports row-level security DISABLED/i);
  });

  it("stays silent when the deployed database matches the migrations", () => {
    const findings = checkMigrationDrift([table("quotes", true)], [policy("quotes", "tenant reads own quotes")], migration(PROTECTED));
    expect(ids(findings)).toEqual(["SB-DRIFT-00"]);
  });

  // The FP that would make this detector unusable: a migration that turns RLS on and a later one
  // that turns it back off leaves the table legitimately open. Reporting that as drift flags the
  // repo's own stated intent.
  it("does not flag RLS a later migration deliberately disabled", () => {
    const migrations = [
      { file: "1_on.sql", sql: "create table quotes (\n  id uuid\n);\nalter table quotes enable row level security;" },
      { file: "2_off.sql", sql: "alter table quotes disable row level security;" },
    ];
    const findings = checkMigrationDrift([table("quotes", false)], [], migrations);
    expect(findings.filter((f) => f.id.startsWith("SB-DRIFT-RLS"))).toEqual([]);
  });

  it("flags a policy the migrations create and the deployed database is missing", () => {
    const findings = checkMigrationDrift([table("quotes", true)], [], migration(PROTECTED));
    const missing = findings.find((f) => f.id.startsWith("SB-DRIFT-POLICY-MISSING"));
    expect(missing).toBeDefined();
    expect(missing!.severity).toBe("High");
    expect(missing!.title).toContain("tenant reads own quotes");
  });

  it("flags a policy on the deployed database that no migration creates", () => {
    const findings = checkMigrationDrift(
      [table("quotes", true)],
      [policy("quotes", "tenant reads own quotes"), policy("quotes", "temp debug allow all")],
      migration(PROTECTED),
    );
    const unmanaged = findings.filter((f) => f.id.startsWith("SB-DRIFT-POLICY-UNMANAGED"));
    expect(unmanaged).toHaveLength(1);
    expect(unmanaged[0]!.title).toContain("temp debug allow all");
  });

  // A policy the migration parser could not READ is still a policy the migrations create. Counting
  // only the parsed set would report every unreadable-but-present policy as hand-added.
  it("does not report an unparseable migration policy as one added by hand", () => {
    const unreadable = `
create table quotes (
  id uuid
);
alter table quotes enable row level security;
create policy "half written" on quotes for select using ((tenant_id = auth.uid()
`;
    const findings = checkMigrationDrift([table("quotes", true)], [policy("quotes", "half written")], migration(unreadable));
    expect(findings.filter((f) => f.id.startsWith("SB-DRIFT-POLICY-UNMANAGED"))).toEqual([]);
  });

  it("flags a deployed table no migration creates, but not one an extension owns", () => {
    const findings = checkMigrationDrift(
      [table("quotes", true), table("scratch_notes", false), table("spatial_ref_sys", false, true)],
      [policy("quotes", "tenant reads own quotes")],
      migration(PROTECTED),
    );
    const unmanaged = findings.filter((f) => f.id.startsWith("SB-DRIFT-TABLE-UNMANAGED"));
    expect(ids(unmanaged)).toEqual(["SB-DRIFT-TABLE-UNMANAGED-public-scratch_notes"]);
  });

  // The shared CREATE_TABLE regex needs the column body to end with `);` on its own line, so a
  // single-line create is invisible to it. Accusing a client of hand-creating a table that is
  // written plainly in their own migration file is the worst output this detector could produce.
  it("does not call a table unmanaged when its CREATE is written on one line", () => {
    const oneLine = "create table quotes (id uuid primary key, tenant_id uuid);\nalter table quotes enable row level security;";
    const findings = checkMigrationDrift([table("quotes", true)], [], migration(oneLine));
    expect(findings.filter((f) => f.id.startsWith("SB-DRIFT-TABLE-UNMANAGED"))).toEqual([]);
  });

  it("flags a migration-created table absent from the deployed database", () => {
    const findings = checkMigrationDrift([], [], migration(PROTECTED));
    expect(ids(findings)).toContain("SB-DRIFT-TABLE-MISSING-public-quotes");
  });

  // A missing table already explains why all of its policies are missing; a row per policy on top
  // would bury the one finding that accounts for them.
  it("does not add a missing-policy row for a table that is itself missing", () => {
    const findings = checkMigrationDrift([], [], migration(PROTECTED));
    expect(findings.filter((f) => f.id.startsWith("SB-DRIFT-POLICY-MISSING"))).toEqual([]);
  });

  describe("SB-DRIFT-00", () => {
    it("is emitted exactly once on every run, drifted or clean", () => {
      const clean = checkMigrationDrift([table("quotes", true)], [policy("quotes", "tenant reads own quotes")], migration(PROTECTED));
      const drifted = checkMigrationDrift([table("quotes", false)], [], migration(PROTECTED));
      const notRun = checkMigrationDrift([], [], []);
      for (const set of [clean, drifted, notRun]) {
        expect(set.filter((f) => f.id === "SB-DRIFT-00")).toHaveLength(1);
      }
    });

    it("names the classes it did NOT compare, so their absence is not read as a match", () => {
      const row = checkMigrationDrift([table("quotes", true)], [], migration(PROTECTED)).find((f) => f.id === "SB-DRIFT-00")!;
      // Policy bodies are the bound that matters most — a USING clause edited in the dashboard under
      // an unchanged name is invisible here, and the row has to say so.
      expect(row.evidence).toMatch(/NOT COMPARED/);
      expect(row.evidence).toMatch(/BODIES of policies/i);
      expect(row.impact).toMatch(/USING clause was edited in the dashboard is NOT detected/i);
      for (const cls of ["column definitions", "indexes", "triggers", "grants"]) expect(row.evidence).toContain(cls);
    });

    it("reports not-assessed, with the caller's reason, when there is no migration history", () => {
      const row = checkMigrationDrift([table("quotes", false)], [], [], "No migrations directory was supplied to this scan.")
        .find((f) => f.id === "SB-DRIFT-00")!;
      expect(row.title).toMatch(/NOT assessed/);
      expect(row.evidence).toContain("No migrations directory was supplied to this scan.");
      expect(row.impact).toMatch(/never asked — not that the deployed database matches/);
    });

    it("emits no drift findings at all when it could not run", () => {
      const findings = checkMigrationDrift([table("quotes", false)], [policy("quotes", "whatever")], []);
      expect(ids(findings)).toEqual(["SB-DRIFT-00"]);
    });
  });
});

describe("expectedRlsEnabled", () => {
  it("reads the last toggle per table, across files", () => {
    const migrations = [
      { file: "1.sql", sql: "alter table a enable row level security; alter table b enable row level security;" },
      { file: "2.sql", sql: "alter table b disable row level security;" },
      { file: "3.sql", sql: "alter table public.c enable row level security;" },
    ];
    expect([...expectedRlsEnabled(migrations)].sort()).toEqual(["public.a", "public.c"]);
  });
});

describe("loadMigrations", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const scratch = (): string => {
    const d = mkdtempSync(join(tmpdir(), "harvey-drift-"));
    dirs.push(d);
    return d;
  };

  it("reads .sql files in filename order from the directory itself", () => {
    const d = scratch();
    writeFileSync(join(d, "20260102_b.sql"), "select 2;");
    writeFileSync(join(d, "20260101_a.sql"), "select 1;");
    writeFileSync(join(d, "README.md"), "not sql");
    expect(loadMigrations(d).map((m) => m.file)).toEqual(["20260101_a.sql", "20260102_b.sql"]);
  });

  it("falls back to supabase/migrations when handed the repo root", () => {
    const d = scratch();
    mkdirSync(join(d, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(d, "supabase", "migrations", "1.sql"), "select 1;");
    expect(loadMigrations(d).map((m) => m.file)).toEqual(["1.sql"]);
  });

  it("returns nothing for a path that does not exist", () => {
    expect(loadMigrations(join(tmpdir(), "harvey-drift-does-not-exist"))).toEqual([]);
  });
});

// #1280 — M2's scope statement can only say drift WAS observed on an engagement if something proves
// it. The proof is the connected pass's own recorded artifact, not a flag: these assert the reader
// distinguishes "compared", "recorded but did not compare", "rejected" and "never recorded".
describe("readDriftPassEvidence", () => {
  const NOW = Date.parse("2026-07-30T12:00:00.000Z");
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const artifactsWith = (artifact: unknown): string => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-drift-pass-"));
    dirs.push(dir);
    writeFileSync(join(dir, "M1.pass.json"), JSON.stringify(artifact));
    return dir;
  };

  const pass = (findings: unknown[], over: Record<string, unknown> = {}) => ({
    module: "M1",
    target: "/repo",
    pass: "connected",
    generatedAt: "2026-07-30T11:00:00.000Z",
    findings,
    ...over,
  });

  it("reports OBSERVED with the drift-row count when the connected pass compared", () => {
    const dir = artifactsWith(
      pass([
        ...checkMigrationDrift([table("quotes", false)], [], migration(PROTECTED)),
        { id: "SB-RLS-01", evidence: "unrelated connected-tier row" },
      ]),
    );
    const ev = readDriftPassEvidence(dir, "/repo", NOW);
    expect(ev).toEqual({ observed: true, generatedAt: "2026-07-30T11:00:00.000Z", driftFindings: 2 });
  });

  it("reports NOT observed, with the reason, when the pass ran but made no comparison", () => {
    const dir = artifactsWith(pass(checkMigrationDrift([], [], [])));
    const ev = readDriftPassEvidence(dir, "/repo", NOW);
    expect(ev).toMatchObject({ observed: false });
    expect((ev as { reason: string }).reason).toMatch(/drift comparison did not run/);
  });

  it("carries the rejection reason rather than dropping a wrong-target artifact", () => {
    const dir = artifactsWith(pass(checkMigrationDrift([table("quotes", false)], [], migration(PROTECTED)), { target: "/some-other-repo" }));
    const ev = readDriftPassEvidence(dir, "/repo", NOW);
    expect(ev).toMatchObject({ observed: false });
    expect((ev as { reason: string }).reason).toMatch(/not evidence THIS target's M1 ran/);
  });

  it("carries the rejection reason for a stale artifact", () => {
    const dir = artifactsWith(pass(checkMigrationDrift([table("quotes", false)], [], migration(PROTECTED)), { generatedAt: "2026-01-01T00:00:00.000Z" }));
    expect((readDriftPassEvidence(dir, "/repo", NOW) as { reason: string }).reason).toMatch(/stale/);
  });

  it("is silent — not a rejection — for an M1 pass that is not a connected one, and for no artifact at all", () => {
    const semantic = artifactsWith(pass([{ id: "M1-SEM-01", evidence: "a semantic triage row" }]));
    expect(readDriftPassEvidence(semantic, "/repo", NOW)).toBeUndefined();
    const empty = mkdtempSync(join(tmpdir(), "harvey-drift-pass-"));
    dirs.push(empty);
    expect(readDriftPassEvidence(empty, "/repo", NOW)).toBeUndefined();
  });
});
