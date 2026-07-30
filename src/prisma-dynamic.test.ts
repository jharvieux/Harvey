// #759 — the routed Prisma M2 decision logic: layout reading, migrate-command selection, stand-up
// assessment, and the orchestrator over an injected fake runner (no Docker). Proves the Prisma path
// records the RLS matrix not-applicable, emits a finding+artifact on a schema-apply failure, and
// never writes a clean-`ran` artifact for a DB that stood up but whose app never booted.

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { StandUpResult } from "./dynamic-validate.js";
import type { Finding } from "./findings.js";
import { detectOrm } from "./scan/framework-detect.js";
import {
  assessPrismaStandUp,
  hasCommittedMigrations,
  type PrismaLayout,
  type PrismaStandUpRunner,
  prismaCliMajor,
  prismaV7ApplyArgs,
  prismaV7ConfigSource,
  readPrismaLayout,
  RLS_NOT_APPLICABLE,
  runPrismaDynamicValidation,
  selectPrismaMigrateCommand,
  stripSchemaDatasourceUrl,
} from "./prisma-dynamic.js";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "prisma-dyn-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

// The CLI routes `dynamic-validate --execute` by detectOrm: prisma ⇒ this module's Postgres path,
// supabase/unknown ⇒ the unchanged Supabase migrations/PostgREST path. Proven here so the routing
// contract is a test, not a comment.
describe("ORM routing (the CLI branch key)", () => {
  it("a Prisma app routes to the Prisma path", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "@prisma/client": "5" } }));
    mkdirSync(join(dir, "prisma"), { recursive: true });
    writeFileSync(join(dir, "prisma/schema.prisma"), "datasource db { provider = \"postgresql\" }");
    expect(detectOrm(dir)).toBe("prisma");
  });
  it("a Supabase app stays on the Supabase path (RLS surface never suppressed)", () => {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "@supabase/supabase-js": "2" } }));
    expect(detectOrm(dir)).toBe("supabase");
  });
});

const migLayout = (over: Partial<PrismaLayout> = {}): PrismaLayout => ({
  schemaPath: join(dir, "prisma/schema.prisma"),
  migrationsDir: join(dir, "prisma/migrations"),
  scripts: { build: "next build", start: "next start" },
  ...over,
});

describe("readPrismaLayout", () => {
  it("finds prisma/schema.prisma, its migrations dir, and scripts", () => {
    mkdirSync(join(dir, "prisma/migrations/20230101_init"), { recursive: true });
    writeFileSync(join(dir, "prisma/schema.prisma"), "datasource db { provider = \"postgresql\" }");
    writeFileSync(join(dir, "prisma/migrations/20230101_init/migration.sql"), "CREATE TABLE t (id int);");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ scripts: { build: "next build" } }));
    const l = readPrismaLayout(dir);
    expect(l.schemaPath).toBe(join(dir, "prisma/schema.prisma"));
    expect(l.migrationsDir).toBe(join(dir, "prisma/migrations"));
    expect(l.scripts.build).toBe("next build");
  });

  it("returns migrationsDir=null when prisma/migrations has no migration.sql (db push target)", () => {
    mkdirSync(join(dir, "prisma"), { recursive: true });
    writeFileSync(join(dir, "prisma/schema.prisma"), "x");
    const l = readPrismaLayout(dir);
    expect(l.schemaPath).toBe(join(dir, "prisma/schema.prisma"));
    expect(l.migrationsDir).toBeNull();
  });

  it("returns schemaPath=null for a non-Prisma dir", () => {
    writeFileSync(join(dir, "package.json"), "{}");
    expect(readPrismaLayout(dir).schemaPath).toBeNull();
  });
});

describe("hasCommittedMigrations", () => {
  it("is true only when a child dir carries a migration.sql", () => {
    mkdirSync(join(dir, "m/20230101_init"), { recursive: true });
    expect(hasCommittedMigrations(join(dir, "m"))).toBe(false);
    writeFileSync(join(dir, "m/20230101_init/migration.sql"), "");
    expect(hasCommittedMigrations(join(dir, "m"))).toBe(true);
  });
  it("is false for a missing dir", () => {
    expect(hasCommittedMigrations(join(dir, "nope"))).toBe(false);
  });
});

describe("selectPrismaMigrateCommand", () => {
  it("uses `migrate deploy` when versioned migrations exist", () => {
    expect(selectPrismaMigrateCommand(migLayout())).toEqual(["migrate", "deploy"]);
  });
  it("falls back to `db push` when there are no committed migrations", () => {
    expect(selectPrismaMigrateCommand(migLayout({ migrationsDir: null }))).toEqual(["db", "push", "--skip-generate"]);
  });
});

// #1163 — Prisma 7 rejects `url = env()` in schema.prisma (P1012) and dropped --skip-generate. These
// pure helpers let the live stand-up apply a Prisma-5/6-style schema under a v7 CLI.
describe("prismaCliMajor", () => {
  it("parses the major version from `prisma --version` output", () => {
    expect(prismaCliMajor("prisma               : 7.9.0\n@prisma/client       : Not found\n")).toBe(7);
    expect(prismaCliMajor("prisma                  : 5.18.0")).toBe(5);
  });
  it("returns null when no prisma version line is present (⇒ pre-v7, unchanged path)", () => {
    expect(prismaCliMajor("no version here")).toBeNull();
  });
});

describe("stripSchemaDatasourceUrl", () => {
  it("removes the datasource url/directUrl assignment lines (the P1012 trigger) but keeps models", () => {
    const schema = [
      "datasource db {",
      '  provider = "postgresql"',
      '  url      = env("DATABASE_URL")',
      '  directUrl = env("DIRECT_URL")',
      "}",
      "model Team { id String @id url String }",
    ].join("\n");
    const out = stripSchemaDatasourceUrl(schema);
    expect(out).not.toMatch(/^\s*url\s*=/m);
    expect(out).not.toMatch(/^\s*directUrl\s*=/m);
    expect(out).toContain('provider = "postgresql"');
    expect(out).toContain("model Team { id String @id url String }"); // a model field named url survives (no `=`)
  });
});

describe("prismaV7ConfigSource + prismaV7ApplyArgs", () => {
  it("synthesizes a plain-object config that points the datasource at DATABASE_URL", () => {
    const src = prismaV7ConfigSource("/tmp/x/schema.prisma");
    expect(src).toContain('schema: "/tmp/x/schema.prisma"');
    expect(src).toContain("datasource: { url: process.env.DATABASE_URL }");
    expect(src).not.toContain("import"); // no prisma/config import — loads before the target's deps install
  });
  it("drops --skip-generate and points the CLI at the config", () => {
    expect(prismaV7ApplyArgs(["db", "push", "--skip-generate"], "/tmp/c.ts")).toEqual(["db", "push", "--config", "/tmp/c.ts"]);
    expect(prismaV7ApplyArgs(["migrate", "deploy"], "/tmp/c.ts")).toEqual(["migrate", "deploy", "--config", "/tmp/c.ts"]);
  });
});

describe("assessPrismaStandUp", () => {
  it("NO-GO with no schema.prisma", () => {
    const v = assessPrismaStandUp({ schemaPath: null, migrationsDir: null, scripts: {} });
    expect(v.canStandUp).toBe(false);
    expect(v.coverage).toBe("none");
  });
  it("full coverage + RLS-not-applicable disclosure when app is runnable", () => {
    const v = assessPrismaStandUp(migLayout());
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("full");
    expect(v.limitations).toContain(RLS_NOT_APPLICABLE);
  });
  it("coverage=none (not rounded up) when the app can't be booted — no PostgREST fallback", () => {
    const v = assessPrismaStandUp(migLayout({ scripts: {} }));
    expect(v.canStandUp).toBe(true);
    expect(v.coverage).toBe("none");
    expect(v.limitations).toContain(RLS_NOT_APPLICABLE);
    expect(v.limitations.some((l) => /no dev\/build\/start script/.test(l))).toBe(true);
  });
});

// ---- orchestrator over an injected fake runner (no Docker) ------------------

const okDb = (over: Partial<StandUpResult> = {}): StandUpResult => ({ ok: true, output: "stood up + seeded", ...over });

function fakeRunner(over: Partial<PrismaStandUpRunner> = {}): PrismaStandUpRunner {
  return {
    standUpDb: () => okDb(),
    runApp: () => ({ ok: true, output: "app booted" }),
    pentest: (coverage) => ({ ok: true, findings: [], output: `probed (coverage=${coverage})` }),
    ...over,
  };
}

const run = (runner: PrismaStandUpRunner, layout = migLayout()) =>
  runPrismaDynamicValidation({ targetDir: dir, layout, artifactsDir: join(dir, "artifacts"), now: () => "2026-07-23T00:00:00.000Z", runner });

describe("runPrismaDynamicValidation", () => {
  it("full path: boots app, probes routes, writes an M2 artifact recording RLS not-applicable", () => {
    const r = run(fakeRunner());
    expect(r.standUp).toBe(true);
    expect(r.coverage).toBe("full");
    expect(r.artifactPath).not.toBeNull();
    expect(existsSync(r.artifactPath!)).toBe(true);
    expect(r.limitations).toContain(RLS_NOT_APPLICABLE);
    const artifact = JSON.parse(readFileSync(r.artifactPath!, "utf8")) as { summary: string; module: string };
    expect(artifact.module).toBe("M2");
    expect(artifact.summary).toMatch(/RLS matrix not-applicable/);
  });

  it("passes 'full' coverage to pentest only after a successful app boot", () => {
    let seen: string | undefined;
    run(fakeRunner({ pentest: (coverage) => { seen = coverage; return { ok: true, findings: [], output: "" }; } }));
    expect(seen).toBe("full");
  });

  it("app-boot failure ⇒ coverage none, NO artifact (no PostgREST fallback to probe), honest limitation", () => {
    const r = run(fakeRunner({ runApp: () => ({ ok: false, output: "next build failed: missing env" }) }));
    expect(r.coverage).toBe("none");
    expect(r.artifactPath).toBeNull();
    expect(r.limitations.some((l) => /failed to boot/.test(l) && /no PostgREST/.test(l))).toBe(true);
  });

  it("schema-apply failure ⇒ M2-PRISMA-MIGRATE finding AND an artifact (a real M2 finding, not a skip)", () => {
    const r = run(fakeRunner({ standUpDb: () => okDb({ ok: false, migrationApplyFailed: true, output: "P3009 migrate failed" }) }));
    expect(r.findings.map((f) => f.id)).toContain("M2-PRISMA-MIGRATE");
    expect(r.artifactPath).not.toBeNull();
  });

  it("seed-apply failure ⇒ honest requires-live-run, NO artifact, NO client finding (harness issue)", () => {
    const r = run(fakeRunner({ standUpDb: () => okDb({ ok: false, seedApplyFailed: true, output: "seed insert violated x" }) }));
    expect(r.findings).toHaveLength(0);
    expect(r.artifactPath).toBeNull();
    expect(r.reason).toMatch(/harness\/seed issue/);
  });

  it("NO-GO layout ⇒ no artifact, canStandUp reason surfaced", () => {
    const r = run(fakeRunner(), { schemaPath: null, migrationsDir: null, scripts: {} });
    expect(r.standUp).toBe(false);
    expect(r.artifactPath).toBeNull();
  });

  it("proven app-route findings flow into the artifact", () => {
    const finding = { id: "M2-APP-IDOR-OBJECT", title: "x", severity: "High" } as unknown as Finding;
    const r = run(fakeRunner({ pentest: () => ({ ok: true, findings: [finding], output: "1 proven" }) }));
    expect(r.findings.map((f) => f.id)).toContain("M2-APP-IDOR-OBJECT");
    expect(r.artifactPath).not.toBeNull();
  });

  // #1280 — the Prisma path builds the same M2 scope statement, so it reads the same engagement
  // evidence. Without this, deleting its one-line wiring leaves the whole suite green.
  it("reads the engagement's connected pass into its scope statement", () => {
    const artifacts = join(dir, "artifacts");
    mkdirSync(artifacts, { recursive: true });
    writeFileSync(
      join(artifacts, "M1.pass.json"),
      JSON.stringify({
        module: "M1", target: dir, pass: "connected", generatedAt: "2026-07-22T00:00:00.000Z",
        findings: [{ id: "SB-DRIFT-00", evidence: "The deployed database was compared against the end state of 2 committed migration files." }],
      }),
    );
    const r = run(fakeRunner());
    const scope = r.findings.find((f) => f.id === "M2-SCOPE-RECONSTRUCTION")!;
    expect(scope.evidence).toMatch(/PROD-VS-MIGRATION DRIFT WAS OBSERVED ON THIS ENGAGEMENT/);
  });
});
