import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkEdgeFunctionVerifyJwt, checkMigrationRlsStatic } from "./supabase-static.js";

describe("checkMigrationRlsStatic", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-rls-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  it("flags a public table that never gets ENABLE RLS", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.audit_logs (id uuid primary key);",
    });
    const findings = checkMigrationRlsStatic(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("public.audit_logs");
    expect(findings[0]!.precisionTier).toBe("high");
  });

  it("clears a table whose RLS is enabled in a LATER migration file", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.documents (id uuid primary key);",
      "0002_rls.sql": "alter table public.documents enable row level security;",
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("clears a service-only deny-all table (RLS enabled, zero policies)", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.service_state (id uuid primary key);",
      "0002_rls.sql": "alter table public.service_state enable row level security;",
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("ignores views (no RLS concept) and if-not-exists / only variants", () => {
    const dir = writeMigrations({
      "0001.sql": [
        "create view public.user_directory as select id from auth.users;",
        "create table if not exists public.reports (id uuid primary key);",
        "alter table only public.reports enable row level security;",
      ].join("\n"),
    });
    expect(checkMigrationRlsStatic(dir)).toEqual([]);
  });

  it("does not treat commented-out DDL as a real enable statement", () => {
    const dir = writeMigrations({
      "0001_schema.sql": "create table public.audit_logs (id uuid primary key);",
      "0002_rls.sql": '-- (Intentionally NO "alter table public.audit_logs enable row level security;")',
    });
    expect(checkMigrationRlsStatic(dir)).toHaveLength(1);
  });

  it("flags only the uncovered table when a migration set mixes both", () => {
    const dir = writeMigrations({
      "0001_schema.sql": [
        "create table public.notes (id uuid primary key);",
        "create table public.audit_logs (id uuid primary key);",
      ].join("\n"),
      "0002_rls.sql": "alter table public.notes enable row level security;",
    });
    const names = checkMigrationRlsStatic(dir).map((f) => f.title);
    expect(names).toHaveLength(1);
    expect(names[0]).toContain("audit_logs");
  });
});

describe("checkEdgeFunctionVerifyJwt", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeConfig(toml: string): string {
    root = mkdtempSync(join(tmpdir(), "harvey-verifyjwt-"));
    mkdirSync(join(root, "supabase"), { recursive: true });
    writeFileSync(join(root, "supabase", "config.toml"), toml);
    return root;
  }

  it("flags a [functions.X] section with verify_jwt = false", () => {
    const dir = writeConfig("[functions.admin-refund]\nverify_jwt = false\n");
    const findings = checkEdgeFunctionVerifyJwt(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("admin-refund");
    expect(findings[0]!.precisionTier).toBe("review");
  });

  it("clears verify_jwt = true and a bare verify_jwt = false outside any [functions.X] table", () => {
    const dir = writeConfig("[functions.user-profile]\nverify_jwt = true\n\n[auth]\nverify_jwt = false\n");
    expect(checkEdgeFunctionVerifyJwt(dir)).toEqual([]);
  });
});
