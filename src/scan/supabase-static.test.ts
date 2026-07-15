import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkEdgeFunctionVerifyJwt, checkMigrationPolicySemantics, checkMigrationRlsStatic } from "./supabase-static.js";

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

// #220 — the source-tier semantic policy review. Fixtures are modelled on the two REAL Criticals
// from the 2026-07-12 public sweep (both plain `create policy` text in committed migrations) and
// their benign lookalikes, per the #61 positive/negative-pair discipline.
describe("checkMigrationPolicySemantics", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function writeMigrations(files: Record<string, string>): string {
    root = mkdtempSync(join(tmpdir(), "harvey-policy-"));
    const dir = join(root, "supabase", "migrations");
    mkdirSync(dir, { recursive: true });
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return root;
  }

  const schema = "create table public.memberships (id uuid primary key, tenant_id uuid not null, user_id uuid not null);";

  it("flags an INSERT policy that checks the caller but never the tenant column (the self-join Critical)", () => {
    // supabase-multi-tenant-starter …_rls_policies.sql:92-97 — WITH CHECK keys on auth.uid()
    // alone, so a member can insert a membership row into any tenant.
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy memberships_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    const findings = checkMigrationPolicySemantics(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("tenant key");
    expect(findings[0]!.category).toBe("Multi-tenant security");
  });

  it("flags an UPDATE policy whose WITH CHECK drops the tenant constraint (the unscoped-invite Critical)", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_update on public.memberships for update using (tenant_id = current_tenant()) with check (true);",
    });
    expect(checkMigrationPolicySemantics(dir)[0]!.evidence).toContain("WITH CHECK");
  });

  it("clears a correctly tenant-scoped policy — the benign lookalike", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_all on public.memberships for all using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid) with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);",
    });
    expect(checkMigrationPolicySemantics(dir)).toEqual([]);
  });

  it("locates the finding at its migration file:line — the address a source-tier reader can act on", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "-- header\ncreate policy m_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    expect(checkMigrationPolicySemantics(dir)[0]!.location).toContain("supabase/migrations/0002.sql:2");
  });

  it("stays at review tier — static shape is an indicator, never a graded verdict (#227)", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_insert on public.memberships for insert with check (user_id = auth.uid());",
    });
    expect(checkMigrationPolicySemantics(dir).every((f) => f.precisionTier === "review")).toBe(true);
  });

  it("reviews a per-user app in per-user mode rather than inventing a tenant key (the #206 FP)", () => {
    // No tenant column in the schema: id = auth.uid() is correct owner isolation here, and must
    // not be flagged for failing to reference a tenant key the app doesn't have.
    const dir = writeMigrations({
      "0001.sql": "create table public.profiles (id uuid primary key, email text);",
      "0002.sql": "create policy p_select on public.profiles for select using (id = auth.uid());",
    });
    expect(checkMigrationPolicySemantics(dir)).toEqual([]);
  });

  it("reports a policy it could not parse rather than passing over it in silence", () => {
    const dir = writeMigrations({
      "0001.sql": schema,
      "0002.sql": "create policy m_broken on public.memberships for select using (tenant_id = current_tenant()",
    });
    const findings = checkMigrationPolicySemantics(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toContain("could not be read");
    expect(findings[0]!.evidence).toContain("not assessed");
  });

  it("returns nothing for a target with no migrations at all", () => {
    root = mkdtempSync(join(tmpdir(), "harvey-policy-"));
    expect(checkMigrationPolicySemantics(root)).toEqual([]);
  });
});
