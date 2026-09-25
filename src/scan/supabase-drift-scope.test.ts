import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHtml } from "../../report-template/render.mjs";
import { esc } from "../../report-template/sections.mjs";
import type { FindingsDocument, ReportMeta } from "../findings.js";
import { runSupabaseScan } from "./supabase.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function fixture(failure?: "denied" | "query" | "foreign") {
  const dir = mkdtempSync(join(tmpdir(), "harvey-drift-scope-"));
  dirs.push(dir);
  writeFileSync(join(dir, "001.sql"), [
    "create table extensions.maintenance_heartbeats (\n id uuid\n);",
    "create table public.missing_table (\n id uuid\n);",
    "create table public.same_name (\n id uuid\n);",
    "create table extensions.same_name (\n id uuid\n);",
  ].join("\n"));
  const queries: string[] = [];
  const fetchImpl = vi.fn<typeof fetch>(async (url, init) => {
    const path = String(url);
    if (path.includes("/advisors/")) return Response.json({ lints: [] });
    if (path.endsWith("/config/auth")) return Response.json({});
    if (path.endsWith("/postgrest")) return Response.json({ db_schema: "public" });
    const { query, read_only } = JSON.parse(String(init?.body)) as { query: string; read_only: boolean };
    expect(read_only).toBe(true);
    queries.push(query);
    const schema = /(?:n\.nspname|schemaname) = '([^']+)'/.exec(query)?.[1];
    if (query.includes("catalogAccessible")) return Response.json([{ schema, catalogAccessible: !(schema === "extensions" && failure === "denied") }]);
    if (query.includes("extensionOwned")) {
      if (schema === "extensions" && failure === "query") return new Response("access denied", { status: 403 });
      const names = schema === "extensions" ? ["maintenance_heartbeats"] : ["same_name"];
      return Response.json(names.map((name) => ({ schema: failure === "foreign" ? "foreign" : schema, name, rlsEnabled: true, extensionOwned: false })));
    }
    if (query.includes("nspname = 'cron'")) return Response.json([{ exists: false }]);
    return Response.json([]);
  });
  return { dir, fetchImpl, queries };
}

describe("connected drift schema populations (#2129)", () => {
  it("delivers authorized scope through the real scan CLI and machine export", () => {
    const f = fixture();
    const loader = join(f.dir, "local-fetch.mjs");
    const out = join(f.dir, "findings.json");
    writeFileSync(loader, `
globalThis.fetch = async (url, init) => {
  if (url.includes('/advisors/')) return Response.json({ lints: [] });
  if (url.endsWith('/config/auth')) return Response.json({});
  if (url.endsWith('/postgrest')) return Response.json({ db_schema: 'public' });
  const { query, read_only } = JSON.parse(init.body);
  if (read_only !== true) throw new Error('Query lost read-only boundary');
  const schema = query.includes("= 'extensions'") ? 'extensions' : 'public';
  if (query.includes('catalogAccessible')) return Response.json([{ schema, catalogAccessible: true }]);
  if (query.includes('extensionOwned')) return Response.json([{ schema, name: schema === 'extensions' ? 'maintenance_heartbeats' : 'same_name', rlsEnabled: true, extensionOwned: false }]);
  if (query.includes("nspname = 'cron'")) return Response.json([{ exists: false }]);
  return Response.json([]);
};`);
    const root = fileURLToPath(new URL("../..", import.meta.url));
    const run = spawnSync(process.execPath, ["--import", loader, "--import", "tsx", "src/cli/scan.ts", "--supabase", "synthetic", "--migrations", f.dir, "--drift-schemas", "public,extensions", "--out", out], {
      cwd: root, encoding: "utf8", env: { ...process.env, SUPABASE_ACCESS_TOKEN: "synthetic-fixture-token" },
    });
    expect(run.status, run.stderr).toBe(0);
    const rows = JSON.parse(readFileSync(out, "utf8")) as { id: string; evidence: string }[];
    expect(rows.filter((row) => row.id.startsWith("SB-DRIFT-")).map((row) => row.id)).toEqual([
      "SB-DRIFT-00", "SB-DRIFT-TABLE-MISSING-public-missing_table", "SB-DRIFT-TABLE-MISSING-extensions-same_name",
    ]);
    expect(rows.find((row) => row.id === "SB-DRIFT-00")?.evidence).toContain("2/2 authorized schemas (public, extensions)");
  });

  it("folds bare uppercase schemas and keeps dollar-bearing authorized schemas in both populations", async () => {
    const f = fixture();
    writeFileSync(join(f.dir, "001.sql"), "CREATE TABLE PUBLIC.missing_table (\n id uuid\n);\nCREATE TABLE tenant$archive.maintenance_heartbeats (\n id uuid\n);");
    const fetchImpl = vi.fn<typeof fetch>(async (url, init) => {
      const path = String(url);
      if (path.includes("/advisors/")) return Response.json({ lints: [] });
      if (path.endsWith("/config/auth")) return Response.json({});
      if (path.endsWith("/postgrest")) return Response.json({ db_schema: "public" });
      const { query } = JSON.parse(String(init?.body)) as { query: string };
      const schema = query.includes("'tenant$archive'") ? "tenant$archive" : "public";
      if (query.includes("catalogAccessible")) return Response.json([{ schema, catalogAccessible: true }]);
      if (query.includes("extensionOwned")) return Response.json(schema === "public" ? [] : [{ schema, name: "maintenance_heartbeats", rlsEnabled: true, extensionOwned: false }]);
      if (query.includes("nspname = 'cron'")) return Response.json([{ exists: false }]);
      return Response.json([]);
    });
    const rows = await runSupabaseScan({ projectRef: "synthetic", managementApiToken: "fixture-token", fetchImpl, migrationsDir: f.dir, driftSchemas: ["public", "tenant$archive"] });
    expect(rows.filter(row => row.id.startsWith("SB-DRIFT-")).map(row => row.id)).toEqual(["SB-DRIFT-00", "SB-DRIFT-TABLE-MISSING-public-missing_table"]);
    expect(rows.find(row => row.id === "SB-DRIFT-00")?.evidence).toContain("1 live relations, 2 migration relations");
  });

  it("preserves quoted identities, dollar policy names and exact schema scope through CLI and HTML", () => {
    const f = fixture();
    writeFileSync(join(f.dir, "001.sql"), [
      'CREATE TABLE "PUBLIC".same_name (\n id uuid\n);',
      'ALTER TABLE "PUBLIC".same_name ENABLE ROW LEVEL SECURITY;',
      'CREATE TABLE public."Same_Name" (\n id uuid\n);',
      'CREATE TABLE tenant$archive.events (\n id uuid\n);',
      'CREATE POLICY READ$ALLOWED ON tenant$archive.events USING (true);',
      'CREATE POLICY "Case.Policy" ON tenant$archive.events USING (true);',
      'CREATE POLICY "case.policy" ON tenant$archive.events USING (true);',
      'DROP POLICY "case.policy" ON tenant$archive.events;',
      'CREATE TABLE public."a.b" (\n id uuid\n);',
      'CREATE TABLE public."a.c" (\n id uuid\n);',
      'CREATE TABLE public."a--b" (\n id uuid\n); -- real comment',
      'CREATE POLICY p ON policy_only.events USING (true);',
      'ALTER TABLE rls_only.events ENABLE ROW LEVEL SECURITY;',
      'CREATE TABLE public."escaped""name" (\n id uuid\n);',
    ].join("\n"));
    const loader = join(f.dir, "identity-fetch.mjs");
    const out = join(f.dir, "identity-findings.json");
    writeFileSync(loader, `
      globalThis.fetch = async (url, init) => {
        if (url.includes('/advisors/')) return Response.json({lints: []});
        if (url.endsWith('/config/auth')) return Response.json({});
        if (url.endsWith('/postgrest')) return Response.json({db_schema: 'public'});
        const {query} = JSON.parse(init.body);
        const schema = query.includes("'tenant$archive'") ? 'tenant$archive' : 'public';
        if (query.includes('catalogAccessible')) return Response.json([{schema, catalogAccessible: true}]);
        if (query.includes('extensionOwned')) return Response.json([{schema, name: schema === 'public' ? 'same_name' : 'events', rlsEnabled: false, extensionOwned: false}]);
        if (query.includes('policyname')) return Response.json(schema === 'public' ? [] : [{schema, table: 'events', name: 'read$allowed'}]);
        if (query.includes("nspname = 'cron'")) return Response.json([{exists: false}]);
        return Response.json([]);
      };
    `);
    const root = fileURLToPath(new URL("../..", import.meta.url));
    const run = spawnSync(process.execPath, ["--import", loader, "--import", "tsx", "src/cli/scan.ts", "--supabase", "synthetic", "--migrations", f.dir, "--drift-schemas", "public,tenant$archive", "--out", out], {
      cwd: root, encoding: "utf8", env: {...process.env, SUPABASE_ACCESS_TOKEN: "synthetic-fixture-token"},
    });
    expect(run.status, run.stderr).toBe(0);
    const findings = JSON.parse(readFileSync(out, "utf8")) as FindingsDocument["findings"];
    const drift = findings.filter(row => row.id.startsWith("SB-DRIFT-"));
    expect(drift.map(row => row.id)).toEqual([
      "SB-DRIFT-00", "SB-DRIFT-TABLE-UNMANAGED-public-same_name",
      "SB-DRIFT-TABLE-MISSING-public-Same_Name", "SB-DRIFT-TABLE-MISSING-public-a%2Eb",
      "SB-DRIFT-TABLE-MISSING-public-a%2Ec", "SB-DRIFT-TABLE-MISSING-public-a%2D%2Db",
      'SB-DRIFT-TABLE-MISSING-public-escaped"name',
      "SB-DRIFT-POLICY-MISSING-tenant$archive.events-Case%2EPolicy",
    ]);
    expect(drift[0]!.evidence).toContain("2 live relations, 6 migration relations");
    expect(drift[0]!.evidence).toContain("PUBLIC: not queried");
    expect(drift[0]!.evidence).toContain("policy_only: not queried");
    expect(drift[0]!.evidence).toContain("rls_only: not queried");
    expect(drift[0]!.evidence).toContain("UNASSESSED REFERENCED RELATIONS: 3");
    expect(drift[0]!.evidence).toContain("UNASSESSED RELATIONS: 1 migration-declared");
    const meta: ReportMeta = { client: "Synthetic", subtitle: "Scope", date: "2026-09-25", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase", headline: "Schema identities", scope: "Synthetic catalog", methodology: "M1", outOfScope: "Production rows" };
    const html = buildHtml({meta, findings});
    for (const row of drift) expect(html).toContain(esc(row.evidence));
  });

  it("defaults both sides to public and discloses unqueried migration schemas", async () => {
    const f = fixture();
    const findings = await runSupabaseScan({ projectRef: "synthetic", managementApiToken: "fixture-token", fetchImpl: f.fetchImpl, migrationsDir: f.dir });
    const drift = findings.filter((row) => row.id.startsWith("SB-DRIFT-"));
    expect(drift.map((row) => row.id)).toEqual(["SB-DRIFT-00", "SB-DRIFT-TABLE-MISSING-public-missing_table"]);
    expect(drift[0]?.evidence).toContain("extensions: not queried");
    expect(drift[0]?.evidence).toContain("EXAMINED: 1/1 authorized schemas (public); 1 live relations, 2 migration relations");
    expect(drift[0]?.evidence).toContain("Catalog queries completed 3/3");
    expect(f.queries.filter((q) => /catalogAccessible|extensionOwned|policyname/.test(q)).every((q) => !q.includes("'extensions'"))).toBe(true);
  });

  it("queries authorized non-public schemas and preserves schema-qualified identities through report output", async () => {
    const f = fixture();
    const findings = await runSupabaseScan({ projectRef: "synthetic", managementApiToken: "fixture-token", fetchImpl: f.fetchImpl, migrationsDir: f.dir, driftSchemas: ["public", "extensions"] });
    const drift = findings.filter((row) => row.id.startsWith("SB-DRIFT-"));
    expect(drift.map((row) => row.id)).toEqual(["SB-DRIFT-00", "SB-DRIFT-TABLE-MISSING-public-missing_table", "SB-DRIFT-TABLE-MISSING-extensions-same_name"]);
    expect(drift[0]?.evidence).toContain("EXAMINED: 2/2 authorized schemas (public, extensions); 2 live relations, 4 migration relations");
    expect(drift[0]?.evidence).toContain("Catalog queries completed 6/6");
    const meta: ReportMeta = { client: "Synthetic", subtitle: "Scope", date: "2026-09-25", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase", headline: "Schema comparison", scope: "Synthetic catalog", methodology: "M1", outOfScope: "Production rows" };
    const document = JSON.parse(JSON.stringify({ meta, findings })) as FindingsDocument;
    const html = buildHtml(document);
    expect(html).toContain(esc(drift[0]!.evidence));
    expect(html).toContain("public.missing_table");
    expect(html).not.toContain("maintenance_heartbeats is created by the migrations but is absent");
  });

  it.each(["denied", "query", "foreign"] as const)("discloses %s catalog access without alleging missing non-public tables", async (failure) => {
    const f = fixture(failure);
    const findings = await runSupabaseScan({ projectRef: "synthetic", managementApiToken: "fixture-token", fetchImpl: f.fetchImpl, migrationsDir: f.dir, driftSchemas: ["public", "extensions"] });
    const drift = findings.filter((row) => row.id.startsWith("SB-DRIFT-"));
    // A foreign response invalidates public too; otherwise independent public comparison survives.
    expect(drift.map((row) => row.id)).toEqual(failure === "foreign" ? ["SB-DRIFT-00"] : ["SB-DRIFT-00", "SB-DRIFT-TABLE-MISSING-public-missing_table"]);
    expect(drift[0]?.evidence).toContain("UNASSESSED SCHEMAS:");
    expect(drift[0]?.evidence).toContain("extensions:");
    expect(drift.some((row) => row.id.startsWith("SB-DRIFT-TABLE-MISSING-extensions"))).toBe(false);
  });

  it("rejects unsupported or injection-shaped schema names before any query", async () => {
    const f = fixture();
    await expect(runSupabaseScan({ projectRef: "synthetic", managementApiToken: "fixture-token", fetchImpl: f.fetchImpl, migrationsDir: f.dir, driftSchemas: ["public';select 1;--"] })).rejects.toThrow(/schema names/);
    expect(f.fetchImpl).not.toHaveBeenCalled();
  });
});
