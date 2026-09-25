import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildHtml } from "../../report-template/render.mjs";
import { renderFidelityBreaches } from "../render-fidelity.js";
import { conservationLedger } from "../conservation-ledger.js";
import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding, FindingsDocument, ReportMeta } from "../findings.js";
import { runSupabaseScan } from "./supabase.js";
import { loadEffectiveAuthorization } from "./supabase-authorization.js";

const fixtureUrl = new URL("./__fixtures__/supabase/effective-authorization.sql", import.meta.url);
const snapshotUrl = new URL("./__fixtures__/supabase/effective-authorization-catalog.json", import.meta.url);
const exec = promisify(execFile);
const META: ReportMeta = { client: "Authorization fixture", subtitle: "Disposable PostgreSQL", date: "2026-09-25", commit: "fixture", auditor: "Harvey", confidential: false, overallHealth: 6, tenantIsolation: "Review", authModel: "PostgreSQL roles and RLS", headline: "Effective authorization", scope: "Synthetic local database", methodology: "Read-only catalog plus role controls", outOfScope: "Live clients" };

function hosted(query: (text: string) => Promise<unknown>, schemas: string | null = "public,future") {
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const path = String(url);
    if (path.endsWith("/database/query")) {
      const body = JSON.parse(String(init?.body)) as { query: string; read_only: boolean };
      expect(body.read_only).toBe(true);
      return new Response(JSON.stringify(await query(body.query)), { status: 201 });
    }
    if (path.endsWith("/advisors/security")) return new Response('{"lints":[]}');
    if (path.endsWith("/config/auth")) return new Response("{}");
    if (path.endsWith("/postgrest")) return new Response(JSON.stringify(schemas === null ? {} : { db_schema: schemas }));
    throw new Error("Unexpected external request in authorization fixture");
  }) as typeof fetch;
  return runSupabaseScan({ projectRef: "fixture", managementApiToken: "synthetic-fixture", fetchImpl });
}

async function replay(change?: (snapshot: Record<string, unknown>) => void, schemas: string | null = "public,future"): Promise<Finding[]> {
  const recorded = JSON.parse(readFileSync(snapshotUrl, "utf8")) as { fixtureSqlSha256: string; authorization: Record<string, unknown> };
  expect(recorded.fixtureSqlSha256).toBe(createHash("sha256").update(readFileSync(fixtureUrl)).digest("hex"));
  const snapshot = recorded.authorization;
  change?.(snapshot);
  return hosted(async (query) => query.includes("harvey-effective-authorization-v1") ? [{ authorization: snapshot }] : [], schemas);
}

describe("effective database authorization through the connected producer (#2138)", () => {
  it("asserts only current client read paths with grants, schema usage and unrestricted rows", async () => {
    const findings = await replay();
    expect(findings.filter((f) => f.severity === "High").map((f) => f.location).sort()).toEqual([
      "future.default_open", "public.column_open", "public.disabled", "public.inherited", "public.owner_unforced", "public.policy_other_role", "public.public_grant",
    ]);
    const denied = findings.find((f) => f.id === "SB-AUTHZ-public-deny_all")!;
    expect(denied).toMatchObject({ severity: "Info", precisionTier: "review" });
    expect(denied.evidence).toContain("anon: SELECT=none");
    expect(denied.evidence).toContain("RLS deny-by-default");
    expect(denied.evidence).toContain("service_role: SELECT=all");
  });

  it("returns exact selected-client column reads without borrowing a sibling grant", async () => {
    const snapshot = JSON.parse(readFileSync(snapshotUrl, "utf8")).authorization;
    const result = await loadEffectiveAuthorization(async () => [{ authorization: snapshot }], ["public"]);
    const columns = result.tables.find((t) => t.name === "column_open")!.columns;
    expect(columns.find((c) => c.name === "secret")!.principals).toEqual(expect.arrayContaining([
      expect.objectContaining({ role: "anon", read: "all" }), expect.objectContaining({ role: "authenticated", read: "none" }),
    ]));
    expect(columns.find((c) => c.name === "id")!.principals.every((p) => p.read === "none")).toBe(true);
    expect(result.tables.find((t) => t.name === "column_rls")!.columns.find((c) => c.name === "secret")!.principals[0]!.read).toBe("conditional");
  });

  it.each(["missing", "duplicate"])("rejects %s columns in a principal matrix", async (kind) => {
    const snapshot = JSON.parse(readFileSync(snapshotUrl, "utf8")).authorization;
    const row = snapshot.tables.find((t: { name: string; role: string }) => t.name === "column_open" && t.role === "anon");
    if (kind === "missing") row.columns.pop(); else row.columns[1] = row.columns[0];
    const result = await loadEffectiveAuthorization(async () => [{ authorization: snapshot }], ["public"]);
    expect(result.tables).toEqual([]);
    expect(result.findings[0]!.title).toContain("not assessed");
  });

  it("keeps column access row-bound and accounts for restrictive policy composition", async () => {
    const findings = await replay();
    for (const table of ["restrictive", "restrictive_only", "owner_forced", "no_grant"]) {
      expect(findings.find((f) => f.location === `public.${table}`)).toMatchObject({ severity: "Info", precisionTier: "review" });
    }
    expect(findings.find((f) => f.location === "public.column_rls")!.evidence).toContain("column grant (secret)");
    expect(findings.find((f) => f.location === "public.column_rls")!.evidence).toContain("applicable row predicates require review");
    expect(findings.find((f) => f.location === "public.policy_other_role")!.evidence).toContain("anon: SELECT=none");
  });

  it("requires schema USAGE even when the API advertises that schema", async () => {
    const findings = await replay(undefined, "public,future,hidden");
    const hidden = findings.find((f) => f.location === "hidden.no_schema")!;
    expect(hidden.severity).toBe("Info");
    expect(hidden.evidence).toContain("anon: SELECT=none (no schema USAGE)");
  });

  it("keeps application schemas starting with pg in the catalog population", async () => {
    const findings = await replay(undefined, "public,future,pgtenant");
    expect(findings.find((f) => f.location === "pgtenant.visible")).toMatchObject({ severity: "High" });
  });

  it("does not assert an API read path without the API's schema configuration", async () => {
    const findings = await replay(undefined, null);
    expect(findings.some((f) => f.severity === "High")).toBe(false);
    expect(findings.find((f) => f.location === "public.disabled")!.evidence).toContain("API schema reachability was not established");
  });

  it("retains owner-context review for both guarded and unguarded definers", async () => {
    const findings = await replay();
    const definers = findings.filter((f) => f.taxonomy === "SECURITY DEFINER effective authorization context");
    expect(definers).toHaveLength(4);
    expect(definers.every((f) => f.precisionTier === "review" && f.evidence.includes("Caller restrictions") && f.evidence.includes("remain unproved"))).toBe(true);
    expect(definers.find((f) => f.location === "public.definer_read()")!.evidence).toContain("SELECT=all");
    expect(definers.find((f) => f.location === "public.definer_denied()")!.evidence).toContain("SELECT=none");
    expect(definers.find((f) => f.location === "public.definer_forced()")!.evidence).toContain("SELECT=none");
    expect(definers.some((f) => f.location === "public.definer_private()")).toBe(false);
  });

  it.each(["absent", "wrong flag type", "missing principal", "missing relation", "missing definer"])("discloses incomplete metadata: %s", async (kind) => {
    const findings = await replay((snapshot) => {
      if (kind === "absent") delete snapshot.tables;
      if (kind === "wrong flag type") (snapshot.tables as Record<string, unknown>[])[0]!.rls = "false";
      if (kind === "missing principal") (snapshot.tables as unknown[]).pop();
      if (kind === "missing relation") snapshot.tables = (snapshot.tables as { name: string }[]).filter((t) => t.name !== "disabled");
      if (kind === "missing definer") (snapshot.definers as unknown[]).pop();
    });
    expect(findings.find((f) => f.id === "SB-AUTHZ-00")!.title).toContain("not assessed");
    expect(findings.some((f) => f.severity === "High")).toBe(false);
  });

  it("renders every authorization disposition and uncertainty without dropping findings", async () => {
    const findings = await replay();
    const document: FindingsDocument = { meta: META, findings };
    const html = buildHtml(document);
    expect(renderFidelityBreaches(document, html)).toEqual([]);
    expect(html).toContain("RLS deny-by-default");
    expect(html).toContain("Caller restrictions");
    expect(new Set(findings.map((f) => f.id)).size).toBe(findings.length);
  });
});

// Explicit opt-in starts only a new synthetic cluster; no connection URL from the
// environment is accepted as a test target. The recorded catalog controls run always.
describe.runIf(process.env.HARVEY_AUTHZ_POSTGRES_TESTS === "1")("real disposable PostgreSQL authorization", () => {
  let root = "";
  let sql: ReturnType<typeof postgres>;
  let started = false;
  const binary = (name: string) => process.env.HARVEY_AUTHZ_PG_BIN ? join(process.env.HARVEY_AUTHZ_PG_BIN, name) : name;
  const evidence = process.env.HARVEY_AUTHZ_EVIDENCE_DIR;

  beforeAll(async () => {
    root = mkdtempSync("/tmp/harvey-authz-test-");
    mkdirSync(join(root, "socket"));
    await exec(binary("initdb"), ["-D", join(root, "data"), "-U", "harvey_fixture", "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"]);
    await exec(binary("pg_ctl"), ["-D", join(root, "data"), "-l", join(root, "postgres.log"), "-o", `-k ${join(root, "socket")} -c listen_addresses='' -p 55438`, "-w", "start"]);
    started = true;
    sql = postgres({ host: join(root, "socket"), port: 55438, username: "harvey_fixture", database: "postgres", max: 1, onnotice: () => {} });
    await sql.unsafe(readFileSync(fixtureUrl, "utf8"));
  });

  afterAll(async () => {
    if (sql) await sql.end();
    if (started) await exec(binary("pg_ctl"), ["-D", join(root, "data"), "-m", "fast", "-w", "stop"]);
    if (root) rmSync(root, { recursive: true, force: true });
  });

  async function rowsAs(role: string, query: string): Promise<number> {
    await sql.unsafe(`set role ${role}`);
    await sql.unsafe("set fixture.tenant='a'");
    try { return (await sql.unsafe(query)).length; }
    finally { await sql.unsafe("reset role"); }
  }
  const scan = () => hosted(async (query) => {
    const rows = await sql.unsafe(query);
    if (evidence && query.includes("harvey-effective-authorization-v1")) {
      mkdirSync(evidence, { recursive: true });
      writeFileSync(join(evidence, "authorization-catalog.json"), JSON.stringify(rows[0]!.authorization, null, 2));
    }
    return rows;
  });

  it("pairs real row counts with current grants, restrictive RLS, owners, inheritance and default ACLs", async () => {
    const controls: [string, string, number][] = [
      ["anon", "select * from public.deny_all", 0], ["anon", "select * from public.restrictive", 0],
      ["anon", "select * from public.restrictive_only", 0], ["anon", "select secret from public.column_rls", 1],
      ["anon", "select secret from public.column_open", 2], ["anon", "select * from public.disabled", 2],
      ["anon", "select * from public.policy_other_role", 0], ["authenticated", "select * from public.policy_other_role", 2],
      ["authenticated", "select * from public.inherited", 2], ["authenticated", "select * from public.owner_unforced", 2],
      ["authenticated", "select * from public.owner_forced", 0], ["service_role", "select * from public.deny_all", 2],
      ["anon", "select * from future.default_open", 2], ["anon", "select * from future.default_denied", 0],
    ];
    const observed = [];
    for (const [role, query, expected] of controls) {
      const count = await rowsAs(role, query);
      expect(count, `${role}: ${query}`).toBe(expected);
      observed.push({ role, query, count });
    }
    await expect(rowsAs("anon", "select * from public.no_grant")).rejects.toThrow(/permission denied/);
    await expect(rowsAs("anon", "select * from hidden.no_schema")).rejects.toThrow(/permission denied/);
    const findings = await scan();
    expect(findings.find((f) => f.location === "pgtenant.visible")).toMatchObject({ severity: "Info" });
    expect(findings.find((f) => f.id === "SB-AUTHZ-public-policy_other_role")!.evidence).toContain("anon: SELECT=none");
    expect(findings.filter((f) => f.severity === "High").map((f) => f.location).sort()).toEqual([
      "future.default_open", "public.column_open", "public.disabled", "public.inherited", "public.owner_unforced", "public.policy_other_role", "public.public_grant",
    ]);
    expect(findings.find((f) => f.id.startsWith("SB-DEFAULT-ACL-"))).toMatchObject({ severity: "Info", precisionTier: "review" });
    if (evidence) {
      writeFileSync(join(evidence, "runtime-controls.json"), JSON.stringify(observed, null, 2));
      writeFileSync(join(evidence, "hosted-findings.json"), JSON.stringify(findings, null, 2));
    }
  });

  it("retains definer review across real bypassed, denied, forced and caller-scoped behavior", async () => {
    for (const [name, count] of [["definer_read", 2], ["definer_denied", 0], ["definer_forced", 0], ["definer_scoped", 1]] as const) {
      expect(await rowsAs("anon", `select * from public.${name}()`)).toBe(count);
    }
    await expect(rowsAs("anon", "select * from public.definer_private()")).rejects.toThrow(/permission denied/);
    const findings = await scan();
    const contexts = findings.filter((f) => f.taxonomy === "SECURITY DEFINER effective authorization context");
    expect(contexts).toHaveLength(4);
    expect(contexts.find((f) => f.location === "public.definer_read()")!.evidence).toContain("SELECT=all");
    for (const name of ["definer_denied", "definer_forced"]) {
      expect(contexts.find((f) => f.location === `public.${name}()`)!.evidence).toContain("SELECT=none");
    }
  });

  it("observes actual BYPASSRLS changes on the client role without inferring them from its name", async () => {
    await sql.unsafe("alter role anon bypassrls");
    try {
      expect(await rowsAs("anon", "select * from public.deny_all")).toBe(2);
      expect((await scan()).find((f) => f.id === "SB-AUTHZ-public-deny_all")).toMatchObject({ severity: "High" });
    } finally { await sql.unsafe("alter role anon nobypassrls"); }
    expect(await rowsAs("anon", "select * from public.deny_all")).toBe(0);
    expect((await scan()).find((f) => f.id === "SB-AUTHZ-public-deny_all")).toMatchObject({ severity: "Info" });
  });

  it("uses membership for grants while keeping BYPASSRLS an effective-role attribute", async () => {
    await sql.unsafe("grant service_role to anon");
    try {
      expect(await rowsAs("anon", "select * from public.deny_all")).toBe(0);
      expect((await scan()).find((f) => f.id === "SB-AUTHZ-public-deny_all")).toMatchObject({ severity: "Info" });
    } finally { await sql.unsafe("revoke service_role from anon"); }
    await sql.unsafe("grant readers to authenticated with inherit false");
    try {
      await expect(rowsAs("authenticated", "select * from public.inherited")).rejects.toThrow(/permission denied/);
      expect((await scan()).find((f) => f.id === "SB-AUTHZ-public-inherited")).toMatchObject({ severity: "Info" });
    } finally { await sql.unsafe("grant readers to authenticated with inherit true"); }
    expect((await scan()).find((f) => f.id === "SB-AUTHZ-public-inherited")).toMatchObject({ severity: "High" });
  });

  it("delivers local CLI findings through the real database and renderer", async () => {
    const server = createServer((_request, response) => { response.writeHead(406, { "content-type": "application/json" }); response.end('{"code":"PGRST106","hint":"Only the following schemas are exposed: public, future"}'); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address() as { port: number };
      const out = join(root, "findings.json");
      await exec(process.execPath, ["--import", "tsx", "src/cli/scan.ts", "--supabase", "local", "--rest-url", `http://127.0.0.1:${address.port}`, "--out", out], {
        env: { ...process.env, SUPABASE_LOCAL_DB_URL: "postgres:///postgres", PGHOST: join(root, "socket"), PGPORT: "55438", PGUSER: "harvey_fixture", PGDATABASE: "postgres" }, maxBuffer: 8 * 1024 * 1024,
      });
      const findings = JSON.parse(readFileSync(out, "utf8")) as Finding[];
      expect(findings.find((f) => f.id === "SB-AUTHZ-public-column_rls")).toMatchObject({ severity: "Info", precisionTier: "review" });
      expect(findings.find((f) => f.id === "SB-AUTHZ-public-disabled")).toMatchObject({ severity: "High" });
      expect(findings.find((f) => f.taxonomy === "rls_policy_always_true" && f.location === "public.restrictive")).toMatchObject({ severity: "Info", precisionTier: "review" });
      expect(findings.filter((f) => f.severity === "High").map((f) => f.location).sort()).toEqual([
        "future.default_open", "public.column_open", "public.disabled", "public.inherited", "public.owner_unforced", "public.policy_other_role", "public.public_grant",
      ]);
      expect(findings.filter((f) => f.taxonomy === "Column-level privilege inventory").every((f) => !f.location.startsWith("pg_catalog."))).toBe(true);
      expect(findings.filter((f) => f.taxonomy === "Column-level privilege inventory" && f.location === "public.column_rls.secret")).toHaveLength(2);
      const document: FindingsDocument = { meta: META, findings };
      const html = buildHtml(document);
      expect(renderFidelityBreaches(document, html)).toEqual([]);
      expect(new Set(findings.map((f) => f.id)).size).toBe(findings.length);
      const related = (finding: Finding) => ["SB-AUTHZ-", "SB-COLUMN-GRANT-", "SB-DEFAULT-ACL-"].some((prefix) => finding.id.startsWith(prefix));
      const ledger = conservationLedger(enrichFindingsCwe((await scan()).filter(related)), findings.filter(related));
      expect(ledger).toMatchObject({ ok: true, unaccounted: 0, suppressed: 0, capped: 0, deduped: 0 });
      expect(ledger.produced).toBeGreaterThan(20);
      if (evidence) {
        writeFileSync(join(evidence, "cli-findings.json"), JSON.stringify(findings, null, 2));
        writeFileSync(join(evidence, "report.html"), html);
        writeFileSync(join(evidence, "authorization-conservation.json"), JSON.stringify(ledger, null, 2));
      }
    } finally { await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
  });
});
