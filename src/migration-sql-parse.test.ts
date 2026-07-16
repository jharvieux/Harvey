import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseColumns, parseDefinerFunctions, parsePolicies, parseRlsState, parseTableNames } from "./migration-sql-parse.js";

// Fixtures are the real calibration-target migrations (targets/calibration/supabase/migrations) —
// this test asserts the parser extracts exactly what GROUND-TRUTH.md says is there, so a change
// to either the target or the parser that breaks the dry-run harness's M1/PII feed fails loudly.
const TARGET_DIR = join(import.meta.dirname, "..", "targets", "calibration", "supabase", "migrations");
const schemaSql = readFileSync(join(TARGET_DIR, "20260708000001_schema.sql"), "utf8");
const rlsSql = readFileSync(join(TARGET_DIR, "20260708000002_rls.sql"), "utf8");

describe("parseTableNames", () => {
  it("finds every table in the calibration schema", () => {
    const tables = parseTableNames(schemaSql).map((t) => t.table);
    expect(tables.sort()).toEqual(
      ["audit_logs", "counters", "documents", "invoices", "notes", "profiles", "service_state", "tenants"].sort(),
    );
  });
});

describe("parseColumns", () => {
  it("extracts tenant_id on every tenant-scoped table", () => {
    const cols = parseColumns(schemaSql);
    const documentsCols = cols.filter((c) => c.table_name === "documents").map((c) => c.column_name);
    expect(documentsCols).toContain("tenant_id");
    expect(documentsCols).toContain("title");
  });

  it("extracts the profiles.email column with its type, for the PII data map", () => {
    const cols = parseColumns(schemaSql);
    const email = cols.find((c) => c.table_name === "profiles" && c.column_name === "email");
    expect(email?.data_type).toBe("text");
  });
});

// #299: Prisma-generated migrations (prisma/migrations/**/migration.sql, not Supabase's own
// supabase/migrations) double-quote every identifier. Verified 2026-07-15 against boxyhq's real
// prisma/migrations/20230625203909_init/migration.sql — the fixture below is that file's actual
// "Account"/"userId" CreateTable statement, not a synthetic approximation, so this test fails
// loudly if a future regex change regresses the exact shape that motivated the fix.
const QUOTED_ACCOUNT_TABLE = `
-- CreateTable
CREATE TABLE "Account" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "expires_at" INTEGER,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("id")
);
`;
// The same table shape, unquoted — the regression guard the acceptance criteria asks for: the
// pre-#299 path must keep working unchanged.
const UNQUOTED_ACCOUNT_TABLE = `
create table account (
    id text not null,
    user_id text not null,
    provider text not null,
    expires_at integer
);
`;

describe("parseColumns — quoted vs unquoted identifiers (#299)", () => {
  it("reads a double-quoted Prisma table/column pair, preserving camelCase", () => {
    const cols = parseColumns(QUOTED_ACCOUNT_TABLE);
    expect(cols.map((c) => c.column_name)).toEqual(["id", "userId", "provider", "expires_at"]);
    expect(cols.find((c) => c.column_name === "userId")).toMatchObject({ table_name: "Account", data_type: "text" });
  });

  it("still reads the equivalent unquoted table — no regression to the pre-#299 path", () => {
    const cols = parseColumns(UNQUOTED_ACCOUNT_TABLE);
    expect(cols.map((c) => c.column_name)).toEqual(["id", "user_id", "provider", "expires_at"]);
    expect(cols.find((c) => c.column_name === "user_id")).toMatchObject({ table_name: "account", data_type: "text" });
  });

  it("does not lowercase a quoted identifier the way Postgres folds a bare one", () => {
    const cols = parseColumns(QUOTED_ACCOUNT_TABLE);
    expect(cols.some((c) => c.column_name === "userid")).toBe(false);
  });

  it("unescapes a doubled double-quote inside a quoted identifier (SQL's \"\" escape)", () => {
    const cols = parseColumns('create table "weird" (\n    "na""me" text not null\n);');
    expect(cols).toEqual([{ table_name: "weird", column_name: 'na"me', data_type: "text" }]);
  });

  it("reads a schema-qualified quoted table name", () => {
    const cols = parseColumns('create table "public"."Team" (\n    "id" text not null\n);');
    expect(cols).toEqual([{ table_name: "Team", column_name: "id", data_type: "text" }]);
  });

  it("parses boxyhq's real jackson_store.value column — the must-not-miss encrypted-secret case (#299/#279)", () => {
    // jackson_store is IF NOT EXISTS and lowercase/unquoted-shaped despite still being
    // double-quoted by Prisma ("jackson_store", "value") — confirms the fix isn't camelCase-only.
    const cols = parseColumns(`
CREATE TABLE IF NOT EXISTS "jackson_store" (
    "key" VARCHAR(1500) NOT NULL,
    "value" TEXT NOT NULL,
    "namespace" VARCHAR(64),

    CONSTRAINT "_jackson_store_key" PRIMARY KEY ("key")
);
`);
    expect(cols.find((c) => c.column_name === "value")).toMatchObject({ table_name: "jackson_store", data_type: "text" });
  });

  it("extracts columns with SERIAL/BIGSERIAL/SMALLSERIAL types (#307)", () => {
    const cols = parseColumns(`
create table jackson_index (
    id serial primary key,
    name text not null
);

create table audit_trail (
    entry_id bigserial,
    tenant_id uuid,
    action smallserial
);
`);
    expect(cols.filter((c) => c.table_name === "jackson_index")).toEqual([
      { table_name: "jackson_index", column_name: "id", data_type: "serial" },
      { table_name: "jackson_index", column_name: "name", data_type: "text" },
    ]);
    expect(cols.filter((c) => c.table_name === "audit_trail")).toEqual([
      { table_name: "audit_trail", column_name: "entry_id", data_type: "bigserial" },
      { table_name: "audit_trail", column_name: "tenant_id", data_type: "uuid" },
      { table_name: "audit_trail", column_name: "action", data_type: "smallserial" },
    ]);
  });
});

describe("parseTableNames — quoted vs unquoted identifiers (#299)", () => {
  it("finds a double-quoted table name", () => {
    expect(parseTableNames(QUOTED_ACCOUNT_TABLE)).toEqual([{ schema: "public", table: "Account" }]);
  });

  it("still finds the equivalent unquoted table name", () => {
    expect(parseTableNames(UNQUOTED_ACCOUNT_TABLE)).toEqual([{ schema: "public", table: "account" }]);
  });

  it("resolves a quoted schema qualifier instead of defaulting to public", () => {
    expect(parseTableNames('create table "tenant_a"."widgets" (\n    id text not null\n);')).toEqual([
      { schema: "tenant_a", table: "widgets" },
    ]);
  });
});

describe("parseDefinerFunctions", () => {
  it("finds current_tenant_id as a SECURITY DEFINER function with the caller-scoping body", () => {
    const fns = parseDefinerFunctions(schemaSql);
    expect(fns).toHaveLength(1);
    expect(fns[0]).toMatchObject({ schema: "public", name: "current_tenant_id", argNames: [] });
    expect(fns[0]!.body).toContain("auth.uid()");
  });
});

describe("parseRlsState", () => {
  it("matches GROUND-TRUTH.md: audit_logs never enables RLS (bug #3), every other table does", () => {
    const state = parseRlsState(schemaSql, rlsSql);
    const auditLogs = state.find((t) => t.table === "audit_logs");
    expect(auditLogs?.rlsEnabled).toBe(false);

    const rest = state.filter((t) => t.table !== "audit_logs");
    expect(rest.every((t) => t.rlsEnabled)).toBe(true);
  });

  it("finds exactly service_state as RLS-enabled-with-zero-policies — the deliberate deny-all negative (N-RLS-DENY-ALL)", () => {
    const state = parseRlsState(schemaSql, rlsSql);
    const noPolicyCandidates = state.filter((t) => t.rlsEnabled && !t.hasPolicy).map((t) => t.table);
    // documents/invoices have wrong policies (not missing ones); service_state is RLS-on with no
    // policy on purpose (deny-all by design), a benign true-negative the scanner must not flag.
    expect(noPolicyCandidates).toEqual(["service_state"]);
  });
});

// #220 — the clauses themselves, not just "does a policy exist". The reviewer downstream
// (rls-policy-review.ts) can only judge what this extracts, so an under-extraction here is a
// silent miss of the highest-value bug class.
describe("parsePolicies", () => {
  it("extracts USING and WITH CHECK from the real calibration policies", () => {
    const { policies } = parsePolicies(rlsSql);
    const notes = policies.find((p) => p.name === "notes_rw_own_tenant");
    expect(notes).toMatchObject({
      schema: "public",
      table: "notes",
      cmd: "ALL",
      qual: "tenant_id = public.current_tenant_id()",
      withCheck: "tenant_id = public.current_tenant_id()",
    });
  });

  it("keeps the planted USING(true) body rather than discarding it (GROUND-TRUTH bug #1)", () => {
    const { policies } = parsePolicies(rlsSql);
    expect(policies.find((p) => p.name === "documents_select_all")).toMatchObject({ cmd: "SELECT", qual: "true", withCheck: null });
  });

  it("defaults cmd to ALL when FOR is omitted, as Postgres does", () => {
    const { policies } = parsePolicies("create policy p on public.t using (tenant_id = x);");
    expect(policies[0]!.cmd).toBe("ALL");
  });

  it("distinguishes an absent WITH CHECK (null) from an empty one — the reviewer reads that", () => {
    const { policies } = parsePolicies("create policy p on public.t for insert with check (tenant_id = x);");
    expect(policies[0]).toMatchObject({ cmd: "INSERT", qual: null, withCheck: "tenant_id = x" });
  });

  it("reads a clause containing a nested subquery/EXISTS join without truncating at the first paren", () => {
    const { policies } = parsePolicies(
      "create policy p on public.docs for select using (exists (select 1 from members m where m.user_id = (select auth.uid()) and m.org_id = docs.org_id));",
    );
    expect(policies[0]!.qual).toBe("exists (select 1 from members m where m.user_id = (select auth.uid()) and m.org_id = docs.org_id)");
  });

  it("is not fooled by parens or semicolons inside a string literal", () => {
    const { policies, unparsed } = parsePolicies("create policy p on public.t for select using (role = 'a);b' and tenant_id = x);");
    expect(unparsed).toEqual([]);
    expect(policies[0]!.qual).toBe("role = 'a);b' and tenant_id = x");
  });

  it("handles a quoted policy name", () => {
    const { policies } = parsePolicies(`create policy "Users can view own" on public.t for select using (id = auth.uid());`);
    expect(policies[0]).toMatchObject({ name: "Users can view own", qual: "id = auth.uid()" });
  });

  it("SURFACES a policy it cannot parse instead of dropping it — a failed parse must not read as clean", () => {
    const { policies, unparsed } = parsePolicies("create policy broken on public.t for select using (tenant_id = x");
    expect(policies).toEqual([]);
    expect(unparsed).toHaveLength(1);
    expect(unparsed[0]).toMatchObject({ table: "t", name: "broken" });
  });
});
