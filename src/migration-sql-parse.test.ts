import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseArrayColumns, parseAuthUserRefs, parseClassifiableColumns, parseDroppedColumns, parseLiveColumns, parseCheckConstraints, parseCheckInConstraints, parseColumns, parseDefinerFunctions, parseForeignKeys, parseLivePolicies, parseLiveTableNames, parseNotNullColumns, parsePolicies, parseRlsState, parseTableNames, parseUniqueColumns } from "./migration-sql-parse.js";

// Fixtures are the real calibration-target migrations (targets/calibration/supabase/migrations) —
// this test asserts the parser extracts exactly what GROUND-TRUTH.md says is there, so a change
// to either the target or the parser that breaks the dry-run harness's M1/PII feed fails loudly.
const TARGET_DIR = join(import.meta.dirname, "..", "targets", "calibration", "supabase", "migrations");
const schemaSql = readFileSync(join(TARGET_DIR, "20260708000001_schema.sql"), "utf8");
const rlsSql = readFileSync(join(TARGET_DIR, "20260708000002_rls.sql"), "utf8");

describe("parseAuthUserRefs", () => {
  it("finds the columns that FK to auth.users (the two-tenant seed must fill these with real user ids)", () => {
    const refs = parseAuthUserRefs(schemaSql).map((r) => `${r.table_name}.${r.column_name}`);
    expect(refs).toContain("profiles.id"); // id uuid primary key references auth.users (id)
  });

  it("does not match a plain uuid column with no auth.users reference", () => {
    const refs = parseAuthUserRefs("create table t (\n  id uuid primary key,\n  tenant_id uuid not null\n);");
    expect(refs).toHaveLength(0);
  });
});

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

describe("parseCheckInConstraints (#547 — enum-like allow-lists the seed must satisfy)", () => {
  it("reads an inline column-level CHECK (col IN (...)) allow-list", () => {
    const sql = "create table subs (\n  id uuid primary key,\n  plan text not null check (plan in ('free','pro','enterprise'))\n);";
    const checks = parseCheckInConstraints(sql);
    expect(checks).toEqual([{ table_name: "subs", column_name: "plan", values: ["free", "pro", "enterprise"] }]);
  });

  it("reads a table-level CHECK constraint the same way", () => {
    const sql = "create table orders (\n  id uuid primary key,\n  status text not null,\n  constraint status_ck check (status in ('pending','shipped'))\n);";
    expect(parseCheckInConstraints(sql)[0]).toEqual({ table_name: "orders", column_name: "status", values: ["pending", "shipped"] });
  });

  it("ignores a CHECK that is not a simple IN allow-list (stays in the seed's fail-loud path)", () => {
    const sql = "create table t (\n  id uuid primary key,\n  qty integer check (qty > 0)\n);";
    expect(parseCheckInConstraints(sql)).toEqual([]);
  });

  // #622 — the constraint that blocked M2 on ATC: the column is a plain TEXT in CREATE TABLE and its
  // allow-list arrives LATER via ALTER TABLE ADD CONSTRAINT, guarded by `IS NULL OR`. A
  // CREATE-TABLE-only scan misses it and the seed placeholders an illegal value.
  it("reads an allow-list added later via ALTER TABLE ADD CONSTRAINT (IS NULL OR col IN (...))", () => {
    const sql = [
      "create table tenants (\n  id uuid primary key,\n  onboarding_stage text\n);",
      "alter table public.tenants",
      "  add constraint tenants_onboarding_stage_check",
      "    check (onboarding_stage is null or onboarding_stage in ('signup','profile','complete'));",
    ].join("\n");
    expect(parseCheckInConstraints(sql)).toEqual([
      { table_name: "tenants", column_name: "onboarding_stage", values: ["signup", "profile", "complete"] },
    ]);
  });

  it("reads a single-value equality CHECK (col = 'x')", () => {
    const sql = "create table t (\n  id uuid primary key,\n  kind text check (kind = 'fixed')\n);";
    expect(parseCheckInConstraints(sql)).toEqual([{ table_name: "t", column_name: "kind", values: ["fixed"] }]);
  });

  it("records an un-derivable inline CHECK with a null allow-list (fail-loud disclosure, not silence)", () => {
    const sql = "create table t (\n  id uuid primary key,\n  slug text check (slug = lower(slug) and slug ~ '^[a-z]+$')\n);";
    expect(parseCheckConstraints(sql)).toEqual([{ table_name: "t", column_name: "slug", values: null }]);
    expect(parseCheckInConstraints(sql)).toEqual([]);
  });
});

describe("parseUniqueColumns (#598 — the ON CONFLICT arbiter for idempotent trigger-safe seeding)", () => {
  it("reads an inline PRIMARY KEY column (the profiles.id → auth.users arbiter)", () => {
    const sql = "create table profiles (\n  id uuid primary key references auth.users (id),\n  email text\n);";
    expect(parseUniqueColumns(sql)).toEqual([{ table_name: "profiles", column_name: "id" }]);
  });

  it("reads an inline UNIQUE column and a table-level primary key (col)", () => {
    const sql = "create table t (\n  id uuid,\n  email text unique,\n  primary key (id)\n);";
    const cols = parseUniqueColumns(sql).map((c) => c.column_name).sort();
    expect(cols).toEqual(["email", "id"]);
  });

  it("does NOT treat a plain non-unique FK column as an arbiter (many-per-user push_tokens)", () => {
    const sql = "create table push_tokens (\n  id uuid primary key default gen_random_uuid(),\n  user_id uuid not null references auth.users (id),\n  token text\n);";
    expect(parseUniqueColumns(sql)).toEqual([{ table_name: "push_tokens", column_name: "id" }]);
  });

  it("skips a multi-column key (not a single-column ON CONFLICT arbiter)", () => {
    const sql = "create table members (\n  org_id uuid,\n  user_id uuid,\n  primary key (org_id, user_id)\n);";
    expect(parseUniqueColumns(sql)).toEqual([]);
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

  it("extracts inet/cidr/citext/bytea/geography/geometry columns — PII-relevant types the M10 feed must see (#375)", () => {
    const cols = parseColumns(`
create table sessions (
    id uuid primary key,
    ip_address inet,
    subnet cidr,
    email citext not null,
    biometric_template bytea,
    last_location geography(point, 4326),
    service_area geometry
);
`);
    expect(cols.filter((c) => c.table_name === "sessions")).toEqual([
      { table_name: "sessions", column_name: "id", data_type: "uuid" },
      { table_name: "sessions", column_name: "ip_address", data_type: "inet" },
      { table_name: "sessions", column_name: "subnet", data_type: "cidr" },
      { table_name: "sessions", column_name: "email", data_type: "citext" },
      { table_name: "sessions", column_name: "biometric_template", data_type: "bytea" },
      { table_name: "sessions", column_name: "last_location", data_type: "geography" },
      { table_name: "sessions", column_name: "service_area", data_type: "geometry" },
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

describe("parseLivePolicies (#937 — drop/replace tracked, only the final live policy survives)", () => {
  const leak = "create policy p on public.docs for select using (true);";
  const scoped = "create policy p on public.docs for select using (tenant_id = current_tenant_id());";

  it("returns a policy that is never dropped, with its file:line", () => {
    const live = parseLivePolicies([{ file: "0001.sql", sql: `\n${leak}` }]);
    expect(live.policies).toHaveLength(1);
    expect(live.policies[0]).toMatchObject({ table: "docs", name: "p", qual: "true", file: "0001.sql", line: 2 });
  });

  it("drops a policy removed by a LATER migration", () => {
    const live = parseLivePolicies([
      { file: "0001.sql", sql: leak },
      { file: "0002.sql", sql: "drop policy p on public.docs;" },
    ]);
    expect(live.policies).toEqual([]);
  });

  it("keeps the FINAL definition when a later migration drops then re-creates the same name", () => {
    const live = parseLivePolicies([
      { file: "0001.sql", sql: leak },
      { file: "0002.sql", sql: `drop policy p on public.docs;\n${scoped}` },
    ]);
    expect(live.policies).toHaveLength(1);
    expect(live.policies[0]).toMatchObject({ name: "p", qual: "tenant_id = current_tenant_id()", file: "0002.sql" });
  });

  it("respects within-file order: drop-then-recreate in ONE migration resolves to the recreate", () => {
    const live = parseLivePolicies([{ file: "0001.sql", sql: `${leak}\ndrop policy p on public.docs;\n${scoped}` }]);
    expect(live.policies).toHaveLength(1);
    expect(live.policies[0]!.qual).toBe("tenant_id = current_tenant_id()");
  });

  it("honours `drop policy if exists` and a quoted policy name", () => {
    const live = parseLivePolicies([
      { file: "0001.sql", sql: `create policy "read all" on public.docs for select using (true);` },
      { file: "0002.sql", sql: `drop policy if exists "read all" on public.docs;` },
    ]);
    expect(live.policies).toEqual([]);
  });

  it("applies the lifecycle to an UNPARSED policy too — a dropped unreadable policy is not carried", () => {
    const live = parseLivePolicies([
      { file: "0001.sql", sql: "create policy broken on public.docs for select using (tenant_id = x" },
      { file: "0002.sql", sql: "drop policy broken on public.docs;" },
    ]);
    expect(live.policies).toEqual([]);
    expect(live.unparsed).toEqual([]);
  });

  it("keeps two DISTINCT policies on the same table independent of each other", () => {
    const live = parseLivePolicies([
      { file: "0001.sql", sql: "create policy a on public.docs for select using (true);\ncreate policy b on public.docs for insert with check (true);" },
      { file: "0002.sql", sql: "drop policy a on public.docs;" },
    ]);
    expect(live.policies.map((p) => p.name)).toEqual(["b"]);
  });
});

describe("parseForeignKeys (#630 — generic FK columns → parent table)", () => {
  it("parses an inline column-level nullable FK (ATC tenants.tier_id → tier_definitions)", () => {
    const fks = parseForeignKeys(`
      create table public.tenants (
        id uuid primary key default gen_random_uuid(),
        tier_id uuid references public.tier_definitions(id)
      );`);
    expect(fks).toEqual([{ table_name: "tenants", column_name: "tier_id", ref_schema: "public", ref_table: "tier_definitions" }]);
  });

  it("defaults the ref schema to public when the reference is unqualified", () => {
    const fks = parseForeignKeys("create table t (\n  parent_id uuid references parents\n);");
    expect(fks).toEqual([{ table_name: "t", column_name: "parent_id", ref_schema: "public", ref_table: "parents" }]);
  });

  it("parses a table-level FOREIGN KEY constraint", () => {
    const fks = parseForeignKeys("create table t (\n  pid uuid,\n  foreign key (pid) references public.parents(id)\n);");
    expect(fks).toEqual([{ table_name: "t", column_name: "pid", ref_schema: "public", ref_table: "parents" }]);
  });

  it("parses an ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY added after the table", () => {
    const fks = parseForeignKeys("create table t (id uuid, pid uuid);\nalter table only public.t add constraint t_pid_fk foreign key (pid) references public.parents(id);");
    expect(fks).toContainEqual({ table_name: "t", column_name: "pid", ref_schema: "public", ref_table: "parents" });
  });

  it("does not treat a table-level FOREIGN KEY line as an inline column named 'foreign'", () => {
    const fks = parseForeignKeys("create table t (\n  pid uuid,\n  foreign key (pid) references parents\n);");
    expect(fks.map((f) => f.column_name)).toEqual(["pid"]);
  });
});

describe("parseNotNullColumns (#630 — nullability drives FK omission vs parent-seeding)", () => {
  it("finds an inline NOT NULL column and omits a nullable one", () => {
    const nn = parseNotNullColumns("create table t (\n  id uuid primary key,\n  a text not null,\n  b text,\n  c uuid not null references parents\n);");
    const cols = nn.map((n) => n.column_name);
    expect(cols).toContain("a");
    expect(cols).toContain("c");
    expect(cols).not.toContain("b");
  });
});

describe("parseLiveTableNames (#640 — DROPped tables excluded, re-CREATE re-includes)", () => {
  it("excludes a table that is created then dropped", () => {
    const live = parseLiveTableNames("create table public.a (\n  id uuid\n);\ncreate table public.b (\n  id uuid\n);\ndrop table if exists public.b;");
    expect(live.map((t) => t.table)).toEqual(["a"]);
  });

  it("keeps a table that is dropped then re-created (last event wins)", () => {
    const live = parseLiveTableNames("create table public.email_log (\n  id uuid\n);\ndrop table if exists public.email_log;\ncreate table public.email_log (\n  id uuid,\n  tenant_id uuid\n);");
    expect(live.map((t) => t.table)).toEqual(["email_log"]);
  });
});

describe("parseArrayColumns (#641 — array columns need an array literal, not a scalar)", () => {
  it("detects text[] and type ARRAY columns, not scalars", () => {
    const arr = parseArrayColumns("create table t (\n  id uuid,\n  tags text[] not null,\n  scores integer array,\n  name text\n);");
    const cols = arr.map((a) => a.column_name);
    expect(cols).toEqual(["tags", "scores"]);
  });
});

describe("parseDroppedColumns (#642 — columns removed via ALTER TABLE DROP COLUMN)", () => {
  it("collects every DROP COLUMN clause of a multi-column ALTER, attributed to its table", () => {
    const sql = "create table public.quotes (\n  id uuid,\n  cruise_line text,\n  ship_name text\n);\nalter table public.quotes\n  drop column if exists cruise_line,\n  drop column if exists ship_name;";
    const dropped = parseDroppedColumns(sql).map((d) => `${d.table_name}.${d.column_name}`);
    expect(dropped).toEqual(["quotes.cruise_line", "quotes.ship_name"]);
  });
});

describe("parseLiveColumns (#643 — re-CREATEd table uses its final definition, not the union)", () => {
  it("uses the last CREATE's columns after a DROP+re-CREATE, dropping stale ones", () => {
    const sql = "create table public.email_log (\n  id uuid,\n  recipient_email text\n);\ndrop table if exists public.email_log;\ncreate table public.email_log (\n  id uuid,\n  to_email text\n);";
    const cols = parseLiveColumns(sql).filter((c) => c.table_name === "email_log").map((c) => c.column_name);
    expect(cols).toContain("to_email");
    expect(cols).not.toContain("recipient_email");
  });

  it("treats CREATE IF NOT EXISTS on an already-live table as a no-op (keeps the first)", () => {
    const sql = "create table public.t (\n  id uuid,\n  a text\n);\ncreate table if not exists public.t (\n  id uuid,\n  a text,\n  b text\n);";
    const cols = parseLiveColumns(sql).filter((c) => c.table_name === "t").map((c) => c.column_name);
    expect(cols.sort()).toEqual(["a", "id"]);
  });
});

describe("parseClassifiableColumns (#851/#852 — CREATE + ALTER ADD, recognized vs unknown types)", () => {
  it("includes columns added by ALTER TABLE ADD COLUMN, then drops one removed by a later ALTER", () => {
    const sql = `
      create table public.users (
        id uuid primary key,
        email text
      );
      alter table public.users add column ssn text;
      alter table users add column if not exists nickname text;
      alter table public.users drop column nickname;
    `;
    const { columns } = parseClassifiableColumns(sql);
    const names = columns.filter((c) => c.table_name === "users").map((c) => c.column_name).sort();
    expect(names).toEqual(["email", "id", "ssn"]); // nickname added then dropped → gone
  });

  it("routes an unrecognized-type column to unknownType (name-classifiable) instead of dropping it silently", () => {
    const sql = `
      create table public.people (
        id uuid primary key,
        gender gender_enum,
        balance money
      );
      alter table public.people add column status workflow_state;
    `;
    const { columns, unknownType } = parseClassifiableColumns(sql);
    expect(columns.map((c) => c.column_name)).toEqual(["id"]); // only the recognized-type column
    expect(unknownType.map((c) => `${c.column_name}:${c.data_type}`).sort()).toEqual([
      "balance:money",
      "gender:gender_enum",
      "status:workflow_state",
    ]);
  });

  it("reads a Prisma-quoted custom (enum) type in generated SQL as an unknown-type column", () => {
    const sql = `create table "Patient" (\n  "id" text not null,\n  "gender" "Gender" not null\n);`;
    const { unknownType } = parseClassifiableColumns(sql);
    expect(unknownType).toContainEqual({ table_name: "Patient", column_name: "gender", data_type: "gender" });
  });

  it("never reads a table-level constraint line as an unknown-type column", () => {
    const sql = `
      create table public.t (
        id uuid primary key,
        email text,
        constraint t_email_key unique (email),
        foreign key (id) references other (id)
      );
    `;
    expect(parseClassifiableColumns(sql).unknownType).toHaveLength(0);
  });
});
