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
