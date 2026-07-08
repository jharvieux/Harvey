import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseColumns, parseDefinerFunctions, parseRlsState, parseTableNames } from "./migration-sql-parse.js";

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
      ["audit_logs", "counters", "documents", "invoices", "notes", "profiles", "tenants"].sort(),
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

  it("finds no RLS-enabled table with zero policies (documents/invoices have wrong policies, not missing ones)", () => {
    const state = parseRlsState(schemaSql, rlsSql);
    const noPolicyCandidates = state.filter((t) => t.rlsEnabled && !t.hasPolicy);
    expect(noPolicyCandidates).toEqual([]);
  });
});
