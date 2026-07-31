// #1370 — the enumerable half of "permission-matrix gaps". docs/free-tier-scope.md declined the
// whole class as "a question about intended authority, not about code shape"; WHICH CELLS EXIST is
// code shape, and parseLivePolicies has produced table x command x role on every Supabase scan
// since #937. These tests pin the split: a table whose policy set leaves a command uncovered fires,
// a table whose set covers all four is silent, and a FOR ALL policy counts as all four.

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkMigrationRlsCommandCoverage } from "./supabase-static.js";

function withMigration(sql: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-cmdgap-"));
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(dir, "supabase", "migrations", "0001_init.sql"), sql);
  return dir;
}

function scan(sql: string): { count: number; evidence: string } {
  const dir = withMigration(sql);
  try {
    const findings = checkMigrationRlsCommandCoverage(dir);
    return { count: findings.length, evidence: findings[0]?.evidence ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const ENABLE = `alter table public.orders enable row level security;`;

describe("SB-RLS-CMDGAP-ROLLUP (#1370)", () => {
  it("fires when an RLS-enabled table has SELECT and INSERT policies but none for UPDATE or DELETE", () => {
    const { count, evidence } = scan(`
      create table public.orders (id uuid primary key, tenant_id uuid);
      ${ENABLE}
      create policy orders_read on public.orders for select to authenticated using (tenant_id = auth.uid());
      create policy orders_write on public.orders for insert to authenticated with check (tenant_id = auth.uid());
    `);
    expect(count).toBe(1);
    expect(evidence).toContain("no policy for UPDATE, DELETE");
    expect(evidence).toContain("SELECT (to authenticated)");
  });

  it("is silent when all four commands are covered", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key, tenant_id uuid);
        ${ENABLE}
        create policy o_s on public.orders for select to authenticated using (true);
        create policy o_i on public.orders for insert to authenticated with check (true);
        create policy o_u on public.orders for update to authenticated using (true);
        create policy o_d on public.orders for delete to authenticated using (true);
      `).count,
    ).toBe(0);
  });

  it("treats a FOR ALL policy as covering all four commands", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key, tenant_id uuid);
        ${ENABLE}
        create policy o_all on public.orders for all to authenticated using (true) with check (true);
      `).count,
    ).toBe(0);
  });

  it("omits a table whose row security is NOT enabled — the matrix question does not apply", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key, tenant_id uuid);
        create policy o_s on public.orders for select to authenticated using (true);
      `).count,
    ).toBe(0);
  });

  it("reports the ROLE axis, defaulting an omitted TO clause to public as Postgres does", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key);
        ${ENABLE}
        create policy o_s on public.orders for select using (true);
      `).evidence,
    ).toContain("SELECT (to public)");
  });

  it("respects DROP POLICY — a command uncovered only because a later migration removed its policy still counts", () => {
    const { count, evidence } = scan(`
      create table public.orders (id uuid primary key);
      ${ENABLE}
      create policy o_s on public.orders for select to authenticated using (true);
      create policy o_u on public.orders for update to authenticated using (true);
      create policy o_i on public.orders for insert to authenticated with check (true);
      create policy o_d on public.orders for delete to authenticated using (true);
      drop policy o_d on public.orders;
    `);
    expect(count).toBe(1);
    expect(evidence).toContain("no policy for DELETE");
  });
});
