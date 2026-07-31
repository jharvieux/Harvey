// #1370 — the enumerable half of "permission-matrix gaps". docs/free-tier-scope.md declined the
// whole class as "a question about intended authority, not about code shape"; WHICH CELLS EXIST is
// code shape, and parseLivePolicies has produced table x command x role on every Supabase scan
// since #937.
//
// WHICH empty cell is worth reporting is the whole test file, because the first version of this
// rule reported every one of them and cried wolf: corpus-drift run 30634899914 failed
// mvp-boilerplate's #227 "must not accuse a sound repo of a tenancy hole" control on five tables
// whose reads are policed and whose writes are server-side by design. These tests pin the narrowed
// rule: a table that grants a WRITE and no SELECT fires (the client writes rows it has no policy
// to read back), a table whose uncovered commands are writes only stays silent, and the upstream schema
// that produced the false positive is reproduced verbatim as a control.

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

function scan(sql: string): { count: number; evidence: string; location: string } {
  const dir = withMigration(sql);
  try {
    const findings = checkMigrationRlsCommandCoverage(dir);
    return { count: findings.length, evidence: findings[0]?.evidence ?? "", location: findings[0]?.location ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const ENABLE = `alter table public.orders enable row level security;`;

describe("SB-RLS-CMDGAP-<table> (#1370)", () => {
  it("fires when a table grants INSERT and UPDATE but has no SELECT policy", () => {
    const { count, evidence } = scan(`
      create table public.orders (id uuid primary key, tenant_id uuid);
      ${ENABLE}
      create policy orders_write on public.orders for insert to authenticated with check (tenant_id = auth.uid());
      create policy orders_edit on public.orders for update to authenticated using (tenant_id = auth.uid());
    `);
    expect(count).toBe(1);
    expect(evidence).toContain("no policy for SELECT");
    expect(evidence).toContain("INSERT (to authenticated)");
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
        create policy o_i on public.orders for insert to authenticated with check (true);
      `).count,
    ).toBe(0);
  });

  it("reports the ROLE axis, defaulting an omitted TO clause to public as Postgres does", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key);
        ${ENABLE}
        create policy o_i on public.orders for insert with check (true);
      `).evidence,
    ).toContain("INSERT (to public)");
  });

  it("respects DROP POLICY — a SELECT policy removed by a later migration leaves the table inverted", () => {
    const { count, evidence } = scan(`
      create table public.orders (id uuid primary key);
      ${ENABLE}
      create policy o_s on public.orders for select to authenticated using (true);
      create policy o_u on public.orders for update to authenticated using (true);
      drop policy o_s on public.orders;
    `);
    expect(count).toBe(1);
    expect(evidence).toContain("no policy for SELECT");
  });

  // --- the precision boundary: an uncovered WRITE is not a gap this rule reports ---

  it("is silent when the only uncovered commands are writes — read policed, writes server-side", () => {
    expect(
      scan(`
        create table public.products (id text primary key, name text);
        alter table public.products enable row level security;
        create policy products_read on public.products for select using (true);
      `).count,
    ).toBe(0);
  });

  it("is silent when SELECT and UPDATE are covered and INSERT/DELETE are not — a partly-covered write side is not the inversion", () => {
    expect(
      scan(`
        create table public.orders (id uuid primary key);
        ${ENABLE}
        create policy o_s on public.orders for select to authenticated using (true);
        create policy o_u on public.orders for update to authenticated using (true);
      `).count,
    ).toBe(0);
  });

  // The exact schema that failed the control, re-typed from devtodollars/mvp-boilerplate@2aac5c2f
  // (supabase/migrations/20240717231009_init.sql). MEASURED against a fresh clone of that pin: the
  // pre-narrowing rule reported checkout_sessions, prices, products, subscriptions and users. This
  // is the regression control — if it ever returns a finding again, the free tier is accusing a
  // sound repo of a tenancy hole and corpus-drift will say so a day later.
  it("is silent on the upstream Stripe-sync schema that produced the mvp-boilerplate false positive", () => {
    const { count, evidence } = scan(`
      create table users (id uuid references auth.users not null primary key, full_name text);
      alter table users enable row level security;
      create policy "Can view own user data." on users for select using (auth.uid() = id);
      create policy "Can update own user data." on users for update using (auth.uid() = id);

      create table products (id text primary key, active boolean, name text);
      alter table products enable row level security;
      create policy "Allow public read-only access." on products for select using (true);

      create table prices (id text primary key, product_id text references products, active boolean);
      alter table prices enable row level security;
      create policy "Allow public read-only access." on prices for select using (true);

      create table subscriptions (id text primary key, user_id uuid not null, status text);
      alter table subscriptions enable row level security;
      create policy "Can only view own subs data." on subscriptions for select using (auth.uid() = user_id);

      create table checkout_sessions (id text primary key, user_id uuid not null, status text);
      alter table checkout_sessions enable row level security;
      create policy "Can only view own checkout session data" on checkout_sessions for select using (auth.uid() = user_id);
    `);
    expect(count).toBe(0);
    expect(evidence).toBe("");
  });

  it("emits one row per inverted table, each anchored at that table's own migration line", () => {
    const dir = withMigration(`
      create table public.orders (id uuid primary key);
      ${ENABLE}
      create policy o_i on public.orders for insert to authenticated with check (true);

      create table public.pings (id uuid primary key);
      alter table public.pings enable row level security;
      create policy p_d on public.pings for delete to authenticated using (true);
    `);
    try {
      const ids = checkMigrationRlsCommandCoverage(dir)
        .map((f) => f.id)
        .sort();
      expect(ids).toEqual(["SB-RLS-CMDGAP-orders", "SB-RLS-CMDGAP-pings"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("states its own bound in the finding, and counts the write-only gaps it spared", () => {
    const { evidence, location } = scan(`
      create table public.orders (id uuid primary key);
      ${ENABLE}
      create policy o_i on public.orders for insert to authenticated with check (true);

      create table public.products (id text primary key, name text);
      alter table public.products enable row level security;
      create policy p_s on public.products for select using (true);
    `);
    expect(evidence).toContain("only a table that grants a WRITE command with no SELECT policy is reported");
    expect(evidence).toContain("1 table(s) in this schema are in that state");
    // Anchored at the reported table's own migration line, not at a repo-wide placeholder.
    expect(location).toMatch(/0001_init\.sql:\d+$/);
  });
});
