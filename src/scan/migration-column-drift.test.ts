// #1230 / D-091 item 13 — app code names a column the migration history already dropped. The
// history FOLD is what makes it precise: a drop that is later re-added, or a rename that is
// reversed, leaves nothing to report. Table-awareness is the other half — `quotes.cruise_line`
// being dropped says nothing about `bookings.cruise_line`.

import { describe, expect, it } from "vitest";
import { detectMigrationColumnDriftFindings, droppedColumns } from "./migration-column-drift.js";

const scan = (sql: { file: string; sql: string }[], text: string, path = "src/lib/quotes.ts") =>
  detectMigrationColumnDriftFindings([{ path, text }], droppedColumns(sql));

const DROPPED = [
  { file: "supabase/migrations/001_create.sql", sql: "create table public.quotes (id uuid primary key, cruise_line text, total_cents integer);" },
  { file: "supabase/migrations/002_contract.sql", sql: "alter table public.quotes drop column cruise_line;" },
];

describe("migration-column-drift — fires on a reader of a dropped column", () => {
  it("catches the column named in a select list on its own table", () => {
    const out = scan(DROPPED, `export const list = () => supabase.from("quotes").select("id, cruise_line");`);
    expect(out).toHaveLength(1);
    expect(out[0]!.taxonomy).toBe("App code reads a column the migrations dropped");
    expect(out[0]!.precisionTier).toBe("high");
    expect(out[0]!.evidence).toContain("002_contract.sql");
  });

  it("catches it in a filter argument, not only a select list", () => {
    expect(scan(DROPPED, `export const list = () => supabase.from("quotes").select("id").eq("cruise_line", "X");`)).toHaveLength(1);
  });

  it("catches a renamed-away column and names what it became", () => {
    const renamed = [
      DROPPED[0]!,
      { file: "supabase/migrations/002_rename.sql", sql: "alter table public.quotes rename column cruise_line to line_name;" },
    ];
    const out = scan(renamed, `export const list = () => supabase.from("quotes").select("id, cruise_line");`);
    expect(out).toHaveLength(1);
    expect(out[0]!.evidence).toContain("renamed to `line_name`");
  });
});

describe("migration-column-drift — the fold and the table key are the precision", () => {
  it("is silent when the same column name is live on another table", () => {
    expect(scan(DROPPED, `export const list = () => supabase.from("bookings").select("id, cruise_line");`)).toEqual([]);
  });

  it("is silent when the reader already switched off the dropped column", () => {
    expect(scan(DROPPED, `export const list = () => supabase.from("quotes").select("id, total_cents");`)).toEqual([]);
  });

  it("is silent when a later migration adds the column back", () => {
    const readded = [...DROPPED, { file: "supabase/migrations/003_restore.sql", sql: "alter table public.quotes add column cruise_line text;" }];
    expect(scan(readded, `export const list = () => supabase.from("quotes").select("id, cruise_line");`)).toEqual([]);
  });

  it("is silent when a later migration recreates the table with the column", () => {
    const recreated = [...DROPPED, { file: "supabase/migrations/003_recreate.sql", sql: "create table public.quotes (id uuid primary key, cruise_line text);" }];
    expect(scan(recreated, `export const list = () => supabase.from("quotes").select("id, cruise_line");`)).toEqual([]);
  });

  it("matches whole words — total_amount is not total_amount_cents", () => {
    const partial = [
      { file: "supabase/migrations/001.sql", sql: "create table public.quotes (id uuid primary key, total_amount integer, total_amount_cents integer);" },
      { file: "supabase/migrations/002.sql", sql: "alter table public.quotes drop column total_amount;" },
    ];
    expect(scan(partial, `export const list = () => supabase.from("quotes").select("id, total_amount_cents");`)).toEqual([]);
  });

  it("ignores a DROP that is only present in a comment", () => {
    const commented = [
      DROPPED[0]!,
      { file: "supabase/migrations/002.sql", sql: "-- alter table public.quotes drop column cruise_line;\nselect 1;" },
    ];
    expect(scan(commented, `export const list = () => supabase.from("quotes").select("id, cruise_line");`)).toEqual([]);
  });
});
