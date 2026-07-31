import { describe, expect, it } from "vitest";
import { detectDedupWithoutUniqueFindings, uniqueConstraints } from "./dedup-unique.js";

// #1257 / D-091 item 25. The intent under test is the FOLD — an app-side predicate read against a
// schema-side constraint set — so every case holds one side fixed and moves the other. A test that
// only exercised the app side would pass with the schema half deleted, which is the shape that made
// #1230 call this un-mechanical in the first place.

const SCHEMA = (extra = "") => [
  {
    file: "supabase/migrations/0001_init.sql",
    sql: `create table public.contacts (
  id uuid primary key,
  tenant_id uuid not null,
  external_ref text not null${extra ? `,\n  ${extra}` : ""}
);`,
  },
];

const DEDUP = `export async function findOrCreate(t, ref) {
  const { data: existing } = await supabase.from("contacts").select("id").eq("tenant_id", t).eq("external_ref", ref).maybeSingle();
  if (existing) return existing.id;
  const { data } = await supabase.from("contacts").insert({ tenant_id: t, external_ref: ref }).select("id").single();
  return data.id;
}`;

function run(text: string, sources = SCHEMA()) {
  return detectDedupWithoutUniqueFindings([{ path: "src/contacts.ts", text }], uniqueConstraints(sources));
}

describe("dedup-unique (#1257 — SELECT-then-INSERT dedup with no UNIQUE constraint)", () => {
  it("flags a read-then-insert whose predicate columns carry no unique constraint", () => {
    const findings = run(DEDUP);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review" });
    expect(findings[0]?.taxonomy).toBe("SELECT-then-INSERT dedup with no unique constraint");
    expect(findings[0]?.fix).toContain("unique (tenant_id, external_ref)");
  });

  // Same app code, schema moved. Each spelling is a separate parse path in uniqueConstraints.
  it.each([
    ["a table-level UNIQUE in the CREATE TABLE", SCHEMA("unique (tenant_id, external_ref)")],
    [
      "an ALTER TABLE ADD CONSTRAINT",
      [...SCHEMA(), { file: "supabase/migrations/0002.sql", sql: "alter table public.contacts add constraint contacts_ref_key unique (tenant_id, external_ref);" }],
    ],
    [
      "a CREATE UNIQUE INDEX",
      [...SCHEMA(), { file: "supabase/migrations/0002.sql", sql: "create unique index contacts_ref_idx on public.contacts (tenant_id, external_ref);" }],
    ],
    // A UNIQUE on a SUBSET of the columns read still makes the second insert fail, so it is
    // protection — which is why matching is subset-based and not equality-based.
    [
      "a column-level UNIQUE on one of the two columns read",
      [{ file: "supabase/migrations/0001_init.sql", sql: `create table public.contacts (\n  id uuid primary key,\n  tenant_id uuid not null,\n  external_ref text not null unique\n);` }],
    ],
  ])("stays silent when the schema declares %s", (_label, sources) => {
    expect(run(DEDUP, sources)).toEqual([]);
  });

  it("still fires when the only unique constraint covers a column the dedup does not read", () => {
    // The primary key is a unique constraint, and it is why equality-based matching would be wrong:
    // `unique (id)` says nothing about a predicate on (tenant_id, external_ref).
    expect(run(DEDUP, SCHEMA())).toHaveLength(1);
  });

  it("stays silent on a single-row read with no insert after it", () => {
    expect(
      run(`export async function lookup(t, ref) {
  const { data } = await supabase.from("contacts").select("id").eq("tenant_id", t).eq("external_ref", ref).maybeSingle();
  return data?.id ?? null;
}`),
    ).toEqual([]);
  });

  it("stays silent on the upsert remedy it recommends", () => {
    expect(
      run(`export async function upsert(t, ref) {
  const { data } = await supabase.from("contacts").upsert({ tenant_id: t, external_ref: ref }, { onConflict: "tenant_id,external_ref" }).select("id").single();
  return data.id;
}`),
    ).toEqual([]);
  });

  it("stays silent when the read and the insert are in different functions", () => {
    expect(
      run(`export async function read(t, ref) {
  const { data } = await supabase.from("contacts").select("id").eq("tenant_id", t).eq("external_ref", ref).maybeSingle();
  return data;
}
export async function write(t, ref) {
  return supabase.from("contacts").insert({ tenant_id: t, external_ref: ref });
}`),
    ).toEqual([]);
  });

  // The soundness rule that keeps this off every Supabase repo: "no constraint found" and "no
  // schema found" are the same silence, and the second is not a finding.
  it("stays silent on a table the schema never declared", () => {
    expect(run(DEDUP.replace(/contacts/g, "unknown_table"))).toEqual([]);
  });

  it("stays silent when no schema source was read at all", () => {
    expect(run(DEDUP, [])).toEqual([]);
  });

  it("drops a table's constraints when a later migration drops the table", () => {
    const dropped = uniqueConstraints([...SCHEMA("unique (tenant_id, external_ref)"), { file: "0002.sql", sql: "drop table public.contacts;" }]);
    expect(dropped.has("contacts")).toBe(false);
  });
});
