import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildDataMap, gatherProtectionFacts } from "../tools/pii-classify.mjs";
import { loadProtectionCatalog, type ProtectionCatalogOptions } from "./pii-protection-review-catalog.js";
import { piiProtectionFindings } from "./pii-protection-review.js";

const fixture = new URL("./scan/__fixtures__/m10-protection/schema.sql", import.meta.url);
const catalog = new URL("./scan/__fixtures__/m10-protection/catalog.json", import.meta.url);
const options: ProtectionCatalogOptions = { schemas: ["public", " private ", "pgtenant"], schemaSource: "explicit fixture allowlist", exposedSchemas: ["public", "private", "pgtenant"] };
type RecordedQuery = { tag: string; parameters: string[]; rows: Record<string, unknown>[] };
function replay(change?: (queries: RecordedQuery[]) => void) {
  const recorded = JSON.parse(readFileSync(catalog, "utf8")) as { fixtureSqlSha256: string; queries: RecordedQuery[] };
  expect(createHash("sha256").update(readFileSync(fixture)).digest("hex")).toBe(recorded.fixtureSqlSha256);
  change?.(recorded.queries);
  return async (query: string, parameters: string[] = []) => {
    const match = recorded.queries.find((r) => query.includes(r.tag) && JSON.stringify(parameters) === JSON.stringify(r.parameters));
    if (!match) throw new Error("unrecorded metadata query");
    return match.rows;
  };
}
function findings(result: Awaited<ReturnType<typeof loadProtectionCatalog>>) {
  return piiProtectionFindings(result.columns.filter((c) => c.column_name === "ssn" || c.column_name === "email").map((c) => ({ schema: c.table_schema, table: c.table_name, column: c.column_name, category: c.column_name === "ssn" ? "SENSITIVE_PII" as const : "PII" as const, infotype: c.column_name === "ssn" ? "US_SSN" : "EMAIL", encrypted: false })), result.facts);
}
const temporary: string[] = [];
afterEach(() => { for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe("M10 multi-schema catalog and protection evidence (#2134)", () => {
  it("preserves exact population and denied/unrestricted/conditional column twins through the shipping adapter", async () => {
    const result = await gatherProtectionFacts({ unsafe: replay() }, options);
    expect(result.columns).toHaveLength(11);
    expect(result.schemas.map((s) => [s.schema, s.status, s.relations, s.columns])).toEqual([
      ["public", "examined", 1, 1], ["private", "examined", 6, 9], ["pgtenant", "examined", 1, 1], ["unselected", "not-selected", 1, 1],
    ]);
    expect(result.detail).toContain("examined 3 schema(s), 8 relation(s), 11 column(s); unexamined 1 schema(s), 1 relation(s), 1 column(s)");
    const rows = findings(result);
    expect(rows.map((f) => f.location).sort()).toEqual(["pgtenant.customer.ssn", "private.encrypted_patient.ssn", "private.patient_conditional.ssn", "private.patient_open.ssn", "private.patient_view.ssn", "public.contacts.email"]);
    expect(rows.find((f) => f.location === "private.patient_open.ssn")).toMatchObject({ severity: "High", precisionTier: "review" });
    expect(rows.find((f) => f.location === "public.contacts.email")).toMatchObject({ severity: "Medium", precisionTier: "review" });
    expect(rows.find((f) => f.location === "private.patient_conditional.ssn")!.evidence).toContain("SELECT=conditional");
    expect(result.facts.columnAccess!.find((c) => c.table === "patient" && c.column === "nickname")!.principals[0]!.read).toBe("all");
    expect(result.detail).toContain("absence does not establish plaintext");
  });

  it("retains discovered non-public denominators when only public is authorized", async () => {
    const result = await loadProtectionCatalog(replay(), { ...options, schemas: ["public"] });
    expect(result.columns).toHaveLength(1);
    expect(result.schemas.find((s) => s.schema === "private")).toMatchObject({ status: "not-selected", relations: 6, columns: 9 });
    expect(result.detail).toContain("unexamined 3 schema(s), 8 relation(s), 11 column(s)");
  });

  it("keeps sensitivity maps distinct for the same table name in different schemas", () => {
    const map = buildDataMap([{ table_schema: "public", table_name: "patient", column_name: "email" }, { table_schema: "private", table_name: "patient", column_name: "ssn" }]);
    expect(Object.keys(map)).toEqual(["public.patient", "private.patient"]);
    expect(map["public.patient"]!.columns.map((c) => c.column)).toEqual(["email"]);
    expect(map["private.patient"]!.columns.map((c) => c.column)).toEqual(["ssn"]);
  });

  it.each(["query-failure", "count-mismatch", "duplicate-column"])("discloses partial private inventory for %s", async (failure) => {
    const base = replay((queries) => {
      const row = queries.find((q) => q.tag === "harvey-m10-columns-v1" && q.parameters[0] === "private")!;
      if (failure === "query-failure") row.tag = "unavailable";
      else if (failure === "count-mismatch") row.rows.pop();
      else row.rows[1] = row.rows[0]!;
    });
    const result = await loadProtectionCatalog(base, options);
    expect(result.columns).toHaveLength(2);
    expect(result.schemas.find((s) => s.schema === "private")).toMatchObject({ status: "unavailable", columns: 9 });
    expect(result.detail).toContain("no absence or clean result is inferred");
    expect(result.detail).toContain("Falsifier:");
  });

  it("uses unknown denominators when the schema census is unavailable", async () => {
    const result = await loadProtectionCatalog(replay((qs) => { qs.find((q) => q.tag === "harvey-m10-schemas-v1")!.tag = "unavailable"; }), options);
    expect(result.columns).toHaveLength(11);
    expect(result.detail).toContain("unexamined unknown schema(s), unknown relation(s), unknown column(s)");
  });

  it("does not turn missing API configuration or authorization into clearance", async () => {
    const result = await loadProtectionCatalog(replay((qs) => { qs.find((q) => q.tag === "harvey-effective-authorization-v1")!.rows = []; }), { ...options, exposedSchemas: undefined });
    expect(result.facts.apiConfigurationKnown).toBe(false);
    expect(findings(result)).toHaveLength(8);
    expect(findings(result).every((f) => f.evidence.includes("unavailable"))).toBe(true);
  });

  it.each(["missing-column", "duplicate-column"])("rejects an incomplete principal column matrix: %s", async (kind) => {
    const result = await loadProtectionCatalog(replay((qs) => {
      const auth = qs.find((q) => q.tag === "harvey-effective-authorization-v1")!.rows[0]!.authorization as { tables: { name: string; role: string; columns: { name: string }[] }[] };
      const row = auth.tables.find((t) => t.name === "patient" && t.role === "anon")!;
      if (kind === "missing-column") row.columns.pop(); else row.columns[1] = row.columns[0]!;
    }), options);
    expect(result.facts.columnAccess).toEqual([]);
    expect(findings(result)).toHaveLength(8);
  });

  it("records encryption labels as configuration without certifying encrypted bytes", async () => {
    const result = await loadProtectionCatalog(replay((qs) => { qs.find((q) => q.tag === "harvey-m10-encryption-config-v1")!.rows.push({ schema: "private", relation: "patient_open", column: "ssn", provider: "pgsodium", encryption_configured: true }); }), options);
    expect(result.detail).toContain("configuration observed for 1 selected column(s): private.patient_open.ssn");
    expect(findings(result).some((f) => f.location === "private.patient_open.ssn")).toBe(true);
  });

  it("binds reviewed source references to file bytes without claiming crypto correctness", async () => {
    const root = mkdtempSync("/tmp/harvey-m10-source-boundary-"); temporary.push(root);
    const source = readFileSync(new URL("./scan/__fixtures__/m10-protection/encrypt-patient.mjs.txt", import.meta.url));
    writeFileSync(join(root, "encrypt.mjs"), source);
    const ref = { schema: "private", table: "encrypted_patient", column: "ssn", path: "encrypt.mjs", line: 2, sha256: createHash("sha256").update(source).digest("hex") };
    const manifest = join(root, "boundaries.json"); writeFileSync(manifest, JSON.stringify([ref]));
    const result = await loadProtectionCatalog(replay(), { ...options, sourceRoot: root, boundaryManifest: manifest });
    expect(result.detail).toContain("1 source reference(s) checked against file bytes");
    expect(result.detail).toContain("not cryptographic behavior");
    expect(findings(result).some((f) => f.location === "private.encrypted_patient.ssn")).toBe(true);
    writeFileSync(join(root, "encrypt.mjs"), "// Changed source, retaining the referenced line.\nexport const encryptPatient = value => value;\n");
    expect((await loadProtectionCatalog(replay(), { ...options, sourceRoot: root, boundaryManifest: manifest })).detail).toContain("did not match file bytes");
  });
});
