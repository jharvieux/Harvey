import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { loadEffectiveAuthorization } from "./scan/supabase-authorization.js";
import type { ExposureFacts } from "./pii-protection-review.js";

export interface InventoryColumn {
  table_schema: string;
  table_name: string;
  column_name: string;
  data_type: string;
  relation_kind: string;
}
export interface SchemaInventory {
  schema: string;
  status: "examined" | "not-selected" | "unavailable";
  relations: number | null;
  columns: number | null;
  reason: string;
}
export interface ProtectionCatalog {
  columns: InventoryColumn[];
  schemas: SchemaInventory[];
  facts: ExposureFacts;
  detail: string;
  limitations: string[];
}
type Query = (sql: string, parameters?: string[]) => Promise<Record<string, unknown>[]>;
export interface ProtectionCatalogOptions {
  schemas: string[];
  schemaSource: string;
  exposedSchemas?: string[];
  sourceRoot?: string;
  boundaryManifest?: string;
}

const SCHEMAS = `/* harvey-m10-schemas-v1 */
SELECT n.nspname AS schema, count(DISTINCT c.oid)::int AS relations,
 count(a.attnum)::int AS columns
FROM pg_namespace n
LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relkind IN ('r','p','v','m','f')
LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'
GROUP BY n.nspname ORDER BY n.nspname`;
const COLUMNS = `/* harvey-m10-columns-v1 */
SELECT n.nspname AS table_schema, c.relname AS table_name, a.attname AS column_name,
 pg_catalog.format_type(a.atttypid,a.atttypmod) AS data_type, c.relkind AS relation_kind
FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f')
ORDER BY c.relname,a.attnum`;
const LABELS = `/* harvey-m10-encryption-config-v1 */
SELECT n.nspname AS schema,c.relname AS relation,a.attname AS column,s.provider,
 (s.label ~* '^ENCRYPT[[:space:]]+WITH[[:space:]]+KEY') AS encryption_configured
FROM pg_seclabel s JOIN pg_class c ON s.classoid='pg_class'::regclass AND s.objoid=c.oid
JOIN pg_namespace n ON c.relnamespace=n.oid
JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=s.objsubid
WHERE s.provider='pgsodium' AND n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'`;

function failure(label: string): string {
  return `${label} unavailable: query failed or returned an unsupported shape; no absence or clean result is inferred. Falsifier: rerun the named read-only catalog query with complete catalog visibility. Next step: provide its non-secret output and access scope.`;
}
function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function isColumn(value: Record<string, unknown>): value is Record<string, unknown> & InventoryColumn {
  return ["table_schema", "table_name", "column_name", "data_type", "relation_kind"].every((field) => typeof value[field] === "string" && value[field] !== "");
}
export function reviewSourceEncryptionBoundaries(options: Pick<ProtectionCatalogOptions, "sourceRoot" | "boundaryManifest">): string {
  const prefix = "Source encryption boundaries";
  if (!options.boundaryManifest) return `${prefix} unassessed: no reviewed source-reference manifest supplied. Falsifier: supply --source-root and --encryption-boundaries with schema/table/column/path/sha256/line references. Next step: review all relevant write, read and decrypt paths using synthetic inputs.`;
  try {
    if (!options.sourceRoot) throw new Error("source root required");
    const root = realpathSync(options.sourceRoot);
    const raw: unknown = JSON.parse(readFileSync(options.boundaryManifest, "utf8"));
    if (!Array.isArray(raw) || raw.length === 0 || raw.length > 1000) throw new Error("unsupported manifest");
    const refs = raw.map((item: unknown) => {
      if (typeof item !== "object" || item === null) throw new Error("invalid reference");
      const r = item as Record<string, unknown>;
      if (!["schema", "table", "column", "path", "sha256"].every((key) => typeof r[key] === "string" && r[key] !== "") || !Number.isSafeInteger(r.line) || Number(r.line) < 1) throw new Error("invalid reference");
      const path = r.path as string;
      const digest = r.sha256 as string;
      if (isAbsolute(path) || !/^[a-f0-9]{64}$/.test(digest)) throw new Error("invalid source identity");
      const file = realpathSync(resolve(root, path));
      const rel = relative(root, file);
      if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("source escapes root");
      const bytes = readFileSync(file);
      if (createHash("sha256").update(bytes).digest("hex") !== digest || Number(r.line) > bytes.toString("utf8").split(/\r?\n/).length) throw new Error("source reference mismatch");
      return `${r.schema}.${r.table}.${r.column} at ${path}:${r.line} sha256=${digest}`;
    });
    return `${prefix}: ${refs.length} source reference(s) checked against file bytes: ${refs.join("; ")}. This verifies reference integrity, not cryptographic behavior, key management or complete path coverage. Falsifier for unassessed behavior: a reviewed write/read/decrypt trace and paired synthetic runtime controls. Next step: review each referenced path and enumerate bypasses; a declaration or encryption API name alone is insufficient.`;
  } catch {
    return `${prefix} unassessed: supplied references were invalid, unreadable, outside the source root, or did not match file bytes. Falsifier: valid root-contained references with matching SHA-256 and line bounds. Next step: refresh the non-secret source-reference manifest.`;
  }
}

/** Catalog-only inventory. Query failures remain visible, including partial schema failures. */
export async function loadProtectionCatalog(query: Query, options: ProtectionCatalogOptions): Promise<ProtectionCatalog> {
  const selected = [...new Set(options.schemas.map((s) => s.trim()).filter(Boolean))];
  if (!selected.length) throw new Error("M10 requires at least one authorized product schema");
  const limitations: string[] = [];
  const schemas: SchemaInventory[] = [];
  let catalog: Record<string, unknown>[] | undefined;
  try {
    catalog = await query(SCHEMAS);
    if (!Array.isArray(catalog) || catalog.some((r) => typeof r.schema !== "string" || !count(r.relations) || !count(r.columns)) || new Set(catalog.map((r) => r.schema)).size !== catalog.length) throw new Error("invalid schema catalog");
  } catch { catalog = undefined; limitations.push(failure("pg_namespace/pg_class/pg_attribute schema census")); }
  const columns: InventoryColumn[] = [];
  for (const schema of selected) {
    const observed = catalog?.find((r) => r.schema === schema);
    if (catalog && !observed) {
      schemas.push({ schema, status: "unavailable", relations: null, columns: null, reason: "Selected schema was not found in the catalog; no inventory was performed." });
      continue;
    }
    try {
      const rows = await query(COLUMNS, [schema]);
      if (!rows.every(isColumn) || rows.some((r) => r.table_schema !== schema) || (observed && rows.length !== observed.columns) || new Set(rows.map((r) => JSON.stringify([r.table_name, r.column_name]))).size !== rows.length) throw new Error("incomplete column inventory");
      columns.push(...rows);
      schemas.push({ schema, status: "examined", relations: observed ? observed.relations as number : new Set(rows.map((r) => r.table_name)).size, columns: rows.length, reason: "Catalog names/types examined; no relation rows queried." });
    } catch {
      schemas.push({ schema, status: "unavailable", relations: observed ? observed.relations as number : null, columns: observed ? observed.columns as number : null, reason: failure(`Column inventory for ${schema}`) });
    }
  }
  for (const row of catalog ?? []) {
    if (!selected.includes(row.schema as string)) schemas.push({ schema: row.schema as string, status: "not-selected", relations: row.relations as number, columns: row.columns as number, reason: "Outside the configured authorized product-schema allowlist; names/types and protection were not assessed." });
  }
  let exposed = options.exposedSchemas?.map((s) => s.trim()).filter(Boolean);
  let configuration = "operator-supplied --exposed-schemas / PII_EXPOSED_SCHEMAS (not independently verified against the API deployment)";
  if (exposed === undefined) {
    try {
      const rows = await query("/* harvey-m10-api-config-v1 */ SELECT current_setting('pgrst.db_schemas',true) AS schemas");
      const setting = rows[0]?.schemas;
      if (typeof setting !== "string" || !setting.trim()) throw new Error("unavailable API setting");
      exposed = setting.split(",").map((s) => s.trim()).filter(Boolean);
      configuration = "database current_setting('pgrst.db_schemas',true); external PostgREST configuration/reloads remain unverified";
    } catch { limitations.push("API schema configuration unassessed: no explicit list or readable pgrst.db_schemas setting. Falsifier: supply the deployed API schema list and its provenance. Next step: provide --exposed-schemas or PII_EXPOSED_SCHEMAS from deployment configuration."); }
  }
  const authorization = await loadEffectiveAuthorization((text) => query(text), exposed);
  if (!authorization.tables.length) limitations.push(failure("Effective column authorization"));
  const selectedTables = authorization.tables.filter((t) => selected.includes(t.schema));
  const conditional = selectedTables.flatMap((t) => t.columns).filter((c) => c.principals.some((p) => p.read === "conditional")).length;
  if (conditional) limitations.push(`${conditional} table column(s) have conditional row policies: row predicates/caller context unassessed. Falsifier: paired allowed/denied synthetic role/context queries. Next step: review policy predicates with the application authorization owner.`);
  const unsupported = columns.filter((c) => !["r", "p"].includes(c.relation_kind));
  if (unsupported.length) limitations.push(`${unsupported.length} column(s) belong to views, materialized views or foreign tables; effective read/decrypt/owner behavior unassessed. Falsifier: traced underlying grants, view security mode and synthetic caller controls. Next step: review these relation definitions and RPC paths.`);
  let encryption = "";
  try {
    const rows = await query(LABELS);
    if (!rows.every((r) => ["schema", "relation", "column", "provider"].every((key) => typeof r[key] === "string") && typeof r.encryption_configured === "boolean")) throw new Error("unsupported labels");
    const observed = rows.filter((r) => selected.includes(r.schema as string) && r.encryption_configured);
    encryption = `pg_seclabel pgsodium encryption configuration observed for ${observed.length} selected column(s)${observed.length ? `: ${observed.map((r) => `${r.schema}.${r.relation}.${r.column}`).join(", ")}` : ""}. Labels are configuration evidence, not proof of write coverage or safe decrypted views; absence does not establish plaintext.`;
  } catch { encryption = failure("pg_seclabel encryption configuration"); }
  limitations.push("Storage/backups and key management unassessed by database catalogs. Falsifier: scoped non-secret infrastructure/control attestations with synthetic restore and key-access evidence. Next step: obtain those attestations from the infrastructure owner.");
  limitations.push(reviewSourceEncryptionBoundaries(options));
  const examined = schemas.filter((s) => s.status === "examined");
  const unexamined = schemas.filter((s) => s.status !== "examined");
  const total = (rows: SchemaInventory[], key: "relations" | "columns") => rows.some((r) => r[key] === null) ? "unknown" : String(rows.reduce((n, r) => n + r[key]!, 0));
  const detail = [
    `Authorized product schemas: ${selected.join(", ")} (${options.schemaSource}).`,
    `Inventory: examined ${examined.length} schema(s), ${total(examined, "relations")} relation(s), ${total(examined, "columns")} column(s); unexamined ${catalog ? unexamined.length : "unknown"} schema(s), ${catalog ? total(unexamined, "relations") : "unknown"} relation(s), ${catalog ? total(unexamined, "columns") : "unknown"} column(s).`,
    ...schemas.map((s) => `${s.schema}: ${s.status}, relations=${s.relations ?? "unknown"}, columns=${s.columns ?? "unknown"}. ${s.reason}`),
    `API schemas: ${exposed?.join(", ") ?? "unknown"}; provenance: ${exposed ? configuration : "unavailable"}.`,
    `Effective access: pg_catalog role membership, schema USAGE, exact column/table SELECT, RLS policies, owners, FORCE and BYPASSRLS; ${selectedTables.length} selected table(s).`,
    encryption,
    ...limitations,
  ].join(" ");
  return {
    columns, schemas, limitations, detail,
    facts: {
      exposedSchemas: exposed ?? [], autoExposedTables: [], apiConfigurationKnown: exposed !== undefined,
      columnAccess: selectedTables.flatMap((t) => t.columns.map((c) => ({ schema: t.schema, table: t.name, column: c.name, principals: c.principals }))),
      provenance: "read-only pg_catalog effective authorization; " + (exposed ? configuration : "API configuration unavailable"),
    },
  };
}
