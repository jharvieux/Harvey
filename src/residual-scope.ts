import { readFileSync } from "node:fs";
import { extname, relative, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import { parseLivePolicies, parseLiveTableNames } from "./migration-sql-parse.js";

export const RESIDUAL_SCOPE_STATUSES = ["implemented", "manual-review", "owned-follow-up", "intentional-exclusion"] as const;
export type ResidualScopeStatus = (typeof RESIDUAL_SCOPE_STATUSES)[number];
export type ResidualScopeDomain = "sql" | "source" | "cache" | "m9" | "vitals" | "database-drift";

export interface ResidualScopeRow {
  id: string;
  domain: ResidualScopeDomain;
  status: ResidualScopeStatus;
  title: string;
  population: { examined: number; unresolved: number; files: string[]; parseFailures?: { file: string; reason: string }[] };
  coverage: string;
  owner?: string;
  reason: string;
  provenance: string;
  falsifier: string;
  nextStep: string;
}

export interface ResidualScopeInventory {
  schemaVersion: 1;
  target: { revision: string; label?: string };
  generatedAt: string;
  summary: { rows: number; implemented: number; unresolved: number; filesExamined: number };
  rows: ResidualScopeRow[];
}

interface PriorFinding { id?: string; title?: string; evidence?: string }
interface BuildOptions { revision: string; label?: string; generatedAt?: string; priorFindings?: PriorFinding[]; vitalsArtifact?: unknown }

const EXCLUDED_DIR = /^(node_modules|\.git|\.next|\.stryker-tmp|\.pnpm-store|dist|build|coverage|out|vendor|venv|\.venv|__pycache__|target)$/;

function targetFiles(root: string): string[] {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readEntriesSafe(dir).entries) {
      if (entry.isDirectory) {
        if (!EXCLUDED_DIR.test(entry.name)) walk(entry.path);
      } else files.push(relative(root, entry.path).split(sep).join("/"));
    }
  };
  walk(root);
  return files.sort();
}

export type SqlPlacement = "supabase-migration" | "schema-snapshot" | "seed-or-fixture" | "unrelated-sql";
export function classifySqlPlacement(path: string): SqlPlacement {
  const lower = path.toLowerCase();
  if (/(^|\/)supabase\/migrations\/[^/]+\.sql$/.test(lower)) return "supabase-migration";
  if (/(^|\/)(schema\.sql|prisma\/migrations\/[^/]+\/migration\.sql)$/.test(lower)) return "schema-snapshot";
  if (/(^|\/)(seeds?|fixtures?|tests?|examples?|backups?|dumps?)\//.test(lower) || /(^|\/)(seed|backup|dump)[^/]*\.sql$/.test(lower)) return "seed-or-fixture";
  return "unrelated-sql";
}

export type PythonRole = "application-service" | "maintenance-tool" | "unknown-manual-review";
export function classifyPythonRole(path: string, text: string): PythonRole {
  if (/(^|\/)(codemods?|scripts?|tools?|migrations?|fixtures?|docs?)\//i.test(path)) return "maintenance-tool";
  if (/\b(?:from|import)\s+(?:django|flask|fastapi|celery|sqlalchemy)\b/.test(text)) return "application-service";
  return "unknown-manual-review";
}

function disclosure(findings: PriorFinding[], id: string): PriorFinding | undefined {
  return findings.find((finding) => finding.id === id || finding.id?.startsWith(`${id}@`));
}

function countFromEvidence(finding: PriorFinding | undefined, pattern: RegExp): number {
  return Number(pattern.exec(finding?.evidence ?? "")?.[1] ?? 0);
}

function vitalsPopulation(vitals: unknown): { files: string[]; complete: boolean; detail: string } {
  if (!vitals || typeof vitals !== "object") return { files: [], complete: false, detail: "No Vitals machine artifact was supplied." };
  const value = vitals as Record<string, unknown>;
  const explicit = [value.population, value.files].find(Array.isArray) as unknown[] | undefined;
  const health = value.file_health && typeof value.file_health === "object" && !Array.isArray(value.file_health) ? Object.keys(value.file_health as Record<string, unknown>) : undefined;
  const files = health ?? (explicit ?? []).map((row) => typeof row === "string" ? row : row && typeof row === "object" ? String((row as Record<string, unknown>).path ?? (row as Record<string, unknown>).file ?? "") : "").filter(Boolean);
  // Vitals 0.2.0's file_health contract is one entry per scored code file and is not display-capped.
  // The capped hotspots/knowledge/coupling projections remain separate and are never called full.
  const historicalOnly = value.currentSourceExamined === false;
  const complete = !historicalOnly && (health !== undefined || value.populationComplete === true || value.completePopulation === true);
  return { files, complete, detail: historicalOnly ? `Historical cache population retained (${files.length} paths), but it did not freshly examine the bound source revision and cannot replace the empty recorded raw capture.` : health !== undefined ? "Vitals file_health is the complete scored-file machine population; capped hotspot, coupling and knowledge projections remain separate." : complete ? "Artifact declares a complete population." : "Artifact does not declare its population complete." };
}

export function buildResidualScopeInventory(root: string, options: BuildOptions): ResidualScopeInventory {
  const files = targetFiles(root);
  const findings = options.priorFindings ?? [];
  const sql = files.filter((file) => extname(file).toLowerCase() === ".sql");
  const migrationFiles = sql.filter((file) => classifySqlPlacement(file) === "supabase-migration");
  const snapshots = sql.filter((file) => classifySqlPlacement(file) === "schema-snapshot");
  const excludedSql = sql.filter((file) => !migrationFiles.includes(file) && !snapshots.includes(file));
  const migrationGroups = new Map<string, { file: string; sql: string }[]>();
  for (const file of migrationFiles) {
    const marker = file.toLowerCase().lastIndexOf("supabase/migrations/");
    const project = file.slice(0, marker + "supabase/migrations/".length);
    migrationGroups.set(project, [...(migrationGroups.get(project) ?? []), { file, sql: readFileSync(`${root}/${file}`, "utf8") }]);
  }
  const policyParses = [...migrationGroups.values()].map((inputs) => parseLivePolicies(inputs));
  const parsedPolicies = policyParses.flatMap((result) => result.policies);
  const unparsedPolicies = policyParses.flatMap((result) => result.unparsed);
  const liveTables = [...migrationGroups.values()].flatMap((inputs) => parseLiveTableNames(inputs.map((input) => input.sql).join("\n")));
  const pythonFiles = files.filter((file) => extname(file).toLowerCase() === ".py");
  const pythonByRole = new Map<PythonRole, string[]>();
  for (const file of pythonFiles) {
    const role = classifyPythonRole(file, readFileSync(`${root}/${file}`, "utf8"));
    pythonByRole.set(role, [...(pythonByRole.get(role) ?? []), file]);
  }
  const cache = disclosure(findings, "CACHE-SCOPE-00");
  const cacheUnscoped = countFromEvidence(cache, /(\d+) read-through cache get\/set pair/);
  const cacheWrites = countFromEvidence(cache, /(\d+) cache write/);
  const m9Rows = findings.filter((finding) => finding.id?.startsWith("M9-") && /excluded by policy/i.test(finding.title ?? ""));
  const m9Pairs = m9Rows.reduce((sum, finding) => sum + Number(/(\d+) of \d+ adjacent query pairs excluded/i.exec(`${finding.title ?? ""} ${finding.evidence ?? ""}`)?.[1] ?? 0), 0);
  const vitals = vitalsPopulation(options.vitalsArtifact);

  const rows: ResidualScopeRow[] = [
    {
      id: "sql-supported-schema-surfaces", domain: "sql", status: unparsedPolicies.length ? "owned-follow-up" : "implemented",
      title: "Supported migration and schema SQL placements", population: { examined: migrationFiles.length + snapshots.length, unresolved: unparsedPolicies.length, files: [...migrationFiles, ...snapshots], parseFailures: unparsedPolicies.map((row) => ({ file: `${row.file}:${row.line}`, reason: row.reason })) },
      coverage: `Lifecycle-aware table/policy identity parsing examined ${migrationFiles.length} migration files in ${migrationGroups.size} independent project history stream(s) and derived ${liveTables.length} live tables and ${parsedPolicies.length} live policies. Schema snapshots remain distinct from ordered migration history.`,
      ...(unparsedPolicies.length ? { owner: "#2142" } : {}), reason: unparsedPolicies.length ? "Policy clauses with incomplete statements or unbalanced parentheses cannot be judged safely." : "Every supported migration file was parsed without a retained policy parse failure.",
      provenance: "Residual scope CLI filesystem census plus migration-sql-parse lifecycle fold.", falsifier: "Add a supported migration with an unreadable policy or remove a migration from the census; the unresolved count or examined population must change.",
      nextStep: unparsedPolicies.length ? "Repair the listed SQL statements or extend the bounded parser shape, then regenerate." : "Regenerate after migration changes.",
    },
    {
      id: "sql-non-schema-surfaces", domain: "sql", status: excludedSql.length ? "intentional-exclusion" : "implemented", title: "SQL outside supported schema placements",
      population: { examined: excludedSql.length, unresolved: excludedSql.length, files: excludedSql }, coverage: "Every remaining SQL file is retained and classified; seed, fixture, dump, and unrelated SQL is not folded into deployed schema state.",
      reason: excludedSql.length ? "Treating arbitrary SQL as ordered schema history creates false live-table and policy claims." : "The complete SQL census found no files outside supported schema placements.", provenance: "Complete target .sql path census with placement classification.",
      falsifier: "Move a file under a supported Supabase migration placement or name it as a schema snapshot; regeneration must move it to the supported row.", nextStep: "Review only files known to define deployed schema; otherwise retain this intentional exclusion.",
    },
    ...([...pythonByRole.entries()].map(([role, roleFiles]): ResidualScopeRow => ({
      id: `python-${role}`, domain: "source", status: role === "maintenance-tool" ? "intentional-exclusion" : "manual-review", title: `Python source classified as ${role}`,
      population: { examined: roleFiles.length, unresolved: role === "maintenance-tool" ? 0 : roleFiles.length, files: roleFiles }, coverage: role === "maintenance-tool" ? "Path evidence identifies bounded tooling/codemod source; it is not represented as a tenant-serving application." : "No JS/TS tenant-isolation adapter claims coverage over this source.",
      ...(role === "maintenance-tool" ? {} : { owner: "#871" }), reason: role === "maintenance-tool" ? "Maintenance tools are outside request-serving tenant boundary analysis unless runtime evidence says otherwise." : "Framework evidence is insufficient for an automatic tenant-boundary judgment.",
      provenance: "Complete .py path census plus framework import classification.", falsifier: "Move the file into an application surface or add a supported server-framework import; regeneration must reclassify it.", nextStep: role === "maintenance-tool" ? "Confirm tooling-only use during review." : "Review database and privileged-client access manually or add a framework adapter.",
    }))),
    {
      id: "cache-alias-and-unpaired", domain: "cache", status: cacheUnscoped + cacheWrites ? "manual-review" : "implemented", title: "Cache aliases and unpaired writes",
      population: { examined: cacheUnscoped + cacheWrites, unresolved: cacheUnscoped + cacheWrites, files: [] }, coverage: `Shipping CACHE-SCOPE-00 measured ${cacheUnscoped} unscoped read-through pairs and ${cacheWrites} unpaired writes in the supplied findings artifact.`, owner: "#1196",
      reason: "Receiver aliases and write-only sites do not prove shared reads or tenant exposure.", provenance: cache?.id ? `Finding ${cache.id} from the supplied engagement artifact.` : "No CACHE-SCOPE-00 finding was supplied.", falsifier: "Run the shipping cache detector after adding a recognized tenant discriminator or matching read; the measured unresolved count must fall.", nextStep: "Review the measured sites for tenant keying and declare project-specific cache aliases where needed.",
    },
    {
      id: "m9-guarded-query-pairs", domain: "m9", status: m9Pairs ? "intentional-exclusion" : "implemented", title: "Guarded query pairs excluded from parallelization",
      population: { examined: m9Pairs, unresolved: m9Pairs, files: [] }, coverage: `${m9Rows.length} shipping M9 disclosure row(s) account for ${m9Pairs} guarded pairs.`,
      reason: m9Pairs ? "Hoisting a query across a return/break/continue guard, or a write across an error guard, changes which requests execute side effects. No optimization is recommended without pair-specific equivalence and side-effect proof." : "The supplied shipping artifact contains no policy-excluded guarded-pair population; no exclusion limit is claimed.", provenance: "Supplied shipping M9 disclosure findings.", falsifier: "Add a shipping policy-exclusion disclosure; regeneration must record its measured pair count.", nextStep: m9Pairs ? "Keep guarded writes sequential; manually assess read-only pairs when latency justifies it." : "Regenerate when the M9 population changes.",
    },
    {
      id: "vitals-complete-population", domain: "vitals", status: vitals.complete ? "implemented" : "owned-follow-up", title: "Traceable Vitals full population export",
      population: { examined: vitals.files.length, unresolved: vitals.complete ? 0 : 1, files: vitals.files }, coverage: `${vitals.detail} The inventory retains the complete supplied path list rather than a display cap.`, owner: vitals.complete ? undefined : "#2135",
      reason: vitals.complete ? "The producer explicitly bound completeness to the machine export." : "A top-K list or an unmarked file list cannot prove the full population.", provenance: "Supplied Vitals machine artifact.", falsifier: "Remove the completeness marker or one source path; validation must reject or report the export as incomplete.", nextStep: vitals.complete ? "Use concise report rollups while retaining this full machine list." : "Supply the accepted #2135 complete population artifact and regenerate.",
    },
    {
      id: "database-drift-table-policy-rls", domain: "database-drift", status: "implemented", title: "Deployed table, policy and RLS-state identity drift",
      population: { examined: 3, unresolved: 0, files: migrationFiles }, coverage: "The connected supabase-drift producer compares table identities, policy identities and final RLS enabled state for explicitly queried schemas.",
      reason: "These are identity and boolean-state contracts; agreement does not imply column or behavioral equivalence.", provenance: "src/scan/supabase-drift.ts shipping producer.", falsifier: "Remove an authorized live catalog response or migration expectation; SB-DRIFT-00 must disclose the unassessed schema instead of claiming agreement.", nextStep: "Keep the three populations and authorized schema counts in the connected receipt.",
    },
    {
      id: "database-drift-app-column-usage", domain: "database-drift", status: "implemented", title: "Migration-to-application dropped or renamed column usage",
      population: { examined: migrationFiles.length, unresolved: 0, files: migrationFiles }, coverage: "migration-column-drift folds DROP/RENAME/ADD history and checks literal PostgREST .from(table) query-chain column names in shipping JS/TS source.",
      reason: "This is an app-contract check over migration history, not a deployed-catalog column comparison.", provenance: "src/scan/migration-column-drift.ts shipping producer.", falsifier: "Reference a finally dropped literal column inside a matching .from(table) chain; the producer must emit SCHEMA-dropped-column-read.", nextStep: "Retain its literal-query boundary separately from connected database drift.",
    },
    {
      id: "database-drift-deployed-column-shape", domain: "database-drift", status: "owned-follow-up", title: "Deployed column identity and nullability drift",
      population: { examined: 0, unresolved: 1, files: migrationFiles }, coverage: "The current connected drift query does not fetch deployed columns or nullability; table agreement cannot clear this class.", owner: "#2142",
      reason: "No complete authorized live-column population is present in the supplied artifacts.", provenance: "Negative capability census of src/scan/supabase-drift.ts and the supplied connected artifacts.", falsifier: "A bound connected receipt containing complete authorized live-column identities/nullability plus migration expectations makes this class comparable.", nextStep: "Add a read-only catalog adapter and compare this population independently of table/policy identity.",
    },
    {
      id: "database-drift-deployed-semantics", domain: "database-drift", status: "intentional-exclusion", title: "Deployed type, default, constraint, index, trigger and function drift",
      population: { examined: 0, unresolved: 1, files: migrationFiles }, coverage: "No claim is made for semantic database objects beyond the explicitly implemented identity/RLS contracts.",
      reason: "Those object families require separate canonicalization and authorized catalog populations; inferring them from table presence would create false equivalence.", provenance: "Bounded consumer census of current connected drift queries.", falsifier: "Introduce a complete, canonicalized, receipt-bound live population for one object family; that family can move to its own implemented row.", nextStep: "Add object families individually when a precise comparison contract and negative fixtures exist.",
    },
  ];
  const inventory: ResidualScopeInventory = {
    schemaVersion: 1, target: { revision: options.revision, ...(options.label ? { label: options.label } : {}) }, generatedAt: options.generatedAt ?? new Date().toISOString(),
    summary: { rows: rows.length, implemented: rows.filter((row) => row.status === "implemented").length, unresolved: rows.reduce((sum, row) => sum + row.population.unresolved, 0), filesExamined: files.length }, rows,
  };
  const errors = residualScopeErrors(inventory);
  if (errors.length) throw new Error(errors.join("\n"));
  return inventory;
}

export function residualScopeErrors(value: unknown): string[] {
  if (!value || typeof value !== "object") return ["residualScope: expected an object"];
  const inventory = value as Partial<ResidualScopeInventory>;
  const errors: string[] = [];
  if (inventory.schemaVersion !== 1) errors.push("residualScope.schemaVersion: expected 1");
  if (!inventory.target?.revision) errors.push("residualScope.target.revision: required");
  if (!Array.isArray(inventory.rows)) return [...errors, "residualScope.rows: expected an array"];
  const ids = new Set<string>();
  for (const [index, row] of inventory.rows.entries()) {
    const at = `residualScope.rows[${index}]`;
    if (!row.id || ids.has(row.id)) errors.push(`${at}.id: required and unique`); else ids.add(row.id);
    if (!RESIDUAL_SCOPE_STATUSES.includes(row.status)) errors.push(`${at}.status: invalid`);
    if (!row.reason || !row.provenance || !row.falsifier || !row.nextStep) errors.push(`${at}: reason, provenance, falsifier and nextStep are required`);
    if ((row.status === "manual-review" || row.status === "owned-follow-up") && !row.owner) errors.push(`${at}.owner: required for unresolved owned work`);
    if (!row.population || !Number.isInteger(row.population.examined) || !Number.isInteger(row.population.unresolved) || !Array.isArray(row.population.files)) errors.push(`${at}.population: invalid`);
  }
  if (inventory.summary) {
    const unresolved = inventory.rows.reduce((sum, row) => sum + (row.population?.unresolved ?? 0), 0);
    if (inventory.summary.rows !== inventory.rows.length || inventory.summary.unresolved !== unresolved) errors.push("residualScope.summary: row and unresolved populations must reconcile");
  } else errors.push("residualScope.summary: required");
  return errors;
}
