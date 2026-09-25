import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { extname, isAbsolute, join, relative, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import { parseLivePolicies, parseLiveTableNames, schemaSqlParseFailures } from "./migration-sql-parse.js";

const RESIDUAL_SCOPE_STATUSES = ["implemented", "manual-review", "owned-follow-up", "intentional-exclusion"] as const;
type ResidualScopeStatus = (typeof RESIDUAL_SCOPE_STATUSES)[number];
type ResidualScopeDomain = "sql" | "source" | "cache" | "m9" | "vitals" | "database-drift";

export interface ResidualScopeRow {
  id: string;
  domain: ResidualScopeDomain;
  status: ResidualScopeStatus;
  title: string;
  population: { examined: number; unresolved: number; files: string[]; parseFailures?: { file: string; reason: string }[]; binding?: { revision: string; declared: number; pathsSha256: string; artifactSha256: string } };
  sourceFindingIds?: string[];
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

interface PriorFinding { id?: string; title?: string; evidence?: string; category?: string; taxonomy?: string; confidence?: string; location?: string; fix?: string }
interface BuildOptions { revision: string; label?: string; generatedAt?: string; priorFindings?: PriorFinding[]; vitalsArtifact?: unknown; vitalsArtifactSha256?: string }

/** The supplied limitation population retained by the inventory and checked by document validation. */
export function residualScopeDisclosures(findings: readonly unknown[]): PriorFinding[] {
  return findings.filter((input): input is PriorFinding => {
    if (!input || typeof input !== "object") return false;
    const row = input as PriorFinding;
    if (typeof row.id !== "string" || /^Superseded\b/i.test(row.title ?? "")) return false;
    // Explicit assessment scopes carry their own meaning regardless of confidence.
    // A coverage defect (such as an untested module) is not an assessment limitation.
    const explicitScope = /(?:^|[—:]\s*)(?:coverage\b|(?:input\s+)?scope\b|not[- ]assessed\b|not[- ]applicable\b|unavailable\b)/i.test(row.taxonomy ?? "");
    const unresolvedAssessment = row.confidence === "N/A"
      && /scope|not assessed|not judged|not verified|not graded|ungraded|could not|excluded|did not run|partially resolved/i.test(`${row.title} ${row.taxonomy}`);
    return row.category === "Coverage" || explicitScope || unresolvedAssessment;
  });
}

const EXCLUDED_DIR = /^(node_modules|\.git|\.next|\.stryker-tmp|\.pnpm-store|dist|build|coverage|out|vendor|venv|\.venv|__pycache__|target)$/;

function targetFiles(root: string): { files: string[]; gaps: { file: string; reason: string }[] } {
  const files: string[] = [];
  const gaps: { file: string; reason: string }[] = [];
  const visited = new Set<string>();
  const fileTargets = new Set<string>();
  const physicalRoot = realpathSync(root);
  const local = (path: string): string => relative(root, path).split(sep).join("/") || ".";
  const inside = (path: string): boolean => path === physicalRoot || path.startsWith(`${physicalRoot}${sep}`);
  const walk = (dir: string): void => {
    const physical = realpathSync(dir);
    if (!inside(physical) || physical !== join(physicalRoot, local(dir)) || visited.has(physical)) { gaps.push({ file: local(dir), reason: "Directory alias escapes the target or refers to a different canonical path; its separate path is unresolved and is not traversed again." }); return; }
    visited.add(physical);
    const listing = readEntriesSafe(dir);
    gaps.push(...listing.dangling.map(name => ({ file: local(join(dir, name)), reason: "Unresolvable source link; no file content was examined." })));
    for (const entry of listing.entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory) {
        if (!EXCLUDED_DIR.test(entry.name)) {
          try { walk(entry.path); } catch (error) { gaps.push({ file: local(entry.path), reason: `Unreadable directory: ${String(error)}` }); }
        }
      } else {
        try {
          const target = realpathSync(entry.path);
          if (!inside(target) || target !== join(physicalRoot, local(entry.path)) || fileTargets.has(target)) gaps.push({ file: local(entry.path), reason: "File alias escapes the target or refers to another canonical path; it is retained as a gap and is not counted as a separate file." });
          else { fileTargets.add(target); files.push(local(entry.path)); }
        } catch (error) { gaps.push({ file: local(entry.path), reason: `Unreadable file identity: ${String(error)}` }); }
      }
    }
  };
  walk(root);
  return { files: files.sort(), gaps };
}

type SqlPlacement = "supabase-migration" | "prisma-migration" | "schema-snapshot" | "seed-or-fixture" | "unrelated-sql";
export function classifySqlPlacement(path: string): SqlPlacement {
  const lower = path.toLowerCase();
  if (/(^|\/)supabase\/migrations\/[^/]+\.sql$/.test(lower)) return "supabase-migration";
  if (/(^|\/)prisma\/migrations\/[^/]+\/migration\.sql$/.test(lower)) return "prisma-migration";
  if (/(^|\/)schema\.sql$/.test(lower)) return "schema-snapshot";
  if (/(^|\/)(seeds?|fixtures?|tests?|examples?|backups?|dumps?)\//.test(lower) || /(^|\/)(seed|backup|dump)[^/]*\.sql$/.test(lower)) return "seed-or-fixture";
  return "unrelated-sql";
}

type PythonRole = "application-service" | "maintenance-tool" | "unknown-manual-review";
export function classifyPythonRole(path: string, text: string): PythonRole {
  if (/(^|\/)(codemods?|scripts?|tools?|migrations?|fixtures?|docs?)\//i.test(path)) return "maintenance-tool";
  if (/\b(?:from|import)\s+(?:django|flask|fastapi|celery|sqlalchemy)\b/.test(text)) return "application-service";
  return "unknown-manual-review";
}

function disclosures(findings: PriorFinding[], id: string): PriorFinding[] {
  return findings.filter((finding) => finding.id === id || finding.id?.startsWith(`${id}@`) || finding.id?.startsWith(`${id}#`));
}

function countFromEvidence(finding: PriorFinding | undefined, pattern: RegExp): number {
  return Number(pattern.exec(finding?.evidence ?? "")?.[1] ?? 0);
}

const pathsDigest = (files: string[]): string => createHash("sha256").update(JSON.stringify([...files].sort())).digest("hex");

function vitalsPopulation(vitals: unknown, target: string[], revision: string, artifactSha256: string): { files: string[]; complete: boolean; detail: string; binding?: ResidualScopeRow["population"]["binding"] } {
  if (!vitals || typeof vitals !== "object") return { files: [], complete: false, detail: "No Vitals machine artifact was supplied." };
  const value = vitals as Record<string, unknown>;
  const explicit = [value.population, value.files].find(Array.isArray) as unknown[] | undefined;
  const health = value.file_health && typeof value.file_health === "object" && !Array.isArray(value.file_health) ? Object.keys(value.file_health as Record<string, unknown>) : undefined;
  const files = health ?? (explicit ?? []).map((row) => typeof row === "string" ? row : row && typeof row === "object" ? String((row as Record<string, unknown>).path ?? (row as Record<string, unknown>).file ?? "") : "").filter(Boolean);
  const historicalOnly = value.currentSourceExamined === false;
  const declaredCounts = [value.filesScored, value.declaredFilesScored, value.exportedFiles, value.populationCount].filter(count => count !== undefined);
  const exactTarget = pathsDigest(files) === pathsDigest(target);
  const countBound = declaredCounts.length > 0 ? declaredCounts.every(count => Number.isInteger(count) && count === files.length) : exactTarget;
  const contained = files.every(path => !isAbsolute(path) && target.includes(path));
  const revisionBound = value.sourceRevision === revision;
  const complete = files.length > 0 && new Set(files).size === files.length && !historicalOnly && revisionBound && contained && countBound && (health !== undefined || value.populationComplete === true || value.completePopulation === true);
  const limits = [historicalOnly ? "Historical cache population retained; it did not freshly examine the bound source revision and cannot replace the recorded capture." : "", !revisionBound ? "The artifact has no matching sourceRevision; retained paths are historical or unbound." : "", !contained ? "Some supplied paths are outside or absent from the target census." : "", !countBound ? "The scored population count is missing or disagrees with the retained path population." : ""].filter(Boolean);
  return { files, complete, detail: complete ? "Revision and scored-file population reconcile with the target paths; display caps do not truncate this machine population." : limits.join(" ") || "Artifact does not establish a complete nonempty scored population.", ...(complete ? { binding: { revision, declared: files.length, pathsSha256: pathsDigest(files), artifactSha256 } } : {}) };
}

export function buildResidualScopeInventory(root: string, options: BuildOptions): ResidualScopeInventory {
  const census = targetFiles(root);
  const files = census.files;
  const findings = options.priorFindings ?? [];
  const sql = files.filter((file) => extname(file).toLowerCase() === ".sql");
  const migrationFiles = sql.filter((file) => ["supabase-migration", "prisma-migration"].includes(classifySqlPlacement(file)));
  const snapshots = sql.filter((file) => classifySqlPlacement(file) === "schema-snapshot");
  const excludedSql = sql.filter((file) => !migrationFiles.includes(file) && !snapshots.includes(file));
  const migrationGroups = new Map<string, { file: string; sql: string }[]>();
  const parseFailures: { file: string; reason: string }[] = [];
  const examinedSql: string[] = [];
  for (const file of migrationFiles) {
    const marker = /(?:supabase|prisma)\/migrations\//i.exec(file)!;
    const project = file.slice(0, marker.index + marker[0].length);
    try {
      const text = readFileSync(join(root, file), "utf8"); examinedSql.push(file);
      parseFailures.push(...schemaSqlParseFailures(text).map(failure => ({ file: `${file}:${failure.line}`, reason: failure.reason })));
      migrationGroups.set(project, [...(migrationGroups.get(project) ?? []), { file, sql: text }]);
    } catch (error) { parseFailures.push({ file, reason: `SQL content unreadable: ${String(error)}` }); }
  }
  for (const file of snapshots) {
    try {
      const text = readFileSync(join(root, file), "utf8"); examinedSql.push(file);
      parseFailures.push(...schemaSqlParseFailures(text).map(failure => ({ file: `${file}:${failure.line}`, reason: failure.reason })));
    } catch (error) { parseFailures.push({ file, reason: `SQL content unreadable: ${String(error)}` }); }
  }
  parseFailures.push(...census.gaps.filter(gap => extname(gap.file) === ".sql" && ["supabase-migration", "prisma-migration", "schema-snapshot"].includes(classifySqlPlacement(gap.file))));
  const policyParses = [...migrationGroups.values()].map((inputs) => parseLivePolicies(inputs));
  const parsedPolicies = policyParses.flatMap((result) => result.policies);
  const liveTables = [...migrationGroups.values()].flatMap((inputs) => parseLiveTableNames(inputs.map((input) => input.sql).join("\n")));
  const pythonFiles = files.filter((file) => extname(file).toLowerCase() === ".py");
  const pythonByRole = new Map<PythonRole, string[]>();
  for (const file of pythonFiles) {
    let text = "";
    try { text = readFileSync(join(root, file), "utf8"); } catch (error) { census.gaps.push({ file, reason: `Source unreadable: ${String(error)}` }); }
    const role = classifyPythonRole(file, text);
    pythonByRole.set(role, [...(pythonByRole.get(role) ?? []), file]);
  }
  const cache = disclosures(findings, "CACHE-SCOPE-00");
  const cacheUnscoped = cache.reduce((sum, row) => sum + countFromEvidence(row, /(\d+) read-through cache get\/set pair/), 0);
  const cacheWrites = cache.reduce((sum, row) => sum + countFromEvidence(row, /(\d+) cache write/), 0);
  const cacheUnknown = cache.filter(row => !/\d+ (?:read-through cache get\/set pair|cache write)/.test(row.evidence ?? "")).length;
  const m9Rows = findings.filter((finding) => finding.id?.startsWith("M9-") && /excluded by policy/i.test(finding.title ?? ""));
  const m9Pattern = /(\d+) of \d+ adjacent query pairs? excluded/i;
  const m9Pairs = m9Rows.reduce((sum, finding) => sum + Number(m9Pattern.exec(`${finding.title ?? ""} ${finding.evidence ?? ""}`)?.[1] ?? 0), 0);
  const m9Unknown = m9Rows.filter(row => !m9Pattern.test(`${row.title ?? ""} ${row.evidence ?? ""}`)).length;
  const vitalsArtifactSha256 = options.vitalsArtifactSha256 ?? createHash("sha256").update(JSON.stringify(options.vitalsArtifact) ?? "null").digest("hex");
  const vitals = vitalsPopulation(options.vitalsArtifact, files, options.revision, vitalsArtifactSha256);
  const sqlDisclosures = disclosures(findings, "M1-SQL-SCOPE-00");
  const pythonDisclosures = pythonFiles.length ? disclosures(findings, "M1-LANG-00").filter(row => /python/i.test(`${row.title} ${row.evidence}`)) : [];
  const mapped = new Set([...cache, ...m9Rows, ...sqlDisclosures, ...pythonDisclosures].flatMap(row => row.id ? [row.id] : []));
  const sourceDisclosures = residualScopeDisclosures(findings).filter(row => !mapped.has(row.id!));

  const rows: ResidualScopeRow[] = [
    {
      id: "sql-supported-schema-surfaces", domain: "sql", status: parseFailures.length ? "manual-review" : "implemented",
      title: "Supported migration and schema SQL placements", population: { examined: examinedSql.length, unresolved: parseFailures.length, files: [...migrationFiles, ...snapshots], parseFailures }, sourceFindingIds: sqlDisclosures.flatMap(row => row.id ? [row.id] : []),
      coverage: `Bounded structural inspection read ${examinedSql.length} SQL files, including ${snapshots.length} independent schema snapshots. Lifecycle-aware table/policy identity parsing examined ${migrationFiles.length} migration files in ${migrationGroups.size} independent project history stream(s) and derived ${liveTables.length} table and ${parsedPolicies.length} policy identities. This is not PostgreSQL syntax validation or execution; dynamic statements and deeper object semantics remain outside the comparison contract.`,
      ...(parseFailures.length ? { owner: "Engagement reviewer — SQL scope review" } : {}), reason: parseFailures.length ? "The listed unreadable, structurally incomplete or unsupported statements prevent a complete static identity assessment." : "Every supplied supported SQL file received the bounded structural inspection; no structural parse failure was retained.",
      provenance: "Residual scope CLI filesystem census plus migration-sql-parse lifecycle fold.", falsifier: "Add a supported migration with an unreadable policy or remove a migration from the census; the unresolved count or examined population must change.",
      nextStep: parseFailures.length ? "Review each listed statement against an isolated PostgreSQL rebuild or extend its bounded parser shape, then regenerate." : "Regenerate after migration changes.",
    },
    {
      id: "sql-non-schema-surfaces", domain: "sql", status: excludedSql.length ? "intentional-exclusion" : "implemented", title: "SQL outside supported schema placements",
      population: { examined: excludedSql.length, unresolved: excludedSql.length, files: excludedSql }, sourceFindingIds: sqlDisclosures.flatMap(row => row.id ? [row.id] : []), coverage: "Every remaining SQL file is retained and classified; seed, fixture, dump, and unrelated SQL is not folded into deployed schema state.",
      reason: excludedSql.length ? "Treating arbitrary SQL as ordered schema history creates false live-table and policy claims." : "The complete SQL census found no files outside supported schema placements.", provenance: "Complete target .sql path census with placement classification.",
      falsifier: "Move a file under a supported Supabase migration placement or name it as a schema snapshot; regeneration must move it to the supported row.", nextStep: "Review only files known to define deployed schema; otherwise retain this intentional exclusion.",
    },
    ...([...pythonByRole.entries()].map(([role, roleFiles]): ResidualScopeRow => ({
      id: `python-${role}`, domain: "source", status: role === "maintenance-tool" ? "intentional-exclusion" : "manual-review", title: `Python source classified as ${role}`,
      population: { examined: roleFiles.length, unresolved: role === "maintenance-tool" ? 0 : roleFiles.length, files: roleFiles }, sourceFindingIds: pythonDisclosures.flatMap(row => row.id ? [row.id] : []), coverage: role === "maintenance-tool" ? "Path evidence identifies bounded tooling/codemod source; it is not represented as a tenant-serving application." : "No JS/TS tenant-isolation adapter claims coverage over this source.",
      ...(role === "maintenance-tool" ? {} : { owner: "Engagement reviewer — Python source review (historical reference #871)" }), reason: role === "maintenance-tool" ? "Maintenance tools are outside request-serving tenant boundary analysis unless runtime evidence says otherwise." : "Framework evidence is insufficient for an automatic tenant-boundary judgment.",
      provenance: "Complete .py path census plus framework import classification.", falsifier: "Move the file into an application surface or add a supported server-framework import; regeneration must reclassify it.", nextStep: role === "maintenance-tool" ? "Confirm tooling-only use during review." : "Review database and privileged-client access manually or add a framework adapter.",
    }))),
    {
      id: "cache-alias-and-unpaired", domain: "cache", status: cacheUnscoped + cacheWrites + cacheUnknown ? "manual-review" : "implemented", title: "Cache aliases and unpaired writes",
      population: { examined: cacheUnscoped + cacheWrites, unresolved: cacheUnscoped + cacheWrites + cacheUnknown, files: [] }, sourceFindingIds: cache.flatMap(row => row.id ? [row.id] : []), coverage: `Shipping CACHE-SCOPE-00 measured ${cacheUnscoped} unscoped read-through pairs and ${cacheWrites} unpaired writes across ${cache.length} supplied finding row(s). ${cacheUnknown} row(s) have an unrecognized count and remain unresolved in addition to the measured sites.`, owner: "Engagement reviewer — cache key/alias review (historical reference #1196)",
      reason: "Receiver aliases and write-only sites do not prove shared reads or tenant exposure.", provenance: cache.length ? `Findings ${cache.map(row => row.id).join(", ")} from the supplied engagement artifact.` : "No CACHE-SCOPE-00 finding was supplied; no target-wide cache coverage is inferred.", falsifier: "Run the shipping cache detector after adding a recognized tenant discriminator or matching read; the measured unresolved count must fall.", nextStep: "Review the measured sites for tenant keying and declare project-specific cache aliases where needed.",
    },
    {
      id: "m9-guarded-query-pairs", domain: "m9", status: m9Pairs || m9Unknown ? "intentional-exclusion" : "implemented", title: "Guarded query pairs excluded from parallelization",
      population: { examined: m9Pairs, unresolved: m9Pairs + m9Unknown, files: [] }, sourceFindingIds: m9Rows.flatMap(row => row.id ? [row.id] : []), coverage: `${m9Rows.length} shipping M9 disclosure row(s) account for ${m9Pairs} guarded pairs; ${m9Unknown} additional row(s) have unrecognized counts and remain unresolved.`,
      reason: m9Pairs || m9Unknown ? "Hoisting a query across a return/break/continue guard, or a write across an error guard, changes which requests execute side effects. No optimization is recommended without pair-specific equivalence and side-effect proof." : "The supplied shipping artifact contains no policy-excluded guarded-pair population; no exclusion limit is claimed.", provenance: "Supplied shipping M9 disclosure findings.", falsifier: "Add a shipping policy-exclusion disclosure; regeneration must record its measured pair count.", nextStep: m9Pairs || m9Unknown ? "Keep guarded writes sequential; manually assess read-only pairs when latency justifies it." : "Regenerate when the M9 population changes.",
    },
    {
      id: "vitals-complete-population", domain: "vitals", status: vitals.complete ? "implemented" : "owned-follow-up", title: "Traceable Vitals full population export",
      population: { examined: vitals.files.length, unresolved: vitals.complete ? 0 : 1, files: vitals.files, ...(vitals.binding ? { binding: vitals.binding } : {}) }, coverage: `${vitals.detail} The inventory retains the complete supplied path list rather than a display cap.`, owner: vitals.complete ? undefined : "#2206",
      reason: vitals.complete ? "The producer explicitly bound completeness to the machine export." : "A top-K list or an unmarked file list cannot prove the full population.", provenance: options.vitalsArtifact === undefined ? "No Vitals machine artifact supplied." : `Supplied Vitals ${options.vitalsArtifactSha256 ? "raw bytes" : "parsed JSON serialization"}; SHA-256 ${vitalsArtifactSha256}.`, falsifier: "Remove the completeness marker or one source path; validation must reject or report the export as incomplete.", nextStep: vitals.complete ? "Use concise report rollups while retaining this full machine list." : "Use the isolated #2135 producer to resolve #2206 with a complete revision-bound population, then regenerate.",
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
      population: { examined: 0, unresolved: 1, files: migrationFiles }, coverage: "The current connected drift query does not fetch deployed columns or nullability; table agreement cannot clear this class.", owner: "#2205",
      reason: "No complete authorized live-column population is present in the supplied artifacts.", provenance: "Negative capability census of src/scan/supabase-drift.ts and the supplied connected artifacts.", falsifier: "A bound connected receipt containing complete authorized live-column identities/nullability plus migration expectations makes this class comparable.", nextStep: "Add a read-only catalog adapter and compare this population independently of table/policy identity.",
    },
    {
      id: "database-drift-deployed-semantics", domain: "database-drift", status: "intentional-exclusion", title: "Deployed type, default, constraint, index, trigger and function drift",
      population: { examined: 0, unresolved: 1, files: migrationFiles }, coverage: "No claim is made for semantic database objects beyond the explicitly implemented identity/RLS contracts.",
      reason: "Those object families require separate canonicalization and authorized catalog populations; inferring them from table presence would create false equivalence.", provenance: "Bounded consumer census of current connected drift queries.", falsifier: "Introduce a complete, canonicalized, receipt-bound live population for one object family; that family can move to its own implemented row.", nextStep: "Add object families individually when a precise comparison contract and negative fixtures exist.",
    },
  ];
  if (census.gaps.length) rows.push({
    id: "source-discovery-gaps", domain: "source", status: "manual-review", title: "Unresolved source paths and aliases", population: { examined: 0, unresolved: census.gaps.length, files: [...new Set(census.gaps.map(gap => gap.file))], parseFailures: census.gaps },
    coverage: "Only unique readable physical target paths enter the file census. Unreadable, dangling, escaping and repeated aliases remain explicit; no content assessment is inferred for them.", reason: "These path identities could not be independently inventoried as target files.", provenance: "Filesystem identity census", owner: "Engagement reviewer — source acquisition", falsifier: "Resolve each listed path inside the target without a duplicate physical identity and regenerate the inventory.", nextStep: "Supply the missing source or document each intentional alias/exclusion.",
  });
  rows.push(...sourceDisclosures.map((finding): ResidualScopeRow => {
    const edges = /(\d+) dropped edges? of (\d+)/i.exec(finding.title ?? "");
    return {
      id: `source-disclosure-${createHash("sha256").update(finding.id!).digest("hex").slice(0, 16)}`, domain: "source", status: "manual-review", title: finding.title || "Supplied source or tool scope disclosure", sourceFindingIds: [finding.id!],
      population: { examined: edges ? Number(edges[2]) : 1, unresolved: edges ? Number(edges[1]) : 1, files: [] },
      coverage: `${edges ? "Import edge counts" : "One scope-disclosure row"} retained from the supplied producer; this is not a new source examination. ${finding.evidence ?? "The producer supplied no detailed population evidence."}`,
      owner: "Engagement reviewer — source/framework/tool scope", reason: "The supplied limitation needs an engagement-specific applicability decision; it is not a confirmed product defect.", provenance: `Original finding ${finding.id}; ${finding.location ?? "location not supplied"}.`, falsifier: `Resolve or explicitly exclude the scope named by ${finding.id}, then rerun its owning producer on the same target revision.`, nextStep: finding.fix || "Review the original scope evidence and record the bounded manual assessment or intentional exclusion.",
    };
  }));
  for (const row of rows) if (row.population.unresolved && !row.owner) row.owner = "Engagement reviewer — confirm intentional scope exclusion";
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
  if (typeof inventory.target?.revision !== "string" || !inventory.target.revision.trim()) errors.push("residualScope.target.revision: required");
  if (typeof inventory.generatedAt !== "string" || !Number.isFinite(Date.parse(inventory.generatedAt))) errors.push("residualScope.generatedAt: expected a timestamp");
  if (!Array.isArray(inventory.rows)) return [...errors, "residualScope.rows: expected an array"];
  const ids = new Set<string>();
  for (const [index, row] of inventory.rows.entries()) {
    const at = `residualScope.rows[${index}]`;
    if (!row || typeof row !== "object") { errors.push(`${at}: expected an object`); continue; }
    if (typeof row.id !== "string" || !row.id.trim() || ids.has(row.id)) errors.push(`${at}.id: required and unique`); else ids.add(row.id);
    if (!["sql", "source", "cache", "m9", "vitals", "database-drift"].includes(row.domain)) errors.push(`${at}.domain: invalid`);
    if (!RESIDUAL_SCOPE_STATUSES.includes(row.status)) errors.push(`${at}.status: invalid`);
    if ([row.title, row.coverage, row.reason, row.provenance, row.falsifier, row.nextStep].some(text => typeof text !== "string" || !text.trim())) errors.push(`${at}: title, coverage, reason, provenance, falsifier and nextStep are required`);
    if ((row.status === "manual-review" || row.status === "owned-follow-up") && (typeof row.owner !== "string" || !row.owner.trim())) errors.push(`${at}.owner: required for unresolved owned work`);
    if (row.sourceFindingIds !== undefined && (!Array.isArray(row.sourceFindingIds) || row.sourceFindingIds.some(id => typeof id !== "string" || !id.trim()) || new Set(row.sourceFindingIds).size !== row.sourceFindingIds.length)) errors.push(`${at}.sourceFindingIds: invalid`);
    if (!row.population || !Number.isInteger(row.population.examined) || row.population.examined < 0 || !Number.isInteger(row.population.unresolved) || row.population.unresolved < 0 || !Array.isArray(row.population.files) || row.population.files.some((file) => typeof file !== "string" || !file.trim()) || new Set(row.population.files).size !== row.population.files.length) errors.push(`${at}.population: invalid`);
    else if (row.domain === "vitals" && (row.population.examined !== row.population.files.length || (row.status === "implemented" && row.population.examined === 0))) errors.push(`${at}.population: Vitals examined count must match the retained complete path population`);
    else if (row.domain === "vitals" && row.status === "implemented" && (!row.population.binding || row.population.binding.revision !== inventory.target?.revision || row.population.binding.declared !== row.population.files.length || row.population.binding.pathsSha256 !== pathsDigest(row.population.files) || !/^[a-f0-9]{64}$/.test(row.population.binding.artifactSha256))) errors.push(`${at}.population: complete Vitals needs matching revision, declared count, path digest and artifact digest`);
    if (row.population?.unresolved && (typeof row.owner !== "string" || !row.owner.trim())) errors.push(`${at}.owner: required for an unresolved limitation`);
    if (row.status === "implemented" && row.population?.unresolved) errors.push(`${at}.status: implemented cannot retain unresolved units`);
    if (row.population?.parseFailures !== undefined && (!Array.isArray(row.population.parseFailures) || row.population.parseFailures.some(failure => !failure || typeof failure.file !== "string" || !failure.file || typeof failure.reason !== "string" || !failure.reason))) errors.push(`${at}.population.parseFailures: invalid`);
  }
  if (inventory.summary) {
    const unresolved = inventory.rows.reduce((sum, row) => sum + (row?.population?.unresolved ?? 0), 0);
    if (inventory.summary.rows !== inventory.rows.length || inventory.summary.unresolved !== unresolved || inventory.summary.implemented !== inventory.rows.filter(row => row?.status === "implemented").length || !Number.isInteger(inventory.summary.filesExamined) || inventory.summary.filesExamined < 0) errors.push("residualScope.summary: row and unresolved populations must reconcile");
  } else errors.push("residualScope.summary: required");
  return errors;
}
