import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { validateFindings, type FindingsDocument, type ReportMeta } from "./findings.js";
import { buildResidualScopeInventory, classifyPythonRole, classifySqlPlacement, residualScopeErrors } from "./residual-scope.js";
import { buildHtml } from "../report-template/render.mjs";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-residual-")); roots.push(root);
  mkdirSync(join(root, "apps/web/supabase/migrations"), { recursive: true }); mkdirSync(join(root, "scripts")); mkdirSync(join(root, "sql"));
  writeFileSync(join(root, "apps/web/supabase/migrations/001.sql"), "create table public.before_name(id uuid); create policy p on public.before_name using (true);");
  writeFileSync(join(root, "apps/web/supabase/migrations/002.sql"), "alter table public.before_name rename to after_name; alter policy p on public.after_name rename to scoped; alter table public.after_name set schema tenant;");
  writeFileSync(join(root, "scripts/codemod-safe-await.py"), "print('tool')\n"); writeFileSync(join(root, "sql/example.sql"), "select 1;\n");
  return root;
}
const finding = (overrides: Record<string, unknown> = {}) => ({ id: "M1-LANG-00", title: "Source not assessed", severity: "Info" as const, confidence: "N/A" as const, category: "Coverage", taxonomy: "Coverage — source limitation", location: "src/a.ts", status: "Open" as const, evidence: "Unassessed source", impact: "Unknown coverage", fix: "Review source", value: 1, ease: 1, safety: 5, ...overrides });
const meta: ReportMeta = { client: "Fixture", subtitle: "Residual", date: "2026-09-25", commit: "abc", auditor: "Harvey", confidential: false, overallHealth: 5, tenantIsolation: "Not verified", authModel: "fixture", headline: "Partial audit", scope: "fixture", methodology: "scoped", outOfScope: "none" };

describe("residual scope inventory (#2142)", () => {
  it("classifies supported SQL and codemods without inventing an application service", () => {
    expect(classifySqlPlacement("apps/web/supabase/migrations/001.sql")).toBe("supabase-migration"); expect(classifySqlPlacement("sql/query.sql")).toBe("unrelated-sql");
    expect(classifyPythonRole("scripts/codemod-safe-await.py", "import sqlalchemy")).toBe("maintenance-tool");
  });
  it("keeps independent workspace migration histories separate", () => {
    const root = fixture(); mkdirSync(join(root, "apps/admin/supabase/migrations"), { recursive: true });
    writeFileSync(join(root, "apps/admin/supabase/migrations/001.sql"), "create table public.before_name(id uuid); create policy p on public.before_name using (false);");
    const inventory = buildResidualScopeInventory(root, { revision: "fixture", generatedAt: "2026-09-25T00:00:00.000Z" });
    expect(inventory.rows.find((row) => row.id === "sql-supported-schema-surfaces")?.coverage).toContain("2 independent project history stream(s)");
  });
  it("carries complete populations, owners and falsifiers into the client HTML", () => {
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, generatedAt: "2026-09-25T00:00:00.000Z", priorFindings: [
      { id: "CACHE-SCOPE-00", evidence: "6 read-through cache get/set pairs sit here. 1 cache write has no paired read." },
      { id: "M9-01", title: "M9 partially assessed (4 of 4 adjacent query pairs excluded by policy)", evidence: "4 of 4 adjacent query pairs excluded" },
    ], vitalsArtifact: { populationComplete: true, population: [{ path: "src/a.ts" }, { path: "src/b.ts" }] } });
    expect(inventory.rows.find((row) => row.id === "sql-supported-schema-surfaces")?.population.files).toEqual(["apps/web/supabase/migrations/001.sql", "apps/web/supabase/migrations/002.sql"]);
    expect(inventory.rows.find((row) => row.id === "python-maintenance-tool")?.population.unresolved).toBe(0);
    expect(inventory.rows.find((row) => row.id === "cache-alias-and-unpaired")?.population.unresolved).toBe(7);
    expect(inventory.rows.find((row) => row.id === "vitals-complete-population")?.population.files).toEqual(["src/a.ts", "src/b.ts"]);
    const doc: FindingsDocument = { meta, findings: [finding({ id: "CACHE-SCOPE-00" }), finding({ id: "M9-01" })], residualScope: inventory };
    expect(validateFindings(doc)).toEqual({ ok: true, errors: [] });
    const html = buildHtml(doc); expect(html).toContain("Residual assessment scope"); expect(html).toContain("cache-alias-and-unpaired"); expect(html).toContain("Falsifier:"); expect(html).toContain("#1196");
  });
  it("fails both directions when an unresolved row loses its owner or counts drift", () => {
    const inventory = buildResidualScopeInventory(fixture(), { revision: "fixture", generatedAt: "2026-09-25T00:00:00.000Z" });
    const cache = inventory.rows.find((row) => row.id === "cache-alias-and-unpaired")!; cache.status = "manual-review"; delete cache.owner;
    expect(residualScopeErrors(inventory).join("\n")).toContain("owner: required"); cache.owner = "#1196"; inventory.summary.unresolved += 1;
    expect(residualScopeErrors(inventory)).toContain("residualScope.summary: row and unresolved populations must reconcile");
  });
  it("rejects truncated Vitals populations in the canonical document validator", () => {
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, vitalsArtifact: { populationComplete: true, population: ["src/a.ts", "src/b.ts"] } });
    const row = inventory.rows.find((item) => item.domain === "vitals")!;
    const document: FindingsDocument = { meta, findings: [], residualScope: inventory };
    expect(validateFindings(document).ok).toBe(true);
    row.population.files.pop();
    expect(validateFindings(document).errors.join("\n")).toContain("Vitals examined count must match");
  });
  it.each([{ file_health: {} }, { populationComplete: true, population: [] }, { populationComplete: true, population: ["a.ts", "a.ts"] }])("does not certify an empty or repeated Vitals population %j", (vitalsArtifact) => {
    if (Array.isArray(vitalsArtifact.population) && vitalsArtifact.population.length) {
      expect(() => buildResidualScopeInventory(fixture(), { revision: meta.commit, vitalsArtifact })).toThrow("population: invalid");
    } else {
      const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, vitalsArtifact });
      expect(inventory.rows.find((row) => row.domain === "vitals")).toMatchObject({ status: "owned-follow-up", owner: "#2206", population: { examined: 0, unresolved: 1 } });
    }
  });
  it("ships the CLI inventory into the same document the report renderer consumes", () => {
    const target = fixture(); const findings = join(target, "findings.json"); const out = join(target, "client.json"); const vitals = join(target, "vitals.json");
    writeFileSync(findings, JSON.stringify({ meta, findings: [] }));
    writeFileSync(vitals, JSON.stringify({ sourceRevision: meta.commit, filesScored: 1, file_health: { "scripts/codemod-safe-await.py": {} } }, null, 2));
    const repo = fileURLToPath(new URL("..", import.meta.url));
    const run = spawnSync(process.execPath, ["--import", "tsx", "src/cli/residual-scope.ts", "--target", target, "--revision", meta.commit, "--findings", findings, "--vitals", vitals, "--out", out], { cwd: repo, encoding: "utf8" });
    expect(run.status, run.stderr).toBe(0);
    const document = JSON.parse(readFileSync(out, "utf8")) as FindingsDocument;
    expect(validateFindings(document)).toEqual({ ok: true, errors: [] });
    expect(buildHtml(document)).toContain('data-residual-scope-id="sql-supported-schema-surfaces"');
    const digest = createHash("sha256").update(readFileSync(vitals)).digest("hex");
    expect(document.residualScope?.rows.find(row => row.domain === "vitals")?.population.binding?.artifactSha256).toBe(digest);
    expect(buildHtml(document)).toContain(digest);
  });
});

function add(root: string, path: string, text: string): void {
  const full = join(root, path); mkdirSync(join(full, ".."), { recursive: true }); writeFileSync(full, text);
}

describe("residual scope evidence boundaries", () => {
  it.each(["schema.sql", "db/schema.sql", "prisma/migrations/001/migration.sql", "supabase/migrations/001.sql"])("inspects malformed SQL in %s", path => {
    const root = fixture(); add(root, path, "create policy broken on public.a using (id = x");
    const row = buildResidualScopeInventory(root, { revision: meta.commit }).rows.find(row => row.id === "sql-supported-schema-surfaces")!;
    expect(row.status).toBe("manual-review"); expect(row.population.parseFailures).toEqual(expect.arrayContaining([expect.objectContaining({ file: expect.stringContaining(path) })]));
    expect(row.coverage).toContain("not PostgreSQL syntax validation");
  });
  it("retains malformed table and procedural SQL as unresolved structure", () => {
    const root = fixture(); add(root, "schema.sql", "create table public.a(id uuid"); add(root, "supabase/migrations/001.sql", "do $$ begin execute 'create table x(id uuid)'; end $$;");
    const row = buildResidualScopeInventory(root, { revision: meta.commit }).rows.find(row => row.id === "sql-supported-schema-surfaces")!;
    expect(row.population.parseFailures?.map(failure => failure.reason).join(" ")).toMatch(/Unterminated.*Procedural|Procedural.*Unterminated/);
  });
  it("keeps Prisma histories independent from snapshots and other project histories", () => {
    const root = fixture(); add(root, "prisma/migrations/001/migration.sql", "create table public.a(id uuid); create policy p on public.a using(true);"); add(root, "prisma/migrations/002/migration.sql", "alter policy p on public.a rename to q;"); add(root, "schema.sql", "create table public.a(id uuid);");
    const row = buildResidualScopeInventory(root, { revision: meta.commit }).rows.find(row => row.id === "sql-supported-schema-surfaces")!;
    expect(row.status).toBe("implemented"); expect(row.coverage).toContain("2 independent project history stream(s)"); expect(row.coverage).toContain("1 independent schema snapshots");
  });
  it("counts a physical migration once and retains dangling, cycle and file aliases", () => {
    const root = fixture(); symlinkSync(".", join(root, "again")); symlinkSync("missing.sql", join(root, "apps/web/supabase/migrations/003.sql")); symlinkSync("001.sql", join(root, "apps/web/supabase/migrations/004.sql"));
    const inventory = buildResidualScopeInventory(root, { revision: meta.commit });
    expect(inventory.summary.filesExamined).toBe(4);
    expect(inventory.rows.find(row => row.id === "source-discovery-gaps")?.population.unresolved).toBe(3);
    expect(inventory.rows.find(row => row.id === "sql-supported-schema-surfaces")?.population.examined).toBe(2);
    expect(inventory.rows.find(row => row.id === "sql-supported-schema-surfaces")?.population.parseFailures?.some(failure => failure.file.endsWith("003.sql"))).toBe(true);
  });
  it("keeps the canonical SQL placement when earlier aliases have different names", () => {
    const root = fixture(); symlinkSync("apps", join(root, "aaa")); symlinkSync("apps/web/supabase/migrations/001.sql", join(root, "aaa.ts"));
    const inventory = buildResidualScopeInventory(root, { revision: meta.commit });
    expect(inventory.summary.filesExamined).toBe(4);
    expect(inventory.rows.find(row => row.id === "sql-supported-schema-surfaces")?.population.files).toEqual(["apps/web/supabase/migrations/001.sql", "apps/web/supabase/migrations/002.sql"]);
    expect(inventory.rows.find(row => row.id === "source-discovery-gaps")?.population.files).toEqual(["aaa", "aaa.ts"]);
  });
  it("aggregates every scoped cache row and singular guarded pair without changing product findings", () => {
    const prior = [finding({ id: "CACHE-SCOPE-00@a", evidence: "2 read-through cache get/set pairs. 3 cache writes." }), finding({ id: "CACHE-SCOPE-00@b", evidence: "7 read-through cache get/set pairs. 11 cache writes." }), finding({ id: "M9-SCOPE", title: "M9 partially assessed (1 of 1 adjacent query pair excluded by policy)" })];
    const before = JSON.stringify(prior); const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, priorFindings: prior });
    expect(inventory.rows.find(row => row.domain === "cache")?.population.unresolved).toBe(23);
    expect(inventory.rows.find(row => row.domain === "m9")).toMatchObject({ status: "intentional-exclusion", population: { examined: 1, unresolved: 1 } });
    const doc: FindingsDocument = { meta, findings: prior, residualScope: inventory }; expect(validateFindings(doc).ok).toBe(true); expect(JSON.stringify(prior)).toBe(before);
    expect(buildHtml(doc)).toContain("23");
  });
  it("keeps unrecognized cache and guarded-pair counts unresolved", () => {
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, priorFindings: [{ id: "CACHE-SCOPE-00", evidence: "New unknown population encoding" }, { id: "M9-SCOPE", title: "Query pairs excluded by policy", evidence: "Unknown total" }] });
    for (const domain of ["cache", "m9"]) expect(inventory.rows.find(row => row.domain === domain)?.population.unresolved).toBe(1);
  });
  it("retains unsupported source and both import-graph scopes with an engagement owner", () => {
    const prior = [finding({ title: "Tenant isolation not assessed in PHP source" }), finding({ id: "M1-IMPORTGRAPH-00@a", title: "Cross-file import graph partially resolved: 29 dropped edges of 2808" }), finding({ id: "M1-IMPORTGRAPH-00@b", title: "Cross-file import graph partially resolved: 1 dropped edge of 144" })];
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, priorFindings: prior }); const rows = inventory.rows.filter(row => row.id.startsWith("source-disclosure-"));
    expect(rows).toHaveLength(3); expect(rows.map(row => row.population.unresolved).sort((a, b) => a - b)).toEqual([1, 1, 29]);
    for (const row of rows) { expect(row.owner).toContain("Engagement reviewer"); expect(row.sourceFindingIds).toHaveLength(1); }
    const doc: FindingsDocument = { meta, findings: prior, residualScope: inventory }; expect(validateFindings(doc).ok).toBe(true); for (const f of prior) expect(buildHtml(doc)).toContain(f.id);
  });
  it("maps explicit applicability and confirmed scope disclosures without relabeling ordinary scope defects", () => {
    const prior = [
      finding({ id: "M9-01@apps/web", title: "M9 N/A — non-SSR SPA", category: "M9 — Database patterns", taxonomy: "M9 — Not applicable (non-Next SPA)" }),
      finding({ id: "M3-SCOPE-00", title: "M3 scan scope capped", confidence: "Confirmed", category: "M3", taxonomy: "M3 — Input scope" }),
      finding({ id: "M2-UNAVAILABLE", title: "Probe unavailable", confidence: "Review", category: "M2", taxonomy: "M2 — Unavailable" }),
      finding({ id: "M2-SCOPE", title: "What the dynamic probe covered", confidence: "Confirmed", category: "M2", taxonomy: "M2 — Scope disclosure" }),
      finding({ id: "M10-PROT-00", title: "PII protection NOT verified — no live database connection", category: "Data protection", taxonomy: "M10 — PII protection" }),
      finding({ id: "SEC-GL-ALLOW-00", title: "Secret matches suppressed by allowlist (not graded)", category: "Secret exposure", taxonomy: "Committed credential — suppressed by allowlist" }),
      finding({ id: "M8-05-01", title: "No test coverage at all: src/module", confidence: "Confirmed", category: "Test quality", taxonomy: "M8 — Module has no mutation test coverage" }),
      finding({ id: "M10-VERIFIED", title: "PII protection verified", category: "Data protection", taxonomy: "M10 — PII protection" }),
      finding({ id: "M2-SESSION", title: "Session fixation surface assessed (GoTrue session model)", category: "Dynamic pen-test (M2)", taxonomy: "M2 — Auth attack / session fixation" }),
      finding({ id: "BOLA-01", title: "Tenant scope missing", confidence: "Confirmed", category: "M1", taxonomy: "Tenant scope bypass" }),
      finding({ id: "CACHE-01", title: "Cache tenant scope missing", confidence: "Review", category: "M1", taxonomy: "Cache tenant scope" }),
    ];
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, priorFindings: prior });
    const ids = inventory.rows.flatMap(row => row.sourceFindingIds ?? []);
    expect(ids).toEqual(expect.arrayContaining(["M9-01@apps/web", "M3-SCOPE-00", "M2-UNAVAILABLE", "M2-SCOPE", "M10-PROT-00", "SEC-GL-ALLOW-00"]));
    expect(ids).not.toContain("BOLA-01"); expect(ids).not.toContain("CACHE-01");
    expect(ids).not.toContain("M8-05-01"); expect(ids).not.toContain("M10-VERIFIED"); expect(ids).not.toContain("M2-SESSION");
    const doc: FindingsDocument = { meta, findings: prior, residualScope: inventory };
    expect(validateFindings(doc).ok).toBe(true);
    const html = buildHtml(doc);
    for (const id of ["M9-01@apps/web", "M3-SCOPE-00", "M2-UNAVAILABLE", "M2-SCOPE", "M10-PROT-00", "SEC-GL-ALLOW-00"]) {
      const row = inventory.rows.find(row => row.sourceFindingIds?.includes(id))!;
      expect(row.owner).toContain("Engagement reviewer");
      expect(html).toContain(row.provenance);
      const missing = structuredClone(doc);
      missing.residualScope!.rows.find(candidate => candidate.id === row.id)!.sourceFindingIds = [];
      expect(validateFindings(missing).errors).toContain(`residualScope.sourceFindingIds: missing disposition for ${id}`);
    }
  });
  it("rejects omission of a supplied scope disclosure even when summary counts reconcile", () => {
    const prior = [finding({ title: "Tenant isolation not assessed in PHP source" })];
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit, priorFindings: prior });
    const doc: FindingsDocument = { meta, findings: prior, residualScope: inventory }; expect(validateFindings(doc).ok).toBe(true);
    const removed = inventory.rows.find(row => row.sourceFindingIds?.includes(prior[0]!.id))!;
    inventory.rows = inventory.rows.filter(row => row !== removed); inventory.summary.rows--; inventory.summary.unresolved -= removed.population.unresolved;
    expect(validateFindings(doc).errors).toContain("residualScope.sourceFindingIds: missing disposition for M1-LANG-00");
  });
  it.each([
    { sourceRevision: "other", filesScored: 2, file_health: { "src/a.ts": {}, "src/b.ts": {} } },
    { sourceRevision: "abc", filesScored: 2, file_health: { "src/a.ts": {} } },
    { sourceRevision: "abc", filesScored: 1, file_health: { "outside/a.ts": {} } },
    { sourceRevision: "abc", currentSourceExamined: false, populationComplete: true, population: ["src/a.ts", "src/b.ts"] },
    { file_health: { "src/a.ts": {}, "src/b.ts": {} } },
  ])("does not certify an unbound or incomplete Vitals export %j", vitalsArtifact => {
    const root = fixture(); add(root, "src/a.ts", "export {}"); add(root, "src/b.ts", "export {}");
    const inventory = buildResidualScopeInventory(root, { revision: meta.commit, vitalsArtifact });
    const row = inventory.rows.find(row => row.domain === "vitals")!; expect(row).toMatchObject({ status: "owned-follow-up", owner: "#2206", population: { unresolved: 1 } });
    const html = buildHtml({ meta, findings: [], residualScope: inventory }); expect(html).toContain(row.coverage);
  });
  it("certifies a revision/count/path-bound Vitals population and rejects later truncation", () => {
    const root = fixture(); add(root, "src/a.ts", "export {}"); add(root, "src/b.ts", "export {}");
    const inventory = buildResidualScopeInventory(root, { revision: meta.commit, vitalsArtifact: { sourceRevision: meta.commit, filesScored: 2, captureKind: "fresh-rerun", capturedAt: "2026-09-25T14:00:00.000Z", file_health: { "src/a.ts": {}, "src/b.ts": {} } } });
    const row = inventory.rows.find(row => row.domain === "vitals")!; expect(row.status).toBe("implemented");
    const doc: FindingsDocument = { meta, findings: [], residualScope: inventory }; expect(validateFindings(doc).ok).toBe(true);
    expect(buildHtml(doc)).toContain("Fresh Vitals rerun captured 2026-09-25T14:00:00.000Z at source revision abc; this does not replace the original historical capture.");
    row.population.files.pop(); row.population.examined--; expect(validateFindings(doc).errors.join(" ")).toContain("path digest");
  });
  it("rejects a missing comparison contract or a mismatched attached revision", () => {
    const inventory = buildResidualScopeInventory(fixture(), { revision: meta.commit }); const doc: FindingsDocument = { meta, findings: [], residualScope: inventory };
    inventory.rows[0]!.coverage = ""; expect(validateFindings(doc).errors.join(" ")).toContain("coverage"); inventory.rows[0]!.coverage = "Bounded static SQL identities";
    inventory.target.revision = "different"; expect(validateFindings(doc).errors.join(" ")).toContain("must match meta.commit");
  });
});
