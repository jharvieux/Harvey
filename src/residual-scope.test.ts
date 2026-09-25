import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
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
    const inventory = buildResidualScopeInventory(fixture(), { revision: "fixture-revision", generatedAt: "2026-09-25T00:00:00.000Z", priorFindings: [
      { id: "CACHE-SCOPE-00", evidence: "6 read-through cache get/set pairs sit here. 1 cache write has no paired read." },
      { id: "M9-01", title: "M9 partially assessed (4 of 4 adjacent query pairs excluded by policy)", evidence: "4 of 4 adjacent query pairs excluded" },
    ], vitalsArtifact: { populationComplete: true, population: [{ path: "src/a.ts" }, { path: "src/b.ts" }] } });
    expect(inventory.rows.find((row) => row.id === "sql-supported-schema-surfaces")?.population.files).toEqual(["apps/web/supabase/migrations/001.sql", "apps/web/supabase/migrations/002.sql"]);
    expect(inventory.rows.find((row) => row.id === "python-maintenance-tool")?.population.unresolved).toBe(0);
    expect(inventory.rows.find((row) => row.id === "cache-alias-and-unpaired")?.population.unresolved).toBe(7);
    expect(inventory.rows.find((row) => row.id === "vitals-complete-population")?.population.files).toEqual(["src/a.ts", "src/b.ts"]);
    const doc: FindingsDocument = { meta, findings: [], residualScope: inventory };
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
    const inventory = buildResidualScopeInventory(fixture(), { revision: "fixture", vitalsArtifact: { populationComplete: true, population: ["src/a.ts", "src/b.ts"] } });
    const row = inventory.rows.find((item) => item.domain === "vitals")!;
    const document: FindingsDocument = { meta, findings: [], residualScope: inventory };
    expect(validateFindings(document).ok).toBe(true);
    row.population.files.pop();
    expect(validateFindings(document).errors.join("\n")).toContain("Vitals examined count must match");
  });
  it.each([{ file_health: {} }, { populationComplete: true, population: [] }, { populationComplete: true, population: ["a.ts", "a.ts"] }])("does not certify an empty or repeated Vitals population %j", (vitalsArtifact) => {
    if (Array.isArray(vitalsArtifact.population) && vitalsArtifact.population.length) {
      expect(() => buildResidualScopeInventory(fixture(), { revision: "fixture", vitalsArtifact })).toThrow("population: invalid");
    } else {
      const inventory = buildResidualScopeInventory(fixture(), { revision: "fixture", vitalsArtifact });
      expect(inventory.rows.find((row) => row.domain === "vitals")).toMatchObject({ status: "owned-follow-up", owner: "#2206", population: { examined: 0, unresolved: 1 } });
    }
  });
  it("ships the CLI inventory into the same document the report renderer consumes", () => {
    const target = fixture(); const findings = join(target, "findings.json"); const out = join(target, "client.json");
    writeFileSync(findings, JSON.stringify({ meta, findings: [] }));
    const repo = fileURLToPath(new URL("..", import.meta.url));
    const run = spawnSync(process.execPath, ["--import", "tsx", "src/cli/residual-scope.ts", "--target", target, "--revision", "fixture", "--findings", findings, "--out", out], { cwd: repo, encoding: "utf8" });
    expect(run.status, run.stderr).toBe(0);
    const document = JSON.parse(readFileSync(out, "utf8")) as FindingsDocument;
    expect(validateFindings(document)).toEqual({ ok: true, errors: [] });
    expect(buildHtml(document)).toContain('data-residual-scope-id="sql-supported-schema-surfaces"');
  });
});
