import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { mutationWorkspaceFinding, planMutationWorkspaces } from "./mutation-workspace.js";
import { runMutationWorkspaces } from "./mutation-workspace-runner.js";
import { testQualityFromArtifact } from "./mutation-scan.js";
import { findingFamilyKind } from "./findings.js";

const roots: string[] = [];
const fixture = (files: Record<string, unknown>): string => {
  const root = mkdtempSync(join(tmpdir(), "mutation-workspace-plan-")); roots.push(root);
  for (const [path, value] of Object.entries(files)) { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), typeof value === "string" ? value : JSON.stringify(value)); }
  return root;
};
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

const twoApps = () => fixture({
  "package.json": { private: true, workspaces: ["apps/*"], devDependencies: { vitest: "3.2.6" } },
  "apps/main/package.json": { name: "main" }, "apps/rag/package.json": { name: "rag" },
  "apps/main/src/main.ts": "export const main = 1", "apps/rag/src/rag.ts": "export const rag = 2",
  "apps/rag/src/remaining.ts": "export const remaining = 3",
  "apps/main/test/main.test.ts": "test('main',()=>expect(main).toBe(1))", "apps/rag/test/rag.test.ts": "test('rag',()=>expect(rag).toBe(2))",
  "stryker.config.json": { testRunner: "vitest", mutate: ["apps/main/src/**/*.ts"], reporters: ["html"] },
  "stryker.rag.config.json": { testRunner: "vitest", mutate: ["apps/rag/src/rag.ts"], vitest: { configFile: "apps/rag/vitest.config.ts" } },
  "apps/rag/vitest.config.ts": "export default {test:{include:['test/**/*.test.ts']}}",
});

describe("mutation workspace execution plan", () => {
  it("enumerates every declared package, alternate config, production and test population", () => {
    const plan = planMutationWorkspaces(twoApps());
    expect(plan.schemaVersion).toBe(1);
    expect(plan.workspaces.map(row => row.id)).toEqual(["workspace:root", "workspace:apps/main", "workspace:apps/rag"]);
    const rag = plan.workspaces[2]!;
    expect(rag.productionSources).toEqual(["apps/rag/src/rag.ts", "apps/rag/src/remaining.ts"]);
    expect(rag.selectedSources).toEqual(["apps/rag/src/rag.ts"]);
    expect(rag.unselectedSources).toEqual(["apps/rag/src/remaining.ts"]);
    expect(rag.selectedConfiguration).toBe("stryker.rag.config.json");
    expect(rag.runnerConfig).toBe("apps/rag/vitest.config.ts");
    expect(rag.candidateTests).toContain("apps/rag/test/rag.test.ts");
    expect(rag.relatedTests.status).toBe("pending");
  });
  it("retains the complete configured population when an explicit production selection is bounded", () => {
    const plan = planMutationWorkspaces(twoApps(), { selection: ["apps/main/src/main.ts"] });
    const rag = plan.workspaces[2]!;
    expect(rag.selectedSources).toEqual([]);
    expect(rag.configuredSources).toEqual(["apps/rag/src/rag.ts"]);
    expect(rag.unselectedSources).toEqual(rag.productionSources);
    expect(mutationWorkspaceFinding(rag, "not-selected", "bounded selection").evidence).toContain("apps/rag/src/rag.ts");
  });
  it("does not discard configured sources merely because inventory identifies emitted output", () => {
    const root = twoApps();
    writeFileSync(join(root, "tsconfig.json"), JSON.stringify({ compilerOptions: { outDir: "generated" }, include: ["apps/**/*.ts"] }));
    mkdirSync(join(root, "generated")); writeFileSync(join(root, "generated", "entry.ts"), "export const generated = 1");
    writeFileSync(join(root, "stryker.generated.config.json"), JSON.stringify({ mutate: ["generated/*.ts"], testRunner: "vitest" }));
    const plan = planMutationWorkspaces(root);
    expect(plan.workspaces[0]!.configuredSources).toContain("generated/entry.ts");
    expect(plan.workspaces[0]!.selectedSources).toContain("generated/entry.ts");
  });
  it("marks dynamic or unreadable configuration as unresolved rather than a clean empty scope", () => {
    const root = twoApps(); writeFileSync(join(root, "apps/rag/stryker.config.mjs"), "export default createConfig(process.env);");
    expect(planMutationWorkspaces(root).workspaces.filter(row => row.directory === "apps/rag").flatMap(row => row.gaps).join(" ")).toContain("stryker.config.mjs");
  });
  it("retains unresolved source links as discovery gaps while preserving healthy siblings", () => {
    const root = twoApps(); symlinkSync("missing.ts", join(root, "apps/rag/src/unavailable.ts"));
    const plan = planMutationWorkspaces(root);
    expect(plan.gaps).toContain("Unresolved source link: apps/rag/src/unavailable.ts");
    expect(plan.workspaces[1]!.selectedSources).toEqual(["apps/main/src/main.ts"]);
  });
  it("plans alternate runner populations independently instead of certifying the widest configuration alone", () => {
    const root = twoApps();
    writeFileSync(join(root, "stryker.rag.integration.json"), JSON.stringify({ testRunner: "vitest", mutate: ["apps/rag/src/*.ts"], vitest: { configFile: "apps/rag/vitest.integration.config.ts" } }));
    const rows = planMutationWorkspaces(root).workspaces.filter(row => row.directory === "apps/rag");
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map(row => row.id)).size).toBe(2);
    expect(rows.flatMap(row => row.strykerConfigurations)).toHaveLength(2);
    expect(rows.map(row => row.runnerConfig).sort()).toEqual(["apps/rag/vitest.config.ts", "apps/rag/vitest.integration.config.ts"]);
    expect(rows.flatMap(row => row.configuredSources)).toContain("apps/rag/src/remaining.ts");
  });
  it.each([
    { buildCommand: "node prepare.js" }, { files: ["src", "test"] }, { coverageAnalysis: "all" },
    { ignoreStatic: false }, { mutator: { excludedMutations: ["StringLiteral"] } }, { plugins: ["custom-runner"] },
  ])("preserves a distinct declared execution contract %j", difference => {
    const root = twoApps(); const base = JSON.parse(readFileSync(join(root, "stryker.rag.config.json"), "utf8"));
    writeFileSync(join(root, "stryker.rag.alternate.json"), JSON.stringify({ ...base, ...difference }));
    const rows = planMutationWorkspaces(root).workspaces.filter(row => row.directory === "apps/rag");
    expect(rows).toHaveLength(2); expect(rows.flatMap(row => row.strykerConfigurations)).toHaveLength(2);
  });
  it("coalesces equivalent execution contracts while retaining both source populations", () => {
    const root = twoApps(); const base = JSON.parse(readFileSync(join(root, "stryker.rag.config.json"), "utf8"));
    writeFileSync(join(root, "stryker.rag.other.json"), JSON.stringify({ ...base, mutate: ["apps/rag/src/remaining.ts"] }));
    const rows = planMutationWorkspaces(root).workspaces.filter(row => row.directory === "apps/rag");
    expect(rows).toHaveLength(1); expect(rows[0]!.strykerConfigurations).toHaveLength(2);
    expect(rows[0]!.selectedSources).toEqual(["apps/rag/src/rag.ts", "apps/rag/src/remaining.ts"]);
  });
  it("preserves the package invocation context of an explicitly selected discovered config", () => {
    const root = twoApps(); const configPath = join(root, "apps/rag/stryker.config.json");
    writeFileSync(configPath, JSON.stringify({ testRunner: "vitest", mutate: ["src/rag.ts"], vitest: { configFile: "vitest.config.ts" } }));
    const plan = planMutationWorkspaces(root, { configPath });
    const selected = plan.workspaces.filter(row => row.selectedSources.length);
    expect(selected).toHaveLength(1); expect(selected[0]).toMatchObject({ configurationDirectory: "apps/rag", runnerConfig: "apps/rag/vitest.config.ts", selectedSources: ["apps/rag/src/rag.ts"] });
    expect(plan.gaps).toEqual([]);
  });
  it.each([true, false])("discloses zero-match explicit configuration scope (discovered: %s)", discovered => {
    const root = twoApps(); const configPath = discovered ? join(root, "apps/rag/stryker.empty.json") : join(fixture({}), "override.json");
    writeFileSync(configPath, JSON.stringify({ testRunner: "vitest", mutate: ["absent/*.ts"] }));
    const plan = planMutationWorkspaces(root, { configPath });
    expect(plan.gaps.join(" ")).toContain("zero source files");
    expect(plan.gaps.join(" ")).toContain("Explicit mutation configuration");
    const output = runMutationWorkspaces(plan, { storage: "/unused", cliPath: "/unused" });
    expect(output.workspaceCoverage).toMatchObject({ complete: false, reported: 0 });
    expect(output.moduleRecord).toMatchObject({ note: expect.stringContaining("zero source files") });
    expect(output).not.toHaveProperty("summary");
  });
  it("rejects source selectors which silently reach no planned production file", () => {
    expect(planMutationWorkspaces(twoApps(), { selection: ["missing.ts"] }).gaps).toContain("Requested production source was not assigned to a workspace: missing.ts");
  });
  it("exposes unresolved workspace declarations", () => {
    const root = fixture({ "package.json": { workspaces: ["absent/*"] } });
    expect(planMutationWorkspaces(root).gaps.join(" ")).toContain("unresolved-glob");
  });
  it("plan-only output conserves every package as unexecuted and emits report-visible gaps", () => {
    const plan = planMutationWorkspaces(twoApps());
    const output = runMutationWorkspaces(plan, { storage: "/unused", cliPath: "/unused", planOnly: true });
    expect(output.workspaceCoverage).toMatchObject({ complete: false, planned: 3, observed: 3 });
    expect(output.moduleRecord).toMatchObject({ status: "partial" });
    expect(output).not.toHaveProperty("summary");
    expect(output).not.toHaveProperty("reportRows");
    expect(testQualityFromArtifact(output)).toBeUndefined();
    const findings = output.findings as ReturnType<typeof mutationWorkspaceFinding>[];
    expect(findings.some(row => row.location === "apps/rag/package.json")).toBe(true);
    expect(findings.every(row => findingFamilyKind(row) === "coverage-disclosure")).toBe(true);
  });
  it("source identity changes when a test/config changes, with original bytes left untouched", () => {
    const root = twoApps(), before = planMutationWorkspaces(root);
    const path = join(root, "apps/rag/vitest.config.ts"), content = readFileSync(path, "utf8");
    expect(readFileSync(path, "utf8")).toBe(content);
    writeFileSync(path, `${content}\n// changed`);
    expect(planMutationWorkspaces(root).sourceSha256).not.toBe(before.sourceSha256);
  });
});
