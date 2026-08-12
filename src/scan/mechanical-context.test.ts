import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "../detectors/common.js";
import { MechanicalScanContext } from "./mechanical-context.js";
import { MECHANICAL_DETECTORS, runRegisteredMechanicalDetectors } from "./mechanical-detector-registry.js";

const roots: string[] = [];

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-shared-context-"));
  roots.push(root);
  mkdirSync(join(root, "src"));
  mkdirSync(join(root, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", dependencies: { express: "4.21.0" } }));
  writeFileSync(join(root, "src", "repo.ts"), "export const findUserById = (id: string) => ({ id });\n");
  writeFileSync(join(root, "src", "route.ts"), "import { findUserById } from './repo';\nexport const route = (id: string) => findUserById(id);\n");
  writeFileSync(join(root, "supabase", "migrations", "001.sql"), "create table users (id uuid primary key, tenant_id uuid);\n");
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("#1851 immutable one-scan context", () => {
  it("builds one source/workspace/dependency/schema inventory with content invalidation", () => {
    const root = fixture();
    const first = new MechanicalScanContext(root);
    expect(first.sourceFiles.map((file) => file.path)).toEqual(["src/repo.ts", "src/route.ts"]);
    expect(first.workspace.manifests.map((manifest) => manifest.label)).toEqual(["package.json"]);
    expect(first.schemas.orderedMigrations.map((migration) => migration.file)).toEqual(["supabase/migrations/001.sql"]);
    expect(first.identity.lifetime).toBe("one-mechanical-scan");
    expect(Object.isFrozen(first.sourceFiles)).toBe(true);
    expect(Object.isFrozen(first.sourceFiles[0])).toBe(true);
    const digest = first.identity.contentDigest;
    first.dispose();

    writeFileSync(join(root, "src", "route.ts"), "export const route = () => 'changed';\n");
    const second = new MechanicalScanContext(root);
    expect(second.identity.contentDigest).not.toBe(digest);
    second.dispose();
  });

  it("includes lockfile-derived dependency state in identity and freezes nested context values", () => {
    const root = fixture();
    const lockfile = join(root, "package-lock.json");
    const writeLock = (version: string) => writeFileSync(lockfile, JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: { "": { dependencies: { express: version } }, "node_modules/express": { version } },
    }));
    writeLock("1.0.0");
    const first = new MechanicalScanContext(root);
    const before = first.identity.contentDigest;
    expect(first.dependencyTree?.versions.get("express")).toBe("1.0.0");
    expect(() => (first.dependencyTree?.versions as Map<string, string>).set("express", "mutated"))
      .toThrow("mechanical scan context maps are immutable");
    expect(() => { (first.workspace.manifests[0]!.dependencies as Record<string, string>).express = "mutated"; })
      .toThrow();
    first.dispose();

    writeLock("2.0.0");
    const second = new MechanicalScanContext(root);
    expect(second.dependencyTree?.versions.get("express")).toBe("2.0.0");
    expect(second.identity.contentDigest).not.toBe(before);
    second.dispose();
  });

  it("includes pnpm workspace declarations in identity and freezes cached AST nodes and statements", () => {
    const root = fixture();
    const workspace = join(root, "pnpm-workspace.yaml");
    writeFileSync(workspace, "packages:\n  - packages/*\n");
    const first = new MechanicalScanContext(root);
    const before = first.identity.contentDigest;
    const ast = first.asts.get("src/route.ts")!;
    expect(Object.isFrozen(ast)).toBe(true);
    expect(Object.isFrozen(ast.statements)).toBe(true);
    expect(() => { (ast.statements as unknown as { pop(): unknown }).pop(); }).toThrow();
    expect(() => { (ast.statements[0] as unknown as { pos: number }).pos = 99; }).toThrow();
    expect(() => { (first.pathAliases as unknown as { push(value: unknown): void }).push({}); }).toThrow();
    first.dispose();

    writeFileSync(workspace, "packages:\n  - apps/*\n");
    const second = new MechanicalScanContext(root);
    expect(second.identity.contentDigest).not.toBe(before);
    second.dispose();
  });

  it("reuses ASTs, derives the import graph, and reports before/after counters", () => {
    const context = new MechanicalScanContext(fixture());
    const route = context.sourceFiles.find((file) => file.path === "src/route.ts")!;
    const cached = context.withAstCache(() => [parse(route.path, route.text), parse(route.path, route.text)]);
    expect(cached[0]).toBe(cached[1]);
    expect(context.importGraph.get("src/route.ts")).toEqual(["src/repo.ts"]);

    const execution = runRegisteredMechanicalDetectors(context);
    const metrics = context.metrics();
    expect(execution.records.map((record) => record.detector)).toEqual(MECHANICAL_DETECTORS.map((definition) => definition.id));
    expect(execution.records.every((record) => Number.isInteger(record.unitsExamined) && record.unitsExamined >= 0)).toBe(true);
    expect(metrics.filesParsed).toBe(2);
    expect(metrics.astsBuilt).toBe(2);
    expect(metrics.astCacheHits).toBeGreaterThan(2);
    expect(metrics.importGraphNodes).toBe(2);
    expect(metrics.legacyEquivalentFileReads).toBeGreaterThan(metrics.filesRead);
    expect(metrics.avoidedFileReads).toBeGreaterThan(0);
    expect(metrics.aggregateRunnerMs).toBeGreaterThanOrEqual(metrics.criticalPathMs);
    context.dispose();
  });

  it("owns tool results once and refuses use after explicit disposal", () => {
    const context = new MechanicalScanContext(fixture());
    context.recordToolResult("semgrep", { findings: 2 });
    expect(context.toolResult("semgrep")).toEqual({ findings: 2 });
    expect(() => { (context.toolResult<{ findings: number }>("semgrep")!).findings = 3; }).toThrow();
    expect(() => context.recordToolResult("semgrep", { findings: 3 })).toThrow("recorded twice");
    context.dispose();
    expect(() => context.metrics()).toThrow("used after its scan lifetime ended");
  });

  it("preserves Vite-aware env-schema findings through the registry invocation", () => {
    const root = fixture();
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", devDependencies: { vite: "7.0.0" } }));
    writeFileSync(join(root, "src", "env.ts"), `import { z } from "zod";
export const env = z.object({ VITE_API_URL: z.string() }).parse(import.meta.env);
`);
    writeFileSync(join(root, "src", "analytics.ts"), "export const api = import.meta.env.VITE_API_URL;\nexport const analytics = import.meta.env.VITE_ANALYTICS_ID;\n");
    const context = new MechanicalScanContext(root);
    expect(context.framework).toBe("vite");
    const ids = runRegisteredMechanicalDetectors(context).findings.map((finding) => finding.id);
    expect(ids).toContain("ENV-undeclared-read-VITE_ANALYTICS_ID");
    expect(ids).not.toContain("ENV-unused-declaration-VITE_API_URL");
    context.dispose();
  });

  it("accepts the live M6IND finding prefix through runtime ownership", () => {
    const root = fixture();
    writeFileSync(join(root, "src", "token.ts"), "export const requestId = () => Math.random().toString(36).slice(2, 10);\n");
    const context = new MechanicalScanContext(root);
    const execution = runRegisteredMechanicalDetectors(context, { handrolledIndicators: true });
    const indicator = execution.findings.find((finding) => finding.taxonomy === "M6 — Indicator: random-string id");
    expect(indicator?.id).toMatch(/^M6IND-/);
    expect(execution.records.find((record) => record.detector === "handrolled-indicators")?.findings).toBe(1);
    context.dispose();
  });
});
