import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import ts from "typescript";
import { parse, parseFresh, readonlySourceFile, type AstMembraneMetrics } from "../detectors/common.js";
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
  writeFileSync(join(root, "src", "runner.mts"), "export const configured = process.env.RUN_CONFIGURED;\n");
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
    expect(first.envSourceFiles.map((file) => file.path)).toEqual(["src/repo.ts", "src/route.ts", "src/runner.mts"]);
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

  it("retains the canonical in-root workspace population while rejecting physical and parent escapes", () => {
    const container = mkdtempSync(join(tmpdir(), "harvey-shared-workspace-boundary-"));
    roots.push(container);
    const root = join(container, "repo");
    const outside = join(container, "outside");
    mkdirSync(join(root, "packages", "zeta"), { recursive: true });
    mkdirSync(join(root, "packages", "alpha"), { recursive: true });
    mkdirSync(outside);
    writeFileSync(join(root, "package.json"), JSON.stringify({
      name: "root",
      workspaces: ["./packages//*", "../outside", "linked"],
    }));
    writeFileSync(join(root, "packages", "zeta", "package.json"), JSON.stringify({ name: "zeta" }));
    writeFileSync(join(root, "packages", "alpha", "package.json"), JSON.stringify({ name: "alpha" }));
    writeFileSync(join(outside, "package.json"), JSON.stringify({ name: "escaped" }));
    symlinkSync(outside, join(root, "linked"), "dir");

    const context = new MechanicalScanContext(root);
    expect(context.workspace.manifests.map(({ label, name }) => ({ label, name }))).toEqual([
      { label: "package.json", name: "root" },
      { label: "packages/alpha/package.json", name: "alpha" },
      { label: "packages/zeta/package.json", name: "zeta" },
    ]);
    expect(context.workspace.unresolvedGlobs).toEqual(["../outside", "linked"]);
    context.dispose();
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
    const route = first.sourceFiles.find((file) => file.path === "src/route.ts")!;
    const ast = first.withAstCache(() => parse(route.path, route.text));
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
    const originalStart = cached[0]!.statements[0]!.pos;
    expect(() => { (cached[0]!.statements[0] as unknown as { pos: number }).pos = 999; })
      .toThrow("shared TypeScript AST is immutable");
    expect(() => { (cached[0]!.statements as unknown as { pop(): unknown }).pop(); })
      .toThrow("shared TypeScript AST is immutable");
    const laterConsumer = context.withAstCache(() => parse(route.path, route.text));
    expect(laterConsumer).toBe(cached[0]);
    expect(laterConsumer.statements[0]!.pos).toBe(originalStart);
    expect(laterConsumer.statements).toHaveLength(2);
    expect(context.importGraph.get("src/route.ts")).toEqual(["src/repo.ts"]);

    const execution = runRegisteredMechanicalDetectors(context);
    const metrics = context.metrics();
    expect(execution.records.map((record) => record.detector)).toEqual(MECHANICAL_DETECTORS.map((definition) => definition.id));
    expect(execution.records.every((record) => Number.isInteger(record.unitsExamined) && record.unitsExamined >= 0)).toBe(true);
    expect(execution.records.every((record) => record.examinedUnitIdentities.length === record.unitsExamined)).toBe(true);
    expect(execution.records.every((record) => record.examinedUnitIdentities.every((unit) => unit.producer === record.detector))).toBe(true);
    const defaultSurface = execution.records.find((record) => record.detector === "counter-race")!;
    const pagesRouterSurface = execution.records.find((record) => record.detector === "bola-owner")!;
    expect(defaultSurface.examinedUnitIdentities).toEqual([
      { producer: "counter-race", kind: "target-path", identity: "src/repo.ts" },
      { producer: "counter-race", kind: "target-path", identity: "src/route.ts" },
    ]);
    expect(pagesRouterSurface.examinedUnitIdentities).toEqual([]);
    expect(metrics.filesParsed).toBe(3);
    expect(metrics.astsBuilt).toBe(3);
    expect(metrics.astCacheHits).toBeGreaterThan(2);
    expect(metrics.importGraphNodes).toBe(3);
    expect(metrics.legacyEquivalentFileReads).toBeGreaterThan(metrics.filesRead);
    expect(metrics.avoidedFileReads).toBeGreaterThan(0);
    expect(metrics.aggregateRunnerMs).toBeGreaterThanOrEqual(metrics.criticalPathMs);
    expect(metrics.astMembraneObjects).toBeGreaterThan(metrics.astsBuilt);
    expect(metrics.astMembraneMethodWrappers).toBeGreaterThan(0);
    expect(metrics.astMembraneCallbacks).toBeGreaterThan(0);
    expect(metrics.astMembraneIteratorResults).toBeGreaterThanOrEqual(0);
    context.dispose();
  });

  it("keeps producer receipts checkout-independent across two roots containing the same target", () => {
    const first = new MechanicalScanContext(fixture());
    const second = new MechanicalScanContext(fixture());
    const firstReceipts = runRegisteredMechanicalDetectors(first).records.map(({ detector, examinedUnitIdentities }) => ({ detector, examinedUnitIdentities }));
    const secondReceipts = runRegisteredMechanicalDetectors(second).records.map(({ detector, examinedUnitIdentities }) => ({ detector, examinedUnitIdentities }));
    expect(secondReceipts).toEqual(firstReceipts);
    expect(JSON.stringify(firstReceipts)).not.toContain(tmpdir());
    first.dispose();
    second.dispose();
  });

  it("never exposes mutable AST nodes through callbacks, iterators, methods, or nested arrays", () => {
    const context = new MechanicalScanContext(fixture());
    const route = context.sourceFiles.find((file) => file.path === "src/route.ts")!;
    const sourceFile = context.withAstCache(() => parse(route.path, route.text));
    const original = sourceFile.statements.map((statement) => statement.pos);
    const mutate = (node: { pos: number }): boolean => { node.pos = 777; return true; };
    for (const run of [
      () => sourceFile.statements.forEach(mutate),
      () => sourceFile.statements.map(mutate),
      () => sourceFile.statements.find(mutate),
      () => sourceFile.statements.filter(mutate),
      () => sourceFile.statements.reduce((_prior, node) => mutate(node), false),
      () => sourceFile.statements.some(mutate),
      () => sourceFile.statements.every(mutate),
    ]) expect(run).toThrow("shared TypeScript AST is immutable");

    const iterated = sourceFile.statements.values().next().value!;
    expect(() => { (iterated as unknown as { pos: number }).pos = 777; }).toThrow("shared TypeScript AST is immutable");
    const entry = sourceFile.statements.entries().next().value!;
    expect(() => { (entry[1] as unknown as { pos: number }).pos = 777; }).toThrow("shared TypeScript AST is immutable");
    const spread = [...sourceFile.statements];
    expect(() => { (spread[0] as unknown as { pos: number }).pos = 777; }).toThrow("shared TypeScript AST is immutable");

    const children = sourceFile.getChildren();
    expect(children[0]!.getSourceFile()).toBe(sourceFile);
    expect(() => { (children[0] as unknown as { pos: number }).pos = 777; }).toThrow("shared TypeScript AST is immutable");
    const variable = sourceFile.statements.find((statement) => "declarationList" in statement) as unknown as { declarationList?: { declarations: readonly { pos: number }[] } };
    const nested = variable.declarationList?.declarations[0];
    expect(nested).toBeDefined();
    expect(() => { nested!.pos = 777; }).toThrow("shared TypeScript AST is immutable");

    const later = context.withAstCache(() => parse(route.path, route.text));
    expect(later).toBe(sourceFile);
    expect(later.statements.map((statement) => statement.pos)).toEqual(original);
    expect(later.statements).toHaveLength(2);
    context.dispose();
  });

  it("keeps uncached large-population parses consumer-local while retaining a bounded shared set", () => {
    const root = fixture();
    for (let index = 0; index < 300; index++) {
      writeFileSync(join(root, "src", `overflow-${String(index).padStart(3, "0")}.ts`), `export const value${index} = ${index};\n`);
    }
    const context = new MechanicalScanContext(root);
    void context.importGraph;
    const overflow = context.sourceFiles.find((file) => file.path === "src/overflow-299.ts")!;
    const first = context.withAstCache(() => parse(overflow.path, overflow.text));
    const original = first.statements[0]!.pos;
    (first.statements[0] as unknown as { pos: number }).pos = 777;
    const later = context.withAstCache(() => parse(overflow.path, overflow.text));
    expect(later).not.toBe(first);
    expect(later.statements[0]!.pos).toBe(original);
    expect(context.metrics().astCacheRejectedEntries).toBeGreaterThan(0);
    context.dispose();
  });

  it("wraps Map/Set callbacks, descriptors, callable values, and iterator results with stable identities", () => {
    const raw = parseFresh("fixture.ts", "export const value = 1;\n");
    const firstRaw = raw.statements[0]!;
    Object.defineProperties(raw, {
      detectorMap: { configurable: true, enumerable: true, writable: true, value: new Map([["node", firstRaw]]) },
      detectorSet: { configurable: true, enumerable: true, writable: true, value: new Set([firstRaw]) },
      detectorCallback: { configurable: true, enumerable: true, writable: true, value: () => firstRaw },
      detectorConstructorFactory: { configurable: true, enumerable: true, writable: true, value: () => function NodeConstructor() { return firstRaw; } },
    });
    const counters: AstMembraneMetrics = {
      objectsWrapped: 0,
      methodWrappersCreated: 0,
      callbacksWrapped: 0,
      iteratorResultsWrapped: 0,
      rejectedMutations: 0,
    };
    const source = readonlySourceFile(raw, counters) as ts.SourceFile & {
      detectorMap: Map<string, ts.Node>;
      detectorSet: Set<ts.Node>;
      detectorCallback: () => ts.Node;
      detectorConstructorFactory: () => new () => ts.Node;
    };
    const node = source.statements[0]!;
    expect(source.statements[Symbol.iterator]).toBe(source.statements[Symbol.iterator]);
    expect(source.getChildren).toBe(source.getChildren);
    expect(source.detectorMap.get("node")).toBe(node);
    expect(source.detectorSet.values().next().value).toBe(node);
    expect(source.detectorMap.entries().next().value?.[1]).toBe(node);
    expect(source.detectorCallback()).toBe(node);
    const constructed = new (source.detectorConstructorFactory())();
    expect(constructed).toBe(node);
    expect(() => { (constructed as unknown as { pos: number }).pos = 902; }).toThrow("shared TypeScript AST is immutable");
    expect(source.statements.indexOf(node)).toBe(0);
    expect(node.parent).toBe(source);
    expect(node.getSourceFile()).toBe(source);
    expect(Object.getOwnPropertyDescriptor(source, "statements")?.value).toBe(source.statements);

    let callbackOwner: unknown;
    expect(() => source.detectorMap.forEach((value, _key, owner) => {
      callbackOwner = owner;
      (value as unknown as { pos: number }).pos = 900;
    })).toThrow("shared TypeScript AST is immutable");
    expect(callbackOwner).toBe(source.detectorMap);
    expect(() => source.detectorSet.forEach((value, duplicate, owner) => {
      expect(duplicate).toBe(value);
      callbackOwner = owner;
      (value as unknown as { pos: number }).pos = 901;
    })).toThrow("shared TypeScript AST is immutable");
    expect(callbackOwner).toBe(source.detectorSet);
    expect(() => source.detectorMap.set("other", node)).toThrow("shared TypeScript AST is immutable");
    expect(() => source.detectorSet.add(node)).toThrow("shared TypeScript AST is immutable");
    expect(counters.objectsWrapped).toBeGreaterThan(5);
    expect(counters.methodWrappersCreated).toBeGreaterThan(5);
    expect(counters.callbacksWrapped).toBe(2);
    expect(counters.iteratorResultsWrapped).toBeGreaterThanOrEqual(2);
    expect(counters.rejectedMutations).toBe(5);
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
