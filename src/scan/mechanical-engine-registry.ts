import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize, relative as relativePath } from "node:path";
import ts from "typescript";
import { readRecursiveSafe } from "../fs-walk.js";
import {
  MECHANICAL_DETECTORS,
  validateMechanicalDetectorRegistry,
} from "./mechanical-detector-registry.js";
import { CONFIGURATION_DETECTORS } from "./mechanical-configuration-registry.js";
import { DEPENDENCY_DETECTORS } from "./mechanical-dependency-registry.js";
import { NORMALIZATION_ENGINES } from "./mechanical-normalization-registry.js";
import { SECRETS_ENGINES } from "./mechanical-secrets-registry.js";
import { SEMGREP_ENGINES } from "./mechanical-semgrep-registry.js";

export interface MechanicalRegistryEntry {
  id: string;
  order: number;
  module: "M1" | "M6";
  phase: "secrets-history" | "dependency-advisory" | "semgrep" | "configuration" | "structural-ast" | "normalization";
  implementations: readonly { file: string; exportName: string }[];
  taxonomies: readonly string[];
  applicableFiles: string;
  examinedUnits: string;
  select: (...args: never[]) => readonly unknown[];
  countExaminedUnits: (...args: never[]) => number;
  prerequisites: readonly string[];
  fallback: string;
  positiveFixture: { status: "covered" | "structured-exception"; path?: string; detail: string };
  benignTwin: { status: "covered" | "structured-exception"; path?: string; detail: string };
  conservation: { status: "covered" | "structured-exception"; path?: string; detail: string };
  corpus: { status: "covered" | "structured-exception"; path?: string; detail: string };
  cadence: { status: "covered" | "structured-exception"; path?: string; detail: string };
  registryFile: string;
}

const structural: MechanicalRegistryEntry[] = MECHANICAL_DETECTORS.map((definition) => ({
  id: definition.id, order: definition.order, module: definition.module, phase: "structural-ast",
  implementations: [definition.implementation], taxonomies: definition.taxonomies,
  applicableFiles: definition.applicableFiles.description, prerequisites: definition.prerequisites, fallback: definition.fallback,
  examinedUnits: "The detector-specific examinedUnits(context, selected) function records its selected file/schema population.",
  select: definition.applicableFiles.select as (...args: never[]) => readonly unknown[],
  countExaminedUnits: definition.examinedUnits as (...args: never[]) => number,
  positiveFixture: definition.positiveFixture, benignTwin: definition.benignTwin, conservation: definition.conservation,
  corpus: definition.corpus, cadence: definition.cadence, registryFile: "src/scan/mechanical-detector-registry.ts",
}));

const configuration: MechanicalRegistryEntry[] = CONFIGURATION_DETECTORS.map((definition) => ({
  ...definition, applicableFiles: definition.applicableFiles.description,
  implementations: [definition.implementation, ...(definition.additionalImplementations ?? [])], examinedUnits: "The producer-specific examinedUnits(input, selected) function counts exactly its executable selector population.",
  select: definition.applicableFiles.select as (...args: never[]) => readonly unknown[],
  countExaminedUnits: definition.countExaminedUnits as (...args: never[]) => number,
  registryFile: "src/scan/mechanical-configuration-registry.ts",
}));
const dependency: MechanicalRegistryEntry[] = DEPENDENCY_DETECTORS.map((definition) => ({
  ...definition, applicableFiles: definition.applicableFiles.description,
  implementations: [definition.implementation, ...(definition.additionalImplementations ?? [])], examinedUnits: "The producer-specific examinedUnits(state, selected) function counts exactly its executable selector population.",
  select: definition.applicableFiles.select as (...args: never[]) => readonly unknown[],
  countExaminedUnits: definition.countExaminedUnits as (...args: never[]) => number,
  registryFile: "src/scan/mechanical-dependency-registry.ts",
}));
const normalizeAggregate = <T extends { id: string; order: number; module: "M1"; phase: MechanicalRegistryEntry["phase"]; implementations: readonly { file: string; exportName: string }[]; taxonomies: readonly string[]; applicableFiles: string; examinedUnits: string; prerequisites: readonly string[]; fallback: string; positiveFixture: MechanicalRegistryEntry["positiveFixture"]; benignTwin: MechanicalRegistryEntry["benignTwin"]; conservation: MechanicalRegistryEntry["conservation"]; corpus: MechanicalRegistryEntry["corpus"]; cadence: MechanicalRegistryEntry["cadence"]; select: (...args: never[]) => readonly unknown[]; countExaminedUnits: (...args: never[]) => number; }>(entries: readonly T[], registryFile: string): MechanicalRegistryEntry[] => entries.map((definition) => ({
  ...definition, examinedUnits: "The producer-specific countExaminedUnits(input, selected) function counts exactly its executable selector population.", registryFile,
}));

export const MECHANICAL_REGISTRY: readonly MechanicalRegistryEntry[] = Object.freeze([
  ...normalizeAggregate(SECRETS_ENGINES, "src/scan/mechanical-secrets-registry.ts"),
  ...dependency,
  ...normalizeAggregate(SEMGREP_ENGINES, "src/scan/mechanical-semgrep-registry.ts"),
  ...configuration,
  ...structural,
  ...normalizeAggregate(NORMALIZATION_ENGINES, "src/scan/mechanical-normalization-registry.ts"),
]);

function evidenceProblems(entry: MechanicalRegistryEntry, repoRoot: string): string[] {
  const problems: string[] = [];
  for (const [name, evidence] of Object.entries({ positiveFixture: entry.positiveFixture, benignTwin: entry.benignTwin, conservation: entry.conservation, corpus: entry.corpus, cadence: entry.cadence })) {
    if (evidence.detail.trim().length < 20) problems.push(`${entry.phase}:${entry.id}: ${name} has no substantive detail`);
    if (!evidence.detail.includes(entry.id)) problems.push(`${entry.phase}:${entry.id}: ${name} is generic rather than producer-specific`);
    if (evidence.status === "structured-exception" && evidence.path) problems.push(`${entry.phase}:${entry.id}: ${name} exception must not claim a path`);
    if (evidence.status !== "covered") continue;
    if (!evidence.path || !existsSync(join(repoRoot, evidence.path))) {
      problems.push(`${entry.phase}:${entry.id}: ${name} points to missing evidence ${evidence.path ?? "(none)"}`);
      continue;
    }
    const proof = readFileSync(join(repoRoot, evidence.path), "utf8");
    if ((name === "positiveFixture" || name === "benignTwin")
      && !entry.implementations.some((implementation) => proof.includes(implementation.exportName))
      && !proof.includes(entry.id)) {
      problems.push(`${entry.phase}:${entry.id}: ${name} does not consume a registered implementation or registry id`);
    }
    if (name === "corpus" && (!proof.includes("runMechanicalScanDetailed") || !proof.includes("mechanicalRun.detectors"))) {
      problems.push(`${entry.phase}:${entry.id}: corpus evidence does not execute the mechanical registry and retain its execution census`);
    }
    if (name === "cadence" && !proof.includes("corpus-drift")) {
      problems.push(`${entry.phase}:${entry.id}: cadence evidence does not invoke the pinned-corpus runner`);
    }
  }
  return problems;
}

function metadataIdentity(entry: MechanicalRegistryEntry): string {
  return JSON.stringify({
    id: entry.id,
    order: entry.order,
    module: entry.module,
    phase: entry.phase,
    implementations: entry.implementations,
    taxonomies: entry.taxonomies,
    applicableFiles: entry.applicableFiles,
    examinedUnits: entry.examinedUnits,
    select: String(entry.select),
    countExaminedUnits: String(entry.countExaminedUnits),
    prerequisites: entry.prerequisites,
    fallback: entry.fallback,
    positiveFixture: entry.positiveFixture,
    benignTwin: entry.benignTwin,
    conservation: entry.conservation,
    corpus: entry.corpus,
    cadence: entry.cadence,
    registryFile: entry.registryFile,
  });
}

const PHASE_RUNNERS: Readonly<Record<MechanicalRegistryEntry["phase"], string>> = Object.freeze({
  "secrets-history": "runRegisteredSecretsEngines",
  "dependency-advisory": "runRegisteredDependencyDetectors",
  semgrep: "runRegisteredSemgrepEngines",
  configuration: "runRegisteredConfigurationDetectors",
  "structural-ast": "runRegisteredMechanicalDetectors",
  normalization: "runRegisteredNormalizationEngines",
});

const NON_PRODUCER_REGISTRY_CALLS = new Set([
  "src/scan/mechanical-registry-assurance.ts#producerAssurance",
  "src/scan/mechanical-registry-contract.ts#assertProducerTaxonomyOwnership",
  "src/scan/framework-detect.ts#detectOrm",
  "src/sbom.ts#licenseScope",
]);

interface DiscoveredMechanicalFindingProducer {
  file: string;
  exportName: string;
  canonicalId: string;
  supportCanonicalIds: readonly string[];
}

// These producers intentionally belong to a scanner outside the free runMechanicalScanDetailed
// path. Each exception is bound to both the exported bridge and a real CLI caller; it is not a
// name allowlist that can silently absorb a copied or newly implemented producer elsewhere in
// src/scan. A self-bridge is itself the exported boundary consumed by the CLI.
interface ExternalMechanicalProducerOwner {
  bridgeFile: string;
  bridgeExport: string;
  runnerFile: string;
  selfBridge?: true;
}

const EXTERNAL_MECHANICAL_PRODUCER_OWNERS: Readonly<Record<string, ExternalMechanicalProducerOwner>> = Object.freeze(Object.fromEntries([
  "checkAuthConfig",
  "checkRealtimeAuthorization",
  "checkGraphqlIntrospection",
  "checkGotrueVersion",
].map((exportName) => [`src/scan/supabase-config.ts#${exportName}`, {
  bridgeFile: "src/scan/supabase.ts", bridgeExport: "runSupabaseScan", runnerFile: "src/cli/scan.ts",
}]).concat([
  ["src/scan/supabase-drift.ts#checkMigrationDrift", {
  bridgeFile: "src/scan/supabase.ts", bridgeExport: "runSupabaseScan", runnerFile: "src/cli/scan.ts",
  }],
  ["src/scan/prisma-app-perf.ts#detectPrismaAppPerfFindings", {
    bridgeFile: "src/scan/prisma-app-perf.ts", bridgeExport: "scanPrismaAppPerf", runnerFile: "src/cli/static-detect.ts",
  }],
  ["src/scan/prisma-app-perf.ts#scanPrismaAppPerf", {
    bridgeFile: "src/scan/prisma-app-perf.ts", bridgeExport: "scanPrismaAppPerf", runnerFile: "src/cli/static-detect.ts", selfBridge: true,
  }],
  ["src/scan/supabase.ts#runSupabaseScan", {
    bridgeFile: "src/scan/supabase.ts", bridgeExport: "runSupabaseScan", runnerFile: "src/cli/scan.ts", selfBridge: true,
  }],
  ["src/scan/ext-coverage.ts#checkUnreadSourceExtensions", {
    bridgeFile: "src/scan/ext-coverage.ts", bridgeExport: "checkUnreadSourceExtensions", runnerFile: "src/cli/static-detect.ts", selfBridge: true,
  }],
  ["src/scan/import-graph-scope.ts#importGraphNotAssessedRows", {
    bridgeFile: "src/scan/import-graph-scope.ts", bridgeExport: "importGraphNotAssessedRows", runnerFile: "src/cli/static-detect.ts", selfBridge: true,
  }],
] as [string, ExternalMechanicalProducerOwner][])));

interface MechanicalProducerDiscovery {
  producers: DiscoveredMechanicalFindingProducer[];
  problems: string[];
}

const mechanicalProducerDiscoveryCache = new Map<string, MechanicalProducerDiscovery>();

function discoverMechanicalFindingProducerExports(repoRoot: string): MechanicalProducerDiscovery {
  const cached = mechanicalProducerDiscoveryCache.get(repoRoot);
  if (cached) return cached;
  const scanDir = join(repoRoot, "src", "scan");
  if (!existsSync(scanDir)) return { producers: [], problems: [] };
  const rootNames = readRecursiveSafe(scanDir)
    .filter((path) => path.endsWith(".ts") && !path.endsWith(".test.ts"))
    .map((path) => join(scanDir, path))
    .sort();
  const program = ts.createProgram(rootNames, {
    allowJs: false,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.Latest,
  });
  const checker = program.getTypeChecker();
  const problems: string[] = [];
  const functionBodies = new Map<ts.Symbol, ts.ConciseBody>();
  const callableSymbols = new Set<ts.Symbol>();
  const valueEdges = new Map<ts.Symbol, Set<ts.Symbol>>();
  const callEdges = new Map<ts.Symbol, Set<ts.Symbol>>();
  const direct = new Set<ts.Symbol>();
  const dynamicCalls: { owner: ts.Symbol; candidates: Set<ts.Symbol>; location: string }[] = [];
  const exported: { file: string; exportName: string; symbol: ts.Symbol }[] = [];
  const starExports = new Map<string, { target: ts.SourceFile; location: string }[]>();
  const repoRelative = (source: ts.SourceFile): string => normalize(relativePath(repoRoot, source.fileName));
  const unalias = (symbol: ts.Symbol | undefined): ts.Symbol | undefined => {
    const seen = new Set<ts.Symbol>();
    let current = symbol;
    while (current && (current.flags & ts.SymbolFlags.Alias) !== 0 && !seen.has(current)) {
      seen.add(current);
      const next = checker.getAliasedSymbol(current);
      if (!next || next === current) break;
      current = next;
    }
    return current;
  };
  const addEdge = (map: Map<ts.Symbol, Set<ts.Symbol>>, from: ts.Symbol, to: ts.Symbol | undefined): void => {
    const target = unalias(to);
    if (!target) return;
    const edges = map.get(from) ?? new Set<ts.Symbol>();
    edges.add(target);
    map.set(from, edges);
  };
  const expressionSymbols = (node: ts.Node): Set<ts.Symbol> => {
    const out = new Set<ts.Symbol>();
    const visit = (child: ts.Node): void => {
      if (ts.isIdentifier(child) || ts.isPropertyAccessExpression(child)) {
        const symbol = unalias(checker.getSymbolAtLocation(ts.isPropertyAccessExpression(child) ? child.name : child));
        if (symbol) out.add(symbol);
      }
      ts.forEachChild(child, visit);
    };
    visit(node);
    return out;
  };
  const directFindingObject = (node: ts.ObjectLiteralExpression): boolean => {
    const names = new Set(node.properties.flatMap((property) => {
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) return [];
      const name = property.name;
      return ts.isIdentifier(name) || ts.isStringLiteral(name) ? [name.text] : [];
    }));
    return ["id", "title", "severity", "category", "taxonomy", "location", "evidence", "impact", "fix"]
      .every((name) => names.has(name));
  };
  for (const source of program.getSourceFiles().filter((file) => rootNames.includes(file.fileName))) {
    const file = repoRelative(source);
    const moduleSymbol = checker.getSymbolAtLocation(source);
    if (moduleSymbol) for (const exportSymbol of checker.getExportsOfModule(moduleSymbol)) {
      const target = unalias(exportSymbol);
      if (target) exported.push({ file, exportName: exportSymbol.getName(), symbol: target });
    }
    const stars: { target: ts.SourceFile; location: string }[] = [];
    for (const statement of source.statements) {
      if (!ts.isExportDeclaration(statement) || statement.exportClause || !statement.moduleSpecifier
        || !ts.isStringLiteral(statement.moduleSpecifier) || !statement.moduleSpecifier.text.startsWith(".")) continue;
      const target = checker.getSymbolAtLocation(statement.moduleSpecifier)?.declarations?.[0]?.getSourceFile();
      if (target) stars.push({ target, location: `${file}:${source.getLineAndCharacterOfPosition(statement.getStart()).line + 1}` });
    }
    if (stars.length > 0) starExports.set(file, stars);
    const collect = (node: ts.Node): void => {
      if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) && node.body) {
        const nameNode = ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) ? node.name : node.parent && ts.isVariableDeclaration(node.parent) ? node.parent.name : undefined;
        const owner = nameNode ? unalias(checker.getSymbolAtLocation(nameNode)) : undefined;
        if (owner) {
          functionBodies.set(owner, node.body);
          callableSymbols.add(owner);
        }
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const owner = unalias(checker.getSymbolAtLocation(node.name));
        if (owner) {
          if (ts.isIdentifier(node.initializer) || ts.isPropertyAccessExpression(node.initializer)) callableSymbols.add(owner);
          for (const target of expressionSymbols(node.initializer)) if (target !== owner) addEdge(valueEdges, owner, target);
        }
        const statement = node.parent.parent;
        if ((ts.isIdentifier(node.initializer) || ts.isPropertyAccessExpression(node.initializer))
          && ts.isVariableStatement(statement)
          && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
          && !checker.getSymbolAtLocation(ts.isPropertyAccessExpression(node.initializer) ? node.initializer.name : node.initializer)) {
          problems.push(`${file}#${node.name.text}: stale exported helper alias cannot be resolved`);
        }
      }
      if (ts.isExportSpecifier(node)) {
        const target = unalias(checker.getSymbolAtLocation(node.propertyName ?? node.name));
        if (!target) problems.push(`${file}#${node.name.text}: stale exported helper alias cannot be resolved`);
      }
      ts.forEachChild(node, collect);
    };
    collect(source);
  }
  const commonSource = program.getSourceFiles().find((source) => repoRelative(source) === "src/scan/common.ts");
  const commonModule = commonSource ? checker.getSymbolAtLocation(commonSource) : undefined;
  const mechanicalFinding = commonModule
    ? checker.getExportsOfModule(commonModule).find((candidate) => candidate.getName() === "mechanicalFinding")
    : undefined;
  const seed = unalias(mechanicalFinding);
  for (const [owner, body] of functionBodies) {
    const visit = (node: ts.Node): void => {
      if (node !== body && ts.isFunctionLike(node)) return;
      if (owner !== seed && ts.isObjectLiteralExpression(node) && directFindingObject(node)) direct.add(owner);
      if (ts.isCallExpression(node)) {
        const called = unalias(checker.getSymbolAtLocation(ts.isPropertyAccessExpression(node.expression) ? node.expression.name : node.expression));
        if (called) {
          if (called === seed) direct.add(owner);
          else addEdge(callEdges, owner, called);
        } else if (!ts.isIdentifier(node.expression) && !ts.isPropertyAccessExpression(node.expression)) {
          dynamicCalls.push({
            owner,
            candidates: expressionSymbols(node.expression),
            location: `${repoRelative(node.getSourceFile())}:${node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1}`,
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(body);
  }

  const dependencies = new Map<ts.Symbol, Set<ts.Symbol>>();
  for (const [owner, targets] of [...valueEdges, ...callEdges]) {
    const combined = dependencies.get(owner) ?? new Set<ts.Symbol>();
    for (const target of targets) combined.add(target);
    dependencies.set(owner, combined);
  }
  const producers = new Set(direct);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [key, called] of dependencies) if (!producers.has(key) && [...called].some((target) => producers.has(target))) {
      producers.add(key);
      changed = true;
    }
  }
  for (const dynamic of dynamicCalls) {
    const reachable = new Set(dynamic.candidates);
    let grew = true;
    while (grew) {
      grew = false;
      for (const candidate of [...reachable]) for (const target of dependencies.get(candidate) ?? []) if (!reachable.has(target)) {
        reachable.add(target);
        grew = true;
      }
    }
    if ([...reachable].some((candidate) => producers.has(candidate))) {
      problems.push(`${dynamic.location}: ambiguous dynamic mechanical producer dispatch is not registry-auditable`);
      producers.add(dynamic.owner);
    }
  }
  for (const [file, stars] of starExports) {
    if (stars.length < 2) continue;
    const owners = new Map<string, Set<ts.Symbol>>();
    for (const star of stars) {
      const moduleSymbol = checker.getSymbolAtLocation(star.target);
      if (!moduleSymbol) continue;
      for (const candidate of checker.getExportsOfModule(moduleSymbol)) {
        const target = unalias(candidate);
        if (!target || !producers.has(target)) continue;
        const symbols = owners.get(candidate.getName()) ?? new Set<ts.Symbol>();
        symbols.add(target);
        owners.set(candidate.getName(), symbols);
      }
    }
    for (const [name, symbols] of owners) if (symbols.size > 1) problems.push(`${file}#${name}: ambiguous export-star mechanical producer ownership`);
  }
  const canonicalId = (symbol: ts.Symbol): string => {
    const declaration = symbol.declarations?.[0];
    return declaration ? `${repoRelative(declaration.getSourceFile())}#${symbol.getName()}@${declaration.pos}` : `symbol#${symbol.getName()}`;
  };
  const result = exported
    .filter((entry) => producers.has(entry.symbol) && callableSymbols.has(entry.symbol))
    .map(({ file, exportName, symbol }) => {
      const reachable = new Set<ts.Symbol>();
      const pending = [...(dependencies.get(symbol) ?? [])];
      while (pending.length > 0) {
        const candidate = pending.pop()!;
        if (reachable.has(candidate)) continue;
        reachable.add(candidate);
        pending.push(...(dependencies.get(candidate) ?? []));
      }
      return {
        file: normalize(file),
        exportName,
        canonicalId: canonicalId(symbol),
        supportCanonicalIds: [...reachable].filter((candidate) => producers.has(candidate)).map(canonicalId).sort(),
      };
    });
  const discovery = {
    producers: [...new Map(result.map((entry) => [`${entry.file}#${entry.exportName}`, entry])).values()]
      .sort((a, b) => `${a.file}#${a.exportName}`.localeCompare(`${b.file}#${b.exportName}`)),
    problems: [...new Set(problems)].sort(),
  };
  mechanicalProducerDiscoveryCache.set(repoRoot, discovery);
  return discovery;
}

function validateMechanicalFindingProducerDiscovery(
  producerSurfaceRoot: string,
  registry: readonly MechanicalRegistryEntry[] = MECHANICAL_REGISTRY,
): string[] {
  const problems: string[] = [];
  const registered = new Set(registry.flatMap((entry) => entry.implementations.map((implementation) => `${implementation.file}#${implementation.exportName}`)));
  const discovery = discoverMechanicalFindingProducerExports(producerSurfaceRoot);
  problems.push(...discovery.problems);
  const byKey = new Map(discovery.producers.map((producer) => [`${producer.file}#${producer.exportName}`, producer]));
  const ownerCanonicalIds = new Set<string>();
  for (const key of [...registered, ...Object.keys(EXTERNAL_MECHANICAL_PRODUCER_OWNERS)]) {
    const owner = byKey.get(key);
    if (owner) ownerCanonicalIds.add(owner.canonicalId);
  }
  const supportCanonicalIds = new Set(discovery.producers
    .filter((producer) => ownerCanonicalIds.has(producer.canonicalId))
    .flatMap((producer) => [...producer.supportCanonicalIds]));
  for (const producer of discovery.producers) {
    const key = `${producer.file}#${producer.exportName}`;
    if (registered.has(key)) continue;
    const external = EXTERNAL_MECHANICAL_PRODUCER_OWNERS[key];
    if (!external && (ownerCanonicalIds.has(producer.canonicalId) || supportCanonicalIds.has(producer.canonicalId))) continue;
    if (!external) {
      problems.push(`${key}: implemented mechanical finding producer is not registered`);
      continue;
    }
    const bridgePath = join(producerSurfaceRoot, external.bridgeFile);
    const runnerPath = join(producerSurfaceRoot, external.runnerFile);
    const bridge = existsSync(bridgePath) ? readFileSync(bridgePath, "utf8") : "";
    const runner = existsSync(runnerPath) ? readFileSync(runnerPath, "utf8") : "";
    if ((!external.selfBridge && !bridge.includes(`${producer.exportName}(`))
      || !new RegExp(`\\bexport (?:async )?function ${external.bridgeExport}\\b`).test(bridge)
      || !runner.includes(`${external.bridgeExport}(`)) {
      problems.push(`${key}: stale external owner ${external.bridgeFile}#${external.bridgeExport} -> ${external.runnerFile}`);
    }
  }
  return problems;
}

export function discoverMechanicalRegistryImplementations(repoRoot: string): { file: string; exportName: string; registryFile: string }[] {
  const registryFiles = [...new Set(MECHANICAL_REGISTRY.filter((entry) => entry.phase !== "structural-ast").map((entry) => entry.registryFile))];
  const discovered = new Map<string, { file: string; exportName: string; registryFile: string }>();
  for (const registryFile of registryFiles) {
    const source = readFileSync(join(repoRoot, registryFile), "utf8");
    const parsed = ts.createSourceFile(registryFile, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const imports = new Map<string, { file: string; exportName: string }>();
    for (const statement of parsed.statements) {
      if (!ts.isImportDeclaration(statement) || statement.importClause?.isTypeOnly || !statement.importClause
        || !ts.isStringLiteral(statement.moduleSpecifier) || !statement.moduleSpecifier.text.startsWith(".")) continue;
      const bindings = statement.importClause.namedBindings;
      if (!bindings || !ts.isNamedImports(bindings)) continue;
      const file = normalize(join(dirname(registryFile), statement.moduleSpecifier.text)).replace(/\.js$/, ".ts");
      for (const element of bindings.elements) {
        if (element.isTypeOnly) continue;
        imports.set(element.name.text, { file, exportName: element.propertyName?.text ?? element.name.text });
      }
    }
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        const implementation = imports.get(node.expression.text);
        if (implementation) {
          const key = `${implementation.file}#${implementation.exportName}`;
          if (!NON_PRODUCER_REGISTRY_CALLS.has(key)) discovered.set(`${registryFile}:${key}`, { ...implementation, registryFile });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
  }
  return [...discovered.values()].sort((a, b) => `${a.registryFile}:${a.file}:${a.exportName}`.localeCompare(`${b.registryFile}:${b.file}:${b.exportName}`));
}

export function validateMechanicalOrchestrationSource(source: string, registry: readonly MechanicalRegistryEntry[] = MECHANICAL_REGISTRY): string[] {
  const problems: string[] = [];
  for (const [phase, runner] of Object.entries(PHASE_RUNNERS)) {
    if (!new RegExp(`\\b${runner}\\s*\\(`).test(source)) problems.push(`${phase}: mechanical orchestrator does not invoke ${runner}`);
  }

  const approvedComposition = new Set([
    "...secrets.findings",
    "...dependencyFindings",
    "...semgrepPhase.findings",
    "...configuration.findings",
    "...supplyFindings",
    "...structural.findings",
  ]);
  const pushes = [...source.matchAll(/findings\.push\(([^;\n]+)\);/g)].map((match) => match[1]!.trim());
  const unexpectedPushes = pushes.filter((expression) => !approvedComposition.has(expression));
  const missingPushes = [...approvedComposition].filter((expression) => !pushes.includes(expression));
  for (const expression of unexpectedPushes) problems.push(`mechanical orchestrator contains an unregistered direct finding composition: findings.push(${expression})`);
  for (const expression of missingPushes) problems.push(`mechanical orchestrator is missing registered phase composition: findings.push(${expression})`);

  const ownedImplementations = new Set(registry.flatMap((entry) => entry.implementations.map((implementation) => `${implementation.file}#${implementation.exportName}`)));
  const parsed = ts.createSourceFile("src/scan/mechanical.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  for (const statement of parsed.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause || statement.importClause.isTypeOnly
      || !ts.isStringLiteral(statement.moduleSpecifier) || !statement.moduleSpecifier.text.startsWith(".")) continue;
    const relativeFile = `src/scan/${statement.moduleSpecifier.text.replace(/^\.\//, "").replace(/\.js$/, ".ts")}`;
    const bindings = statement.importClause.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      if (element.isTypeOnly) continue;
      const imported = element.propertyName?.text ?? element.name.text;
      if (ownedImplementations.has(`${relativeFile}#${imported}`)) {
        problems.push(`mechanical orchestrator directly imports registered producer ${relativeFile}#${imported}; invoke it through its phase registry`);
      }
    }
  }
  return problems;
}

function orchestrationProblems(repoRoot: string, registry: readonly MechanicalRegistryEntry[]): string[] {
  const mechanicalPath = join(repoRoot, "src/scan/mechanical.ts");
  if (!existsSync(mechanicalPath)) return ["mechanical orchestrator is missing: src/scan/mechanical.ts"];
  return validateMechanicalOrchestrationSource(readFileSync(mechanicalPath, "utf8"), registry);
}

export function validateMechanicalEngineRegistry(
  repoRoot: string,
  registry: readonly MechanicalRegistryEntry[] = MECHANICAL_REGISTRY,
  producerSurfaceRoot: string = repoRoot,
): string[] {
  const problems: string[] = validateMechanicalDetectorRegistry(repoRoot).map((problem) => `structural-ast: ${problem}`);
  problems.push(...validateMechanicalFindingProducerDiscovery(producerSurfaceRoot, registry));
  const discoveredImplementations = discoverMechanicalRegistryImplementations(repoRoot);
  const registeredNonStructural = new Set(registry.filter((entry) => entry.phase !== "structural-ast").flatMap((entry) => entry.implementations.map((implementation) => `${entry.registryFile}:${implementation.file}#${implementation.exportName}`)));
  const discoveredKeys = new Set(discoveredImplementations.map((implementation) => `${implementation.registryFile}:${implementation.file}#${implementation.exportName}`));
  for (const implementation of discoveredImplementations) {
    const key = `${implementation.registryFile}:${implementation.file}#${implementation.exportName}`;
    if (!registeredNonStructural.has(key)) problems.push(`${implementation.registryFile}: live implementation ${implementation.file}#${implementation.exportName} is invoked but unregistered`);
  }
  for (const key of registeredNonStructural) {
    if (!discoveredKeys.has(key)) problems.push(`${key}: registered implementation is not invoked by its live phase registry`);
  }
  const canonical = new Map(MECHANICAL_REGISTRY.map((entry) => [`${entry.phase}:${entry.id}`, entry]));
  const supplied = new Map(registry.map((entry) => [`${entry.phase}:${entry.id}`, entry]));
  for (const key of canonical.keys()) if (!supplied.has(key)) problems.push(`${key}: registered mechanical producer is missing`);
  for (const [key, entry] of supplied) {
    const expected = canonical.get(key);
    if (!expected) problems.push(`${key}: unrecognized mechanical producer is registered`);
    else if (metadataIdentity(entry) !== metadataIdentity(expected)) problems.push(`${key}: registry metadata differs from canonical invocation ownership`);
  }
  for (const entry of registry) {
    if (entry.implementations.length === 0 || entry.taxonomies.length === 0 || entry.applicableFiles.trim().length === 0 || entry.examinedUnits.trim().length === 0 || entry.fallback.trim().length === 0 || typeof entry.select !== "function" || typeof entry.countExaminedUnits !== "function") problems.push(`${entry.phase}:${entry.id}: required implementation/taxonomy/executable-applicability/examined-unit/fallback metadata is missing`);
    const registrySource = existsSync(join(repoRoot, entry.registryFile)) ? readFileSync(join(repoRoot, entry.registryFile), "utf8") : "";
    for (const implementation of entry.implementations) {
      const implementationPath = join(repoRoot, implementation.file);
      if (!existsSync(implementationPath)) {
        problems.push(`${entry.phase}:${entry.id}: missing implementation ${implementation.file}`);
        continue;
      }
      const source = readFileSync(implementationPath, "utf8");
      if (!new RegExp(`\\bexport (?:async )?function ${implementation.exportName}\\b`).test(source)) problems.push(`${entry.phase}:${entry.id}: stale implementation export ${implementation.file}#${implementation.exportName}`);
      if ((registrySource.match(new RegExp(`\\b${implementation.exportName}\\b`, "g")) ?? []).length < 2) problems.push(`${entry.phase}:${entry.id}: invocation registry does not consume ${implementation.exportName}`);
    }
    problems.push(...evidenceProblems(entry, repoRoot));
  }
  const duplicate = registry.map((entry) => `${entry.phase}:${entry.id}`).filter((key, index, all) => all.indexOf(key) !== index);
  for (const key of new Set(duplicate)) problems.push(`${key}: duplicate registry identity`);
  const duplicateIds = registry.map((entry) => entry.id).filter((id, index, all) => all.indexOf(id) !== index);
  for (const id of new Set(duplicateIds)) problems.push(`${id}: duplicate producer id across mechanical phases`);
  const implementationOwners = new Map<string, string[]>();
  for (const entry of registry) for (const implementation of entry.implementations) {
    const key = `${implementation.file}#${implementation.exportName}`;
    const owners = implementationOwners.get(key) ?? [];
    owners.push(`${entry.phase}:${entry.id}`);
    implementationOwners.set(key, owners);
  }
  for (const [implementation, owners] of implementationOwners) {
    if (owners.length > 1) problems.push(`${implementation}: duplicate implementation ownership [${owners.join(", ")}]`);
  }
  for (const phase of new Set(registry.map((entry) => entry.phase))) {
    const entries = registry.filter((entry) => entry.phase === phase);
    const duplicateOrders = entries.map((entry) => entry.order).filter((order, index, all) => all.indexOf(order) !== index);
    for (const order of new Set(duplicateOrders)) problems.push(`${phase}: duplicate execution order ${order}`);
    if (entries.some((entry, index) => index > 0 && entries[index - 1]!.order >= entry.order)) problems.push(`${phase}: registry order is not strictly increasing`);
  }
  problems.push(...orchestrationProblems(repoRoot, registry));
  return problems;
}

export function operatorMechanicalScopeRows(): readonly { id: string; module: "M1" | "M6"; phase: MechanicalRegistryEntry["phase"]; taxonomies: readonly string[]; selector: string; examinedUnits: string; prerequisites: readonly string[]; fallback: string; positiveFixture: MechanicalRegistryEntry["positiveFixture"]; benignTwin: MechanicalRegistryEntry["benignTwin"]; conservation: MechanicalRegistryEntry["conservation"]; corpus: MechanicalRegistryEntry["corpus"]; cadence: MechanicalRegistryEntry["cadence"] }[] {
  return Object.freeze(MECHANICAL_REGISTRY.map((entry) => Object.freeze({
    id: entry.id, module: entry.module, phase: entry.phase, taxonomies: entry.taxonomies,
    selector: entry.applicableFiles, examinedUnits: entry.examinedUnits, prerequisites: entry.prerequisites,
    fallback: entry.fallback, positiveFixture: entry.positiveFixture, benignTwin: entry.benignTwin,
    conservation: entry.conservation, corpus: entry.corpus, cadence: entry.cadence,
  })));
}
