import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
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
}

// These producers intentionally belong to the connected Supabase scanner rather than the free
// runMechanicalScanDetailed path. Each exception is bound to both the exported bridge and a real
// CLI caller; it is not a name allowlist that can silently absorb a copied or newly implemented
// producer elsewhere in src/scan.
const EXTERNAL_MECHANICAL_PRODUCER_OWNERS: Readonly<Record<string, { bridgeFile: string; bridgeExport: string; runnerFile: string }>> = Object.freeze(Object.fromEntries([
  "checkAuthConfig",
  "checkRealtimeAuthorization",
  "checkGraphqlIntrospection",
  "checkGotrueVersion",
].map((exportName) => [`src/scan/supabase-config.ts#${exportName}`, {
  bridgeFile: "src/scan/supabase.ts", bridgeExport: "runSupabaseScan", runnerFile: "src/cli/scan.ts",
}]).concat([["src/scan/supabase-drift.ts#checkMigrationDrift", {
  bridgeFile: "src/scan/supabase.ts", bridgeExport: "runSupabaseScan", runnerFile: "src/cli/scan.ts",
}]])));

function exportedFunctionBodies(parsed: ts.SourceFile): { exportName: string; type: ts.TypeNode | undefined; body: ts.ConciseBody }[] {
  const functions: { exportName: string; type: ts.TypeNode | undefined; body: ts.ConciseBody }[] = [];
  for (const statement of parsed.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body
      && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      functions.push({ exportName: statement.name.text, type: statement.type, body: statement.body });
      continue;
    }
    if (!ts.isVariableStatement(statement)
      || !statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer
        || (!ts.isArrowFunction(declaration.initializer) && !ts.isFunctionExpression(declaration.initializer))) continue;
      functions.push({ exportName: declaration.name.text, type: declaration.initializer.type, body: declaration.initializer.body });
    }
  }
  return functions;
}

function discoverMechanicalFindingProducerExports(repoRoot: string): DiscoveredMechanicalFindingProducer[] {
  const scanDir = join(repoRoot, "src", "scan");
  if (!existsSync(scanDir)) return [];
  const discovered: DiscoveredMechanicalFindingProducer[] = [];
  for (const relativeFile of readRecursiveSafe(scanDir).filter((path) => path.endsWith(".ts") && !path.endsWith(".test.ts")).sort()) {
    const file = `src/scan/${relativeFile}`;
    const source = readFileSync(join(scanDir, relativeFile), "utf8");
    const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    let mechanicalFindingLocal: string | undefined;
    for (const statement of parsed.statements) {
      if (!ts.isImportDeclaration(statement) || statement.importClause?.isTypeOnly || !statement.importClause
        || !ts.isStringLiteral(statement.moduleSpecifier) || !statement.moduleSpecifier.text.startsWith(".")) continue;
      const importedFile = normalize(join(dirname(file), statement.moduleSpecifier.text)).replace(/\.js$/, ".ts");
      if (importedFile !== "src/scan/common.ts") continue;
      const bindings = statement.importClause.namedBindings;
      if (!bindings || !ts.isNamedImports(bindings)) continue;
      const binding = bindings.elements.find((element) => (element.propertyName?.text ?? element.name.text) === "mechanicalFinding");
      if (binding && !binding.isTypeOnly) mechanicalFindingLocal = binding.name.text;
    }
    if (!mechanicalFindingLocal) continue;
    for (const candidate of exportedFunctionBodies(parsed)) {
      if (!candidate.type || !/\bFinding\b/.test(candidate.type.getText(parsed))) continue;
      let emitsMechanicalFinding = false;
      const visit = (node: ts.Node): void => {
        if (node !== candidate.body && ts.isFunctionLike(node)) return;
        if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === mechanicalFindingLocal) {
          emitsMechanicalFinding = true;
        }
        ts.forEachChild(node, visit);
      };
      visit(candidate.body);
      if (emitsMechanicalFinding) discovered.push({ file, exportName: candidate.exportName });
    }
  }
  return discovered.sort((a, b) => `${a.file}#${a.exportName}`.localeCompare(`${b.file}#${b.exportName}`));
}

function validateMechanicalFindingProducerDiscovery(
  producerSurfaceRoot: string,
  registry: readonly MechanicalRegistryEntry[] = MECHANICAL_REGISTRY,
): string[] {
  const problems: string[] = [];
  const registered = new Set(registry.flatMap((entry) => entry.implementations.map((implementation) => `${implementation.file}#${implementation.exportName}`)));
  for (const producer of discoverMechanicalFindingProducerExports(producerSurfaceRoot)) {
    const key = `${producer.file}#${producer.exportName}`;
    if (registered.has(key)) continue;
    const external = EXTERNAL_MECHANICAL_PRODUCER_OWNERS[key];
    if (!external) {
      problems.push(`${key}: implemented mechanical finding producer is not registered`);
      continue;
    }
    const bridgePath = join(producerSurfaceRoot, external.bridgeFile);
    const runnerPath = join(producerSurfaceRoot, external.runnerFile);
    const bridge = existsSync(bridgePath) ? readFileSync(bridgePath, "utf8") : "";
    const runner = existsSync(runnerPath) ? readFileSync(runnerPath, "utf8") : "";
    if (!bridge.includes(`${producer.exportName}(`)
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
