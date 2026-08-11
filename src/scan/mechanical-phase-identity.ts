import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import ts from "typescript";
import { statSafe } from "../fs-walk.js";
import {
  CACHEABLE_MECHANICAL_PHASES,
  binaryVersion,
  digestFiles,
  digestParts,
  digestTree,
  type MechanicalPhase,
  type MechanicalPhaseCacheOptions,
} from "./mechanical-phase-cache.js";
import { materializeRegistryPacks } from "./semgrep.js";

interface PhaseIdentityOptions {
  repoRoot: string;
  cacheDir: string;
  mode: MechanicalPhaseCacheOptions["mode"];
  targetRevision: string;
  targetTree: string;
  optionIdentity: string;
  onEvent?: (message: string) => void;
  registryPackIdentity?: { identity?: string; files?: string[]; failure?: string };
}

function resolveRelativeImplementation(from: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const unresolved = resolve(dirname(from), specifier);
  const withoutJs = unresolved.replace(/\.js$/, "");
  const candidates = [unresolved, `${withoutJs}.ts`, `${withoutJs}.tsx`, join(withoutJs, "index.ts")];
  const found = candidates.find((candidate) => statSafe(candidate)?.isFile());
  if (!found) throw new Error(`mechanical phase implementation import cannot be resolved: ${from} -> ${specifier}`);
  return found;
}

function sourceFile(path: string): ts.SourceFile {
  return ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function importedBindings(path: string, parsed: ts.SourceFile): Map<string, string> {
  const bindings = new Map<string, string>();
  for (const statement of parsed.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const imported = resolveRelativeImplementation(path, statement.moduleSpecifier.text);
    if (!imported || !statement.importClause) continue;
    if (statement.importClause.name) bindings.set(statement.importClause.name.text, imported);
    const named = statement.importClause.namedBindings;
    if (named && ts.isNamespaceImport(named)) bindings.set(named.name.text, imported);
    if (named && ts.isNamedImports(named)) for (const element of named.elements) bindings.set(element.name.text, imported);
  }
  return bindings;
}

function transitiveImplementationClosure(roots: readonly string[]): string[] {
  const closure = new Set<string>();
  const visit = (path: string): void => {
    if (closure.has(path)) return;
    closure.add(path);
    const parsed = sourceFile(path);
    for (const statement of parsed.statements) {
      if ((!ts.isImportDeclaration(statement) && !ts.isExportDeclaration(statement)) || !statement.moduleSpecifier || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
      const imported = resolveRelativeImplementation(path, statement.moduleSpecifier.text);
      if (imported) visit(imported);
    }
  };
  for (const root of roots) visit(root);
  return [...closure].sort();
}

/**
 * Discovers the implementation closure from the identifiers each runPhase callback actually
 * references. A new relative helper import used by a cacheable phase joins its key automatically;
 * an unresolved helper fails loud instead of leaving a stale key. Top-level local helper functions
 * are followed too, adding their imported dependencies to the same closure.
 */
export function discoverMechanicalPhaseImplementationFiles(repoRoot: string): Partial<Record<MechanicalPhase, string[]>> {
  const mechanical = join(repoRoot, "src", "scan", "mechanical.ts");
  const parsed = sourceFile(mechanical);
  const imports = importedBindings(mechanical, parsed);
  const localFunctions = new Map<string, ts.FunctionDeclaration>();
  for (const statement of parsed.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name) localFunctions.set(statement.name.text, statement);
  }

  const rootsByPhase = new Map<MechanicalPhase, Set<string>>();
  const collect = (node: ts.Node, roots: Set<string>, visitedFunctions: Set<string>): void => {
    if (ts.isIdentifier(node)) {
      const imported = imports.get(node.text);
      if (imported) roots.add(imported);
      const local = localFunctions.get(node.text);
      if (local && !visitedFunctions.has(node.text)) {
        visitedFunctions.add(node.text);
        collect(local, roots, visitedFunctions);
      }
    }
    ts.forEachChild(node, (child) => collect(child, roots, visitedFunctions));
  };

  const findPhases = (node: ts.Node): void => {
    if (ts.isCallExpression(node)
      && ts.isIdentifier(node.expression)
      && node.expression.text === "runPhase"
      && node.arguments.length >= 2
      && ts.isStringLiteral(node.arguments[0]!)) {
      const phase = node.arguments[0]!.text as MechanicalPhase;
      if (CACHEABLE_MECHANICAL_PHASES.includes(phase)) {
        const roots = new Set<string>();
        collect(node.arguments[1]!, roots, new Set<string>());
        rootsByPhase.set(phase, roots);
      }
    }
    ts.forEachChild(node, findPhases);
  };
  findPhases(parsed);

  const discovered: Partial<Record<MechanicalPhase, string[]>> = {};
  for (const phase of CACHEABLE_MECHANICAL_PHASES) {
    const roots = rootsByPhase.get(phase);
    if (!roots || roots.size === 0) throw new Error(`${phase}: no implementation helpers discovered from its runPhase callback`);
    discovered[phase] = transitiveImplementationClosure([...roots]);
  }
  return discovered;
}

export function buildMechanicalPhaseCache(options: PhaseIdentityOptions): MechanicalPhaseCacheOptions {
  const scanDir = join(options.repoRoot, "src", "scan");
  const mechanical = join(scanDir, "mechanical.ts");
  const semgrepRules = join(scanDir, "rules", "semgrep");
  const implementationFiles = discoverMechanicalPhaseImplementationFiles(options.repoRoot);
  const orchestration = digestFiles([mechanical]);
  const toolchain = digestFiles([join(options.repoRoot, "package.json"), join(options.repoRoot, "pnpm-lock.yaml")]);
  const registry = options.registryPackIdentity ?? materializeRegistryPacks(options.cacheDir);
  const implementation: Partial<Record<MechanicalPhase, string>> = {
    semgrep: digestParts([orchestration, digestFiles(implementationFiles.semgrep!), digestTree(semgrepRules)]),
    configuration: digestParts([orchestration, digestFiles(implementationFiles.configuration!)]),
    "structural-ast": digestParts([orchestration, digestFiles(implementationFiles["structural-ast"]!)]),
  };
  const externalInputs: MechanicalPhaseCacheOptions["externalInputs"] = {
    semgrep: {
      semgrep: binaryVersion("semgrep"),
      registryPacks: registry.identity ? digestParts([registry.identity]) : "unresolved",
      toolchain,
      options: options.optionIdentity,
    },
    configuration: { node: process.version, toolchain, options: options.optionIdentity },
    "structural-ast": { node: process.version, toolchain, options: options.optionIdentity },
  };
  return {
    dir: options.cacheDir,
    mode: options.mode,
    targetRevision: options.targetRevision,
    targetTree: options.targetTree,
    implementation,
    externalInputs,
    disabled: registry.failure ? { semgrep: `${registry.failure}; phase is explicitly non-cacheable for this run` } : undefined,
    materializedInputs: registry.files ? { semgrep: registry.files } : undefined,
    onEvent: options.onEvent,
  };
}
