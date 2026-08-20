import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { cypressJourneyAdapter } from "./journey-adapters/cypress.js";
import { playwrightJourneyAdapter } from "./journey-adapters/playwright.js";
import { vitestBrowserJourneyAdapter } from "./journey-adapters/vitest-browser.js";
import { webdriverioJourneyAdapter } from "./journey-adapters/webdriverio.js";
import {
  JOURNEY_ADAPTER_IDS,
  type JourneyAdapterDefinition,
  type JourneyAdapterId,
  type JourneyConfigFamilyDefinition,
} from "./journey-schema.js";
import { readEntriesSafe } from "./fs-walk.js";

export const JOURNEY_ADAPTER_REGISTRY: readonly JourneyAdapterDefinition[] = Object.freeze([
  playwrightJourneyAdapter,
  cypressJourneyAdapter,
  webdriverioJourneyAdapter,
  vitestBrowserJourneyAdapter,
]);

interface DiscoveredJourneyAdapter {
  id: string;
  file: string;
  exportName: string;
  configFamilyIds: string[];
}

function property(object: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  for (const member of object.properties) {
    if (!ts.isPropertyAssignment(member)) continue;
    const key = ts.isIdentifier(member.name) || ts.isStringLiteral(member.name) ? member.name.text : undefined;
    if (key === name) return member.initializer;
  }
  return undefined;
}

function unwrap(expression: ts.Expression): ts.Expression {
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression)) return unwrap(expression.expression);
  if (ts.isCallExpression(expression)
    && ts.isPropertyAccessExpression(expression.expression)
    && ts.isIdentifier(expression.expression.expression)
    && expression.expression.expression.text === "Object"
    && expression.expression.name.text === "freeze"
    && expression.arguments[0]) return unwrap(expression.arguments[0]);
  return expression;
}

function stringLiteral(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  const value = unwrap(expression);
  return ts.isStringLiteralLike(value) ? value.text : undefined;
}

function sourceParseProblems(file: string, source: ts.SourceFile): string[] {
  const parsed = source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] };
  return (parsed.parseDiagnostics ?? []).map((diagnostic) => `${file}: adapter source is malformed (${diagnostic.code})`);
}

function discoverAdapterSource(repoRoot: string): { rows: DiscoveredJourneyAdapter[]; problems: string[] } {
  const directory = join(repoRoot, "src", "journey-adapters");
  if (!existsSync(directory)) return { rows: [], problems: ["src/journey-adapters: adapter directory is missing"] };
  const rows: DiscoveredJourneyAdapter[] = [];
  const problems: string[] = [];
  for (const entry of readEntriesSafe(directory).entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isDirectory || !entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
    const file = `src/journey-adapters/${entry.name}`;
    let text: string;
    try { text = readFileSync(entry.path, "utf8"); }
    catch { problems.push(`${file}: adapter source is unreadable`); continue; }
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    problems.push(...sourceParseProblems(file, source));
    let declarations = 0;
    for (const statement of source.statements) {
      if (!ts.isVariableStatement(statement) || !statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !declaration.name.text.endsWith("JourneyAdapter") || !declaration.initializer) continue;
        declarations += 1;
        const root = unwrap(declaration.initializer);
        if (!ts.isObjectLiteralExpression(root)) {
          problems.push(`${file}#${declaration.name.text}: adapter definition is not a static object literal`);
          continue;
        }
        const id = stringLiteral(property(root, "id"));
        const implementation = property(root, "implementation");
        const families = property(root, "configFamilies");
        if (!id || !implementation || !ts.isObjectLiteralExpression(unwrap(implementation)) || !families || !ts.isArrayLiteralExpression(unwrap(families))) {
          problems.push(`${file}#${declaration.name.text}: adapter identity, implementation, or configFamilies is dynamic`);
          continue;
        }
        const implementationObject = unwrap(implementation) as ts.ObjectLiteralExpression;
        const implementationFile = stringLiteral(property(implementationObject, "file"));
        const exportName = stringLiteral(property(implementationObject, "exportName"));
        if (implementationFile !== file || exportName !== declaration.name.text) {
          problems.push(`${file}#${declaration.name.text}: implementation receipt does not name its own file and export`);
        }
        const configFamilyIds: string[] = [];
        for (const element of (unwrap(families) as ts.ArrayLiteralExpression).elements) {
          const candidate = unwrap(element as ts.Expression);
          if (!ts.isObjectLiteralExpression(candidate)) {
            problems.push(`${file}#${declaration.name.text}: config family is not a static object literal`);
            continue;
          }
          const familyId = stringLiteral(property(candidate, "id"));
          if (!familyId) problems.push(`${file}#${declaration.name.text}: config family id is dynamic`);
          else configFamilyIds.push(familyId);
        }
        rows.push({ id, file, exportName: declaration.name.text, configFamilyIds: [...configFamilyIds].sort() });
      }
    }
    if (declarations === 0) problems.push(`${file}: production adapter file exports no *JourneyAdapter definition`);
  }
  return { rows: rows.sort((a, b) => `${a.file}#${a.exportName}`.localeCompare(`${b.file}#${b.exportName}`)), problems };
}

/** Source-discovery half of the adapter-registry completeness gate. */
export function discoverJourneyAdapterImplementations(repoRoot: string): DiscoveredJourneyAdapter[] {
  return discoverAdapterSource(repoRoot).rows;
}

function compilePattern(source: string, flags = ""): string | undefined {
  try { void new RegExp(source, flags); return undefined; }
  catch { return `invalid regular expression /${source}/${flags}`; }
}

export function validateJourneyAdapterRegistry(
  repoRoot: string,
  registry: readonly JourneyAdapterDefinition[] = JOURNEY_ADAPTER_REGISTRY,
): string[] {
  const problems: string[] = [];
  const ids = registry.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) problems.push("journey adapter registry contains duplicate adapter ids");
  const orders = registry.map((entry) => entry.order);
  if (new Set(orders).size !== orders.length) problems.push("journey adapter registry contains duplicate adapter orders");
  if (JSON.stringify(orders) !== JSON.stringify([...orders].sort((a, b) => a - b))) problems.push("journey adapter registry is not in declared order");
  const expectedIds = [...JOURNEY_ADAPTER_IDS].sort();
  if (JSON.stringify([...ids].sort()) !== JSON.stringify(expectedIds)) {
    problems.push(`journey adapter population differs from the supported adapter contract: expected ${expectedIds.join(", ")}; observed ${[...ids].sort().join(", ")}`);
  }

  const familyOwners = new Map<string, string>();
  for (const entry of registry) {
    if (!entry.implementation.file.startsWith("src/journey-adapters/") || !entry.implementation.file.endsWith(".ts")) problems.push(`${entry.id}: implementation path is outside src/journey-adapters`);
    if (!entry.implementation.exportName.endsWith("JourneyAdapter")) problems.push(`${entry.id}: implementation export must end with JourneyAdapter`);
    if (entry.configFamilies.length === 0) problems.push(`${entry.id}: adapter has no registered config family`);
    if (entry.dependencyNames.length === 0 || entry.dependencyNames.some((name) => name.trim() === "") || new Set(entry.dependencyNames).size !== entry.dependencyNames.length) {
      problems.push(`${entry.id}: dependency evidence names must be non-empty and unique`);
    }
    if (entry.configFamilies.filter((family) => family.id === `${entry.id}:script-only`).length !== 1) {
      problems.push(`${entry.id}: adapter must register exactly one script-only family`);
    }
    for (const family of entry.configFamilies) {
      if (!family.id.startsWith(`${entry.id}:`)) problems.push(`${entry.id}: config family ${family.id} is not namespaced to its adapter`);
      const previous = familyOwners.get(family.id);
      if (previous) problems.push(`${family.id}: config family is registered by both ${previous} and ${entry.id}`);
      familyOwners.set(family.id, entry.id);
      const patternProblem = compilePattern(family.pathPattern, family.flags);
      if (patternProblem) problems.push(`${family.id}: ${patternProblem}`);
      if (family.shape !== entry.id) problems.push(`${family.id}: shape ${family.shape} does not match owning adapter ${entry.id}`);
      if (family.contentMarkers?.some((marker) => marker.trim().length === 0)) problems.push(`${family.id}: content markers must be non-empty`);
    }
    for (const [kind, patterns] of [["test", entry.testPathPatterns], ["fixture", [entry.fixturePathPattern]], ["page-object", [entry.pageObjectPathPattern]]] as const) {
      for (const pattern of patterns) {
        const patternProblem = compilePattern(pattern, "i");
        if (patternProblem) problems.push(`${entry.id}: ${kind} ${patternProblem}`);
      }
    }
    const scriptProblem = compilePattern(entry.scriptNamePattern, "i");
    if (scriptProblem) problems.push(`${entry.id}: script-name ${scriptProblem}`);
    const probe = entry.focusedArgs("tests/example.spec.ts");
    if (!Array.isArray(probe) || probe.length === 0 || probe.some((token) => typeof token !== "string" || token.length === 0 || /[\r\n\0]/.test(token))) problems.push(`${entry.id}: focusedArgs does not return safe argument tokens`);
  }

  const discovered = discoverAdapterSource(repoRoot);
  const discoveredRows = discoverJourneyAdapterImplementations(repoRoot);
  problems.push(...discovered.problems);
  const registeredByImplementation = new Map(registry.map((entry) => [`${entry.implementation.file}#${entry.implementation.exportName}`, entry]));
  const discoveredByImplementation = new Map(discoveredRows.map((entry) => [`${entry.file}#${entry.exportName}`, entry]));
  for (const [key, row] of discoveredByImplementation) {
    const registered = registeredByImplementation.get(key);
    if (!registered) {
      problems.push(`${key}: discovered production journey adapter is unregistered`);
      continue;
    }
    if (registered.id !== row.id) problems.push(`${key}: discovered id ${row.id} differs from registered id ${registered.id}`);
    const registeredFamilies = registered.configFamilies.map((family) => family.id).sort();
    if (JSON.stringify(row.configFamilyIds) !== JSON.stringify(registeredFamilies)) {
      problems.push(`${key}: discovered config families differ from the registry (source ${row.configFamilyIds.join(", ")}; registry ${registeredFamilies.join(", ")})`);
    }
  }
  for (const key of registeredByImplementation.keys()) if (!discoveredByImplementation.has(key)) problems.push(`${key}: registered journey adapter implementation was not discovered`);
  return problems;
}

export function journeyRegistrySourceRoot(): string {
  return fileURLToPath(new URL("..", import.meta.url));
}

interface JourneyConfigMatch {
  adapter: JourneyAdapterDefinition;
  family: JourneyConfigFamilyDefinition;
  markersMatched: boolean;
}

export function matchJourneyConfigs(path: string, text: string): JourneyConfigMatch[] {
  const lower = text.toLowerCase();
  const matches: JourneyConfigMatch[] = [];
  for (const adapter of JOURNEY_ADAPTER_REGISTRY) {
    for (const family of adapter.configFamilies) {
      if (!new RegExp(family.pathPattern, family.flags).test(path)) continue;
      const markersMatched = (family.contentMarkers ?? []).every((marker) => lower.includes(marker.toLowerCase()));
      matches.push({ adapter, family, markersMatched });
    }
  }
  return matches.sort((a, b) => a.family.id.localeCompare(b.family.id));
}

const UNSUPPORTED_CONFIG = /(^|\/)(nightwatch(?:\.conf)?|testcafe|karma|jest-puppeteer|puppeteer)(\.[A-Za-z0-9_-]+)*\.(?:json|[cm]?[jt]s)$/i;

export function isUnsupportedJourneyConfig(path: string): boolean {
  return UNSUPPORTED_CONFIG.test(path);
}

export function adapterById(id: JourneyAdapterId): JourneyAdapterDefinition {
  const adapter = JOURNEY_ADAPTER_REGISTRY.find((entry) => entry.id === id);
  if (!adapter) throw new Error(`Unregistered journey adapter: ${id}`);
  return adapter;
}
