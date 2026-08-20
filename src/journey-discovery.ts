import { existsSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import ts from "typescript";
import { readEntriesSafe } from "./fs-walk.js";
import {
  JOURNEY_ADAPTER_REGISTRY,
  adapterById,
  isUnsupportedJourneyConfig,
  journeyRegistrySourceRoot,
  matchJourneyConfigs,
  validateJourneyAdapterRegistry,
} from "./journey-adapter-registry.js";
import {
  compareEvidence,
  journeyCommandId,
  journeyFixtureId,
  journeyPageObjectId,
  journeyProjectId,
  journeySuiteId,
  journeyTestId,
  validateJourneyInventoryV1,
  type JourneyAdapterDefinition,
  type JourneyAdapterId,
  type JourneyCommand,
  type JourneyConfigFamilyDefinition,
  type JourneyEvidence,
  type JourneyFixture,
  type JourneyInventoryV1,
  type JourneyLocation,
  type JourneyObservation,
  type JourneyPageObject,
  type JourneyProject,
  type JourneySuite,
  type JourneyTest,
} from "./journey-schema.js";
import {
  resolvePackageManagerEvidence,
  runPackageScriptCommand,
  type PackageManager,
  type PackageManagerEvidenceSource,
  type PackageManagerNotAssessedReason,
  type PackageManagerResolution,
} from "./package-manager.js";
import {
  discoverWorkspaceInventory,
  workspaceIdForDir,
  type WorkspaceDiscoveryEvidence,
  type WorkspaceInventoryPackage,
  type WorkspaceInventoryObservation,
  type WorkspaceInventoryV1,
  type WorkspaceScriptEvidence,
} from "./workspaces.js";

const SOURCE_PATH = /\.[cm]?[jt]sx?$/i;
const CONFIG_GENERATED = /(^|\/)(generated|__generated__)(\/|$)|\.generated\./i;
const GENERATED_BANNER = /(?:@generated|generated file|do not edit)/i;
const EXCLUDED_DIRECTORY = /^(node_modules|\.git|\.next|dist|build|coverage|out|\.turbo|\.vercel|\.svelte-kit|\.nuxt|\.output)$/;
const CI_PATH = /(^|\/)(\.github\/workflows\/[^/]+\.(ya?ml)|\.circleci\/config\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|\.buildkite\/[^/]+\.ya?ml)$/i;

type StaticValue = null | boolean | number | string | StaticValue[] | { [key: string]: StaticValue };

interface StaticConfigResult {
  status: "dynamic" | "malformed" | "static";
  value?: StaticValue;
}

interface ConfigProjectShape {
  name: string;
  testRoots: string[];
  testPatterns: string[];
}

interface ConfigShape {
  projects: ConfigProjectShape[];
  testRoots: string[];
  testPatterns: string[];
}

interface TreeFile {
  path: string;
  absolute: string;
}

interface ParsedTest {
  title: string;
  titlePath: string[];
  location: JourneyLocation;
  routes: string[];
  fixtures: string[];
  personas: string[];
  roles: string[];
}

function posixPath(value: string): string {
  return value.split(sep).join("/");
}

function sourceEvidence(
  kind: JourneyEvidence["kind"],
  path: string,
  adapterId?: JourneyAdapterId,
  configFamilyId?: JourneyConfigFamilyDefinition["id"],
  location?: { line: number; column: number },
): JourneyEvidence {
  return {
    kind,
    path,
    ...(location ? location : {}),
    ...(adapterId ? { adapterId } : {}),
    ...(configFamilyId ? { configFamilyId } : {}),
  };
}

function sortedEvidence(evidence: readonly JourneyEvidence[]): JourneyEvidence[] {
  return [...new Map(evidence.map((entry) => [JSON.stringify(entry), entry])).values()].sort(compareEvidence);
}

function sorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function walkRepository(repoRoot: string): TreeFile[] {
  const logicalRoot = resolve(repoRoot);
  const physicalRoot = realpathSync(logicalRoot);
  const seen = new Set<string>();
  const out: TreeFile[] = [];
  const walk = (directory: string): void => {
    let physical: string;
    try { physical = realpathSync(directory); }
    catch { return; }
    const relPhysical = relative(physicalRoot, physical);
    if (relPhysical === ".." || relPhysical.startsWith(`..${sep}`)) return;
    if (seen.has(physical)) return;
    seen.add(physical);
    let entries: ReturnType<typeof readEntriesSafe>["entries"];
    try { entries = readEntriesSafe(directory).entries; }
    catch { return; }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory) {
        if (!EXCLUDED_DIRECTORY.test(entry.name)) walk(entry.path);
        continue;
      }
      const path = posixPath(relative(logicalRoot, entry.path));
      if (path && !path.startsWith("../")) out.push({ path, absolute: entry.path });
    }
  };
  walk(logicalRoot);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

function workspaceForPath(path: string, packages: readonly WorkspaceInventoryPackage[]): WorkspaceInventoryPackage {
  const owners = packages.filter((pkg) => pkg.dir === "." || path === pkg.dir || path.startsWith(`${pkg.dir}/`));
  return owners.sort((a, b) => b.dir.length - a.dir.length || a.id.localeCompare(b.id))[0]
    ?? { id: workspaceIdForDir("."), dir: ".", manifestPath: "package.json", scripts: [], discoveredBy: [] };
}

function declarationEvidence(source: WorkspaceDiscoveryEvidence): JourneyEvidence {
  return {
    kind: "workspace-manifest",
    path: source.sourcePath,
    pointer: source.sourceField === "root" ? "/" : `/${source.sourceField.replace(".", "/")}`,
  };
}

function workspaceEvidence(workspace: WorkspaceInventoryPackage): JourneyEvidence[] {
  return sortedEvidence([
    sourceEvidence("workspace-manifest", workspace.manifestPath),
    ...workspace.discoveredBy.map(declarationEvidence),
  ]);
}

const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

function pointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function adapterDependencyEvidence(
  repoRoot: string,
  workspace: WorkspaceInventoryPackage,
  adapter: JourneyAdapterDefinition,
): JourneyEvidence[] {
  let manifest: Record<string, unknown>;
  try { manifest = JSON.parse(readFileSync(resolve(repoRoot, ...workspace.manifestPath.split("/")), "utf8")) as Record<string, unknown>; }
  catch { return []; }
  const names = new Set(adapter.dependencyNames);
  const evidence: JourneyEvidence[] = [];
  for (const field of DEPENDENCY_FIELDS) {
    const dependencies = manifest[field];
    if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) continue;
    for (const name of Object.keys(dependencies).filter((candidate) => names.has(candidate)).sort()) {
      evidence.push({
        kind: "workspace-manifest", path: workspace.manifestPath,
        pointer: `/${field}/${pointerToken(name)}`, adapterId: adapter.id,
      });
    }
  }
  return evidence;
}

function workspaceObservationRows(observations: readonly WorkspaceInventoryObservation[]): JourneyObservation[] {
  return observations.map((observation): JourneyObservation => {
    if (observation.kind === "excluded") return {
      status: "examined", subject: "workspace", unitsExamined: 1,
      scope: `${observation.path} excluded by ${observation.glob}`,
      provenance: [sourceEvidence("workspace-manifest", observation.sourcePath)],
    };
    const path = observation.kind === "unreadable-manifest" ? observation.path : observation.sourcePath;
    const scope = observation.kind === "unreadable-manifest" ? observation.path : observation.glob;
    return {
      status: "not-assessed", subject: "workspace", reason: "workspace-inventory-incomplete",
      populationCount: 1, unitsExamined: 0, scope,
      provenance: [sourceEvidence("workspace-manifest", path)],
      falsifier: observation.kind === "unreadable-manifest"
        ? "Restore a readable JSON manifest at this path, then rerun discovery."
        : "Correct the declared workspace glob so it resolves to an in-repository package, then rerun discovery.",
    };
  });
}

function packageManagerEvidence(source: PackageManagerEvidenceSource): JourneyEvidence {
  return {
    kind: "package-manager",
    path: source.path,
    ...(source.kind === "package-manager-field" ? { pointer: "/packageManager" } : {}),
  };
}

function unresolvedPackageManagerObservation(resolution: Extract<PackageManagerResolution, { status: "not-assessed" }>): JourneyObservation {
  const reason: PackageManagerNotAssessedReason = resolution.reason;
  return {
    status: "not-assessed", subject: "scripts", reason: "package-manager-unresolved", populationCount: 1, unitsExamined: 0,
    scope: `repository package-manager evidence (${reason})`,
    provenance: sortedEvidence(resolution.evidence.map(packageManagerEvidence).concat(
      resolution.evidence.length === 0 ? [sourceEvidence("package-manager", "package.json", undefined, undefined)] : [],
    )),
    falsifier: "Add one consistent supported lockfile or exact packageManager declaration, then rerun discovery.",
  };
}

function parseDiagnostics(source: ts.SourceFile): readonly ts.Diagnostic[] {
  return (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression) || ts.isNonNullExpression(expression)) return unwrapExpression(expression.expression);
  if (ts.isCallExpression(expression) && expression.arguments[0]) {
    const name = expressionName(expression.expression);
    if (["defineConfig", "defineProject"].includes(name)) return unwrapExpression(expression.arguments[0]);
  }
  return expression;
}

function expressionName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return `${expressionName(expression.expression)}.${expression.name.text}`;
  return "";
}

function staticValue(
  expression: ts.Expression,
  declarations: ReadonlyMap<string, ts.Expression>,
  seen: ReadonlySet<string> = new Set(),
): { value?: StaticValue; dynamic: boolean } {
  const node = unwrapExpression(expression);
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return { value: node.text, dynamic: false };
  if (ts.isNumericLiteral(node)) return { value: Number(node.text), dynamic: false };
  if (node.kind === ts.SyntaxKind.TrueKeyword) return { value: true, dynamic: false };
  if (node.kind === ts.SyntaxKind.FalseKeyword) return { value: false, dynamic: false };
  if (node.kind === ts.SyntaxKind.NullKeyword) return { value: null, dynamic: false };
  if (ts.isPrefixUnaryExpression(node) && ts.isNumericLiteral(node.operand) && [ts.SyntaxKind.MinusToken, ts.SyntaxKind.PlusToken].includes(node.operator)) {
    const value = Number(node.operand.text) * (node.operator === ts.SyntaxKind.MinusToken ? -1 : 1);
    return { value, dynamic: false };
  }
  if (ts.isIdentifier(node)) {
    const target = declarations.get(node.text);
    if (!target || seen.has(node.text)) return { dynamic: true };
    return staticValue(target, declarations, new Set([...seen, node.text]));
  }
  if (ts.isArrayLiteralExpression(node)) {
    const values: StaticValue[] = [];
    let dynamic = false;
    for (const element of node.elements) {
      if (ts.isSpreadElement(element)) { dynamic = true; continue; }
      const parsed = staticValue(element as ts.Expression, declarations, seen);
      dynamic ||= parsed.dynamic;
      if (parsed.value !== undefined) values.push(parsed.value);
    }
    return { value: values, dynamic };
  }
  if (ts.isObjectLiteralExpression(node)) {
    const value: Record<string, StaticValue> = {};
    let dynamic = false;
    for (const member of node.properties) {
      if (ts.isSpreadAssignment(member)) { dynamic = true; continue; }
      if (!ts.isPropertyAssignment(member) && !ts.isShorthandPropertyAssignment(member)) { dynamic = true; continue; }
      const key = ts.isIdentifier(member.name) || ts.isStringLiteralLike(member.name) || ts.isNumericLiteral(member.name) ? member.name.text : undefined;
      if (!key) { dynamic = true; continue; }
      const initializer = ts.isShorthandPropertyAssignment(member) ? declarations.get(member.name.text) : member.initializer;
      if (!initializer) { dynamic = true; continue; }
      const parsed = staticValue(initializer, declarations, seen);
      dynamic ||= parsed.dynamic;
      if (parsed.value !== undefined) value[key] = parsed.value;
    }
    return { value, dynamic };
  }
  return { dynamic: true };
}

function parseStaticConfig(path: string, text: string): StaticConfigResult {
  if (path.endsWith(".json")) {
    try { return { status: "static", value: JSON.parse(text) as StaticValue }; }
    catch { return { status: "malformed" }; }
  }
  const kind = path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind);
  if (parseDiagnostics(source).length > 0) return { status: "malformed" };
  const declarations = new Map<string, ts.Expression>();
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.initializer) declarations.set(declaration.name.text, declaration.initializer);
    }
  }
  let root: ts.Expression | undefined;
  for (const statement of source.statements) {
    if (ts.isExportAssignment(statement)) { root = statement.expression; break; }
    if (ts.isExpressionStatement(statement) && ts.isBinaryExpression(statement.expression)
      && expressionName(statement.expression.left) === "module.exports") { root = statement.expression.right; break; }
    if (ts.isVariableStatement(statement) && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      const config = statement.declarationList.declarations.find((declaration) => ts.isIdentifier(declaration.name) && declaration.name.text === "config" && declaration.initializer);
      if (config?.initializer) { root = config.initializer; break; }
    }
  }
  if (!root) {
    const findDefineConfig = (node: ts.Node): void => {
      if (root) return;
      if (ts.isCallExpression(node) && ["defineConfig", "defineProject"].includes(expressionName(node.expression)) && node.arguments[0]) root = node.arguments[0];
      ts.forEachChild(node, findDefineConfig);
    };
    findDefineConfig(source);
  }
  if (!root) return { status: "dynamic" };
  const parsed = staticValue(root, declarations);
  return parsed.value === undefined ? { status: "dynamic" } : { status: parsed.dynamic ? "dynamic" : "static", value: parsed.value };
}

function record(value: StaticValue | undefined): Record<string, StaticValue> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

function array(value: StaticValue | undefined): StaticValue[] {
  return Array.isArray(value) ? value : [];
}

function strings(value: StaticValue | undefined): string[] {
  if (typeof value === "string") return [value];
  return array(value).filter((entry): entry is string => typeof entry === "string");
}

function at(value: StaticValue | undefined, ...path: string[]): StaticValue | undefined {
  let current = value;
  for (const segment of path) {
    const object = record(current);
    if (!object) return undefined;
    current = object[segment];
  }
  return current;
}

function globRoot(pattern: string): string | undefined {
  const cleaned = pattern.replace(/^!/, "").replace(/^\.\//, "");
  const wildcard = cleaned.search(/[*!?[{]/);
  const prefix = wildcard < 0 ? dirname(cleaned) : cleaned.slice(0, wildcard);
  const normalized = prefix.replace(/\/$/, "").replace(/\/[^/]*$/, (part) => part.includes(".") ? "" : part);
  return normalized && normalized !== "." ? normalized : undefined;
}

function configShape(shape: JourneyConfigFamilyDefinition["shape"], value: StaticValue | undefined): ConfigShape {
  const projects: ConfigProjectShape[] = [];
  const testRoots: string[] = [];
  const testPatterns: string[] = [];
  if (shape === "playwright") {
    for (const project of array(at(value, "projects"))) {
      const projectRecord = record(project);
      const name = projectRecord?.name;
      if (typeof name === "string") projects.push({
        name,
        testRoots: sorted(strings(projectRecord?.testDir)),
        testPatterns: sorted(strings(projectRecord?.testMatch)),
      });
    }
    testRoots.push(...strings(at(value, "testDir")));
    testPatterns.push(...strings(at(value, "testMatch")));
  } else if (shape === "cypress") {
    const object = record(value);
    if (record(object?.e2e)) projects.push({ name: "e2e", testRoots: [], testPatterns: [] });
    if (record(object?.component)) projects.push({ name: "component", testRoots: [], testPatterns: [] });
    if (projects.length === 0) projects.push({ name: "e2e", testRoots: [], testPatterns: [] });
    testPatterns.push(...strings(at(value, "e2e", "specPattern")), ...strings(object?.testFiles));
    testRoots.push(...strings(object?.integrationFolder));
    for (const pattern of testPatterns) {
      const root = globRoot(pattern);
      if (root) testRoots.push(root);
    }
  } else if (shape === "webdriverio") {
    const suites = record(at(value, "suites"));
    if (suites) {
      projects.push(...Object.keys(suites).map((name) => ({ name, testRoots: [], testPatterns: [] })));
      for (const patterns of Object.values(suites)) testPatterns.push(...strings(patterns));
    }
    for (const capability of array(at(value, "capabilities"))) {
      const capabilityRecord = record(capability);
      const name = capabilityRecord?.browserName ?? capabilityRecord?.name;
      if (typeof name === "string") projects.push({ name, testRoots: [], testPatterns: [] });
    }
    testPatterns.push(...strings(at(value, "specs")));
  } else {
    const browser = at(value, "test", "browser") ?? at(value, "browser");
    for (const instance of array(at(browser, "instances"))) {
      const instanceRecord = record(instance);
      const name = instanceRecord?.name ?? instanceRecord?.browser;
      if (typeof name === "string") projects.push({ name, testRoots: [], testPatterns: [] });
    }
    const browserRecord = record(browser);
    if (projects.length === 0 && browserRecord) {
      const name = browserRecord.name ?? browserRecord.provider;
      projects.push({ name: typeof name === "string" ? name : "browser", testRoots: [], testPatterns: [] });
    }
    testPatterns.push(...strings(at(value, "test", "include")), ...strings(at(value, "include")));
  }
  if (projects.length === 0) projects.push({ name: "default", testRoots: [], testPatterns: [] });
  const uniqueProjects = [...new Map(projects.map((project) => [project.name, project])).values()]
    .sort((a, b) => a.name.localeCompare(b.name));
  return { projects: uniqueProjects, testRoots: sorted(testRoots), testPatterns: sorted(testPatterns) };
}

function hasStaticVitestBrowser(value: StaticValue | undefined): boolean {
  const candidates = [value, ...array(value), ...array(at(value, "projects")), ...array(at(value, "test", "projects"))];
  return candidates.some((candidate) => record(at(candidate, "test", "browser")) !== undefined || record(at(candidate, "browser")) !== undefined);
}

function relativeToWorkspace(path: string, workspace: WorkspaceInventoryPackage): string {
  return workspace.dir === "." ? path : path.startsWith(`${workspace.dir}/`) ? path.slice(workspace.dir.length + 1) : path;
}

function joinRepo(base: string, child: string): string {
  return [base === "." ? "" : base, child.replace(/^\.\//, "")].filter(Boolean).join("/");
}

function globPattern(pattern: string): RegExp | undefined {
  if (pattern.startsWith("!")) return undefined;
  const escaped = pattern.replace(/^\.\//, "").replace(/[.+^$()|\\]/g, "\\$&")
    .replace(/\*\*\//g, "__HARVEY_DOUBLE_STAR_SLASH__").replace(/\*\*/g, "__HARVEY_DOUBLE_STAR__")
    .replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")
    .replaceAll("__HARVEY_DOUBLE_STAR_SLASH__", "(?:.*/)?").replaceAll("__HARVEY_DOUBLE_STAR__", ".*");
  try { return new RegExp(`^${escaped}$`, "i"); }
  catch { return undefined; }
}

function isTestFileForScope(
  path: string,
  workspace: WorkspaceInventoryPackage,
  adapter: JourneyAdapterDefinition,
  configDirectory: string,
  testRoots: readonly string[],
  testPatterns: readonly string[],
): boolean {
  if (!SOURCE_PATH.test(path)) return false;
  const relWorkspace = relativeToWorkspace(path, workspace);
  const relConfig = configDirectory === "." ? path : path.startsWith(`${configDirectory}/`) ? path.slice(configDirectory.length + 1) : path;
  const explicitPatterns = testPatterns.map(globPattern).filter((pattern): pattern is RegExp => pattern !== undefined);
  const patternMatches = explicitPatterns.some((pattern) => pattern.test(relConfig) || pattern.test(relWorkspace));
  if (explicitPatterns.length > 0 && testRoots.length === 0) return patternMatches;
  const roots = testRoots.length > 0 ? testRoots : adapter.defaultTestRoots;
  const inRoot = roots.some((root) => {
    const repoRoot = joinRepo(configDirectory, root).replace(/\/$/, "");
    return path === repoRoot || path.startsWith(`${repoRoot}/`) || relWorkspace.startsWith(`${root.replace(/^\.\//, "").replace(/\/$/, "")}/`);
  });
  if (explicitPatterns.length > 0) return patternMatches && inRoot;
  return inRoot && adapter.testPathPatterns.some((pattern) => new RegExp(pattern, "i").test(path));
}

function matchingProjectNames(
  path: string,
  workspace: WorkspaceInventoryPackage,
  adapter: JourneyAdapterDefinition,
  configDirectory: string,
  shape: ConfigShape,
): string[] {
  return shape.projects
    .filter((project) => isTestFileForScope(
      path,
      workspace,
      adapter,
      configDirectory,
      project.testRoots.length > 0 ? project.testRoots : shape.testRoots,
      project.testPatterns.length > 0 ? project.testPatterns : shape.testPatterns,
    ))
    .map((project) => project.name);
}

function literalText(expression: ts.Expression | undefined): string | undefined {
  if (!expression) return undefined;
  return ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression) ? expression.text : undefined;
}

function callName(call: ts.CallExpression, aliases: ReadonlyMap<string, string>): string {
  const raw = expressionName(call.expression);
  const [head, ...tail] = raw.split(".");
  const canonicalHead = aliases.get(head ?? "") ?? head;
  return [canonicalHead, ...tail].filter(Boolean).join(".");
}

function normalizedRoute(value: string): string | undefined {
  if (!value || value.includes("${") || /[\r\n\0]/.test(value)) return undefined;
  try {
    const parsed = new URL(value, "https://harvey.invalid");
    return parsed.pathname || "/";
  } catch {
    const path = value.split(/[?#]/, 1)[0];
    return path?.startsWith("/") ? path : undefined;
  }
}

function callbackOf(call: ts.CallExpression): ts.FunctionLikeDeclaration | undefined {
  return [...call.arguments].reverse().find((argument): argument is ts.ArrowFunction | ts.FunctionExpression => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument));
}

function fixturesOf(callback: ts.FunctionLikeDeclaration | undefined): string[] {
  const names: string[] = [];
  for (const parameter of callback?.parameters ?? []) {
    if (!ts.isObjectBindingPattern(parameter.name)) continue;
    for (const element of parameter.name.elements) {
      const name = element.propertyName ?? element.name;
      if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) names.push(name.text);
    }
  }
  return sorted(names);
}

const ROLE_WORDS = ["admin", "anonymous", "auditor", "customer", "editor", "guest", "member", "moderator", "operator", "owner", "user", "viewer"];

function inferredActors(titlePath: readonly string[], fixtures: readonly string[]): { roles: string[]; personas: string[] } {
  const text = [...titlePath, ...fixtures].join(" ").toLowerCase();
  const roles = ROLE_WORDS.filter((word) => new RegExp(`(^|[^a-z])${word}([^a-z]|$)`).test(text));
  const personas: string[] = [];
  if (/\b(anonymous|guest|signed[- ]?out|unauthenticated)\b/.test(text)) personas.push("unauthenticated");
  if (/\b(authenticated|signed[- ]?in|logged[- ]?in|member|user|admin|owner)\b/.test(text)) personas.push("authenticated");
  return { roles: sorted(roles), personas: sorted(personas) };
}

function parseTestFile(path: string, text: string, adapter: JourneyAdapterDefinition): ParsedTest[] {
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (parseDiagnostics(source).length > 0) return [];
  const aliases = new Map<string, string>();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause) continue;
    const bindings = statement.importClause.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) aliases.set(element.name.text, element.propertyName?.text ?? element.name.text);
  }
  const suites = new Set(adapter.suiteCalls);
  const tests = new Set(adapter.testCalls);
  const routeCalls = new Set(adapter.routeCalls);
  const out: ParsedTest[] = [];
  const walk = (node: ts.Node, titleStack: readonly string[]): void => {
    if (ts.isCallExpression(node)) {
      const name = callName(node, aliases).replace(/\.(only|skip|fixme|todo)$/, "");
      if (suites.has(name)) {
        const title = literalText(node.arguments[0]);
        const callback = callbackOf(node);
        if (callback?.body) walk(callback.body, title ? [...titleStack, title] : titleStack);
        return;
      }
      if (tests.has(name)) {
        const title = literalText(node.arguments[0]);
        const callback = callbackOf(node);
        if (!title || !callback?.body) return;
        const titlePath = [...titleStack, title];
        const routes: string[] = [];
        const routeWalk = (child: ts.Node): void => {
          if (ts.isCallExpression(child)) {
            const routeName = expressionName(child.expression).split(".").at(-1) ?? "";
            if (routeCalls.has(routeName)) {
              const route = normalizedRoute(literalText(child.arguments[0]) ?? "");
              if (route) routes.push(route);
            }
          }
          ts.forEachChild(child, routeWalk);
        };
        routeWalk(callback.body);
        const fixtures = fixturesOf(callback);
        const actors = inferredActors(titlePath, fixtures);
        const position = source.getLineAndCharacterOfPosition(node.getStart(source));
        out.push({
          title,
          titlePath,
          location: { path, line: position.line + 1, column: position.character + 1 },
          routes: sorted(routes),
          fixtures,
          personas: actors.personas,
          roles: actors.roles,
        });
        return;
      }
    }
    ts.forEachChild(node, (child) => walk(child, titleStack));
  };
  walk(source, []);
  return out.sort((a, b) => `${a.location.path}\0${a.titlePath.join("\0")}`.localeCompare(`${b.location.path}\0${b.titlePath.join("\0")}`));
}

function sourceNames(path: string, text: string, kind: "fixture" | "page-object"): string[] {
  const names: string[] = [];
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (parseDiagnostics(source).length === 0) {
    const visit = (node: ts.Node): void => {
      if (ts.isClassDeclaration(node) && node.name) names.push(node.name.text);
      if (kind === "fixture" && ts.isCallExpression(node) && expressionName(node.expression).endsWith(".extend")) {
        const object = node.arguments[0];
        if (object && ts.isObjectLiteralExpression(object)) {
          for (const member of object.properties) {
            if (!member.name) continue;
            if (ts.isIdentifier(member.name) || ts.isStringLiteralLike(member.name)) names.push(member.name.text);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  if (names.length === 0) names.push(basename(path).replace(/\.[^.]+$/, ""));
  return sorted(names);
}

function addCommand(commands: Map<string, JourneyCommand>, command: Omit<JourneyCommand, "id">): JourneyCommand {
  const id = journeyCommandId(command);
  const existing = commands.get(id);
  const row: JourneyCommand = { id, ...command, evidence: sortedEvidence([...(existing?.evidence ?? []), ...command.evidence]) };
  commands.set(id, row);
  return row;
}

function packageCommands(
  suites: JourneySuite[],
  tests: JourneyTest[],
  packages: readonly WorkspaceInventoryPackage[],
  manager: PackageManager | undefined,
  commands: Map<string, JourneyCommand>,
  observations: JourneyObservation[],
): void {
  const packageById = new Map(packages.map((entry) => [entry.id, entry]));
  for (const suite of suites) {
    const adapter = adapterById(suite.adapterId);
    const ownPackage = packageById.get(suite.workspaceId);
    const rootPackage = packageById.get("workspace:root");
    const candidates: WorkspaceScriptEvidence[] = [...(ownPackage?.scripts ?? []), ...(ownPackage?.id === rootPackage?.id ? [] : rootPackage?.scripts ?? [])]
      .filter((script) => new RegExp(adapter.scriptNamePattern, "i").test(script.name))
      .sort((a, b) => `${a.source.path}\0${a.name}`.localeCompare(`${b.source.path}\0${b.name}`));
    if (candidates.length === 0) {
      observations.push({
        status: "not-assessed", subject: "scripts", workspaceId: suite.workspaceId, adapterId: suite.adapterId,
        configFamilyId: suite.configFamilyId, reason: "missing-script", populationCount: 1, unitsExamined: 0,
        scope: suite.configPath, provenance: suite.evidence,
        falsifier: `Declare a package script whose name identifies ${suite.framework} verification, then rerun discovery.`,
      });
      continue;
    }
    if (!manager) continue;
    const suiteTests = tests.filter((test) => test.suiteId === suite.id);
    for (const script of candidates) {
      const workspace = packageById.get(script.source.path === rootPackage?.manifestPath ? "workspace:root" : suite.workspaceId) ?? ownPackage!;
      const evidence: JourneyEvidence[] = [{
        kind: "package-script", path: script.source.path, pointer: script.source.pointer, adapterId: suite.adapterId,
        configFamilyId: suite.configFamilyId,
      }];
      const fullBase = runPackageScriptCommand(manager, script.name);
      const full = addCommand(commands, {
        kind: "package-script", scope: "full", workspaceId: workspace.id, adapterId: suite.adapterId,
        suiteId: suite.id, cwd: workspace.dir, bin: fullBase.bin, args: fullBase.args, evidence,
      });
      suite.commandIds.push(full.id);
      for (const test of suiteTests) {
        const focusBase = runPackageScriptCommand(manager, script.name);
        const focusedTestPath = workspace.dir === "." ? test.location.path : relativeToWorkspace(test.location.path, workspace);
        const focused = addCommand(commands, {
          kind: "package-script", scope: "focused", workspaceId: workspace.id, adapterId: suite.adapterId,
          suiteId: suite.id, testId: test.id, cwd: workspace.dir, bin: focusBase.bin,
          args: [...focusBase.args, "--", ...adapter.focusedArgs(focusedTestPath)], evidence,
        });
        suite.commandIds.push(focused.id);
        test.commandIds.push(focused.id);
      }
    }
  }
}

function literalCiArguments(line: string, start: number): string[] {
  const input = line.slice(start);
  const tokens: string[] = [];
  let index = 0;
  while (index < input.length) {
    while (/\s/.test(input[index] ?? "")) index += 1;
    if (index >= input.length || input[index] === "#" || /[;&|<>]/.test(input[index] ?? "")) break;
    let token = "";
    const quote = input[index] === "\"" || input[index] === "'" ? input[index++] : undefined;
    while (index < input.length) {
      const character = input[index]!;
      if (quote) {
        if (character === quote) { index += 1; break; }
        if (character === "\\" && quote === "\"" && index + 1 < input.length) token += input[++index]!;
        else token += character;
        index += 1;
        continue;
      }
      if (/\s/.test(character) || character === "#" || /[;&|<>]/.test(character)) break;
      token += character;
      index += 1;
    }
    if (!token || token.includes("$") || token.includes("`") || /[\r\n\0]/.test(token)) break;
    tokens.push(token);
    if (!quote && index < input.length && (input[index] === "#" || /[;&|<>]/.test(input[index]!))) break;
  }
  return tokens;
}

function ciCommands(
  files: readonly TreeFile[],
  packages: readonly WorkspaceInventoryPackage[],
  suites: JourneySuite[],
  commands: Map<string, JourneyCommand>,
  observations: JourneyObservation[],
): void {
  let examined = 0;
  let invocations = 0;
  for (const file of files.filter((entry) => CI_PATH.test(entry.path))) {
    examined += 1;
    let text: string;
    try { text = readFileSync(file.absolute, "utf8"); }
    catch { continue; }
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index] ?? "";
      const matches: { manager: PackageManager; args: string[]; scriptOrTool: string }[] = [];
      for (const match of line.matchAll(/\b(pnpm|npm|yarn)\s+(?:(run|run-script)\s+)?([A-Za-z0-9_.:@/-]+)/g)) {
        const manager = match[1] as PackageManager;
        const verb = match[2];
        const name = match[3]!;
        if (manager === "npm" && !verb) continue;
        if (["install", "add", "exec", "dlx"].includes(name)) continue;
        const end = (match.index ?? 0) + match[0].length;
        matches.push({ manager, args: [...(verb ? [verb, name] : [name]), ...literalCiArguments(line, end)], scriptOrTool: name });
      }
      for (const match of line.matchAll(/\b(npx|pnpm|npm|yarn)\s+(exec\s+|dlx\s+)?(?:--\s+)?(playwright|cypress|wdio|vitest)\b(?:\s+(test|run))?/g)) {
        if (match[1] !== "npx" && !match[2]) continue;
        const manager: PackageManager = match[1] === "npx" ? "npm" : match[1] as PackageManager;
        const tool = match[3]!;
        const action = match[4];
        const args = manager === "npm" ? ["exec", "--", tool] : [match[2]?.trim() ?? "exec", tool];
        if (action) args.push(action);
        args.push(...literalCiArguments(line, (match.index ?? 0) + match[0].length));
        matches.push({ manager, args, scriptOrTool: tool });
      }
      for (const match of matches) {
        for (const adapter of JOURNEY_ADAPTER_REGISTRY.filter((entry) => new RegExp(entry.scriptNamePattern, "i").test(match.scriptOrTool)
          || (entry.id === "vitest-browser" && match.scriptOrTool === "vitest" && /--browser\b/.test(line)))) {
          invocations += 1;
          const workspace = workspaceForPath(file.path, packages);
          const evidence = [sourceEvidence("ci-invocation", file.path, adapter.id, undefined, { line: index + 1, column: 1 })];
          const row = addCommand(commands, {
            kind: "ci-literal", scope: "ci", workspaceId: workspace.id, adapterId: adapter.id,
            cwd: workspace.dir, bin: match.manager, args: match.args, evidence,
          });
          for (const suite of suites.filter((candidate) => candidate.adapterId === adapter.id)) suite.commandIds.push(row.id);
        }
      }
    }
  }
  if (examined > 0) observations.push({
    status: "examined", subject: "ci-invocations", unitsExamined: examined,
    scope: `${examined} CI file(s); ${invocations} literal journey invocation(s)`,
    provenance: files.filter((entry) => CI_PATH.test(entry.path)).map((entry) => sourceEvidence("ci-invocation", entry.path)),
  });
}

function linkCollections(
  suites: JourneySuite[],
  projects: JourneyProject[],
  tests: JourneyTest[],
  fixtures: JourneyFixture[],
  pageObjects: JourneyPageObject[],
): void {
  for (const suite of suites) {
    suite.projectIds = sorted(projects.filter((row) => row.suiteId === suite.id).map((row) => row.id)) as JourneyProject["id"][];
    suite.testIds = sorted(tests.filter((row) => row.suiteId === suite.id).map((row) => row.id)) as JourneyTest["id"][];
    suite.fixtureIds = sorted(fixtures.filter((row) => row.workspaceId === suite.workspaceId && row.adapterIds.includes(suite.adapterId)).map((row) => row.id)) as JourneyFixture["id"][];
    suite.pageObjectIds = sorted(pageObjects.filter((row) => row.workspaceId === suite.workspaceId && row.adapterIds.includes(suite.adapterId)).map((row) => row.id)) as JourneyPageObject["id"][];
    suite.commandIds = sorted(suite.commandIds) as JourneyCommand["id"][];
  }
  for (const project of projects) project.testIds = sorted(tests.filter((row) => row.suiteId === project.suiteId && row.projectIds.includes(project.id)).map((row) => row.id)) as JourneyTest["id"][];
  for (const test of tests) test.commandIds = sorted(test.commandIds) as JourneyCommand["id"][];
}

/**
 * Discover candidate end-to-end journeys without importing configs or running target commands.
 * Package-script bodies remain inside WorkspaceInventoryV1 as provenance and are never inspected.
 */
export function discoverJourneyInventory(repoRoot: string): JourneyInventoryV1 {
  const root = resolve(repoRoot);
  const registryProblems = validateJourneyAdapterRegistry(journeyRegistrySourceRoot());
  if (registryProblems.length > 0) throw new Error(`Journey adapter registry is incomplete:\n${registryProblems.join("\n")}`);
  const workspaceInventory: WorkspaceInventoryV1 = discoverWorkspaceInventory(root);
  const packages: WorkspaceInventoryPackage[] = [...workspaceInventory.packages];
  if (!packages.some((entry) => entry.id === workspaceIdForDir("."))) {
    packages.push({ id: workspaceIdForDir("."), dir: ".", manifestPath: "package.json", scripts: [], discoveredBy: [] });
  }
  const files = walkRepository(root);
  const observations: JourneyObservation[] = [];
  const suites: JourneySuite[] = [];
  const projects: JourneyProject[] = [];
  const tests: JourneyTest[] = [];
  const fixtureMap = new Map<string, JourneyFixture>();
  const pageObjectMap = new Map<string, JourneyPageObject>();
  const suitePopulation = new Set<string>();

  const populateSuite = (
    suite: JourneySuite,
    workspace: WorkspaceInventoryPackage,
    adapter: JourneyAdapterDefinition,
    family: JourneyConfigFamilyDefinition,
    shape: ConfigShape,
    configDirectory: string,
    evidence: JourneyEvidence[],
  ): void => {
    const projectIdsByName = new Map<string, JourneyProject["id"]>();
    for (const projectShape of shape.projects) {
      const projectId = journeyProjectId(suite.id, projectShape.name);
      projectIdsByName.set(projectShape.name, projectId);
      projects.push({
        id: projectId, suiteId: suite.id, name: projectShape.name, location: suite.location,
        testIds: [], criticality: "unconfirmed", evidence,
      });
    }
    for (const candidate of files) {
      const matchingNames = matchingProjectNames(candidate.path, workspace, adapter, configDirectory, shape);
      if (matchingNames.length === 0) continue;
      let source: string;
      try { source = readFileSync(candidate.absolute, "utf8"); }
      catch { continue; }
      const projectIds = matchingNames.map((name) => projectIdsByName.get(name)!).sort();
      for (const parsedTest of parseTestFile(candidate.path, source, adapter)) {
        const testId = journeyTestId(suite.id, candidate.path, parsedTest.titlePath);
        tests.push({
          id: testId, suiteId: suite.id, projectIds, title: parsedTest.title, titlePath: parsedTest.titlePath,
          location: parsedTest.location, routes: parsedTest.routes, fixtures: parsedTest.fixtures,
          personas: parsedTest.personas, roles: parsedTest.roles, commandIds: [], criticality: "unconfirmed",
          evidence: [sourceEvidence("test-source", candidate.path, adapter.id, family.id, { line: parsedTest.location.line, column: parsedTest.location.column })],
        });
      }
    }
    const suiteTests = tests.filter((test) => test.suiteId === suite.id);
    if (suiteTests.length === 0) observations.push({
      status: "not-assessed", subject: "tests", workspaceId: workspace.id, adapterId: adapter.id, configFamilyId: family.id,
      reason: "zero-tests", populationCount: 1, unitsExamined: 0, scope: suite.configPath, provenance: evidence,
      falsifier: "Add one literal-title test under the declared or conventional test population, then rerun discovery.",
    });
    else observations.push({
      status: "examined", subject: "tests", workspaceId: workspace.id, adapterId: adapter.id, configFamilyId: family.id,
      unitsExamined: suiteTests.length, scope: suite.configPath,
      provenance: sortedEvidence(suiteTests.flatMap((test) => test.evidence)),
    });
  };

  observations.push(...workspaceObservationRows(workspaceInventory.observations));

  for (const workspace of packages) observations.push({
    status: "examined", subject: "workspace", workspaceId: workspace.id, unitsExamined: 1,
    scope: workspace.dir, provenance: workspaceEvidence(workspace),
  });

  for (const file of files) {
    const pathMatches = matchJourneyConfigs(file.path, "");
    if (pathMatches.length === 0) {
      if (isUnsupportedJourneyConfig(file.path)) {
        const workspace = workspaceForPath(file.path, packages);
        observations.push({
          status: "not-assessed", subject: "suite", workspaceId: workspace.id, reason: "unsupported-framework",
          populationCount: 1, unitsExamined: 0, scope: file.path,
          provenance: [sourceEvidence("config", file.path)],
          falsifier: "Register a production adapter for this config family and rerun discovery.",
        });
      }
      continue;
    }
    let text: string;
    try { text = readFileSync(file.absolute, "utf8"); }
    catch {
      for (const { adapter, family } of pathMatches) {
        const workspace = workspaceForPath(file.path, packages);
        observations.push({
          status: "not-assessed", subject: "config", workspaceId: workspace.id, adapterId: adapter.id,
          configFamilyId: family.id, reason: "unreadable-config", populationCount: 1, unitsExamined: 0,
          scope: file.path, provenance: [sourceEvidence("config", file.path, adapter.id, family.id)],
          falsifier: "Make the config readable as target source and rerun discovery.",
        });
      }
      continue;
    }
    for (const { adapter, family, markersMatched } of matchJourneyConfigs(file.path, text)) {
      if (!markersMatched) {
        observations.push({
          status: "examined", subject: "config", workspaceId: workspaceForPath(file.path, packages).id,
          adapterId: adapter.id, configFamilyId: family.id, unitsExamined: 1, scope: `${file.path} (required browser marker absent)`,
          provenance: [sourceEvidence("config", file.path, adapter.id, family.id)],
        });
        continue;
      }
      const workspace = workspaceForPath(file.path, packages);
      const evidence = [sourceEvidence("config", file.path, adapter.id, family.id, { line: 1, column: 1 })];
      const generated = CONFIG_GENERATED.test(file.path) || GENERATED_BANNER.test(text.slice(0, 512));
      const parsed: StaticConfigResult = generated ? { status: "dynamic" } : parseStaticConfig(file.path, text);
      if (adapter.id === "vitest-browser" && parsed.status === "static" && !hasStaticVitestBrowser(parsed.value)) {
        observations.push({
          status: "examined", subject: "config", workspaceId: workspace.id, adapterId: adapter.id,
          configFamilyId: family.id, unitsExamined: 1, scope: `${file.path} (no static browser project)`, provenance: evidence,
        });
        continue;
      }
      suitePopulation.add(`${workspace.id}\0${adapter.id}`);
      const id = journeySuiteId(workspace.id, adapter.id, family.id, file.path);
      const suite: JourneySuite = {
        id, workspaceId: workspace.id, adapterId: adapter.id, framework: adapter.framework,
        configFamilyId: family.id, configPath: file.path, title: `${adapter.framework} — ${basename(file.path)}`,
        location: { path: file.path, line: 1, column: 1 }, projectIds: [], testIds: [], fixtureIds: [], pageObjectIds: [], commandIds: [],
        criticality: "unconfirmed", evidence,
      };
      suites.push(suite);
      if (generated || parsed.status !== "static") {
        const reason = generated ? "generated-config" : parsed.status === "malformed" ? "malformed-config" : "dynamic-config";
        observations.push({
          status: "not-assessed", subject: "config", workspaceId: workspace.id, adapterId: adapter.id, configFamilyId: family.id,
          reason, populationCount: 1, unitsExamined: 0, scope: file.path, provenance: evidence,
          falsifier: generated
            ? "Replace the generated config with a checked-in static declaration or supply its source artifact, then rerun discovery."
            : parsed.status === "malformed"
              ? "Make the config syntactically parseable, then rerun discovery."
              : "Replace dynamic config fields with static literals or provide a reviewed inventory override, then rerun discovery.",
        });
      } else observations.push({
        status: "examined", subject: "config", workspaceId: workspace.id, adapterId: adapter.id,
        configFamilyId: family.id, unitsExamined: 1, scope: file.path, provenance: evidence,
      });
      const parsedShape = configShape(family.shape, parsed.value);
      const configDirectory = dirname(file.path) === "." ? "." : dirname(file.path);
      populateSuite(suite, workspace, adapter, family, parsedShape, configDirectory, evidence);
    }
  }

  for (const workspace of packages) {
    for (const adapter of JOURNEY_ADAPTER_REGISTRY) {
      if (suitePopulation.has(`${workspace.id}\0${adapter.id}`)) continue;
      const dependencyEvidence = adapterDependencyEvidence(root, workspace, adapter);
      const scripts = workspace.scripts.filter((script) => new RegExp(adapter.scriptNamePattern, "i").test(script.name));
      if (dependencyEvidence.length === 0 || scripts.length === 0) continue;
      const family = adapter.configFamilies.find((candidate) => candidate.id === `${adapter.id}:script-only`);
      if (!family) continue;
      const evidence = sortedEvidence([
        ...dependencyEvidence,
        ...scripts.map((script): JourneyEvidence => ({
          kind: "package-script", path: script.source.path, pointer: script.source.pointer,
          adapterId: adapter.id, configFamilyId: family.id,
        })),
      ]);
      const id = journeySuiteId(workspace.id, adapter.id, family.id, workspace.manifestPath);
      const suite: JourneySuite = {
        id, workspaceId: workspace.id, adapterId: adapter.id, framework: adapter.framework,
        configFamilyId: family.id, configPath: workspace.manifestPath,
        title: `${adapter.framework} — script-only`, location: { path: workspace.manifestPath, line: 1, column: 1 },
        projectIds: [], testIds: [], fixtureIds: [], pageObjectIds: [], commandIds: [],
        criticality: "unconfirmed", evidence,
      };
      suites.push(suite);
      suitePopulation.add(`${workspace.id}\0${adapter.id}`);
      populateSuite(suite, workspace, adapter, family, configShape(family.shape, undefined), workspace.dir, evidence);
    }
  }

  for (const workspace of packages) {
    for (const adapter of JOURNEY_ADAPTER_REGISTRY) {
      if (suitePopulation.has(`${workspace.id}\0${adapter.id}`)) continue;
      observations.push({
        status: "not-assessed", subject: "suite", workspaceId: workspace.id, adapterId: adapter.id,
        reason: "absent-suite", populationCount: 1, unitsExamined: 0, scope: workspace.dir,
        provenance: workspaceEvidence(workspace),
        falsifier: `Add a registered ${adapter.framework} config in this workspace, then rerun discovery.`,
      });
    }
  }

  for (const file of files.filter((entry) => SOURCE_PATH.test(entry.path))) {
    const workspace = workspaceForPath(file.path, packages);
    const fixtureAdapters = JOURNEY_ADAPTER_REGISTRY.filter((adapter) => suitePopulation.has(`${workspace.id}\0${adapter.id}`)
      && new RegExp(adapter.fixturePathPattern, "i").test(file.path)).map((adapter) => adapter.id);
    const pageAdapters = JOURNEY_ADAPTER_REGISTRY.filter((adapter) => suitePopulation.has(`${workspace.id}\0${adapter.id}`)
      && new RegExp(adapter.pageObjectPathPattern, "i").test(file.path)).map((adapter) => adapter.id);
    if (fixtureAdapters.length === 0 && pageAdapters.length === 0) continue;
    let text: string;
    try { text = readFileSync(file.absolute, "utf8"); }
    catch { continue; }
    if (fixtureAdapters.length > 0) {
      const id = journeyFixtureId(workspace.id, file.path);
      fixtureMap.set(id, {
        id, workspaceId: workspace.id, path: file.path, names: sourceNames(file.path, text, "fixture"), adapterIds: sorted(fixtureAdapters) as JourneyAdapterId[],
        evidence: sortedEvidence(fixtureAdapters.map((adapterId) => sourceEvidence("fixture-source", file.path, adapterId, undefined, { line: 1, column: 1 }))),
      });
    }
    if (pageAdapters.length > 0) {
      const id = journeyPageObjectId(workspace.id, file.path);
      pageObjectMap.set(id, {
        id, workspaceId: workspace.id, path: file.path, names: sourceNames(file.path, text, "page-object"), adapterIds: sorted(pageAdapters) as JourneyAdapterId[],
        evidence: sortedEvidence(pageAdapters.map((adapterId) => sourceEvidence("page-object-source", file.path, adapterId, undefined, { line: 1, column: 1 }))),
      });
    }
  }
  const fixtures = [...fixtureMap.values()].sort((a, b) => a.id.localeCompare(b.id));
  const pageObjects = [...pageObjectMap.values()].sort((a, b) => a.id.localeCompare(b.id));
  if (fixtures.length > 0) observations.push({ status: "examined", subject: "fixtures", unitsExamined: fixtures.length, scope: "registered fixture path conventions", provenance: sortedEvidence(fixtures.flatMap((row) => row.evidence)) });
  if (pageObjects.length > 0) observations.push({ status: "examined", subject: "page-objects", unitsExamined: pageObjects.length, scope: "registered page-object path conventions", provenance: sortedEvidence(pageObjects.flatMap((row) => row.evidence)) });

  const commands = new Map<string, JourneyCommand>();
  const packageManager = resolvePackageManagerEvidence(root);
  if (packageManager.status === "not-assessed") observations.push(unresolvedPackageManagerObservation(packageManager));
  packageCommands(suites, tests, packages, packageManager.status === "selected" ? packageManager.manager : undefined, commands, observations);
  ciCommands(files, packages, suites, commands, observations);
  linkCollections(suites, projects, tests, fixtures, pageObjects);

  const sortedSuites = suites.sort((a, b) => a.id.localeCompare(b.id));
  const sortedProjects = projects.sort((a, b) => a.id.localeCompare(b.id));
  const sortedTests = tests.sort((a, b) => a.id.localeCompare(b.id));
  const sortedCommands = [...commands.values()].sort((a, b) => a.id.localeCompare(b.id));
  const sortedObservations = observations
    .map((row) => ({ ...row, provenance: sortedEvidence(row.provenance) }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const inventory: JourneyInventoryV1 = {
    schemaVersion: 1,
    repoRootId: "workspace:root",
    workspaceIds: packages.map((entry) => entry.id).sort(),
    registry: {
      adapterIds: JOURNEY_ADAPTER_REGISTRY.map((entry) => entry.id).sort(),
      configFamilyIds: JOURNEY_ADAPTER_REGISTRY.flatMap((entry) => entry.configFamilies.map((family) => family.id)).sort(),
    },
    suites: sortedSuites,
    projects: sortedProjects,
    tests: sortedTests,
    fixtures,
    pageObjects,
    commands: sortedCommands,
    observations: sortedObservations,
    summary: {
      workspaces: packages.length, suites: sortedSuites.length, projects: sortedProjects.length, tests: sortedTests.length,
      fixtures: fixtures.length, pageObjects: pageObjects.length, commands: sortedCommands.length,
      examinedRows: sortedObservations.filter((row) => row.status === "examined").length,
      notAssessedRows: sortedObservations.filter((row) => row.status === "not-assessed").length,
    },
  };
  const problems = validateJourneyInventoryV1(inventory);
  if (problems.length > 0) throw new Error(`Journey discovery produced an invalid inventory:\n${problems.join("\n")}`);
  return inventory;
}

export function discoverJourneyInventoryFromCliTarget(target: string): JourneyInventoryV1 {
  if (!existsSync(target)) throw new Error(`Journey target does not exist: ${target}`);
  return discoverJourneyInventory(target);
}
