import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { classifyTaxonomyCwe, enrichFindingsCwe } from "./cwe-map.js";
import type { Finding } from "./findings.js";
import { MECHANICAL_DETECTORS } from "./scan/mechanical-detector-registry.js";
import { runRegisteredNormalizationEngines } from "./scan/mechanical-normalization-registry.js";
import { detectPgResponseExposureFindings } from "./scan/pg-response-exposure.js";
import { detectM1HardcodedTenantFindings } from "./detectors/m5-hardcoded-deployment.js";
import { detectAppRouterFindings } from "./detectors/app-router.js";
import { compareM9TaxonomyDocs } from "./detectors/m9-taxonomy-docs.js";
import type { TargetFramework } from "./scan/framework-detect.js";
import { toSarif } from "./sarif.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1", title: "t", severity: "High", confidence: "Confirmed", category: "c",
    taxonomy: "SQL injection", location: "a.ts:1", status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, ...over,
  };
}

// Discovery scans both producer trees, regardless of which runner owns a file. Unread expressions
// remain failures unless their exact source site has a checked finite-family or forwarding contract.
function sourceFiles(path: string): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    if (entry.isDirectory()) return sourceFiles(child);
    return /\.(?:ts|tsx|mts|cts)$/.test(entry.name) && !/\.(?:test|spec)\./.test(entry.name) ? [child] : [];
  });
}

function finiteStringType(type: ts.Type): string[] | undefined {
  if (type.isStringLiteral()) return [type.value];
  if (!type.isUnion()) return undefined;
  const members = type.types.map(finiteStringType);
  return members.every((member) => member !== undefined) ? members.flat() : undefined;
}

function taxonomyExpressionValues(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  seen = new Set<ts.Symbol>(),
): string[] | undefined {
  if (ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) return [expression.text];
  if (ts.isParenthesizedExpression(expression) || ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression)) return taxonomyExpressionValues(expression.expression, checker, seen);
  if (ts.isConditionalExpression(expression)) {
    const left = taxonomyExpressionValues(expression.whenTrue, checker, seen);
    const right = taxonomyExpressionValues(expression.whenFalse, checker, seen);
    return left && right ? [...left, ...right] : undefined;
  }
  if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = taxonomyExpressionValues(expression.left, checker, seen);
    const right = taxonomyExpressionValues(expression.right, checker, seen);
    return left && right ? left.flatMap((prefix) => right.map((suffix) => prefix + suffix)) : undefined;
  }
  if (ts.isTemplateExpression(expression)) {
    let values = [expression.head.text];
    for (const span of expression.templateSpans) {
      const substitutions = taxonomyExpressionValues(span.expression, checker, seen);
      if (!substitutions) return undefined;
      values = values.flatMap((prefix) => substitutions.map((value) => prefix + value + span.literal.text));
    }
    return values;
  }
  const finite = finiteStringType(checker.getTypeAtLocation(expression));
  if (finite) return finite;
  if (!ts.isIdentifier(expression)) return undefined;
  // A shorthand's ordinary symbol is the object property, not the referenced local variable.
  const initialSymbol = ts.isShorthandPropertyAssignment(expression.parent)
    ? checker.getShorthandAssignmentValueSymbol(expression.parent)
    : checker.getSymbolAtLocation(expression);
  if (!initialSymbol) return undefined;
  const symbol = initialSymbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(initialSymbol) : initialSymbol;
  if (seen.has(symbol)) return undefined;
  const declaration = symbol.valueDeclaration;
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return undefined;
  if (!ts.isVariableDeclarationList(declaration.parent) || !(declaration.parent.flags & ts.NodeFlags.Const)) return undefined;
  return taxonomyExpressionValues(declaration.initializer, checker, new Set(seen).add(symbol));
}

interface TaxonomySite {
  file: string;
  owner: string;
  expression: string;
  line: number;
  node: ts.Expression;
  values?: string[];
  prefixes?: string[];
}

interface TaxonomyDiscovery {
  taxonomies: string[];
  sites: TaxonomySite[];
}

function propertyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
  if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) return name.expression.text;
  return undefined;
}

function ownerName(node: ts.Node): string {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isFunctionDeclaration(parent) && parent.name) return parent.name.text;
  }
  return "<module>";
}

function detectorTaxonomies(program: ts.Program, paths: readonly string[]): TaxonomyDiscovery {
  const checker = program.getTypeChecker();
  const taxonomies = new Set<string>();
  const sites: TaxonomySite[] = [];
  for (const path of paths) {
    const source = program.getSourceFile(path)!;
    const visit = (node: ts.Node) => {
      let expression: ts.Expression | undefined;
      if ((ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) && propertyName(node.name) === "taxonomy") {
        expression = ts.isPropertyAssignment(node) ? node.initializer : node.name;
      } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ((ts.isPropertyAccessExpression(node.left) && node.left.name.text === "taxonomy")
          || (ts.isElementAccessExpression(node.left) && ts.isStringLiteralLike(node.left.argumentExpression) && node.left.argumentExpression.text === "taxonomy"))) {
        expression = node.right;
      }
      if (expression) {
        const values = taxonomyExpressionValues(expression, checker);
        if (values) values.forEach((taxonomy) => taxonomies.add(taxonomy));
        sites.push({ file: path, owner: ownerName(node), expression: expression.getText(source), node: expression,
          line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1, values, prefixes: templatePrefixes(expression, checker) });
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { taxonomies: [...taxonomies].sort(), sites };
}

const paths = [...sourceFiles("src/detectors"), ...sourceFiles("src/scan")];
const program = ts.createProgram(paths, { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2022, skipLibCheck: true });
const checker = program.getTypeChecker();
const discovery = detectorTaxonomies(program, paths);
const boundaryInventory = compareM9TaxonomyDocs(paths.map((path) => ({ path, text: readFileSync(path, "utf8") })), "").registry;

// A prefix is accepted only when the classifier itself contains a literal startsWith rule. This
// proves the whole open suffix is classified; substituting one made-up wildcard string does not.
function noCwePrefixes(): string[] {
  const source = program.getSourceFile("src/cwe-map.ts")!;
  const prefixes: string[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === "NO_CWE" && node.initializer && ts.isArrayLiteralExpression(node.initializer)) {
      for (const row of node.initializer.elements) {
        if (!ts.isObjectLiteralExpression(row)) continue;
        const match = row.properties.find((property) => ts.isPropertyAssignment(property) && propertyName(property.name) === "match");
        if (!match || !ts.isPropertyAssignment(match) || !ts.isArrowFunction(match.initializer)) continue;
        const body = match.initializer.body;
        if (ts.isCallExpression(body) && ts.isPropertyAccessExpression(body.expression)
          && body.expression.name.text === "startsWith" && body.arguments.length === 1 && ts.isStringLiteralLike(body.arguments[0]!)) prefixes.push(body.arguments[0]!.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return prefixes;
}

const classifiedPrefixes = noCwePrefixes();

function templatePrefixes(expression: ts.Expression, checker: ts.TypeChecker): string[] | undefined {
  if (!ts.isTemplateExpression(expression)) return undefined;
  let prefixes = [expression.head.text];
  for (const span of expression.templateSpans) {
    const values = taxonomyExpressionValues(span.expression, checker);
    if (!values) return prefixes;
    prefixes = prefixes.flatMap((prefix) => values.map((value) => prefix + value + span.literal.text));
  }
  return prefixes;
}

function hasClassifiedPrefix(site: TaxonomySite): boolean {
  const prefixes = site.prefixes;
  return !!prefixes?.length && prefixes.every((prefix) => classifiedPrefixes.some((classified) => prefix.startsWith(classified)));
}

// These are expression-level obligations, not file-level exemptions. Changing a site, adding a
// second site, or removing its coverage association fails. Local forwarding is checked separately
// against the actual table/call arguments; external names preserve their upstream CWE authority.
const deferredSites = [
  { file: "src/detectors/app-router.ts", owner: "detectServerActionAuthAndValidation", expression: "`M1 — ${noun} missing authorization check`", coverage: "boundary finite inventory" },
  { file: "src/detectors/app-router.ts", owner: "dataLayerNotAssessed", expression: "`${taxonomy} — not assessed`", coverage: "DATA_LAYER_CHECKS literals plus disclosure suffix" },
  { file: "src/detectors/m5-type-escape.ts", owner: "finding", expression: "names[row.kind].taxonomy", coverage: "names table taxonomy properties" },
  { file: "src/detectors/test-intent.ts", owner: "detectOnlyClass", expression: "meta.taxonomy", coverage: "detectOnlyClass call argument taxonomy properties" },
  { file: "src/scan/leftover-auth.ts", owner: "classifyLeftoverAuth", expression: "c.taxonomy", coverage: "B14_CHECKS table taxonomy properties" },
  { file: "src/scan/pg-response-exposure.ts", owner: "detectFile", expression: "`Excessive data exposure: res.json(...) ${label} (pg-resjson-exposure-${hit.kind})`", coverage: "pg finite kind inventory and emitted controls" },
  { file: "src/scan/common.ts", owner: "mechanicalFinding", expression: "input.taxonomy", coverage: "shared constructor preserves caller taxonomy and CWE" },
  { file: "src/scan/external-corpus.ts", owner: "toDriftRow", expression: "f.taxonomy", coverage: "existing Finding projected to a drift row; no taxonomy created" },
  { file: "src/scan/rule-corpus-pairing.ts", owner: "harveySemgrepRules", expression: '/harveyTaxonomy:\\s*"([^"]+)"/.exec(block)?.[1] ?? `src.scan.rules.semgrep.${id}`', coverage: "upstream rule inventory, not a finding producer" },
  { file: "src/scan/rule-corpus-pairing.ts", owner: "ruleCorpusPairings", expression: "r.taxonomy", coverage: "existing rule projected to a corpus unit; no taxonomy created" },
  { file: "src/scan/rule-corpus-pairing.ts", owner: "freeCountOutsideUnits", expression: "f.taxonomy", coverage: "existing Finding projected to a corpus unit; no taxonomy created" },
  { file: "src/scan/semgrep.ts", owner: "parseSemgrepFindings", expression: "meta?.harveyTaxonomy ?? r.check_id", coverage: "upstream rule declares metadata.cwe; parser preserves it" },
  { file: "src/scan/supabase-advisors.ts", owner: "parseAdvisorFindings", expression: "lint.name", coverage: "#2229: open upstream identifiers and inventory CWE policy require separate advisor review", occurrences: 5 },
];

function sameSite(site: TaxonomySite, contract: typeof deferredSites[number]): boolean {
  return site.file === contract.file && site.owner === contract.owner && site.expression === contract.expression;
}

function unresolvedSites(sites: readonly TaxonomySite[], contracts = deferredSites): string[] {
  return sites.filter((site) => !site.values && !hasClassifiedPrefix(site) && !contracts.some((contract) => sameSite(site, contract)))
    .map((site) => `${site.file}:${site.line} ${site.owner}: ${site.expression}`);
}

function classificationProblems(sites: readonly TaxonomySite[]): string[] {
  return [
    ...unresolvedSites(sites),
    ...sites.filter((site) => !isExternalAdvisorSite(site)).flatMap((site) => (site.values ?? [])
      .filter((taxonomy) => classifyTaxonomyCwe(taxonomy) === undefined).map((taxonomy) => `${site.file}:${site.line} unclassified: ${taxonomy}`)),
  ];
}

function isExternalAdvisorSite(site: TaxonomySite): boolean {
  return sameSite(site, deferredSites[deferredSites.length - 1]!);
}

function referencedInitializer(reference: ts.Expression, name: string): ts.Expression {
  expect(reference.getText()).toBe(name);
  const declaration = checker.getSymbolAtLocation(reference)?.valueDeclaration;
  expect(declaration && ts.isVariableDeclaration(declaration), `${name} must resolve to its source declaration`).toBe(true);
  const variable = declaration as ts.VariableDeclaration;
  expect(ts.isVariableDeclarationList(variable.parent) && !!(variable.parent.flags & ts.NodeFlags.Const)).toBe(true);
  expect(variable.initializer).toBeDefined();
  return variable.initializer!;
}

function containedTaxonomies(root: ts.Node): string[] {
  if (ts.isArrayLiteralExpression(root)) return root.elements.flatMap(containedTaxonomies);
  expect(ts.isObjectLiteralExpression(root), "a forwarded row must have a concrete object initializer").toBe(true);
  const object = root as ts.ObjectLiteralExpression;
  expect(object.properties.some(ts.isSpreadAssignment), "an object spread needs an explicit taxonomy-source proof").toBe(false);
  const taxonomies = object.properties.filter((property) => property.name && propertyName(property.name) === "taxonomy");
  if (taxonomies.length === 0) return object.properties.flatMap((property) => {
    expect(ts.isPropertyAssignment(property), "table members must be concrete taxonomy-bearing rows").toBe(true);
    return containedTaxonomies((property as ts.PropertyAssignment).initializer);
  });
  expect(taxonomies).toHaveLength(1);
  const property = taxonomies[0]!;
  expect(ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)).toBe(true);
  const expression = ts.isPropertyAssignment(property) ? property.initializer : (property as ts.ShorthandPropertyAssignment).name;
  const values = taxonomyExpressionValues(expression, checker);
  expect(values, `forwarded taxonomy cannot be resolved: ${expression.getText()}`).toBeDefined();
  if (!values) return [];
  expect(values.length).toBeGreaterThan(0);
  return values;
}

function localArgumentTaxonomies(file: string, callee: string, argument: number): string[] {
  const source = program.getSourceFile(file)!;
  const declaration = source.statements.find((statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === callee);
  expect(declaration && ts.isFunctionDeclaration(declaration)).toBe(true);
  const fn = declaration as ts.FunctionDeclaration;
  expect(ts.getCombinedModifierFlags(fn) & ts.ModifierFlags.Export, "an exported helper has an open caller population").toBe(0);
  const symbol = checker.getSymbolAtLocation(fn.name!);
  const values: string[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isIdentifier(node) && node !== fn.name && checker.getSymbolAtLocation(node) === symbol) {
      expect(ts.isCallExpression(node.parent) && node.parent.expression === node, "aliased helper needs an explicit forwarding proof").toBe(true);
      if (ts.isCallExpression(node.parent)) values.push(...containedTaxonomies(node.parent.arguments[argument]!));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  expect(values.length).toBeGreaterThan(0);
  return values;
}

const boundaryCases: { fixture: string; framework?: TargetFramework }[] = [
  { fixture: "server-action-auth" },
  { fixture: "remix/action-authz", framework: "remix" },
  { fixture: "remix/action-authz", framework: "react-router" },
  { fixture: "tanstack/action-authz", framework: "tanstack-start" },
];

function boundaryFindings(fixture: string, framework: TargetFramework | undefined, direction: "positive" | "negative"): Finding[] {
  const root = join("src/detectors/__fixtures__", fixture, direction);
  const load = (path: string): { path: string; text: string }[] => readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    if (entry.isDirectory()) return load(child);
    return entry.name.endsWith(".txt") ? [{ path: relative(root, child).replace(/\.txt$/, ""), text: readFileSync(child, "utf8") }] : [];
  });
  return detectAppRouterFindings(load(root), framework).filter((finding) => finding.taxonomy.endsWith(" missing authorization check"));
}

const emittedBoundaryFindings = boundaryCases.flatMap(({ fixture, framework }) => boundaryFindings(fixture, framework, "positive"));

function canaryDiscovery(text: string): TaxonomyDiscovery {
  const path = "src/detectors/cwe-guard-canary.ts";
  const options = { target: ts.ScriptTarget.ES2022, noLib: true };
  const host = ts.createCompilerHost(options);
  host.getSourceFile = (file, languageVersion) => file === path ? ts.createSourceFile(file, text, languageVersion, true) : undefined;
  return detectorTaxonomies(ts.createProgram([path], options, host), [path]);
}

const pgResponseExposureCases = [
  { kind: "direct", positive: `export function getUser(req, res) {
  res.json({ id: 1, passwordHash: "x" });
}`, safe: `export function getUser(req, res) {
  res.json({ id: 1, createdAt: "x" });
}` },
  { kind: "spread", positive: `export function getUser(req, res) {
  const user = { id: 1, refreshToken: "x" };
  res.json({ ...user });
}`, safe: `export function getUser(req, res) {
  const user = { id: 1, createdAt: "x" };
  res.json({ ...user });
}` },
  { kind: "select-star", positive: `export async function getUser(req, res) {
  const { rows } = await db.query("SELECT * FROM users");
  res.json(rows[0]);
}`, safe: `export async function getUser(req, res) {
  const { rows } = await db.query("SELECT id FROM users");
  res.json(rows[0]);
}` },
  { kind: "direct", positive: `export function getUser(req, res) {
  res.json({ "password\\nHash": "x" });
}`, safe: `export function getUser(req, res) {
  res.json({ createdAt: "x" });
}` },
  { kind: "spread", positive: `export function getUser(req, res) {
  const user = { "refresh\\nToken": "x" };
  res.json({ ...user });
}`, safe: `export function getUser(req, res) {
  const user = { createdAt: "x" };
  res.json({ ...user });
}` },
] as const;

function dynamicPgResponseExposureFindings(): Finding[] {
  return pgResponseExposureCases.flatMap(({ kind, positive }, index) => detectPgResponseExposureFindings([
    { path: `pg-response-${kind}-${index}.ts`, text: positive },
  ]));
}

function normalizeAndSarif(findings: Finding[]): { findings: Finding[]; tags: string[][] } {
  const normalized = runRegisteredNormalizationEngines({
    findings: findings.map((finding) => ({ ...finding })),
    scanDir: process.cwd(),
    directDeps: new Set(),
  }).findings;
  const sarif = toSarif(normalized, { coverageAbsent: "#2227 exercises the normal CWE-to-SARIF seam." }) as {
    runs: { tool: { driver: { rules: { properties: { tags: string[] } }[] } } }[];
  };
  return { findings: normalized, tags: sarif.runs[0]!.tool.driver.rules.map((rule) => rule.properties.tags) };
}

describe("#975: every detector taxonomy has a CWE decision (fail loud on an unclassified one)", () => {
  // Advisor names remain an explicit upstream boundary (#2229), including the two names narrowed
  // by a local branch. Neither an external-name string nor that narrowing proves a weakness class.
  const taxonomies = [...new Set([
    ...discovery.sites.filter((site) => !isExternalAdvisorSite(site)).flatMap((site) => site.values ?? []),
    ...boundaryInventory.emittedM9Taxonomies,
    ...boundaryInventory.emittedRoutedTaxonomies,
    ...dynamicPgResponseExposureFindings().map((finding) => finding.taxonomy),
  ])].sort();

  it("harvested a non-trivial set of detector taxonomies", () => {
    // Guards the harvester itself: a zero/tiny count would make the coverage assertion vacuously pass.
    expect(taxonomies.length).toBeGreaterThan(100);
  });

  it("discovers constant and conditional taxonomy expressions beyond quoted assignments", () => {
    expect(taxonomies).toContain("M1 — Hardcoded tenant identifier at client/request boundary");
    expect(taxonomies).toContain("M1 — Client-supplied owner id trusted by authenticated action");
    expect(taxonomies).toContain("M1 — Client-supplied owner id trusted by unauthenticated service-role action");
  });

  it("accounts for every expression across both producer trees without a registry-membership skip", () => {
    expect(classificationProblems(discovery.sites)).toEqual([]);
    for (const contract of deferredSites) {
      const matches = discovery.sites.filter((site) => sameSite(site, contract));
      expect(matches, `${contract.file}#${contract.owner}: stale or duplicated coverage obligation`).toHaveLength(contract.occurrences ?? 1);
      expect(contract.coverage.length).toBeGreaterThan(20);
      if (!isExternalAdvisorSite(matches[0]!)) expect(matches.every((site) => !site.values && !hasClassifiedPrefix(site))).toBe(true);
    }
    for (const prefix of classifiedPrefixes) expect(classifyTaxonomyCwe(prefix)?.kind, `${prefix} has no active no-CWE rule`).toBe("none");
    expect(boundaryInventory.sourcePaths).toContain("src/detectors/app-router.ts");
    expect(boundaryInventory.unreadTaxonomySites).toEqual([]);
  });

  it("binds local forwarding sites to the finite taxonomy properties they consume", () => {
    const escape = discovery.sites.find((site) => site.file === "src/detectors/m5-type-escape.ts" && site.expression === "names[row.kind].taxonomy")!;
    const escapeTable = ((escape.node as ts.PropertyAccessExpression).expression as ts.ElementAccessExpression).expression;
    const leftover = discovery.sites.find((site) => site.file === "src/scan/leftover-auth.ts" && site.expression === "c.taxonomy")!;
    const iterator = checker.getSymbolAtLocation((leftover.node as ts.PropertyAccessExpression).expression)?.valueDeclaration;
    expect(iterator && ts.isVariableDeclaration(iterator)).toBe(true);
    const loop = iterator!.parent.parent;
    expect(ts.isForOfStatement(loop), "the forwarding source must be the declared B14_CHECKS inventory").toBe(true);
    const forwarded = [
      ...containedTaxonomies(referencedInitializer(escapeTable, "names")),
      ...containedTaxonomies(referencedInitializer((loop as ts.ForOfStatement).expression, "B14_CHECKS")),
      ...localArgumentTaxonomies("src/detectors/test-intent.ts", "detectOnlyClass", 3),
    ];
    for (const taxonomy of forwarded) expect(taxonomies).toContain(taxonomy);
    const dataLayer = discovery.sites.find((site) => site.file === "src/detectors/app-router.ts" && site.expression === "`${taxonomy} — not assessed`")!;
    let callback: ts.Node = dataLayer.node;
    while (!ts.isArrowFunction(callback)) callback = callback.parent;
    expect(ts.isCallExpression(callback.parent)).toBe(true);
    const map = (callback.parent as ts.CallExpression).expression;
    expect(ts.isPropertyAccessExpression(map) && map.name.text === "map").toBe(true);
    const dataLayerTaxonomies = containedTaxonomies(referencedInitializer((map as ts.PropertyAccessExpression).expression, "DATA_LAYER_CHECKS"));
    for (const taxonomy of dataLayerTaxonomies) expect(classifyTaxonomyCwe(`${taxonomy} — not assessed`)?.kind).toBe("none");
  });

  it("classifies exact live contracts and proves wildcard coverage from their source populations", () => {
    const emitted = dynamicPgResponseExposureFindings();
    for (const definition of MECHANICAL_DETECTORS) {
      for (const taxonomy of definition.taxonomies) {
        if (!taxonomy.includes("*")) {
          expect(classifyTaxonomyCwe(taxonomy), `${definition.id} declares an unclassified taxonomy`).toBeDefined();
          continue;
        }
        if (taxonomy.endsWith("*") && classifiedPrefixes.some((prefix) => taxonomy.slice(0, -1).startsWith(prefix))) continue;
        expect(definition.id, `${definition.id}: wildcard has neither a whole-prefix decision nor a finite producer proof`).toBe("pg-response-exposure");
        expect(definition.implementation.file).toBe("src/scan/pg-response-exposure.ts");
        expect(taxonomy).toBe("Excessive data exposure: res.json(...)*");
        expect(emitted.length).toBeGreaterThan(0);
        for (const finding of emitted) expect(classifyTaxonomyCwe(finding.taxonomy), `${definition.id} emits an unclassified taxonomy`).toBeDefined();
      }
    }
  });

  it("fails if any unresolved source binding is omitted from its coverage census", () => {
    for (const contract of deferredSites) {
      const reduced = deferredSites.filter((candidate) => candidate !== contract);
      expect(unresolvedSites(discovery.sites, reduced).length, `${contract.file}#${contract.owner} was silently ignored`).toBeGreaterThan(0);
    }
  });

  it.each(taxonomies)("%s is classified (cwe or explicit no-cwe-with-reason)", (taxonomy) => {
    const c = classifyTaxonomyCwe(taxonomy);
    expect(c, `taxonomy "${taxonomy}" is unclassified — add it to SECURITY (with a CWE) or NO_CWE (with a reason) in src/cwe-map.ts`).toBeDefined();
    if (c?.kind === "cwe") {
      expect(c.cwe.length).toBeGreaterThan(0);
      // #1661: every entry, not just the first — the field is a list and a second entry that was
      // never shape-checked would reach the report and SARIF unvalidated.
      for (const id of c.cwe) expect(id).toMatch(/^CWE-\d+:/);
    } else {
      expect(c?.kind).toBe("none");
      expect((c as { reason: string }).reason.length).toBeGreaterThan(0);
    }
  });
});

describe("#2227: taxonomy discovery falsifiers", () => {
  it("discovers quoted keys, computed literal keys, and shorthand constant symbols", () => {
    const canary = canaryDiscovery(`
      const ALIAS = "M1 — unclassified shorthand canary";
      const taxonomy = ALIAS;
      const shorthand = { taxonomy };
      const quoted = { "taxonomy": "M1 — unclassified quoted canary" };
      const computed = { ["taxonomy"]: "M1 — unclassified computed canary" };
    `);
    expect(canary.taxonomies).toEqual([
      "M1 — unclassified computed canary",
      "M1 — unclassified quoted canary",
      "M1 — unclassified shorthand canary",
    ]);
    expect(classificationProblems(canary.sites)).toHaveLength(3);
  });

  it("expands finite template families and rejects unregistered function/template expressions", () => {
    const canary = canaryDiscovery(`
      function finite(kind: "first" | "second") { return { taxonomy: \`M1 — finite \${kind}\` }; }
      declare function makeTaxonomy(): string;
      function dynamic(noun: string) { return { taxonomy: \`M1 — \${noun} new family\` }; }
      const fromCall = { taxonomy: makeTaxonomy() };
      declare const existing: { taxonomy: string };
      existing.taxonomy = "M1 — unclassified assignment canary";
    `);
    expect(canary.taxonomies).toEqual(["M1 — finite first", "M1 — finite second", "M1 — unclassified assignment canary"]);
    expect(unresolvedSites(canary.sites)).toHaveLength(2);
    expect(classificationProblems(canary.sites)).toHaveLength(5);
  });

  it("does not let a known file absorb an added unresolved producer", () => {
    const site = discovery.sites.find((site) => site.file === "src/detectors/app-router.ts" && site.expression === "`M1 — ${noun} missing authorization check`")!;
    const unknown = { ...site, owner: "anotherProducer", expression: "unknownTaxonomy()" };
    expect(unresolvedSites([unknown])).toHaveLength(1);
  });
});

describe("#2227: finite boundary-authorization taxonomy coverage", () => {
  it("exercises every authorization taxonomy in the live boundary dependency inventory", () => {
    expect(emittedBoundaryFindings).toHaveLength(boundaryCases.length);
    const expected = boundaryInventory.emittedRoutedTaxonomies.filter((taxonomy) => taxonomy.endsWith(" missing authorization check"));
    expect(expected.length).toBeGreaterThan(0);
    expect([...new Set(emittedBoundaryFindings.map((finding) => finding.taxonomy))].sort()).toEqual(expected);
    for (const { fixture, framework } of boundaryCases) {
      expect(boundaryFindings(fixture, framework, "positive"), `${fixture}/${framework ?? "next"}`).toHaveLength(1);
      expect(boundaryFindings(fixture, framework, "negative"), `${fixture}/${framework ?? "next"} authorized inverse`).toEqual([]);
    }
  });

  it("preserves the finding while normal enrichment exports CWE-862/A01 into SARIF", () => {
    // IDs repeat across fixture scans, so export each scan separately, as production does.
    for (const finding of emittedBoundaryFindings) {
      expect(finding).toMatchObject({ id: "M9-01", severity: "High", precisionTier: "review" });
      const normalized = normalizeAndSarif([finding]);
      expect(normalized.findings[0]).toMatchObject({
        cwe: ["CWE-862: Missing Authorization"], owasp: ["A01:2021 - Broken Access Control"],
      });
      const preserved = { ...normalized.findings[0]! };
      delete preserved.cwe;
      delete preserved.owasp;
      expect(preserved).toEqual(finding);
      expect(normalized.tags[0]).toContain("external/cwe/cwe-862");
    }
  });
});

describe("#2227: dynamic pg response-exposure taxonomy coverage", () => {
  const findings = dynamicPgResponseExposureFindings();
  const taxonomyKind = (taxonomy: string): string | undefined => taxonomy.match(/\(pg-resjson-exposure-([^)]*)\)$/)?.[1];

  it("enumerates every finite producer kind from emitted findings", () => {
    // Production invocation exposes template-built taxonomies directly; skipping any producer
    // makes this cardinality assertion fail.
    expect(findings).toHaveLength(pgResponseExposureCases.length);
    expect(findings.map((finding) => taxonomyKind(finding.taxonomy)).sort()).toEqual(pgResponseExposureCases.map((entry) => entry.kind).sort());
    const site = discovery.sites.find((site) => site.file === "src/scan/pg-response-exposure.ts" && site.owner === "detectFile")!;
    expect(ts.isTemplateExpression(site.node)).toBe(true);
    const kind = (site.node as ts.TemplateExpression).templateSpans[1]!.expression;
    const producerKinds = finiteStringType(checker.getTypeAtLocation(kind));
    expect(producerKinds, "an open kind requires a new explicit coverage contract").toBeDefined();
    expect([...new Set(findings.map((finding) => taxonomyKind(finding.taxonomy)))].sort()).toEqual(producerKinds!.sort());
    for (const { kind, safe } of pgResponseExposureCases) {
      expect(detectPgResponseExposureFindings([{ path: `pg-response-${kind}-safe.ts`, text: safe }])).toEqual([]);
    }
  });

  it("preserves the detector's severity, review boundary, and stable IDs", () => {
    expect(findings.map(({ id, severity, precisionTier }) => ({ id: /^SEC-PG-RESJSON-pg-response-(?:direct|spread|select-star)-\d+-ts-\d+$/.test(id), severity, precisionTier }))).toEqual(
      pgResponseExposureCases.map(({ kind }) => ({ id: true, severity: kind === "select-star" ? "Medium" : "High", precisionTier: "review" })),
    );
  });

  it.each(findings)("classifies emitted %s taxonomy as CWE-200/A01", (finding) => {
    expect(classifyTaxonomyCwe(finding.taxonomy)).toEqual({
      kind: "cwe",
      cwe: ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
  });

  it("carries each emitted decision through normal enrichment into SARIF CWE tags", () => {
    const normalized = normalizeAndSarif(findings);
    expect(normalized.findings.map((finding) => finding.cwe)).toEqual(Array.from({ length: pgResponseExposureCases.length }, () => ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"]));
    for (const tags of normalized.tags) expect(tags).toContain("external/cwe/cwe-200");
  });
});

describe("#2227: constant producer taxonomy coverage", () => {
  it("normalizes and exports the hardcoded tenant producer with CWE-639", () => {
    const findings = detectM1HardcodedTenantFindings([{
      path: "src/components/tenant-client.tsx",
      text: `"use client"; export const tenant = new TenantClient({ tenantId: "tenant_example-4821" });`,
    }]);
    expect(findings).toHaveLength(1);
    const normalized = normalizeAndSarif(findings);
    expect(normalized.findings[0]).toMatchObject({
      taxonomy: "M1 — Hardcoded tenant identifier at client/request boundary",
      cwe: ["CWE-639: Authorization Bypass Through User-Controlled Key"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
    expect(normalized.tags[0]).toContain("external/cwe/cwe-639");
  });
});

describe("#975: enrichFindingsCwe", () => {
  it("declares the CWE for a security taxonomy that lacks one", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Object-level authorization gap: client-supplied owner id scopes the query" })]);
    expect(f!.cwe).toEqual(["CWE-639: Authorization Bypass Through User-Controlled Key"]);
    expect(f!.owasp).toEqual(["A01:2021 - Broken Access Control"]);
  });

  it("carries the CWE without an OWASP category when OWASP does not categorize it", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Non-atomic read-modify-write race condition" })]);
    expect(f!.cwe).toEqual(["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"]);
    expect(f!.owasp).toBeUndefined();
  });

  it("leaves a non-security (quality) taxonomy without a CWE", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "M6 — Indicator: manual date formatting" })]);
    expect(f!.cwe).toBeUndefined();
  });

  it("does not overwrite a CWE the finding already carries (semgrep/OSV-sourced)", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "SQL injection", cwe: ["CWE-943: something else"] })]);
    expect(f!.cwe).toEqual(["CWE-943: something else"]);
  });
});
