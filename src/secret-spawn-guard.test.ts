// #1778: discovery conserves actual child_process calls into individually audited policy rows.
// Source hashes and runtime-test anchors bind that audit; this is not a control-flow proof or
// a claim that a nearby guard protects a call. Guard bypasses remain the owning runtime tests.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const PROJECT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const POLICY_PATH = "src/secret-spawn-policy.json";
const PRIMITIVES = ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"] as const;
type Primitive = typeof PRIMITIVES[number];
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const TEST_FILE = /\.(?:test|spec|test-d|spec-d)\.[cm]?[jt]sx?$/;
const DECLARATION_FILE = /\.d\.[cm]?ts$/;
const OMIT_DIRECTORIES = new Set(["node_modules", "__tests__", "tests", "__fixtures__", "fixtures", "test-fixtures"]);
const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");
const slash = (path: string): string => path.split(sep).join("/");

interface SpawnCall {
  path: string;
  symbol: string;
  primitive: Primitive;
  callKey: string;
  reviewedSourceSha256: string;
  line: number;
  callee: string;
  commandExpression: string;
  argvExpression: string;
  callExpression: string;
}
interface SpawnCensus {
  files: { path: string; sourceSha256: string }[];
  calls: SpawnCall[];
  errors: string[];
}
interface SourceAnchor { path: string; sourceSha256: string }
interface PolicyEntry {
  path: string;
  symbol: string;
  primitive: Primitive;
  callKey: string;
  argvSource: string;
  disposition: "guarded" | "no-target-secret";
  reason: string;
  provenance: { reviewer: string; evidence: string; inputs: SourceAnchor[] };
  falsifier: string;
  reviewedSourceSha256: string;
  guard?: SourceAnchor & { symbol: string };
  runtimeTests?: (SourceAnchor & { name: string })[];
}
interface SpawnPolicy { schemaVersion: 1; sourceRoot: "src"; entries: PolicyEntry[] }
type ModuleKind = "child_process" | "util" | "module" | "process" | "url";
type BoundValue =
  | { kind: "global" }
  | { kind: "namespace"; module: ModuleKind }
  | { kind: "primitive"; primitive: Primitive }
  | { kind: "promisify" | "require" | "createRequire" | "URL" | "pathToFileURL" | "fileURL" | "fileSpecifier" }
  | { kind: "promise"; module: ModuleKind }
  | { kind: "unknown"; reason: string };

function productionPaths(root: string): string[] {
  const paths: string[] = [];
  function walk(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (OMIT_DIRECTORIES.has(entry.name)) continue;
      const absolute = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Unreviewed source symlink: ${slash(relative(root, absolute))}`);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name)) && !TEST_FILE.test(entry.name) && !DECLARATION_FILE.test(entry.name)) paths.push(slash(relative(root, absolute)));
    }
  }
  walk(join(root, "src"));
  return paths.sort();
}

function parsedSource(path: string, text: string): { source: ts.SourceFile; checker: ts.TypeChecker; syntaxErrors: readonly ts.Diagnostic[] } {
  const filename = resolve("/spawn-policy-source", path);
  // Node files have a module scope, including CommonJS. Script-mode globalThis has a
  // synthetic TS symbol that otherwise hides a real top-level lexical shadow.
  const options: ts.CompilerOptions = { target: ts.ScriptTarget.Latest, module: ts.ModuleKind.ESNext, moduleDetection: ts.ModuleDetectionKind.Force, allowJs: true, noLib: true, noResolve: true, types: [] };
  const host = ts.createCompilerHost(options);
  host.fileExists = (name) => name === filename;
  host.readFile = (name) => name === filename ? text : undefined;
  const program = ts.createProgram([filename], options, host);
  const source = program.getSourceFile(filename)!;
  return { source, checker: program.getTypeChecker(), syntaxErrors: program.getSyntacticDiagnostics(source) };
}

function unwrap(node: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node)) node = node.expression;
  return node;
}

function propertyName(node: ts.Node | undefined): string | undefined {
  return node && (ts.isIdentifier(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) ? node.text : undefined;
}

function printed(source: ts.SourceFile, node: ts.Node): string {
  return ts.createPrinter({ removeComments: true }).printNode(ts.EmitHint.Unspecified, node, source).trim();
}

function functionName(node: ts.Node, source: ts.SourceFile): string | undefined {
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) return node.name?.text ?? "<anonymous-class>";
  if (ts.isConstructorDeclaration(node)) return "constructor";
  if (ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) return propertyName(node.name) ?? `<computed:${sha256(printed(source, node.name)).slice(0, 16)}>`;
  if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) {
    if (node.name) return node.name.text;
  } else if (!ts.isArrowFunction(node)) return undefined;
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)) return propertyName(parent.name) ?? "<binding-function>";
  if (ts.isCallExpression(parent) || ts.isNewExpression(parent)) return `<callback:${printed(source, parent.expression)}:${parent.arguments?.indexOf(node as ts.Expression) ?? -1}>`;
  return "<anonymous-function>";
}

function containingSymbol(node: ts.Node, source: ts.SourceFile, includeSelf = false): string {
  const names: string[] = [];
  for (let parent: ts.Node | undefined = includeSelf ? node : node.parent; parent && !ts.isSourceFile(parent); parent = parent.parent) {
    const name = functionName(parent, source);
    if (name) names.unshift(name);
  }
  return names.join(".") || "<module>";
}

function scanSource(path: string, text: string): { calls: SpawnCall[]; errors: string[] } {
  const { source, checker, syntaxErrors } = parsedSource(path, text);
  const memo = new Map<ts.Symbol, BoundValue | undefined>();
  const active = new Set<ts.Symbol>();
  const calls: SpawnCall[] = [];
  const errors = new Set(syntaxErrors.map((diagnostic) => `${path}: Unparsed source: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, " ")}`));
  const occurrences = new Map<string, number>();
  const childValue = (value: BoundValue | undefined): boolean => value?.kind === "primitive" || value?.kind === "unknown" || ((value?.kind === "namespace" || value?.kind === "promise") && value.module === "child_process");
  const loaderValue = (value: BoundValue | undefined): boolean => value?.kind === "global" || value?.kind === "require" || value?.kind === "createRequire" || ((value?.kind === "namespace" || value?.kind === "promise") && (value.module === "process" || value.module === "module"));
  const watchedValue = (value: BoundValue | undefined): boolean => childValue(value) || loaderValue(value);
  const error = (node: ts.Node, message: string): void => { errors.add(`${path}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}: ${message}`); };
  function moduleValue(name: string | undefined): BoundValue | undefined {
    const module = name?.replace(/^node:/, "");
    return ["child_process", "util", "module", "process", "url"].includes(module ?? "") ? { kind: "namespace", module: module as ModuleKind } : undefined;
  }
  function member(value: BoundValue | undefined, name: string | undefined): BoundValue | undefined {
    if (value?.kind === "global") {
      if (name === "globalThis" || name === "global") return value;
      if (name === "process" || name === "module") return { kind: "namespace", module: name };
      if (name === "require" || name === "URL") return { kind: name };
      if (name === undefined) return { kind: "unknown", reason: "Unresolved native global member can hide a child_process loader" };
    }
    if (value?.kind === "namespace") {
      if (value.module === "child_process") return PRIMITIVES.includes(name as Primitive) ? { kind: "primitive", primitive: name as Primitive } : { kind: "unknown", reason: `Unknown child_process member ${name ?? "<dynamic>"}` };
      if (value.module === "util" && name === "promisify") return { kind: "promisify" };
      if (value.module === "module" && name === "createRequire") return { kind: "createRequire" };
      if ((value.module === "module" && name === "require") || (value.module === "process" && name === "getBuiltinModule")) return { kind: "require" };
      if (value.module === "process" && name === "mainModule") return { kind: "namespace", module: "module" };
      if (value.module === "module" && ["_load", "Module", "constructor", "prototype"].includes(name ?? "")) return { kind: "unknown", reason: "Unsupported native loader module indirection" };
      if ((value.module === "process" || value.module === "module") && name === undefined) return { kind: "unknown", reason: "Unresolved native loader member can hide child_process" };
      if (value.module === "url" && (name === "URL" || name === "pathToFileURL")) return { kind: name };
    }
    // A bound loader's call/apply/bind or dynamic property cannot silently become untracked.
    // require.resolve returns a module name, not an executable loader value.
    if ((value?.kind === "require" || value?.kind === "createRequire") && name !== "resolve") return { kind: "unknown", reason: "Unsupported member access on a native loader" };
    if (value?.kind === "promise" && loaderValue(value)) return { kind: "unknown", reason: "Unsupported member access on a native loader promise" };
    if (value?.kind === "fileURL" && (name === "href" || name === "pathname")) return { kind: "fileSpecifier" };
    if (childValue(value)) return { kind: "unknown", reason: "Unsupported member access on a child_process value" };
    return undefined;
  }
  function constantString(expression: ts.Expression | undefined, seen = new Set<ts.Symbol>()): string | undefined {
    if (!expression) return undefined;
    const node = unwrap(expression);
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isPropertyAccessExpression(node)) {
      if (ts.isMetaProperty(node.expression) && node.expression.keywordToken === ts.SyntaxKind.ImportKeyword && node.name.text === "url") return pathToFileURL(source.fileName).href;
      const object = unwrap(node.expression);
      if (ts.isNewExpression(object) && expressionValue(object.expression)?.kind === "URL" && (node.name.text === "href" || node.name.text === "pathname")) {
        const input = constantString(object.arguments?.[0], new Set(seen));
        const base = constantString(object.arguments?.[1], new Set(seen));
        if (input !== undefined && (object.arguments?.length === 1 || base !== undefined)) {
          try { return new URL(input, base)[node.name.text]; } catch { return undefined; }
        }
      }
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = constantString(node.left, seen), right = constantString(node.right, seen);
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (ts.isIdentifier(node)) {
      const symbol = checker.getSymbolAtLocation(node);
      if (symbol && !seen.has(symbol)) {
        const declaration = symbol.valueDeclaration;
        if (declaration && ts.isVariableDeclaration(declaration) && (declaration.parent.flags & ts.NodeFlags.Const)) return constantString(declaration.initializer, new Set([...seen, symbol]));
      }
    }
    return undefined;
  }
  function symbolValue(symbol: ts.Symbol | undefined): BoundValue | undefined {
    if (!symbol || active.has(symbol)) return undefined;
    if (memo.has(symbol)) return memo.get(symbol);
    active.add(symbol);
    let value: BoundValue | undefined;
    for (const declaration of symbol.declarations ?? []) {
      if (ts.isImportSpecifier(declaration)) {
        const clause = declaration.parent.parent;
        if (!declaration.isTypeOnly && !clause.isTypeOnly) value = member(moduleValue(constantString(clause.parent.moduleSpecifier)), (declaration.propertyName ?? declaration.name).text);
      } else if (ts.isNamespaceImport(declaration)) {
        const clause = declaration.parent;
        if (!clause.isTypeOnly) value = moduleValue(constantString(clause.parent.moduleSpecifier));
      } else if (ts.isImportClause(declaration)) {
        if (!declaration.isTypeOnly) value = moduleValue(constantString(declaration.parent.moduleSpecifier));
      } else if (ts.isImportEqualsDeclaration(declaration) && ts.isExternalModuleReference(declaration.moduleReference)) {
        if (!declaration.isTypeOnly) value = moduleValue(constantString(declaration.moduleReference.expression));
      } else if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
        value = expressionValue(declaration.initializer);
      } else if (ts.isBindingElement(declaration) && ts.isObjectBindingPattern(declaration.parent)) {
        const owner = declaration.parent.parent;
        if (ts.isVariableDeclaration(owner) && owner.initializer) {
          const original = expressionValue(owner.initializer);
          value = declaration.dotDotDotToken && watchedValue(original) ? { kind: "unknown", reason: "Child_process or native loader rest binding escapes discovery" } : member(original, propertyName(declaration.propertyName ?? declaration.name));
        }
      } else if (ts.isShorthandPropertyAssignment(declaration)) {
        value = symbolValue(checker.getShorthandAssignmentValueSymbol(declaration));
      } else if (ts.isExportSpecifier(declaration)) {
        value = symbolValue(checker.getExportSpecifierLocalTargetSymbol(declaration));
      } else if (ts.isParameter(declaration) && declaration.initializer && watchedValue(expressionValue(declaration.initializer))) {
        value = { kind: "unknown", reason: "Child_process value supplied as an overridable parameter default" };
      }
      if (value) break;
    }
    active.delete(symbol);
    memo.set(symbol, value);
    return value;
  }
  function expressionValue(expression: ts.Expression): BoundValue | undefined {
    const node = unwrap(expression);
    if (ts.isIdentifier(node)) {
      const symbol = checker.getSymbolAtLocation(node);
      // TypeScript gives CommonJS require a synthetic symbol with no declarations in JS.
      // Real lexical shadows have declarations and must never become native loaders.
      const unbound = !symbol?.declarations?.length;
      if (unbound && node.text === "require") return { kind: "require" };
      if (unbound && node.text === "URL") return { kind: "URL" };
      if (unbound && (node.text === "globalThis" || node.text === "global")) return { kind: "global" };
      if (unbound && (node.text === "module" || node.text === "process")) return { kind: "namespace", module: node.text };
      return symbolValue(symbol);
    }
    if (ts.isPropertyAccessExpression(node)) return member(expressionValue(node.expression), node.name.text);
    if (ts.isElementAccessExpression(node)) return member(expressionValue(node.expression), constantString(node.argumentExpression));
    if (ts.isAwaitExpression(node)) {
      const value = expressionValue(node.expression);
      return value?.kind === "promise" ? { kind: "namespace", module: value.module } : value;
    }
    if (ts.isCallExpression(node)) {
      const callee = expressionValue(node.expression);
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword || callee?.kind === "require") {
        const name = constantString(node.arguments[0]);
        // A symbol-bound pathToFileURL result can only select a file module, even when its
        // filename is dynamic. It cannot select a builtin such as node:child_process.
        if (name === undefined && node.arguments[0] && expressionValue(node.arguments[0])?.kind === "fileSpecifier") return undefined;
        if (name === undefined) return { kind: "unknown", reason: "Unresolved dynamic module loader can hide child_process" };
        const value = moduleValue(name);
        return node.expression.kind === ts.SyntaxKind.ImportKeyword && value?.kind === "namespace" ? { kind: "promise", module: value.module } : value;
      }
      if (callee?.kind === "createRequire") return { kind: "require" };
      if (callee?.kind === "pathToFileURL") return { kind: "fileURL" };
      if (callee?.kind === "promisify" && node.arguments[0]) {
        const value = expressionValue(node.arguments[0]);
        return value?.kind === "primitive" ? value : childValue(value) ? { kind: "unknown", reason: "Unsupported promisified child_process value" } : undefined;
      }
    }
    return undefined;
  }
  function declarationName(node: ts.Identifier): boolean {
    const parent = node.parent;
    return ts.isImportSpecifier(parent) || ts.isNamespaceImport(parent) || ts.isImportClause(parent) || ts.isImportEqualsDeclaration(parent)
      || ((ts.isVariableDeclaration(parent) || ts.isBindingElement(parent) || ts.isParameter(parent)) && (parent.name === node || (ts.isBindingElement(parent) && parent.propertyName === node)))
      || ((ts.isPropertyAccessExpression(parent) || ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent) || ts.isPropertyDeclaration(parent)) && parent.name === node);
  }
  function permittedUse(node: ts.Expression, value: BoundValue): boolean {
    const parent = node.parent;
    if (ts.isTypeOfExpression(parent)) return true;
    if (ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent) || ts.isTypeAssertionExpression(parent) || ts.isNonNullExpression(parent) || ts.isSatisfiesExpression(parent) || ts.isAwaitExpression(parent)) return true;
    if ((ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) && parent.expression === node) return true;
    if (ts.isCallExpression(parent)) {
      if (parent.expression === node) return value.kind === "primitive" || value.kind === "require" || value.kind === "createRequire";
      if (parent.arguments[0] === node && expressionValue(parent.expression)?.kind === "promisify" && value.kind === "primitive") return true;
    }
    if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
      const statement = parent.parent.parent;
      if (ts.isVariableStatement(statement) && statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) return false;
      if (ts.isIdentifier(parent.name)) return true;
      return ts.isObjectBindingPattern(parent.name) && parent.name.elements.every((element) => {
        if (element.dotDotDotToken || element.initializer || !ts.isIdentifier(element.name)) return false;
        const name = propertyName(element.propertyName ?? element.name);
        const selected = member(value, name);
        return loaderValue(value) ? name !== undefined && selected?.kind !== "unknown" : selected?.kind === "primitive";
      });
    }
    return ts.isExpressionStatement(parent) && (value.kind === "namespace" || value.kind === "global");
  }
  function visit(node: ts.Node): void {
    if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly && ts.isExternalModuleReference(node.moduleReference) && childValue(moduleValue(constantString(node.moduleReference.expression))) && node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) error(node, "Child_process re-export escapes discovery");
    if (ts.isTypeNode(node) || ts.isImportDeclaration(node) || ts.isImportEqualsDeclaration(node)) return;
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && constantString(node.moduleSpecifier as ts.Expression | undefined)?.replace(/^node:/, "") === "child_process") error(node, "Child_process re-export escapes discovery");
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const value = expressionValue(node.expression);
      if (value?.kind === "primitive" && ts.isCallExpression(node)) {
        const symbol = containingSymbol(node, source);
        const callExpression = printed(source, node);
        const base = `${path}#${symbol}:${value.primitive}:${sha256(callExpression).slice(0, 16)}`;
        const occurrence = (occurrences.get(base) ?? 0) + 1;
        occurrences.set(base, occurrence);
        const argvIndex = value.primitive === "exec" || value.primitive === "execSync" ? 0 : 1;
        calls.push({ path, symbol, primitive: value.primitive, callKey: `${base}:${occurrence}`, reviewedSourceSha256: sha256(text),
          line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1, callee: printed(source, node.expression),
          commandExpression: node.arguments[0] ? printed(source, node.arguments[0]) : "<omitted>",
          argvExpression: node.arguments[argvIndex] ? printed(source, node.arguments[argvIndex]) : "<omitted>", callExpression });
      } else if (childValue(value)) error(node, value?.kind === "unknown" ? value.reason : "Unsupported invocation of a child_process value");
    }
    if (ts.isExpression(node) && !(ts.isIdentifier(node) && declarationName(node))) {
      const value = expressionValue(node);
      if (value?.kind === "unknown") error(node, value.reason);
      else if (value && watchedValue(value) && !permittedUse(node, value)) error(node, `Child_process ${value.kind} value escapes an audited direct call/alias`);
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return { calls, errors: [...errors].sort() };
}

function discoverSources(sources: Record<string, string>): SpawnCensus {
  const census: SpawnCensus = { files: [], calls: [], errors: [] };
  for (const [path, text] of Object.entries(sources).sort(([a], [b]) => a.localeCompare(b))) {
    census.files.push({ path, sourceSha256: sha256(text) });
    const result = scanSource(path, text);
    census.calls.push(...result.calls);
    census.errors.push(...result.errors);
  }
  return census;
}

function discoverProduction(root: string): SpawnCensus {
  return discoverSources(Object.fromEntries(productionPaths(root).map((path) => [path, readFileSync(join(root, path), "utf8")])));
}

const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const sourcePath = (value: unknown): value is string => typeof value === "string" && value.length > 0 && !isAbsolute(value) && !value.includes("\\") && !value.split("/").some((part) => part === ".." || part === "." || part === "");

function definitions(text: string, path: string): Set<string> {
  const { source } = parsedSource(path, text);
  const symbols = new Set<string>();
  function visit(node: ts.Node): void {
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) symbols.add(containingSymbol(node, source, true));
    ts.forEachChild(node, visit);
  }
  visit(source);
  return symbols;
}

function runtimeTestNames(text: string, path: string): string[] {
  const { source, checker } = parsedSource(path, text);
  const names: string[] = [];
  function binding(node: ts.Expression, names: string[]): boolean {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "each") return binding(node.expression.expression, names);
    if (!ts.isIdentifier(node)) return false;
    const declaration = checker.getSymbolAtLocation(node)?.declarations?.find(ts.isImportSpecifier);
    return !!declaration && names.includes((declaration.propertyName ?? declaration.name).text) && ts.isStringLiteral(declaration.parent.parent.parent.moduleSpecifier) && declaration.parent.parent.parent.moduleSpecifier.text === "vitest";
  }
  function inactiveSuite(node: ts.Expression): boolean {
    const chain: string[] = [];
    while (ts.isCallExpression(node) || ts.isPropertyAccessExpression(node)) {
      if (ts.isCallExpression(node)) node = node.expression;
      else { chain.push(node.name.text); node = node.expression; }
    }
    return binding(node, ["describe", "suite"]) && chain.some((part) => part !== "each" && part !== "concurrent" && part !== "sequential");
  }
  function visit(node: ts.Node): void {
    // Conditional/skipped suites are not evidence that the anchor runs in the ordinary gate.
    if (ts.isCallExpression(node) && inactiveSuite(node.expression)) return;
    if (ts.isCallExpression(node) && binding(node.expression, ["it", "test"]) && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0]) && node.arguments.some((argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument))) names.push(node.arguments[0].text);
    ts.forEachChild(node, visit);
  }
  visit(source);
  return names;
}

function validatePolicy(census: SpawnCensus, policy: unknown, readSource: (path: string) => string): string[] {
  const errors = [...census.errors];
  if (census.files.length === 0) errors.push("Source discovery examined zero files");
  if (census.calls.length === 0) errors.push("Spawn discovery found zero calls");
  if (!record(policy) || policy.schemaVersion !== 1 || policy.sourceRoot !== "src" || !Array.isArray(policy.entries)) return [...errors, "Expected spawn policy schemaVersion=1, sourceRoot=src, entries array"];
  const discovered = new Map(census.calls.map((call) => [call.callKey, call]));
  if (discovered.size !== census.calls.length) errors.push("Duplicate discovered call keys");
  const seen = new Set<string>();
  const substantial = (value: unknown, label: string, minimum = 30): void => {
    if (typeof value !== "string" || value.trim().length < minimum || /^(?:fixed|safe|internal|toolchain|no target|no secret|reviewed|not applicable)[\w\s/-]*[.!]?$/i.test(value.trim())) errors.push(`${label}: expected a specific audited explanation`);
  };
  function anchor(value: unknown, at: string): { path: string; text: string } | undefined {
    if (!record(value) || !sourcePath(value.path) || typeof value.sourceSha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.sourceSha256)) { errors.push(`${at}: expected repository path and SHA-256 source anchor`); return; }
    try {
      const text = readSource(value.path);
      if (sha256(text) !== value.sourceSha256) errors.push(`${at}: stale source fingerprint for ${value.path}`);
      return { path: value.path, text };
    } catch { errors.push(`${at}: source does not exist: ${value.path}`); }
  }
  for (const [index, entry] of policy.entries.entries()) {
    const at = `entries[${index}]`;
    if (!record(entry) || typeof entry.callKey !== "string") { errors.push(`${at}: expected per-call policy object`); continue; }
    if (seen.has(entry.callKey)) errors.push(`${at}: duplicate policy key ${entry.callKey}`);
    seen.add(entry.callKey);
    const call = discovered.get(entry.callKey);
    if (!call) errors.push(`${at}: stale policy key ${entry.callKey}`);
    else for (const field of ["path", "symbol", "primitive", "reviewedSourceSha256"] as const) if (entry[field] !== call[field]) errors.push(`${at}.${field}: does not match discovered source`);
    if (entry.disposition !== "guarded" && entry.disposition !== "no-target-secret") errors.push(`${at}.disposition: expected guarded or no-target-secret`);
    substantial(entry.argvSource, `${at}.argvSource`);
    substantial(entry.reason, `${at}.reason`);
    if (call) {
      let spawningSource: string | undefined;
      try { spawningSource = readSource(call.path); } catch { errors.push(`${at}: spawning source does not exist: ${call.path}`); }
      for (const field of ["argvSource", "reason"] as const) {
        const explanation = entry[field];
        const snippets = typeof explanation === "string" ? [...explanation.matchAll(/`([^`\r\n]+)`/g)].map((match) => match[1]!) : [];
        if (!snippets.some((snippet) => snippet.trim().length >= 3 && spawningSource?.includes(snippet))) errors.push(`${at}.${field}: expected a backticked snippet from the reviewed spawning source`);
      }
    }
    substantial(entry.falsifier, `${at}.falsifier`);
    if (!record(entry.provenance)) errors.push(`${at}.provenance: expected review evidence and inputs`);
    else {
      substantial(entry.provenance.reviewer, `${at}.provenance.reviewer`, 3);
      substantial(entry.provenance.evidence, `${at}.provenance.evidence`);
      if (!Array.isArray(entry.provenance.inputs)) errors.push(`${at}.provenance.inputs: expected transitive argv input anchors`);
      else {
        const inputs = new Set<string>();
        for (const [inputIndex, input] of entry.provenance.inputs.entries()) {
          const result = anchor(input, `${at}.provenance.inputs[${inputIndex}]`);
          if (result && inputs.has(result.path)) errors.push(`${at}.provenance.inputs: duplicate path ${result.path}`);
          if (result) inputs.add(result.path);
        }
      }
    }
    if (entry.disposition === "guarded") {
      const guard = anchor(entry.guard, `${at}.guard`);
      if (!record(entry.guard) || typeof entry.guard.symbol !== "string" || !guard || !guard.path.startsWith("src/") || TEST_FILE.test(guard.path) || !definitions(guard.text, guard.path).has(entry.guard.symbol)) errors.push(`${at}.guard: expected an existing production guard definition`);
      if (!Array.isArray(entry.runtimeTests) || entry.runtimeTests.length === 0) errors.push(`${at}.runtimeTests: expected owning runtime-test anchors`);
      else for (const [testIndex, test] of entry.runtimeTests.entries()) {
        const found = anchor(test, `${at}.runtimeTests[${testIndex}]`);
        if (!record(test) || typeof test.name !== "string" || !found || !TEST_FILE.test(found.path) || runtimeTestNames(found.text, found.path).filter((name) => name === test.name).length !== 1) errors.push(`${at}.runtimeTests[${testIndex}]: expected one existing runtime test by name`);
      }
    }
  }
  for (const call of census.calls) if (!seen.has(call.callKey)) errors.push(`Missing policy for ${call.callKey}`);
  return errors;
}

function repositoryReader(root: string): (path: string) => string {
  const boundary = realpathSync(root) + sep;
  return (path) => {
    if (!sourcePath(path)) throw new Error("Invalid repository path");
    const absolute = realpathSync(join(root, path));
    if (!absolute.startsWith(boundary)) throw new Error("Source anchor escapes the repository");
    return readFileSync(absolute, "utf8");
  };
}

function fixturePolicy(census: SpawnCensus): SpawnPolicy {
  return { schemaVersion: 1, sourceRoot: "src", entries: census.calls.map((call) => ({
    path: call.path, symbol: call.symbol, primitive: call.primitive, callKey: call.callKey, reviewedSourceSha256: call.reviewedSourceSha256,
    argvSource: "The fixture builds argv from the literal `--version` string in this function.", disposition: "no-target-secret",
    reason: "Only the literal `--version` argument reaches this fixture call; neither parameters nor external input are read.",
    provenance: { reviewer: "fixture reviewer", evidence: "Read the complete fixture function and traced its literal command and argv construction.", inputs: [] },
    falsifier: "Add a target-supplied value to this call's argv and rerun the owning fixture to require a new audit.",
  })) };
}

describe("spawn discovery bindings (#1778)", () => {
  it.each(["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"])("binds native CommonJS loaders and their lexical shadows in .%s", (extension) => {
    const source = 'const {spawn:launch}=require("child_process"); launch("x",[]); function local(require){const cp=require("child_process"); cp.spawn("ordinary");}';
    const result = scanSource(`src/fixture.${extension}`, source);
    expect(result.errors).toEqual([]);
    expect(result.calls.map((call) => call.primitive)).toEqual(["spawn"]);
  });
  it.each([
    ["named aliases", 'import {spawn as launch, exec} from "node:child_process"; launch("x",[]); exec("x",()=>{});', ["spawn", "exec"]],
    ["namespace and computed literal", 'import * as cp from "child_process"; cp.execFile("x",[]); cp["spawnSync"]("x",[]);', ["execFile", "spawnSync"]],
    ["default import", 'import cp from "node:child_process"; cp.fork("worker.js",[]);', ["fork"]],
    ["required aliases", 'const cp=require("node:child_process"); const {execSync:run}=cp; const fire=cp.spawn; const again=fire; run("x"); again("x",[]);', ["execSync", "spawn"]],
    ["inline require", 'require("node:child_process").execFileSync("x",[]);', ["execFileSync"]],
    ["import equals", 'import cp = require("node:child_process"); cp.spawn("x",[]);', ["spawn"]],
    ["promisify alias", 'import {execFile as run} from "node:child_process"; import {promisify as p} from "node:util"; const asyncRun=p(run); asyncRun("x",[]);', ["execFile"]],
    ["namespace promisify", 'import cp from "child_process"; import * as util from "util"; util.promisify(cp.exec)("x");', ["exec"]],
    ["required promisify", 'const {promisify:p}=require("util"); const cp=require("child_process"); const run=p(cp.execFile); run("x",[]);', ["execFile"]],
    ["createRequire binding", 'import {createRequire as make} from "node:module"; const require=make(import.meta.url); const {spawn}=require("node:child_process"); spawn("x",[]);', ["spawn"]],
    ["awaited import", 'const cp=await import("node:child_process"); cp.spawn("x",[]);', ["spawn"]],
    ["static module expression", 'const name="node:"+"child_process"; const cp=require(name); cp.exec("x");', ["exec"]],
    ["static file URL import", 'const file=new URL("../local.ts",import.meta.url).pathname; const local=await import(file); local.spawn("ordinary");', []],
    ["dynamic file URL import", 'import {pathToFileURL as fileURL} from "node:url"; const local=await import(fileURL(filename).href); local.spawn("ordinary");', []],
    ["builtin URL import", 'import {URL as NativeURL} from "node:url"; const cp=await import(new NativeURL("node:child_process").href); cp.spawn("x",[]);', ["spawn"]],
    ["loader type inspection", 'if(typeof require!=="undefined"){require("child_process").spawn("x",[]);}', ["spawn"]],
    ["native globalThis loader", 'globalThis.process.getBuiltinModule("node:child_process").spawn("x",[]);', ["spawn"]],
    ["native bare process loader twin", 'process.getBuiltinModule("node:child_process").spawn("x",[]);', ["spawn"]],
    ["native global loader", 'global.process.getBuiltinModule("child_process").execFile("x",[]);', ["execFile"]],
    ["native global object alias", 'const root=globalThis; root.process.getBuiltinModule("child_process").fork("x",[]);', ["fork"]],
    ["native global process alias", 'const p=global.process; p.getBuiltinModule("child_process").spawnSync("x",[]);', ["spawnSync"]],
    ["native global process destructuring", 'const {process:p}=globalThis; p.getBuiltinModule("child_process").execSync("x");', ["execSync"]],
    ["native global loader destructuring", 'const {getBuiltinModule:load}=globalThis.process; load("child_process").execFileSync("x",[]);', ["execFileSync"]],
    ["native global computed members", 'const key="get"+"BuiltinModule"; globalThis["process"][key]("child_process")["spawn"]("x",[]);', ["spawn"]],
    ["native global self aliases", 'global.globalThis.global.process.getBuiltinModule("child_process").spawn("x",[]);', ["spawn"]],
    ["native global optional members", 'globalThis?.process?.getBuiltinModule?.("child_process").spawn("x",[]);', ["spawn"]],
    ["native global require member", 'globalThis.require("child_process").spawn("x",[]);', ["spawn"]],
    ["native global createRequire chain", 'globalThis.process.getBuiltinModule("module").createRequire(import.meta.url)("child_process").spawn("x",[]);', ["spawn"]],
    ["native global mainModule loader", 'globalThis.process.mainModule.require("child_process").spawn("x",[]);', ["spawn"]],
    ["awaited native process loader", 'const p=await import("node:process");p.getBuiltinModule("child_process").spawn("x",[]);', ["spawn"]],
    ["native global promisify chain", 'const p=globalThis.process; const cp=p.getBuiltinModule("child_process"); p.getBuiltinModule("util").promisify(cp.execFile)("x",[]);', ["execFile"]],
    ["native global ordinary properties", 'const root=globalThis; const {env,cwd}=root.process; root.console.log(env,cwd());', []],
    ["shadowed globalThis parameter", 'function local(globalThis:any){globalThis.process.getBuiltinModule("child_process").spawn("ordinary");}', []],
    ["shadowed global parameter", 'function local(global:any){const {process:p}=global;p.getBuiltinModule("child_process").spawn("ordinary");}', []],
    ["shadowed globalThis declaration", 'const globalThis={process:custom};globalThis.process.getBuiltinModule("child_process").spawn("ordinary");', []],
    ["shadowed global loader alias", 'const load=globalThis.process.getBuiltinModule;function local(load:any){load("child_process").spawn("ordinary");}load("child_process").spawn("native",[]);', ["spawn"]],
    ["shadowed primitive", 'import {spawn} from "child_process"; function local(spawn: Function){spawn("not native");} spawn("x",[]);', ["spawn"]],
    ["shadowed namespace", 'import * as cp from "child_process"; function local(cp:any){cp.spawn("not native");} cp.spawn("x",[]);', ["spawn"]],
    ["sibling lexical aliases", 'import {spawn,exec} from "child_process"; function a(){const run=spawn;run("x",[]);} function b(){const run=exec;run("x");}', ["spawn", "exec"]],
    ["shadowed require", 'function local(require: Function){const cp=require("child_process"); cp.spawn("not native");}', []],
    ["lookalikes and strings", 'import {spawn} from "other-module"; spawn("ordinary"); const example="execFileSync(ignored)"; // spawn("comment")', []],
    ["type-only use", 'import type {spawn} from "child_process"; type Run=typeof spawn;', []],
  ] as const)("discovers %s without binding by global text name", (_label, source, expected) => {
    const result = scanSource("src/fixture.ts", source);
    expect(result.errors).toEqual([]);
    expect(result.calls.map((call) => call.primitive)).toEqual(expected);
  });

  it.each([
    ['import * as cp from "child_process"; cp[operation]("x");', "Unknown child_process member"],
    ['import {spawn} from "child_process"; consume(spawn);', "escapes"],
    ['import {spawn} from "child_process"; export {spawn};', "escapes"],
    ['export {spawn} from "child_process";', "re-export"],
    ['export import cp = require("child_process");', "re-export"],
    ['export const cp=require("child_process");', "escapes"],
    ['import {spawn} from "child_process"; const runners=[spawn]; runners[0]("x");', "escapes"],
    ['import {spawn} from "child_process"; const run=spawn.bind(null); run("x");', "Unsupported member"],
    ['import {spawn} from "child_process"; let run=spawn; run=replacement; run("x");', "escapes"],
    ['import {execFile} from "child_process"; function local(promisify:Function){const run=promisify(execFile); run("x");}', "escapes"],
    ['const {spawn,...rest}=require("child_process");', "escapes"],
    ['const cp=await import(moduleName); cp.spawn("x");', "Unresolved dynamic module loader"],
    ['import("child_process").then(cp=>cp.spawn("x"));', "Unsupported member"],
    ['function loader(){return require;} loader()("child_process").spawn("x");', "escapes"],
    ['import {createRequire} from "node:module"; consume(createRequire);', "escapes"],
    ['function local(URL: any){const cp=await import(new URL("node:child_process").href); cp.spawn("x");}', "Unresolved dynamic module loader"],
    ['function local(pathToFileURL: any){const cp=await import(pathToFileURL(filename).href); cp.spawn("x");}', "Unresolved dynamic module loader"],
    ['globalThis.process.getBuiltinModule(name).spawn("x",[]);', "Unresolved dynamic module loader"],
    ['globalThis.process[operation]("child_process").spawn("x",[]);', "native loader"],
    ['globalThis[property].getBuiltinModule("child_process").spawn("x",[]);', "native global"],
    ['consume(globalThis);', "escapes"],
    ['consume(global.process);', "escapes"],
    ['consume(globalThis.process.getBuiltinModule);', "escapes"],
    ['function loader(){return globalThis.process.getBuiltinModule;}loader()("child_process").spawn("x",[]);', "escapes"],
    ['const {...p}=globalThis.process;p.getBuiltinModule("child_process").spawn("x",[]);', "escapes"],
    ['const {process:{getBuiltinModule:load}}=globalThis;load("child_process").spawn("x",[]);', "escapes"],
    ['function local(p=globalThis.process){p.getBuiltinModule("child_process").spawn("x",[]);}', "overridable parameter default"],
    ['export const nativeRoot=globalThis;', "escapes"],
    ['const load=global.process.getBuiltinModule.bind(global.process);load("child_process").spawn("x",[]);', "native loader"],
    ['globalThis.process.getBuiltinModule.call(globalThis.process,"child_process").spawn("x",[]);', "native loader"],
    ['globalThis.process.getBuiltinModule.apply(globalThis.process,["child_process"]).spawn("x",[]);', "native loader"],
    ['globalThis.process.getBuiltinModule("module")._load("child_process").spawn("x",[]);', "native loader"],
    ['globalThis.process.mainModule.constructor._load("child_process").spawn("x",[]);', "native loader"],
    ['import("node:process").then(p=>p.getBuiltinModule("child_process").spawn("x",[]));', "native loader promise"],
    ['const p=import("node:process");consume(p);', "escapes"],
    ['import {spawn} from "child_process"; spawn("x",[', "Unparsed source"],
  ])("refuses an unresolved or escaping child-process value: %s", (source, message) => {
    expect(scanSource("src/fixture.ts", source).errors.join("\n")).toContain(message);
  });

  it("gives repeated calls unique keys while keeping keys stable across line shifts", () => {
    const source = 'import {spawn} from "child_process"; function run(){spawn("x",[]); spawn("x",[]);}';
    const original = scanSource("src/fixture.ts", source).calls;
    expect(new Set(original.map((call) => call.callKey)).size).toBe(2);
    expect(scanSource("src/fixture.ts", "// shifted\n\n" + source).calls.map((call) => call.callKey)).toEqual(original.map((call) => call.callKey));
    expect(original.every((call) => call.symbol === "run")).toBe(true);
  });
});

describe("spawn policy conservation (#1778)", () => {
  const source = 'import {spawn} from "node:child_process"; function run(){spawn("tool",["--version"]);}';
  const sources = { "src/fixture.ts": source };
  const readSource = (path: string): string => { if (!(path in sources)) throw new Error("missing"); return sources[path as keyof typeof sources]; };
  const census = discoverSources(sources);
  it("accepts one specific audited policy per discovered call", () => { expect(validatePolicy(census, fixturePolicy(census), readSource)).toEqual([]); });
  it.each([
    ["new file", { ...sources, "src/new-module.mjs": 'import {execFile} from "child_process"; execFile("tool",[secret]);' }],
    ["same-file new call", { "src/fixture.ts": source + '\nspawn("second",[secret]);' }],
  ])("refuses an unreviewed call in a %s", (_label, changed) => {
    expect(validatePolicy(discoverSources(changed), fixturePolicy(census), readSource).join("\n")).toContain("Missing policy");
  });
  it("refuses stale rows and a narrowed walk even when its remaining call is valid", () => {
    const wider = discoverSources({ ...sources, "src/nested/second.js": source });
    expect(validatePolicy(census, fixturePolicy(wider), readSource).join("\n")).toContain("stale policy key");
  });
  it("refuses zero discovery, duplicate policies and duplicate discovered keys", () => {
    expect(validatePolicy(discoverSources({}), { schemaVersion: 1, sourceRoot: "src", entries: [] }, readSource)).toEqual(expect.arrayContaining(["Source discovery examined zero files", "Spawn discovery found zero calls"]));
    const policy = fixturePolicy(census); policy.entries.push(policy.entries[0]!);
    expect(validatePolicy(census, policy, readSource).join("\n")).toContain("duplicate policy key");
    expect(validatePolicy({ ...census, calls: [...census.calls, census.calls[0]!] }, fixturePolicy(census), readSource)).toContain("Duplicate discovered call keys");
  });
  it.each(["", "fixed toolchain binary", "No target-derived secrets are in scope", "Safe internal toolchain command with no target-derived secret"])("refuses a blank or generic reason: %j", (reason) => {
    const policy = fixturePolicy(census); policy.entries[0]!.reason = reason;
    expect(validatePolicy(census, policy, readSource).join("\n")).toContain("reason: expected a specific audited explanation");
  });
  it.each(["argvSource", "provenance", "falsifier"])("refuses missing %s", (field) => {
    const policy = fixturePolicy(census); delete (policy.entries[0]! as unknown as Record<string, unknown>)[field];
    expect(validatePolicy(census, policy, readSource).join("\n")).toContain(field);
  });
  it.each(["argvSource", "reason"] as const)("requires a real spawning-source snippet in %s in addition to prose", (field) => {
    const policy = fixturePolicy(census);
    policy.entries[0]![field] = "The argument construction is reviewed and has no source-derived inputs in this particular call.";
    expect(validatePolicy(census, policy, readSource).join("\n")).toContain(`${field}: expected a backticked snippet`);
    policy.entries[0]![field] += " The actual source reads `invented-helper-that-does-not-exist`.";
    expect(validatePolicy(census, policy, readSource).join("\n")).toContain(`${field}: expected a backticked snippet`);
  });
  it("invalidates reviewed source after an argv builder changes without changing the call key", () => {
    const before = discoverSources({ "src/fixture.ts": 'import {spawn} from "child_process"; const args=["--version"]; spawn("tool",args);' });
    const after = discoverSources({ "src/fixture.ts": 'import {spawn} from "child_process"; const args=[secret]; spawn("tool",args);' });
    expect(after.calls[0]!.callKey).toBe(before.calls[0]!.callKey);
    expect(validatePolicy(after, fixturePolicy(before), readSource).join("\n")).toContain("reviewedSourceSha256");
  });
  it("requires and validates transitive helper/data fingerprints", () => {
    const policy = fixturePolicy(census); const row = policy.entries[0]!;
    row.provenance.inputs = [{ path: "src/argv-builder.json", sourceSha256: sha256('["--version"]') }];
    const read = (path: string): string => path === "src/argv-builder.json" ? '["--version"]' : readSource(path);
    expect(validatePolicy(census, policy, read)).toEqual([]);
    expect(validatePolicy(census, policy, () => '["changed"]')).toContainEqual(expect.stringContaining("stale source fingerprint"));
    row.provenance.inputs[0]!.path = "../outside.json";
    expect(validatePolicy(census, policy, read).join("\n")).toContain("repository path");
    delete (row.provenance as unknown as Record<string, unknown>).inputs;
    expect(validatePolicy(census, policy, read).join("\n")).toContain("transitive argv input anchors");
  });
  it("binds guarded rows to real guard definitions and live named runtime tests", () => {
    const guardPath = "src/guard.ts", testPath = "src/guard.test.ts";
    const guard = 'export function assertArgvClean(args: string[]){if(args.includes("watched")) throw new Error("refused");}';
    const test = 'import {it,expect} from "vitest"; import {assertArgvClean} from "./guard"; it("refuses watched argv",()=>expect(()=>assertArgvClean(["watched"])).toThrow());';
    const read = (path: string): string => path === guardPath ? guard : path === testPath ? test : readSource(path);
    const policy = fixturePolicy(census); const row = policy.entries[0]!; row.disposition = "guarded";
    expect(validatePolicy(census, policy, read).join("\n")).toContain("owning runtime-test anchors");
    row.guard = { path: guardPath, symbol: "assertArgvClean", sourceSha256: sha256(guard) };
    row.runtimeTests = [{ path: testPath, name: "refuses watched argv", sourceSha256: sha256(test) }];
    expect(validatePolicy(census, policy, read)).toEqual([]);
    row.guard.symbol = "nonexistent";
    expect(validatePolicy(census, policy, read).join("\n")).toContain("production guard definition");
    row.guard.symbol = "assertArgvClean";
    row.runtimeTests[0]!.name = "does not exist";
    expect(validatePolicy(census, policy, read).join("\n")).toContain("existing runtime test");
    row.runtimeTests[0]!.name = "refuses watched argv";
    const skipped = test.replace('it("refuses', 'it.skip("refuses'); row.runtimeTests[0]!.sourceSha256 = sha256(skipped);
    expect(validatePolicy(census, policy, (path) => path === testPath ? skipped : read(path)).join("\n")).toContain("existing runtime test");
  });
  it.each(["skip", "skipIf(true)", "runIf(false)", "todo"])("does not accept an anchor hidden in describe.%s", (modifier) => {
    const source = `import {describe as suite,it as check} from "vitest"; suite.${modifier}("inactive",()=>{check("hidden",()=>{});}); check("ordinary",()=>{});`;
    expect(runtimeTestNames(source, "src/guard.test.ts")).toEqual(["ordinary"]);
  });
});

describe("spawn source walk (#1778)", () => {
  it.each(["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"])("requires policy for an actual new native-global loader file in .%s", (extension) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-global-spawn-walk-"));
    const base = 'import {spawn} from "child_process"; spawn("tool",["--version"]);';
    try {
      mkdirSync(join(root, "src"));
      writeFileSync(join(root, "src/base.ts"), base);
      const policy = fixturePolicy(discoverProduction(root));
      const path = `src/added.${extension}`;
      writeFileSync(join(root, path), 'const cp=globalThis.process.getBuiltinModule("node:child_process"); cp.spawn("tool",[fixtureSecret]);');
      const current = discoverProduction(root);
      expect(current.errors).toEqual([]);
      expect(current.calls.map((call) => call.path)).toContain(path);
      expect(validatePolicy(current, policy, repositoryReader(root)).join("\n")).toContain(`Missing policy for ${path}#`);
      writeFileSync(join(root, path), 'function local(globalThis){globalThis.process.getBuiltinModule("child_process").spawn("ordinary");}');
      expect(validatePolicy(discoverProduction(root), policy, repositoryReader(root))).toEqual([]);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("discovers nested production files in every JS/TS extension while excluding only tests, fixtures and declarations", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-spawn-walk-"));
    const included = ["src/root.ts", "src/new/nested.tsx", "src/module.mts", "src/module.cts", "src/browser.js", "src/view.jsx", "src/heavy-test-plan.mjs", "src/legacy.cjs"];
    const excluded = ["src/example.test.ts", "src/example.spec.mjs", "src/example.test-d.ts", "src/type.d.ts", "src/type.d.mts", "src/type.d.cts", "src/__tests__/x.ts", "src/tests/x.js", "src/fixtures/x.mjs", "src/__fixtures__/x.ts", "src/test-fixtures/x.cts", "src/node_modules/x.js", "src/readme.md"];
    try {
      for (const path of [...included, ...excluded]) { mkdirSync(dirname(join(root, path)), { recursive: true }); writeFileSync(join(root, path), 'import {spawn} from "child_process"; spawn("tool",["--version"]);'); }
      expect(productionPaths(root)).toEqual([...included].sort());
      const census = discoverProduction(root);
      expect(census.errors).toEqual([]);
      expect(census.calls.map((call) => call.path).sort()).toEqual([...included].sort());
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe("production spawn policy (#1778)", () => {
  it("conserves every discovered production call into an audited, source-bound policy row", () => {
    const census = discoverProduction(PROJECT_ROOT);
    const readSource = repositoryReader(PROJECT_ROOT);
    expect(census.errors, census.errors.join("\n")).toEqual([]);
    const policy: unknown = JSON.parse(readSource(POLICY_PATH));
    const errors = validatePolicy(census, policy, readSource);
    expect(errors, errors.join("\n")).toEqual([]);
  });
});
