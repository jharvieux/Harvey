// Deliberately bounded source proof. Unsupported verifier algorithms or caller control flow
// remain review candidates; a method/function name is never a cryptographic certificate.
import ts from "typescript";
import { collectPathAliases, resolveImport } from "../detectors/app-router.js";
import type { SourceInput } from "../detectors/common.js";
import type { EdgeFunctionSource } from "./supabase-config.js";

interface ResolvedFunction { path: string; sf: ts.SourceFile; fn: ts.FunctionDeclaration }
interface Proof { verifiedBeforeEffect: boolean; provenance: string }
type Input = "request" | "rawBody" | "signatureHeader" | "secret";

// This one supported algorithm is the source-evidenced AoP implementation at
// 956f1990, packages/shared/src/stripe.ts:25-70. Compare the complete runtime AST,
// including HMAC key/input, header extraction, rejection paths and comparison. An
// additional/changed statement, unresolved declaration, or altered input invalidates it.
const STRIPE_HMAC = `async function verify(rawBody, signatureHeader, secret, toleranceSeconds = 300, nowMs = Date.now()) {
  if (!signatureHeader) return false;
  const parts = {};
  for (const kv of signatureHeader.split(',')) {
    const [k, v] = kv.split('=');
    if (k && v) parts[k] = v;
  }
  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) return false;
  const timestampSeconds = Number(timestamp);
  if (!Number.isFinite(timestampSeconds)) return false;
  if (Math.abs(nowMs / 1000 - timestampSeconds) > toleranceSeconds) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signatureBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(\`\${timestamp}.\${rawBody}\`));
  const expected = Array.from(new Uint8Array(signatureBytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return timingSafeEqual(expected, v1);
}`;
const CONSTANT_TIME_COMPARE = `function compare(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}`;

function parse(path: string, text: string): ts.SourceFile {
  return ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
}

function runtimeShape(text: string): string {
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext } }).outputText;
  const fn = parse("proof.js", js).statements.find(ts.isFunctionDeclaration);
  if (!fn) return "";
  const shape = (node: ts.Node): unknown => {
    if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)
      || ts.isRegularExpressionLiteral(node) || ts.isTemplateLiteralToken(node)) return [node.kind, node.text];
    const children: unknown[] = [];
    ts.forEachChild(node, (child) => { children.push(shape(child)); });
    return [node.kind, children];
  };
  // Function names, export modifiers and types do not affect the proven algorithm.
  return JSON.stringify([fn.parameters.map(shape), fn.body ? shape(fn.body) : null]);
}
let stripeShape: string | undefined;
let compareShape: string | undefined;

class SourceGraph {
  readonly files: Map<string, SourceInput>;
  readonly paths: Set<string>;
  readonly aliases: ReturnType<typeof collectPathAliases>;
  constructor(sources: readonly SourceInput[]) {
    this.files = new Map(sources.map((source) => [source.path, source]));
    this.paths = new Set(this.files.keys());
    this.aliases = collectPathAliases([...sources]);
  }
  source(path: string): ts.SourceFile | undefined {
    const file = this.files.get(path);
    return file ? parse(file.path, file.text) : undefined;
  }
  importPath(from: string, specifier: string): string | undefined {
    const standard = resolveImport(from, specifier, this.paths, this.aliases);
    if (standard) return standard;
    const configs = [...this.files.values()].filter((file) => file.path === "deno.json" || file.path.endsWith("/deno.json"))
      .filter((file) => !file.path.includes("/") || from.startsWith(file.path.slice(0, file.path.lastIndexOf("/") + 1)))
      .sort((a, b) => b.path.length - a.path.length);
    for (const file of configs) {
      try {
        const mapped = (JSON.parse(file.text) as { imports?: Record<string, string> }).imports?.[specifier];
        if (mapped) return resolveImport(file.path, mapped, this.paths, this.aliases);
      } catch { /* Invalid configuration cannot establish provenance. */ }
    }
    return undefined;
  }
  resolve(path: string, name: string, exported = false, seen = new Set<string>()): ResolvedFunction | undefined {
    const key = `${path}:${name}:${exported}`;
    if (seen.has(key)) return undefined;
    seen.add(key);
    const sf = this.source(path);
    if (!sf) return undefined;
    for (const stmt of sf.statements) {
      if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === name && stmt.body
        && (!exported || stmt.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword))) {
        return { path, sf, fn: stmt };
      }
      if (!exported && ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)
        && stmt.importClause?.namedBindings && ts.isNamedImports(stmt.importClause.namedBindings)) {
        const item = stmt.importClause.namedBindings.elements.find((element) => element.name.text === name);
        const target = item ? this.importPath(path, stmt.moduleSpecifier.text) : undefined;
        if (item && target) return this.resolve(target, item.propertyName?.text ?? item.name.text, true, seen);
      }
      if (ts.isExportDeclaration(stmt) && stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
        const item = stmt.exportClause.elements.find((element) => element.name.text === name);
        if (!item) continue;
        const target = stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier) ? this.importPath(path, stmt.moduleSpecifier.text) : path;
        if (target) return this.resolve(target, item.propertyName?.text ?? item.name.text, Boolean(stmt.moduleSpecifier), seen);
      }
    }
    return undefined;
  }
}

function unwrapped(expr: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(expr) || ts.isAsExpression(expr) || ts.isNonNullExpression(expr)) expr = expr.expression;
  return expr;
}
function property(expr: ts.Expression, receiver: string, name: string): boolean {
  expr = unwrapped(expr);
  return ts.isPropertyAccessExpression(expr) && !expr.questionDotToken && ts.isIdentifier(expr.expression)
    && expr.expression.text === receiver && expr.name.text === name;
}
function fieldName(node: ts.PropertyName): string | undefined {
  return ts.isIdentifier(node) || ts.isStringLiteral(node) ? node.text : undefined;
}
function objectFields(object: ts.ObjectLiteralExpression): Map<string, ts.Expression> | undefined {
  const fields = new Map<string, ts.Expression>();
  for (const field of object.properties) {
    if (!ts.isPropertyAssignment(field) && !ts.isShorthandPropertyAssignment(field)) return undefined;
    const name = fieldName(field.name);
    if (!name || fields.has(name) || (ts.isShorthandPropertyAssignment(field) && field.objectAssignmentInitializer)) return undefined;
    fields.set(name, ts.isPropertyAssignment(field) ? field.initializer : field.name);
  }
  return fields;
}
function pureValue(expr: ts.Expression): boolean {
  expr = unwrapped(expr);
  if (ts.isStringLiteral(expr) || ts.isNumericLiteral(expr) || ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)
    || [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(expr.kind)) return true;
  if (ts.isIdentifier(expr)) return expr.text === "undefined";
  if (ts.isObjectLiteralExpression(expr)) return Boolean(objectFields(expr) && [...objectFields(expr)!.values()].every(pureValue));
  return false;
}

function requestInput(expr: ts.Expression, inputs: ReadonlyMap<string, Input>): Input | undefined {
  expr = unwrapped(expr);
  if (ts.isIdentifier(expr)) return inputs.get(expr.text);
  if (ts.isAwaitExpression(expr)) {
    const call = expr.expression;
    if (ts.isCallExpression(call) && call.arguments.length === 0 && ts.isPropertyAccessExpression(call.expression)
      && ts.isIdentifier(call.expression.expression) && inputs.get(call.expression.expression.text) === "request"
      && call.expression.name.text === "text" && !call.questionDotToken) return "rawBody";
    return undefined;
  }
  if (ts.isCallExpression(expr) && expr.arguments.length === 1 && ts.isStringLiteral(expr.arguments[0]!)) {
    if (ts.isPropertyAccessExpression(expr.expression) && expr.expression.name.text === "get"
      && ts.isPropertyAccessExpression(expr.expression.expression) && expr.expression.expression.name.text === "headers"
      && ts.isIdentifier(expr.expression.expression.expression) && inputs.get(expr.expression.expression.expression.text) === "request"
      && expr.arguments[0].text.toLowerCase() === "stripe-signature") return "signatureHeader";
    if (expr.expression.getText() === "Deno.env.get" && expr.arguments[0].text.length > 0) return "secret";
  }
  if (ts.isPropertyAccessExpression(expr) && expr.expression.getText() === "process.env") return "secret";
  return undefined;
}

function constantDeclaration(stmt: ts.Statement): ts.VariableDeclaration | undefined {
  if (!ts.isVariableStatement(stmt) || !(stmt.declarationList.flags & ts.NodeFlags.Const)
    || stmt.declarationList.declarations.length !== 1) return undefined;
  return stmt.declarationList.declarations[0];
}

function bindingContains(node: ts.Node, names: ReadonlySet<string>): boolean {
  if (ts.isIdentifier(node)) return names.has(node.text);
  return ts.forEachChild(node, (child) => bindingContains(child, names)) ?? false;
}

function provenVerifier(graph: SourceGraph, resolved: ResolvedFunction): boolean {
  if (runtimeShape(resolved.fn.getText(resolved.sf)) !== (stripeShape ??= runtimeShape(STRIPE_HMAC))) return false;
  const comparator = graph.resolve(resolved.path, "timingSafeEqual");
  if (!comparator || runtimeShape(comparator.fn.getText(comparator.sf)) !== (compareShape ??= runtimeShape(CONSTANT_TIME_COMPARE))) return false;
  // A local/imported replacement of a platform primitive, verifier or comparator is unresolved.
  const protectedNames = new Set(["crypto", "TextEncoder", "Uint8Array", "Array", "Math", "Number", "Date", "timingSafeEqual", resolved.fn.name!.text]);
  let unsafe = false;
  const visit = (node: ts.Node) => {
    if (node === resolved.fn || (ts.isFunctionDeclaration(node) && node.name?.text === "timingSafeEqual" && node.pos === comparator.fn.pos)) return;
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isImportSpecifier(node)
      || ts.isImportClause(node) || ts.isNamespaceImport(node) || ts.isFunctionDeclaration(node)) && node.name && bindingContains(node.name, protectedNames)) unsafe = true;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
      let target: ts.Expression = node.left;
      while (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) target = target.expression;
      if (ts.isIdentifier(target) && protectedNames.has(target.text)) unsafe = true;
    }
    ts.forEachChild(node, visit);
  };
  if (resolved.sf.statements.some(ts.isExpressionStatement)) unsafe = true;
  visit(resolved.sf);
  if (comparator.path !== resolved.path) return false;
  return !unsafe;
}

function provesHelper(graph: SourceGraph, helper: ResolvedFunction): boolean {
  const { fn } = helper;
  const parameter = fn.parameters[0];
  if (fn.parameters.length !== 1 || !parameter || !ts.isIdentifier(parameter.name) || parameter.initializer
    || !fn.body || fn.body.statements.length < 2) return false;
  const declared = constantDeclaration(fn.body.statements[0]!);
  if (!declared || !ts.isIdentifier(declared.name) || !declared.initializer || !ts.isAwaitExpression(declared.initializer)
    || !ts.isCallExpression(declared.initializer.expression)) return false;
  const parameterName = parameter.name.text;
  const verify = declared.initializer.expression;
  if (!ts.isIdentifier(verify.expression) || verify.expression.text === parameter.name.text || verify.questionDotToken
    || verify.arguments.length < 3 || verify.arguments.length > 5) return false;
  if (!["rawBody", "signatureHeader", "secret"].every((name, i) => property(verify.arguments[i]!, parameterName, name))) return false;
  // Only omitted/default tolerance and time are covered by the source certificate.
  if (verify.arguments[3] && (!ts.isIdentifier(verify.arguments[3]) || verify.arguments[3].text !== "undefined")) return false;
  if (verify.arguments[4] && !(ts.isIdentifier(verify.arguments[4]) && verify.arguments[4].text === "undefined")
    && !property(verify.arguments[4], parameterName, "nowMs")) return false;
  const guard = fn.body.statements[1]!;
  if (!ts.isIfStatement(guard) || guard.elseStatement || !ts.isPrefixUnaryExpression(guard.expression)
    || guard.expression.operator !== ts.SyntaxKind.ExclamationToken || !ts.isIdentifier(guard.expression.operand)
    || guard.expression.operand.text !== declared.name.text) return false;
  const rejection = ts.isBlock(guard.thenStatement) && guard.thenStatement.statements.length === 1
    ? guard.thenStatement.statements[0] : guard.thenStatement;
  if (!rejection || !ts.isReturnStatement(rejection) || (rejection.expression && !pureValue(rejection.expression))) return false;
  const verifier = graph.resolve(helper.path, verify.expression.text);
  return Boolean(verifier && provenVerifier(graph, verifier));
}

function provesCaller(fn: ts.FunctionLikeDeclaration, call: ts.CallExpression): boolean {
  if (!fn.body || !ts.isBlock(fn.body) || fn.parameters.length !== 1 || !ts.isIdentifier(fn.parameters[0]!.name)) return false;
  const inputs = new Map<string, Input>([[fn.parameters[0]!.name.text, "request"]]);
  if (ts.isIdentifier(call.expression) && inputs.has(call.expression.text)) return false;
  const guardedSecrets = new Set<string>();
  for (const stmt of fn.body.statements) {
    if (ts.isReturnStatement(stmt) && stmt.expression) {
      const returned = ts.isAwaitExpression(stmt.expression) ? stmt.expression.expression : stmt.expression;
      if (returned !== call || call.arguments.length !== 1 || !ts.isObjectLiteralExpression(call.arguments[0]!)) return false;
      const fields = objectFields(call.arguments[0]);
      const secret = fields?.get("secret");
      if (!secret || !ts.isIdentifier(secret) || !guardedSecrets.has(secret.text)) return false;
      if (!fields || fields.has("nowMs") || !["rawBody", "signatureHeader", "secret"].every((name) => fields.has(name) && requestInput(fields.get(name)!, inputs) === name)) return false;
      return [...fields].every(([name, expr]) => ["rawBody", "signatureHeader", "secret"].includes(name) || pureValue(expr));
    }
    if (ts.isIfStatement(stmt) && !stmt.elseStatement && ts.isPrefixUnaryExpression(stmt.expression)
      && stmt.expression.operator === ts.SyntaxKind.ExclamationToken && ts.isIdentifier(stmt.expression.operand)
      && inputs.get(stmt.expression.operand.text) === "secret") {
      const exit = ts.isBlock(stmt.thenStatement) && stmt.thenStatement.statements.length === 1 ? stmt.thenStatement.statements[0] : stmt.thenStatement;
      const rejects = exit && ((ts.isReturnStatement(exit) && (!exit.expression || pureValue(exit.expression)))
        || (ts.isThrowStatement(exit) && ts.isNewExpression(exit.expression) && ts.isIdentifier(exit.expression.expression)
          && exit.expression.expression.text === "Error" && exit.expression.arguments?.every(pureValue)));
      if (!rejects) return false;
      guardedSecrets.add(stmt.expression.operand.text);
      continue;
    }
    const declaration = constantDeclaration(stmt);
    if (!declaration || !ts.isIdentifier(declaration.name) || inputs.has(declaration.name.text) || !declaration.initializer) return false;
    const value = requestInput(declaration.initializer, inputs);
    if (!value) return false;
    inputs.set(declaration.name.text, value);
  }
  return false;
}

export function assessWebhookVerification(handler: EdgeFunctionSource, projectSources: readonly SourceInput[]): Proof {
  const path = handler.path ?? `${handler.name}.ts`;
  const graph = new SourceGraph([...projectSources.filter((source) => source.path !== path), { path, text: handler.content }]);
  const sf = graph.source(path)!;
  let overriddenPlatform = false;
  const platformNames = new Set(["Deno", "process", "Error"]);
  const inspectBinding = (node: ts.Node) => {
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isFunctionDeclaration(node) || ts.isImportSpecifier(node)
      || ts.isImportClause(node) || ts.isNamespaceImport(node)) && node.name && bindingContains(node.name, platformNames)) overriddenPlatform = true;
    ts.forEachChild(node, inspectBinding);
  };
  inspectBinding(sf);
  const assessments: (Proof & { caller?: ts.Node })[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.arguments.some((arg) => ts.isObjectLiteralExpression(arg)
      && ["rawBody", "signatureHeader", "secret"].every((name) => objectFields(arg)?.has(name)))) {
      let enclosing: ts.Node | undefined = node.parent;
      while (enclosing && !ts.isFunctionDeclaration(enclosing) && !ts.isArrowFunction(enclosing) && !ts.isFunctionExpression(enclosing)) enclosing = enclosing.parent;
      const helper = graph.resolve(path, node.expression.text);
      const proved = Boolean(helper && enclosing && provesCaller(enclosing as ts.FunctionLikeDeclaration, node) && provesHelper(graph, helper));
      assessments.push({ caller: enclosing, verifiedBeforeEffect: proved, provenance: `called ${node.expression.text}(rawBody, signatureHeader, secret)${helper ? `, resolved to ${helper.path}; signature verification ${proved ? "guards and precedes every effect in the supported caller and helper" : "does not provably guard and precede every effect with the actual request inputs and an evidenced verifier"}` : ", but the import or verifier implementation could not be resolved"}` });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  // Multiple entry points/calls require separate proof; no verified sibling can clear another.
  const entryFunctions = sf.statements.filter((stmt) => ts.isFunctionDeclaration(stmt)
    && stmt.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
  const hasOtherEntry = sf.statements.some((stmt) => ts.isExportAssignment(stmt)
    || (ts.isVariableStatement(stmt) && stmt.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword))
    || ts.isExpressionStatement(stmt));
  const proved = !overriddenPlatform && !hasOtherEntry && assessments.length === 1 && assessments[0]!.verifiedBeforeEffect && entryFunctions.length === 1 && assessments[0]!.caller === entryFunctions[0];
  return { verifiedBeforeEffect: proved, provenance: assessments.map((assessment) => assessment.provenance).join("; ") || "Imported verification provenance was not proved; no supported request-to-verifier call was resolved" };
}
