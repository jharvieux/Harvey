import { posix } from "node:path";
import ts from "typescript";
import type { CensusFile } from "./environment-dependency-census-discovery.js";

type Scope = { values: Map<string, unknown>; parent?: Scope; file: CensusFile };
type Closure = { node: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression; scope: Scope };
export interface CensusSourceRecord { value: Record<string, unknown>; file: CensusFile; node: ts.Node }

/** Interpret only the finite data-construction grammar used by the registry. No module is executed. */
export function censusSourceRecords(files: Map<string, CensusFile>, path: string, symbol: string): CensusSourceRecord[] {
  const scopes = new Map<string, Scope>();
  const closures = new WeakMap<object, Closure>();
  const origins = new WeakMap<object, { file: CensusFile; node: ts.Node }>();
  const resolving = new Set<string>();
  let remaining = 250_000;
  const fail = (node: ts.Node, message: string): never => { throw new Error(`environment census: unresolved registry construction ${node.getSourceFile().fileName}:${node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1}: ${message}`); };
  const tick = (node: ts.Node): void => { if (--remaining < 0) fail(node, "finite data-construction budget exhausted"); };
  const scopeFor = (sourcePath: string): Scope => {
    const found = scopes.get(sourcePath); if (found) return found;
    const file = files.get(sourcePath);
    if (!file?.source) throw new Error(`environment census: unresolved registry source ${sourcePath}`);
    for (const statement of file.source.statements) {
      // An admission guard that can only throw does not construct additional registry members.
      if (ts.isIfStatement(statement) && !statement.elseStatement && ts.isBlock(statement.thenStatement) && statement.thenStatement.statements.every(ts.isThrowStatement)) {
        let effect = false;
        const inspect = (node: ts.Node): void => { if (ts.isCallExpression(node) || ts.isNewExpression(node) || ts.isBinaryExpression(node) && (node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment)) effect = true; ts.forEachChild(node, inspect); };
        inspect(statement.expression);
        if (!effect) continue;
      }
      if (ts.isExpressionStatement(statement) || ts.isForOfStatement(statement) || ts.isIfStatement(statement)) fail(statement, "top-level effects are outside the registry grammar");
    }
    const scope = { values: new Map<string, unknown>(), file }; scopes.set(sourcePath, scope); return scope;
  };
  const own = (value: unknown, key: string, node: ts.Node): unknown => {
    if (key === "__proto__" || key === "constructor" || key === "prototype") return fail(node, "prototype access is outside the registry grammar");
    if (value !== null && typeof value === "object") return Object.hasOwn(value, key) ? (value as Record<string, unknown>)[key] : undefined;
    return fail(node, "property receiver is not registry data");
  };
  const bind = (name: ts.BindingName, value: unknown, scope: Scope): void => {
    if (ts.isIdentifier(name)) { scope.values.set(name.text, value); return; }
    if (ts.isObjectBindingPattern(name)) {
      for (const part of name.elements) {
        if (part.dotDotDotToken || part.initializer) fail(part, "rest/default binding is not modeled");
        const key = part.propertyName?.getText().replace(/^["']|["']$/g, "") ?? part.name.getText();
        bind(part.name, own(value, key, part), scope);
      }
      return;
    }
    fail(name, "binding shape is not modeled");
  };
  const closure = (node: Closure["node"], scope: Scope): object => { const marker = {}; closures.set(marker, { node, scope }); return marker; };
  const lookup = (name: string, scope: Scope, at: ts.Node): unknown => {
    if (scope.values.has(name)) return scope.values.get(name);
    if (scope.parent) return lookup(name, scope.parent, at);
    if (name === "undefined") return undefined;
    const key = `${scope.file.path}#${name}`;
    if (resolving.has(key)) return fail(at, `cyclic declaration ${key}`);
    resolving.add(key);
    try {
      for (const statement of scope.file.source!.statements) {
        if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
          const value = closure(statement, scope); scope.values.set(name, value); return value;
        }
        if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) if (ts.isIdentifier(declaration.name) && declaration.name.text === name) {
          if (!(statement.declarationList.flags & ts.NodeFlags.Const) || !declaration.initializer) return fail(declaration, "registry globals must be initialized constants");
          const value = evaluate(declaration.initializer, scope); scope.values.set(name, value); return value;
        }
        if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && !statement.importClause?.isTypeOnly && statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings)) {
          const imported = statement.importClause.namedBindings.elements.find((e) => e.name.text === name && !e.isTypeOnly);
          if (!imported) continue;
          if (!statement.moduleSpecifier.text.startsWith(".")) return fail(statement, "external imports cannot construct registry data");
          const next = posix.normalize(posix.join(posix.dirname(scope.file.path), statement.moduleSpecifier.text)).replace(/\.js$/, ".ts");
          const value = lookup(imported.propertyName?.text ?? imported.name.text, scopeFor(next), imported); scope.values.set(name, value); return value;
        }
      }
      return fail(at, `unresolved declaration ${key}`);
    } finally { resolving.delete(key); }
  };
  const statements = (nodes: readonly ts.Statement[], scope: Scope): { value: unknown } | undefined => {
    for (const node of nodes) {
      tick(node);
      if (ts.isVariableStatement(node)) {
        if (!(node.declarationList.flags & ts.NodeFlags.Const)) fail(node, "factory locals must be constants");
        for (const declaration of node.declarationList.declarations) bind(declaration.name, declaration.initializer ? evaluate(declaration.initializer, scope) : undefined, scope);
      } else if (ts.isReturnStatement(node)) return { value: node.expression ? evaluate(node.expression, scope) : undefined };
      else if (ts.isExpressionStatement(node)) evaluate(node.expression, scope);
      else if (ts.isForOfStatement(node)) {
        if (node.awaitModifier || !ts.isVariableDeclarationList(node.initializer) || !(node.initializer.flags & ts.NodeFlags.Const) || node.initializer.declarations.length !== 1) fail(node, "only finite const for-of data loops are modeled");
        const list = evaluate(node.expression, scope);
        if (!Array.isArray(list)) fail(node, "for-of input must be finite data");
        for (const value of list as unknown[]) {
          const child: Scope = { values: new Map(), parent: scope, file: scope.file };
          bind((node.initializer as ts.VariableDeclarationList).declarations[0]!.name, value, child);
          const returned = statements(ts.isBlock(node.statement) ? node.statement.statements : [node.statement], child);
          if (returned) return returned;
        }
      } else return fail(node, `statement ${ts.SyntaxKind[node.kind]} is not modeled`);
    }
    return undefined;
  };
  const invoke = (value: unknown, args: unknown[], at: ts.Node): unknown => {
    const fn = value && typeof value === "object" ? closures.get(value) : undefined;
    if (!fn || !fn.node.body) return fail(at, "only source-local data factories may be called");
    if (fn.node.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) || fn.node.asteriskToken) return fail(at, "async/generator factories are not modeled");
    const scope: Scope = { values: new Map(), parent: fn.scope, file: fn.scope.file };
    fn.node.parameters.forEach((p, i) => { if (p.dotDotDotToken || p.initializer) fail(p, "factory rest/default parameters are not modeled"); bind(p.name, args[i], scope); });
    return ts.isBlock(fn.node.body) ? statements(fn.node.body.statements, scope)?.value : evaluate(fn.node.body, scope);
  };
  const evaluate = (node: ts.Expression, scope: Scope): unknown => {
    tick(node);
    if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) return evaluate(node.expression, scope);
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (ts.isIdentifier(node)) return lookup(node.text, scope, node);
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return closure(node, scope);
    if (ts.isObjectLiteralExpression(node)) {
      const data: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const property of node.properties) {
        if (ts.isSpreadAssignment(property)) {
          const value = evaluate(property.expression, scope);
          if (!value || typeof value !== "object" || Array.isArray(value) || closures.has(value)) fail(property, "object spread input must be registry data");
          Object.assign(data, value);
        } else if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) {
          if (ts.isComputedPropertyName(property.name)) fail(property, "computed property is not modeled");
          const key = property.name.getText().replace(/^["']|["']$/g, "");
          if (["__proto__", "constructor", "prototype"].includes(key)) fail(property, "prototype property is outside the registry grammar");
          data[key] = ts.isPropertyAssignment(property) ? evaluate(property.initializer, scope) : lookup(property.name.text, scope, property);
        } else fail(property, "object method/accessor is not registry data");
      }
      origins.set(data, { file: scope.file, node }); return data;
    }
    if (ts.isArrayLiteralExpression(node)) {
      const data: unknown[] = [];
      for (const entry of node.elements) {
        const value = evaluate(ts.isSpreadElement(entry) ? entry.expression : entry, scope);
        if (ts.isSpreadElement(entry)) { if (!Array.isArray(value)) fail(entry, "array spread input must be finite data"); data.push(...value as unknown[]); }
        else data.push(value);
      }
      return data;
    }
    if (ts.isTemplateExpression(node)) return node.head.text + node.templateSpans.map((span) => {
      const value = evaluate(span.expression, scope);
      if (value !== null && typeof value === "object") fail(span, "template substitution must be scalar");
      return String(value) + span.literal.text;
    }).join("");
    if (ts.isConditionalExpression(node)) return evaluate(evaluate(node.condition, scope) ? node.whenTrue : node.whenFalse, scope);
    if (ts.isPropertyAccessExpression(node)) return own(evaluate(node.expression, scope), node.name.text, node);
    if (ts.isElementAccessExpression(node)) {
      const key = evaluate(node.argumentExpression, scope);
      if (typeof key !== "string" && typeof key !== "number") return fail(node, "element key must be scalar");
      return own(evaluate(node.expression, scope), String(key), node);
    }
    if (ts.isBinaryExpression(node)) {
      const left = evaluate(node.left, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) return left ?? evaluate(node.right, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) return left || evaluate(node.right, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return left && evaluate(node.right, scope);
      const right = evaluate(node.right, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) return left === right;
      if (node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) return left !== right;
      if (node.operatorToken.kind === ts.SyntaxKind.PlusToken && typeof left === "string" && typeof right === "string") return left + right;
      return fail(node, "binary operation is not modeled");
    }
    if (ts.isCallExpression(node)) {
      if (ts.isPropertyAccessExpression(node.expression)) {
        const receiver = evaluate(node.expression.expression, scope); const method = node.expression.name.text;
        if (typeof receiver === "string" && method === "replace" && node.arguments.length === 2 && ts.isRegularExpressionLiteral(node.arguments[0]!)) {
          // Prefix removal is sufficient for current IDs; arbitrary regex execution is not admitted.
          const prefix = node.arguments[0]!.getText().match(/^\/\^([A-Za-z0-9_-]+)\/$/)?.[1];
          const replacement = evaluate(node.arguments[1]!, scope);
          if (!prefix || typeof replacement !== "string") return fail(node, "only literal anchored-prefix replacement is modeled");
          return receiver.startsWith(prefix) ? replacement + receiver.slice(prefix.length) : receiver;
        }
        const args = node.arguments.map((arg) => evaluate(arg, scope));
        if (typeof receiver === "string" && method === "toUpperCase" && !args.length) return receiver.toUpperCase();
        if (Array.isArray(receiver)) {
          if (method === "map" || method === "flatMap") {
            const mapped = receiver.map((value, index) => invoke(args[0], [value, index, receiver], node));
            return method === "flatMap" ? mapped.flat() : mapped;
          }
          if (method === "push") return receiver.push(...args);
          if (method === "join" && args.length <= 1 && args.every((v) => typeof v === "string") && receiver.every((v) => ["string", "number", "boolean"].includes(typeof v))) return receiver.join(args[0] as string | undefined);
        }
        return fail(node, `method ${method} is not modeled`);
      }
      return invoke(evaluate(node.expression, scope), node.arguments.map((arg) => evaluate(arg, scope)), node);
    }
    return fail(node, `expression ${ts.SyntaxKind[node.kind]} is not modeled`);
  };
  const scope = scopeFor(path);
  const value = lookup(symbol, scope, scope.file.source!);
  if (!Array.isArray(value) || !value.length) throw new Error(`environment census: registry ${path}#${symbol} is not a nonempty array`);
  return value.map((entry) => {
    const origin = entry && typeof entry === "object" && !Array.isArray(entry) ? origins.get(entry) : undefined;
    if (!origin) throw new Error(`environment census: registry ${path}#${symbol} contains an unresolved record`);
    return { value: entry as Record<string, unknown>, ...origin };
  });
}
