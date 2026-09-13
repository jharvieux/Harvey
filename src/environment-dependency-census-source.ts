import { posix } from "node:path";
import ts from "typescript";
import type { CensusFile } from "./environment-dependency-census-discovery.js";

type Scope = { values: Map<string, unknown>; pending: Set<string>; parent?: Scope; file: CensusFile };
type Closure = { node: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression; scope: Scope };
export interface CensusSourceRecord { value: Record<string, unknown>; file: CensusFile; node: ts.Node }
export interface CensusImportBoundary { file: CensusFile; node: ts.Node; dependency: string }

/** Interpret only the finite data-construction grammar used by the registry. No module is executed. */
export function censusSourceRecords(files: Map<string, CensusFile>, path: string, symbol: string, boundary?: (record: CensusImportBoundary) => void): CensusSourceRecord[] {
  const scopes = new Map<string, Scope>();
  const moduleOrder: Scope[] = [];
  const initializationPositions = new WeakMap<ts.Node, number>();
  const moduleConstants = new WeakMap<Scope, Map<string, ts.VariableDeclaration>>();
  const relativeBindings = new WeakMap<Scope, Map<string, { scope: Scope; name: string }>>();
  let initializing: number | null = null;
  const closures = new WeakMap<object, Closure>();
  const origins = new WeakMap<object, { file: CensusFile; node: ts.Node }>();
  const resolving = new Set<string>();
  let remaining = 250_000;
  let mutationAllowed = true;
  const independentArrays = new WeakSet<unknown[]>();
  let construction: object | null = null;
  const localArrays = new WeakMap<unknown[], object>();
  const builtins = new WeakMap<object, string>();
  const snapshotPaths = new WeakMap<object, { path: string; kind: "module-url" | "source-url" | "opaque-path" }>();
  const importGuards = new WeakSet<ts.Node>();
  const fail = (node: ts.Node, message: string): never => { throw new Error(`environment census: unresolved registry construction ${node.getSourceFile().fileName}:${node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1}: ${message}`); };
  const tick = (node: ts.Node): void => { if (--remaining < 0) fail(node, "finite data-construction budget exhausted"); };
  const modulePath = (file: CensusFile, specifier: string): string => posix.normalize(posix.join(posix.dirname(file.path), specifier)).replace(/\.js$/, ".ts");
  const builtin = (key: string): object => { const value = {}; builtins.set(value, key); return value; };
  const snapshotPath = (name: string, kind: "module-url" | "source-url" | "opaque-path"): object => { const value = {}; snapshotPaths.set(value, { path: name, kind }); return value; };
  const isOpaque = (value: unknown): boolean => !!value && typeof value === "object" && (snapshotPaths.has(value) || builtins.has(value));
  const known = (value: unknown, at: ts.Node): unknown => { if (isOpaque(value)) fail(at, "unknown semantic value at an import boundary"); return value; };
  const inertOnly = (at: ts.Node): void => { if (mutationAllowed) fail(at, "native metadata cannot determine registry membership"); };
  const shadows = (name: string, file: CensusFile): boolean => file.source!.statements.some((s) => {
    if (ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) return s.name?.text === name;
    if (ts.isVariableStatement(s)) return s.declarationList.declarations.some((d) => ts.isIdentifier(d.name) && d.name.text === name);
    if (!ts.isImportDeclaration(s) || s.importClause?.isTypeOnly) return false;
    const clause = s.importClause;
    return clause?.name?.text === name || !!clause?.namedBindings && (ts.isNamespaceImport(clause.namedBindings) ? clause.namedBindings.name.text === name : clause.namedBindings.elements.some((e) => !e.isTypeOnly && e.name.text === name));
  });
  const hasDecorator = (node: ts.Node): boolean => ts.isDecorator(node) || !!ts.forEachChild(node, (child) => hasDecorator(child) || undefined);
  const reserveBinding = (name: ts.Identifier, names: Set<string>): void => {
    if (names.has(name.text)) fail(name, `duplicate lexical binding ${name.text}; ambiguous value declarations are outside the registry grammar`);
    names.add(name.text);
  };
  const reservePattern = (name: ts.BindingName, names: Set<string>): void => {
    if (ts.isIdentifier(name)) reserveBinding(name, names);
    else for (const element of name.elements) if (!ts.isOmittedExpression(element)) reservePattern(element.name, names);
  };
  const checkParameters = (node: ts.Node): void => {
    if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) && node.body) {
      const names = new Set<string>();
      for (const parameter of node.parameters) if (!ts.isIdentifier(parameter.name) || parameter.name.text !== "this") reservePattern(parameter.name, names);
    }
    ts.forEachChild(node, checkParameters);
  };
  const scopeFor = (sourcePath: string): Scope => {
    const found = scopes.get(sourcePath); if (found) return found;
    const file = files.get(sourcePath);
    if (!file?.source || file.gitMode === "120000" || file.gitMode === "160000") throw new Error(`environment census: unresolved registry source ${sourcePath}`);
    const names = new Set<string>();
    checkParameters(file.source);
    for (const statement of file.source.statements) {
      // Type-only names and overload signatures are erased; runtime declarations share one table.
      if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) reservePattern(declaration.name, names);
      if ((ts.isFunctionDeclaration(statement) && statement.body || ts.isClassDeclaration(statement)) && statement.name && !statement.modifiers?.some((m) => m.kind === ts.SyntaxKind.DeclareKeyword)) reserveBinding(statement.name, names);
      if (ts.isImportDeclaration(statement) && statement.importClause && !statement.importClause.isTypeOnly) {
        const clause = statement.importClause;
        if (clause.name) reserveBinding(clause.name, names);
        if (clause.namedBindings) {
          if (ts.isNamespaceImport(clause.namedBindings)) reserveBinding(clause.namedBindings.name, names);
          else for (const binding of clause.namedBindings.elements) if (!binding.isTypeOnly) reserveBinding(binding.name, names);
        }
      }
      const throwGuard = ts.isIfStatement(statement) && !statement.elseStatement && ts.isBlock(statement.thenStatement) && statement.thenStatement.statements.length === 1 && ts.isThrowStatement(statement.thenStatement.statements[0]!);
      // Only this exact main-entry guard is false when this dependency is imported. It is not
      // a license to discard arbitrary conditional initialization or a shadowed process value.
      const entryGuard = sourcePath !== path && ts.isIfStatement(statement) && !statement.elseStatement && statement.expression.getText().replace(/\s/g, "") === 'import.meta.url===`file://${process.argv[1]}`' && !shadows("process", file);
      if (entryGuard) { importGuards.add(statement); boundary?.({ file, node: statement, dependency: "standalone-entry-point" }); }
      const inertClass = ts.isClassDeclaration(statement) && !hasDecorator(statement) && !statement.members.some((m) => ts.isClassStaticBlockDeclaration(m) || ts.canHaveModifiers(m) && ts.getModifiers(m)?.some((v) => v.kind === ts.SyntaxKind.StaticKeyword) || m.name && ts.isComputedPropertyName(m.name)) && (!statement.heritageClauses?.length || statement.heritageClauses.length === 1 && statement.heritageClauses[0]!.token === ts.SyntaxKind.ExtendsKeyword && statement.heritageClauses[0]!.types.length === 1 && statement.heritageClauses[0]!.types[0]!.expression.getText() === "Error" && !shadows("Error", file));
      const inertDeclaration = ts.isImportDeclaration(statement) || ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement) || ts.isFunctionDeclaration(statement) || ts.isEmptyStatement(statement) || ts.isExportDeclaration(statement) && statement.isTypeOnly || inertClass;
      if (!inertDeclaration && !ts.isVariableStatement(statement) && !throwGuard && !entryGuard) fail(statement, "top-level effects are outside the registry grammar");
    }
    const scope: Scope = { values: new Map(), pending: new Set(), file }; scopes.set(sourcePath, scope);
    // Value imports initialize their modules even when their imported binding is unused.
    // Walk the entire committed relative graph before resolving any selected declaration.
    for (const statement of file.source.statements) if (ts.isImportDeclaration(statement)) {
      const clause = statement.importClause;
      if (clause?.isTypeOnly || clause?.namedBindings && ts.isNamedImports(clause.namedBindings) && !clause.name && clause.namedBindings.elements.length > 0 && clause.namedBindings.elements.every((e) => e.isTypeOnly)) continue;
      if (!ts.isStringLiteral(statement.moduleSpecifier)) fail(statement, "nonliteral import is not modeled");
      const specifier = (statement.moduleSpecifier as ts.StringLiteral).text;
      if (specifier.startsWith(".")) {
        const imported = scopeFor(modulePath(file, specifier));
        if (clause?.name) fail(statement, "relative default imports are outside the registry grammar");
        if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) for (const binding of clause.namedBindings.elements) {
          if (binding.isTypeOnly) continue;
          const name = binding.propertyName?.text ?? binding.name.text;
          const exported = imported.file.source!.statements.some((s) => ts.canHaveModifiers(s) && ts.getModifiers(s)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) && !ts.getModifiers(s)?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword) && (ts.isFunctionDeclaration(s) && s.name?.text === name || ts.isClassDeclaration(s) && s.name?.text === name || ts.isVariableStatement(s) && s.declarationList.declarations.some((d) => ts.isIdentifier(d.name) && d.name.text === name)));
          if (!exported) fail(binding, `unresolved value import ${name} from ${imported.file.path}`);
        }
      } else boundary?.({ file, node: statement, dependency: specifier });
    }
    // Synchronous value dependencies initialize in depth-first postorder. Back edges share
    // an instantiated scope; readiness below distinguishes eager from deferred cyclic reads.
    moduleOrder.push(scope);
    return scope;
  };
  const propertyKey = (name: ts.Node): string => {
    // AST text decodes escapes; numeric literals use JavaScript's canonical string key.
    const key = ts.isIdentifier(name) || ts.isStringLiteral(name) ? name.text : ts.isNumericLiteral(name) ? String(Number(name.text)) : fail(name, `property name ${ts.SyntaxKind[name.kind]} is not modeled`);
    if (["__proto__", "constructor", "prototype"].includes(key)) fail(name, "prototype property is outside the registry grammar");
    return key;
  };
  const own = (value: unknown, key: string, node: ts.Node): unknown => {
    if (key === "__proto__" || key === "constructor" || key === "prototype") return fail(node, "prototype access is outside the registry grammar");
    if (value instanceof Set) {
      if (key === "size") { if ([...value].some(isOpaque)) fail(node, "unknown semantic Set membership at an import boundary"); return value.size; }
      return fail(node, `Set property ${key} is not modeled`);
    }
    if (value instanceof RegExp) {
      if (key === "source") return value.source;
      return fail(node, `RegExp property ${key} is not modeled`);
    }
    if (value && typeof value === "object" && closures.has(value)) return fail(node, "function properties are outside the registry grammar");
    if (value && typeof value === "object" && snapshotPaths.has(value)) {
      if (key === "pathname" && snapshotPaths.get(value)!.kind === "source-url") return snapshotPath(snapshotPaths.get(value)!.path, "opaque-path");
      return fail(node, `snapshot location property ${key} is not modeled`);
    }
    if (value && typeof value === "object" && builtins.has(value)) {
      const keyPath = `${builtins.get(value)}.${key}`;
      return builtin(keyPath);
    }
    if (value !== null && typeof value === "object") {
      if (Object.hasOwn(value, key)) return (value as Record<string, unknown>)[key];
      if (key in Object.prototype || Array.isArray(value) && key in Array.prototype) return fail(node, `inherited property ${key} is not modeled`);
      return undefined;
    }
    return fail(node, "property receiver is not registry data");
  };
  const bind = (name: ts.BindingName, value: unknown, scope: Scope): void => {
    if (ts.isIdentifier(name)) { scope.values.set(name.text, value); scope.pending.delete(name.text); return; }
    if (ts.isObjectBindingPattern(name)) {
      for (const part of name.elements) {
        if (part.dotDotDotToken || part.initializer) fail(part, "rest/default binding is not modeled");
        const key = propertyKey(part.propertyName ?? part.name);
        bind(part.name, own(value, key, part), scope);
      }
      return;
    }
    fail(name, "binding shape is not modeled");
  };
  const declareLocal = (name: ts.BindingName, scope: Scope): void => {
    if (ts.isIdentifier(name)) {
      if (scope.values.has(name.text)) fail(name, `duplicate lexical binding ${name.text}`);
      reserveBinding(name, scope.pending); return;
    }
    if (ts.isObjectBindingPattern(name)) { for (const part of name.elements) declareLocal(part.name, scope); return; }
    fail(name, "binding shape is not modeled");
  };
  const ready = (name: string, scope: Scope, at: ts.Node): void => {
    if (scope.pending.has(name)) fail(at, `lexical binding ${name} read before initialization`);
    const imported = relativeBindings.get(scope)?.get(name);
    if (imported) { ready(imported.name, imported.scope, at); return; }
    const declaration = moduleConstants.get(scope)?.get(name);
    if (declaration && initializing !== null && initializationPositions.get(declaration)! >= initializing) fail(at, `lexical binding ${scope.file.path}#${name} read before initialization`);
  };
  const closure = (node: Closure["node"], scope: Scope): object => { const marker = {}; closures.set(marker, { node, scope }); return marker; };
  const lookup = (name: string, scope: Scope, at: ts.Node): unknown => {
    // A cached value proves evaluation, not availability at this initializer's source position.
    ready(name, scope, at);
    if (scope.values.has(name)) return scope.values.get(name);
    if (scope.parent) return lookup(name, scope.parent, at);
    const key = `${scope.file.path}#${name}`;
    if (resolving.has(key)) return fail(at, `cyclic declaration ${key}`);
    resolving.add(key);
    try {
      for (const statement of scope.file.source!.statements) {
        if (ts.isFunctionDeclaration(statement) && statement.body && statement.name?.text === name) {
          const value = closure(statement, scope); scope.values.set(name, value); return value;
        }
        if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) if (ts.isIdentifier(declaration.name) && declaration.name.text === name) {
          if (!(statement.declarationList.flags & ts.NodeFlags.Const) || !declaration.initializer) return fail(declaration, "registry globals must be initialized constants");
          // Module initializers have their own readiness point and factory mutation lifetime.
          const previous = construction; const previousPosition: number | null = initializing;
          construction = null; initializing = initializationPositions.get(declaration)!;
          try { const value = evaluate(declaration.initializer, scope); scope.values.set(name, value); return value; }
          finally { construction = previous; initializing = previousPosition; }
        }
        if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && !statement.importClause?.isTypeOnly && statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings)) {
          const imported = statement.importClause.namedBindings.elements.find((e) => e.name.text === name && !e.isTypeOnly);
          if (!imported) continue;
          if (!statement.moduleSpecifier.text.startsWith(".")) { const value = builtin(`${statement.moduleSpecifier.text}.${imported.propertyName?.text ?? imported.name.text}`); scope.values.set(name, value); return value; }
          const next = modulePath(scope.file, statement.moduleSpecifier.text);
          const value = lookup(imported.propertyName?.text ?? imported.name.text, scopeFor(next), imported); scope.values.set(name, value); return value;
        }
        if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && !statement.importClause?.isTypeOnly && statement.importClause?.name?.text === name && !statement.moduleSpecifier.text.startsWith(".")) { const value = builtin(`${statement.moduleSpecifier.text}.default`); scope.values.set(name, value); return value; }
      }
      if (name === "undefined") return undefined;
      if (["Array", "Object", "JSON", "String"].includes(name)) return builtin(name);
      return fail(at, `unresolved declaration ${key}`);
    } finally { resolving.delete(key); }
  };
  const statements = (nodes: readonly ts.Statement[], scope: Scope): { value: unknown } | undefined => {
    // Lexical names shadow outer scopes from block entry, including declarations after return.
    for (const node of nodes) {
      if (ts.isVariableStatement(node)) {
        if (!(node.declarationList.flags & ts.NodeFlags.Const)) fail(node, "factory locals must be constants");
        for (const declaration of node.declarationList.declarations) declareLocal(declaration.name, scope);
      } else if (!ts.isReturnStatement(node) && !ts.isExpressionStatement(node) && !ts.isForOfStatement(node)) fail(node, `statement ${ts.SyntaxKind[node.kind]} is not modeled`);
    }
    for (const node of nodes) {
      tick(node);
      if (ts.isVariableStatement(node)) {
        if (!(node.declarationList.flags & ts.NodeFlags.Const)) fail(node, "factory locals must be constants");
        for (const declaration of node.declarationList.declarations) bind(declaration.name, declaration.initializer ? evaluate(declaration.initializer, scope) : undefined, scope);
      } else if (ts.isReturnStatement(node)) return { value: node.expression ? evaluate(node.expression, scope) : undefined };
      else if (ts.isExpressionStatement(node)) evaluate(node.expression, scope);
      else if (ts.isForOfStatement(node)) {
        if (node.awaitModifier || !ts.isVariableDeclarationList(node.initializer) || !(node.initializer.flags & ts.NodeFlags.Const) || node.initializer.declarations.length !== 1) fail(node, "only finite const for-of data loops are modeled");
        const binding = (node.initializer as ts.VariableDeclarationList).declarations[0]!.name;
        const loop: Scope = { values: new Map(), pending: new Set(), parent: scope, file: scope.file };
        declareLocal(binding, loop);
        const list = evaluate(node.expression, loop);
        if (!Array.isArray(list)) fail(node, "for-of input must be finite data");
        for (const value of list as unknown[]) {
          const iteration: Scope = { values: new Map(), pending: new Set(), parent: scope, file: scope.file };
          bind(binding, value, iteration);
          const block = ts.isBlock(node.statement);
          const child: Scope = block ? { values: new Map(), pending: new Set(), parent: iteration, file: scope.file } : iteration;
          const returned = statements(block ? node.statement.statements : [node.statement], child);
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
    const scope: Scope = { values: new Map(), pending: new Set(), parent: fn.scope, file: fn.scope.file };
    fn.node.parameters.forEach((p, i) => { if (p.dotDotDotToken || p.initializer) fail(p, "factory rest/default parameters are not modeled"); bind(p.name, args[i], scope); });
    const previous = construction; construction ??= {};
    try { return ts.isBlock(fn.node.body) ? statements(fn.node.body.statements, scope)?.value : evaluate(fn.node.body, scope); }
    finally { construction = previous; }
  };
  // These operations prove that otherwise unused import initializers do not alter registry data.
  // Selected registry construction rejects these metadata calls. Paths remain opaque, package values stay unknown,
  // and the sole read is served from retained source bytes rather than the host filesystem.
  const inertCall = (key: string, args: unknown[], node: ts.Node): unknown => {
    inertOnly(node);
    if (key === "Array.isArray" && args.length === 1) return Array.isArray(known(args[0], node));
    if (key === "JSON.parse" && args.length === 1 && typeof args[0] === "string") return JSON.parse(args[0]) as unknown;
    if (key === "Object.fromEntries" && args.length === 1 && Array.isArray(args[0]) && args[0].every((entry) => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === "string")) return Object.fromEntries(args[0] as [string, unknown][]);
    if (key === "node:fs.readFileSync" && args.length === 2 && args[1] === "utf8" && args[0] && typeof args[0] === "object") {
      const source = snapshotPaths.get(args[0]);
      const file = source?.kind === "source-url" ? files.get(source.path) : undefined;
      if (!file || file.text === null || file.gitMode === "120000" || file.gitMode === "160000") return fail(node, "inert source read must resolve to retained text bytes");
      return file.bytes.toString("utf8");
    }
    if (key === "node:url.fileURLToPath" && args.length === 1 && args[0] && typeof args[0] === "object") {
      const source = snapshotPaths.get(args[0]);
      if (source && source.kind !== "opaque-path") return snapshotPath(source.path, "opaque-path");
    }
    if (["node:path.dirname", "node:path.join", "node:path.resolve"].includes(key) && args.length && args.every((arg) => typeof arg === "string" || !!arg && typeof arg === "object" && snapshotPaths.get(arg)?.kind === "opaque-path")) {
      const values = args.map((arg) => typeof arg === "string" ? arg : snapshotPaths.get(arg as object)!.path);
      if (key === "node:path.dirname" && args.length === 1) return snapshotPath(posix.dirname(values[0]!), "opaque-path");
      if (key !== "node:path.dirname") return snapshotPath(posix.join(...values), "opaque-path");
    }
    return fail(node, `import initializer call ${key} is not demonstrably inert`);
  };
  const evaluate = (node: ts.Expression, scope: Scope): unknown => {
    tick(node);
    if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) return evaluate(node.expression, scope);
    if (ts.isStringLiteralLike(node)) return node.text;
    if (ts.isNumericLiteral(node)) return Number(node.text);
    if (ts.isRegularExpressionLiteral(node)) { const text = node.getText(); const end = text.lastIndexOf("/"); return new RegExp(text.slice(1, end), text.slice(end + 1)); }
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
          if (!value || typeof value !== "object" || Array.isArray(value) || closures.has(value) || isOpaque(value)) fail(property, "object spread input must be registry data");
          Object.assign(data, value);
        } else if (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) {
          const key = propertyKey(property.name);
          data[key] = ts.isPropertyAssignment(property) ? evaluate(property.initializer, scope) : lookup(property.name.text, scope, property);
        } else fail(property, "object method/accessor is not registry data");
      }
      origins.set(data, { file: scope.file, node }); return data;
    }
    if (ts.isArrayLiteralExpression(node)) {
      const data: unknown[] = [];
      if (!mutationAllowed) independentArrays.add(data);
      if (scope.parent && construction) localArrays.set(data, construction);
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
    if (ts.isConditionalExpression(node)) return evaluate(known(evaluate(node.condition, scope), node.condition) ? node.whenTrue : node.whenFalse, scope);
    if (ts.isPropertyAccessExpression(node) && ts.isMetaProperty(node.expression) && node.expression.keywordToken === ts.SyntaxKind.ImportKeyword && node.name.text === "url") { inertOnly(node); return snapshotPath(scope.file.path, "module-url"); }
    if (ts.isPropertyAccessExpression(node)) return own(evaluate(node.expression, scope), propertyKey(node.name), node);
    if (ts.isElementAccessExpression(node)) {
      const key = evaluate(node.argumentExpression, scope);
      if (typeof key !== "string" && typeof key !== "number") return fail(node, "element key must be scalar");
      return own(evaluate(node.expression, scope), String(key), node);
    }
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) return !known(evaluate(node.operand, scope), node);
    if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) && ts.isIdentifier(node.tag.expression) && node.tag.expression.text === "String" && node.tag.name.text === "raw" && !scope.parent && !shadows("String", scope.file)) {
      inertOnly(node);
      if (ts.isNoSubstitutionTemplateLiteral(node.template)) return node.template.rawText ?? node.template.text;
      return (node.template.head.rawText ?? node.template.head.text) + node.template.templateSpans.map((span) => {
        const value = known(evaluate(span.expression, scope), span);
        if (value !== null && typeof value === "object") fail(span, "raw template substitution must be scalar");
        return String(value) + (span.literal.rawText ?? span.literal.text);
      }).join("");
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && ["RegExp", "URL"].includes(node.expression.text) && !scope.parent && !shadows(node.expression.text, scope.file)) {
      inertOnly(node);
      const args = node.arguments?.map((arg) => evaluate(arg, scope)) ?? [];
      if (node.expression.text === "RegExp" && args.length >= 1 && args.length <= 2 && args.every((arg) => typeof arg === "string")) return new RegExp(args[0] as string, args[1] as string | undefined);
      if (node.expression.text === "URL" && args.length === 2 && typeof args[0] === "string" && args[0].startsWith(".") && args[1] && typeof args[1] === "object" && snapshotPaths.get(args[1])?.kind === "module-url") {
        const source = posix.normalize(posix.join(posix.dirname(snapshotPaths.get(args[1])!.path), args[0]));
        if (source.startsWith("../") || source.startsWith("/") || /[?#%\\]/.test(source)) return fail(node, "snapshot URL must stay within committed source");
        return snapshotPath(source, "source-url");
      }
      return fail(node, "inert constructor arguments are not modeled");
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "Set" && (!node.arguments || node.arguments.length <= 1)) {
      // The only constructor admitted is the built-in finite Set used by unrelated scorer constants.
      if (scope.parent) return fail(node, "Set construction is admitted only at module scope, without parameter or local shadowing");
      if (shadows("Set", scope.file)) return fail(node, "shadowed Set constructor is not modeled");
      const values = node.arguments?.[0] ? evaluate(node.arguments[0], scope) : [];
      if (!Array.isArray(values)) return fail(node, "Set input must be finite data");
      return new Set(values);
    }
    if (ts.isBinaryExpression(node)) {
      const left = known(evaluate(node.left, scope), node.left);
      if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) return left ?? evaluate(node.right, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) return left || evaluate(node.right, scope);
      if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return left && evaluate(node.right, scope);
      const right = known(evaluate(node.right, scope), node.right);
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) return left === right;
      if (node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) return left !== right;
      if (node.operatorToken.kind === ts.SyntaxKind.GreaterThanToken && typeof left === "number" && typeof right === "number") return left > right;
      if (node.operatorToken.kind === ts.SyntaxKind.PlusToken && typeof left === "string" && typeof right === "string") return left + right;
      if (node.operatorToken.kind === ts.SyntaxKind.AsteriskToken && typeof left === "number" && typeof right === "number") { inertOnly(node); return left * right; }
      return fail(node, "binary operation is not modeled");
    }
    if (ts.isCallExpression(node)) {
      if (ts.isPropertyAccessExpression(node.expression)) {
        const receiver = evaluate(node.expression.expression, scope); const method = propertyKey(node.expression.name);
        if (typeof receiver === "string" && method === "replace" && node.arguments.length === 2 && ts.isRegularExpressionLiteral(node.arguments[0]!)) {
          // The prefix is literal and anchored; native string replacement preserves $ substitutions.
          const prefix = node.arguments[0]!.getText().match(/^\/\^([A-Za-z0-9_-]+)\/$/)?.[1];
          const replacement = evaluate(node.arguments[1]!, scope);
          if (!prefix || typeof replacement !== "string") return fail(node, "only literal anchored-prefix replacement is modeled");
          return receiver.startsWith(prefix) ? receiver.replace(prefix, replacement) : receiver;
        }
        const args = node.arguments.map((arg) => evaluate(arg, scope));
        if (receiver && typeof receiver === "object" && builtins.has(receiver)) return inertCall(`${builtins.get(receiver)}.${method}`, args, node);
        if (typeof receiver === "string" && method === "toUpperCase" && !args.length) return receiver.toUpperCase();
        if (Array.isArray(receiver)) {
          if ((method === "map" || method === "flatMap" || method === "filter" || method === "some") && args.length === 1) {
            if (!args[0] || typeof args[0] !== "object" || !closures.has(args[0])) return fail(node, "array callback must be a source-local function, even for an empty input");
            // Native iteration preserves short-circuiting, captured length and immediate flattening.
            const callback = (value: unknown, index: number) => known(invoke(args[0], [value, index, receiver], node), node);
            if (method === "some") return receiver.some(callback);
            const result = method === "filter" ? receiver.filter(callback) : method === "flatMap" ? receiver.flatMap(callback) : receiver.map(callback);
            if (!mutationAllowed) independentArrays.add(result);
            if (scope.parent && construction) localArrays.set(result, construction);
            return result;
          }
          if (method === "push") {
            if (!mutationAllowed && !independentArrays.has(receiver)) return fail(node, "unused initializer may mutate registry data");
            if (!construction || localArrays.get(receiver) !== construction) return fail(node, "array mutation must stay inside its active factory construction");
            return receiver.push(...args);
          }
          if (method === "join" && args.length <= 1 && args.every((v) => typeof v === "string") && receiver.every((v) => ["string", "number", "boolean"].includes(typeof v))) return receiver.join(args[0] as string | undefined);
        }
        return fail(node, `method ${method} is not modeled`);
      }
      const callable = evaluate(node.expression, scope); const args = node.arguments.map((arg) => evaluate(arg, scope));
      if (callable && typeof callable === "object" && builtins.has(callable)) return inertCall(builtins.get(callable)!, args, node);
      return invoke(callable, args, node);
    }
    return fail(node, `expression ${ts.SyntaxKind[node.kind]} is not modeled`);
  };
  const scope = scopeFor(path);
  let position = 0;
  for (const module of moduleOrder) {
    const constants = new Map<string, ts.VariableDeclaration>(); moduleConstants.set(module, constants);
    const imports = new Map<string, { scope: Scope; name: string }>(); relativeBindings.set(module, imports);
    for (const statement of module.file.source!.statements) {
      if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) {
        if (!(statement.declarationList.flags & ts.NodeFlags.Const) || !ts.isIdentifier(declaration.name) || !declaration.initializer) fail(declaration, "module declarations must be initialized named constants");
        constants.set((declaration.name as ts.Identifier).text, declaration); initializationPositions.set(declaration, position++);
      }
      if (ts.isIfStatement(statement)) initializationPositions.set(statement, position++);
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.moduleSpecifier.text.startsWith(".") && !statement.importClause?.isTypeOnly && statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings)) {
        const imported = scopes.get(modulePath(module.file, statement.moduleSpecifier.text))!;
        for (const binding of statement.importClause.namedBindings.elements) if (!binding.isTypeOnly) imports.set(binding.name.text, { scope: imported, name: binding.propertyName?.text ?? binding.name.text });
      }
    }
  }
  const value = lookup(symbol, scope, scope.file.source!);
  // Lazily resolving the selected export alone would miss side effects in unused initializers.
  // Admit every remaining initializer under the same finite grammar, with mutation refused.
  mutationAllowed = false;
  for (const module of scopes.values()) {
    for (const statement of module.file.source!.statements) {
      if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) {
        if (!(statement.declarationList.flags & ts.NodeFlags.Const) || !ts.isIdentifier(declaration.name) || !declaration.initializer) fail(declaration, "module declarations must be initialized named constants");
        lookup((declaration.name as ts.Identifier).text, module, declaration);
      }
      if (ts.isIfStatement(statement) && !importGuards.has(statement)) {
        const previousPosition: number | null = initializing; initializing = initializationPositions.get(statement)!;
        try { if (known(evaluate(statement.expression, module), statement)) fail(statement, "registry admission guard rejected this source population"); }
        finally { initializing = previousPosition; }
      }
    }
  }
  if (!Array.isArray(value) || !value.length) throw new Error(`environment census: registry ${path}#${symbol} is not a nonempty array`);
  // No adapter may see markers, functions or cyclic/non-data containers disguised as a record.
  // Check the complete selected population before returning any member; shared acyclic data is valid.
  const active = new WeakSet<object>(); const checked = new WeakSet<object>();
  const selectedData = (data: unknown, field: string, at: ts.Node): void => {
    tick(at);
    if (data === null || typeof data === "string" || typeof data === "boolean" || typeof data === "number" && Number.isFinite(data)) return;
    const reject = (detail: string): never => fail(at, `selected registry data ${field}: ${detail}`);
    if (!data || typeof data !== "object") return reject(`unsupported ${typeof data} value`);
    if (isOpaque(data)) return reject("unknown/opaque import or metadata value");
    if (closures.has(data)) return reject("function value is not record data");
    const prototype = Object.getPrototypeOf(data) as unknown;
    if (Array.isArray(data) ? prototype !== Array.prototype : prototype !== null && prototype !== Object.prototype) return reject("non-data object");
    if (active.has(data)) return reject("cyclic record data");
    if (checked.has(data)) return;
    active.add(data);
    const node = origins.get(data)?.node ?? at;
    for (const key of Reflect.ownKeys(data)) {
      if (typeof key !== "string") return reject("symbol property is not record data");
      if (Array.isArray(data) && key === "length") continue;
      if (Array.isArray(data) && (!/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= data.length)) return reject("extended array is not record data");
      const descriptor = Object.getOwnPropertyDescriptor(data, key)!;
      if (!Object.hasOwn(descriptor, "value")) return reject("accessor is not record data");
      selectedData(descriptor.value, Array.isArray(data) ? `${field}[${key}]` : `${field}.${key}`, node);
    }
    if (Array.isArray(data) && Object.keys(data).length !== data.length) return reject("sparse or extended array is not record data");
    active.delete(data); checked.add(data);
  };
  selectedData(value, symbol, scope.file.source!);
  return value.map((entry) => {
    const origin = entry && typeof entry === "object" && !Array.isArray(entry) ? origins.get(entry) : undefined;
    if (!origin) throw new Error(`environment census: registry ${path}#${symbol} contains an unresolved record`);
    return { value: entry as Record<string, unknown>, ...origin };
  });
}
