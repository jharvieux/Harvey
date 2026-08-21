import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import ts from "typescript";
import type {
  EffectivenessCallReceipt,
  EffectivenessConsumerReceipt,
  EffectivenessRouteReceipt,
  ProducerImplementation,
} from "./effectiveness-schema.js";

const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"] as const;
const byText = (a: string, b: string): number => a.localeCompare(b);
const slash = (value: string): string => value.split(sep).join("/");

function repoRelative(root: string, file: string): string | undefined {
  const rel = slash(relative(root, file));
  return rel === "" || rel === ".." || rel.startsWith("../") ? undefined : rel;
}

function sourceCandidates(path: string): string[] {
  const stem = path.replace(/\.(?:js|jsx|mjs|cjs)$/, "");
  return [path, ...SOURCE_EXTENSIONS.map((extension) => `${stem}${extension}`), ...SOURCE_EXTENSIONS.map((extension) => join(path, `index${extension}`))];
}

function resolveLocalModule(root: string, sourceFile: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const base = resolve(root, dirname(sourceFile), specifier);
  return sourceCandidates(base).find((candidate) => existsSync(candidate));
}

function productionRoots(root: string, implementations: readonly ProducerImplementation[]): string[] {
  const roots = new Set<string>();
  const auditRoot = join(root, "src", "cli", "run-audit.ts");
  if (existsSync(auditRoot)) roots.add(auditRoot);
  const packagePath = join(root, "package.json");
  if (existsSync(packagePath)) {
    const manifest = JSON.parse(readFileSync(packagePath, "utf8")) as PackageManifest;
    const manager = manifest.packageManager?.split("@")[0];
    const auditClosure = existsSync(auditRoot)
      ? reachableSources(root, [auditRoot]).files
      : new Set<string>();
    const implementationIds = new Set(implementations
      .filter((item) => !auditClosure.has(join(root, item.file)))
      .map((item) => `${item.file}#${item.symbol}`));
    if (manager) {
      const targets = [...new Set(Object.keys(manifest.scripts ?? {})
        .map((script) => invocationTarget(root, manifest, manager, [script]))
        .filter((target): target is string => !!target))];
      const program = programForSources(targets);
      const checker = program.getTypeChecker();
      for (const target of targets) {
        const source = program.getSourceFile(target);
        let callsImplementation = false;
        const visit = (node: ts.Node): void => {
          if (ts.isCallExpression(node)) {
            const identity = symbolIdentity(root, checker, expressionSymbol(checker, node.expression));
            if (identity && implementationIds.has(`${identity.file}#${identity.symbol}`)) callsImplementation = true;
          }
          ts.forEachChild(node, visit);
        };
        if (source) visit(source);
        if (callsImplementation) roots.add(target);
      }
    }
  }
  return [...roots].sort(byText);
}

interface ReachableSources {
  readonly files: Set<string>;
  readonly rootsByFile: ReadonlyMap<string, readonly string[]>;
  readonly commandReceiptsByFile: ReadonlyMap<string, readonly EffectivenessCallReceipt[]>;
}

interface PackageManifest {
  readonly packageManager?: string;
  readonly scripts?: Readonly<Record<string, string>>;
}

function importedExecutionSymbols(program: ts.Program, checker: ts.TypeChecker): Set<ts.Symbol> {
  const result = new Set<ts.Symbol>();
  for (const source of program.getSourceFiles()) {
    if (source.isDeclarationFile) continue;
    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node)
        && ts.isStringLiteral(node.moduleSpecifier)
        && node.moduleSpecifier.text === "node:child_process") {
        const bindings = node.importClause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          for (const binding of bindings.elements) {
            const symbol = canonicalSymbol(checker, checker.getSymbolAtLocation(binding.name));
            if (symbol) result.add(symbol);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const source of program.getSourceFiles()) {
      if (source.isDeclarationFile) continue;
      const visit = (node: ts.Node): void => {
        if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
          const initializer = canonicalSymbol(checker, expressionSymbol(checker, node.initializer));
          const declared = canonicalSymbol(checker, checker.getSymbolAtLocation(node.name));
          if (initializer && result.has(initializer) && declared && !result.has(declared)) {
            result.add(declared);
            changed = true;
          }
        }
        if (ts.isPropertyAssignment(node)) {
          const initializer = canonicalSymbol(checker, expressionSymbol(checker, node.initializer));
          if (initializer && result.has(initializer)) {
            const own = canonicalSymbol(checker, checker.getSymbolAtLocation(node.name));
            const contextual = checker.getContextualType(node.parent)?.getProperty(node.name.getText(source));
            for (const symbol of [own, canonicalSymbol(checker, contextual)]) {
              if (symbol && !result.has(symbol)) {
                result.add(symbol);
                changed = true;
              }
            }
          }
        }
        if (ts.isCallExpression(node)) {
          const called = canonicalSymbol(checker, expressionSymbol(checker, node.expression));
          if (called && result.has(called)) {
            let owner: ts.Node | undefined = node.parent;
            while (owner && !ts.isFunctionLike(owner)) owner = owner.parent;
            if (owner) {
              const declaration = owner as ts.FunctionLikeDeclaration;
              const named = declaration.name && (ts.isIdentifier(declaration.name) || ts.isStringLiteralLike(declaration.name))
                ? canonicalSymbol(checker, checker.getSymbolAtLocation(declaration.name))
                : ts.isVariableDeclaration(declaration.parent) && ts.isIdentifier(declaration.parent.name)
                  ? canonicalSymbol(checker, checker.getSymbolAtLocation(declaration.parent.name))
                  : undefined;
              if (named && !result.has(named)) {
                result.add(named);
                changed = true;
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
  }
  return result;
}

function literalString(checker: ts.TypeChecker, expression: ts.Expression): string | undefined {
  if (ts.isStringLiteralLike(expression)) return expression.text;
  if (ts.isIdentifier(expression)) {
    const symbol = canonicalSymbol(checker, checker.getSymbolAtLocation(expression));
    const declaration = symbol?.declarations?.find(ts.isVariableDeclaration);
    return declaration?.initializer ? literalString(checker, declaration.initializer) : undefined;
  }
  return undefined;
}

function literalArray(checker: ts.TypeChecker, expression: ts.Expression): string[] | undefined {
  if (ts.isIdentifier(expression)) {
    const symbol = canonicalSymbol(checker, checker.getSymbolAtLocation(expression));
    const declaration = symbol?.declarations?.find(ts.isVariableDeclaration);
    return declaration?.initializer ? literalArray(checker, declaration.initializer) : undefined;
  }
  if (!ts.isArrayLiteralExpression(expression)) return undefined;
  const result: string[] = [];
  for (const element of expression.elements) {
    if (ts.isSpreadElement(element)) {
      const spread = literalArray(checker, element.expression);
      if (!spread) break;
      result.push(...spread);
      continue;
    }
    const value = literalString(checker, element);
    if (value === undefined) break;
    result.push(value);
  }
  return result;
}

function invocationTarget(root: string, manifest: PackageManifest, bin: string, args: readonly string[], seen = new Set<string>()): string | undefined {
  const manager = manifest.packageManager?.split("@")[0];
  const executable = slash(bin).split("/").at(-1);
  if (manager && executable === manager) {
    if (args[0] === "exec") return args[1] ? invocationTarget(root, manifest, args[1], args.slice(2), seen) : undefined;
    const script = args[0] === "run" ? args[1] : args[0];
    if (!script || seen.has(script)) return undefined;
    const command = manifest.scripts?.[script];
    if (!command) return undefined;
    const tokens = command.trim().split(/\s+/);
    if (tokens.some((token) => /^(?:&&|\|\||[|;])$/.test(token))) return undefined;
    return tokens[0] ? invocationTarget(root, manifest, tokens[0], tokens.slice(1), new Set([...seen, script])) : undefined;
  }
  if (executable !== "tsx" && executable !== "node") return undefined;
  const entry = args.find((argument) => !argument.startsWith("-"));
  if (!entry || !SOURCE_EXTENSIONS.includes(extname(entry) as typeof SOURCE_EXTENSIONS[number])) return undefined;
  const target = resolve(root, entry);
  return repoRelative(root, target) && existsSync(target) ? target : undefined;
}

function commandTargets(
  root: string,
  source: ts.SourceFile,
  checker: ts.TypeChecker,
  executionSymbols: ReadonlySet<ts.Symbol>,
  manifest: PackageManifest,
): string[] {
  const result = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const called = canonicalSymbol(checker, expressionSymbol(checker, node.expression));
      if (called && executionSymbols.has(called) && node.arguments[0] && node.arguments[1]) {
        const bin = literalString(checker, node.arguments[0]);
        const args = literalArray(checker, node.arguments[1]);
        const target = bin && args ? invocationTarget(root, manifest, bin, args) : undefined;
        if (target) result.add(target);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return [...result].sort(byText);
}

function reachableSources(root: string, roots: readonly string[]): ReachableSources {
  const packagePath = join(root, "package.json");
  const manifest = existsSync(packagePath)
    ? JSON.parse(readFileSync(packagePath, "utf8")) as PackageManifest
    : {};
  let program = programForSources(roots);
  while (true) {
    const result = reachableSourcesWithProgram(root, roots, program, manifest);
    if ([...result.files].every((file) => program.getSourceFile(file))) return result;
    program = programForSources([...result.files]);
  }
}

function reachableSourcesWithProgram(root: string, roots: readonly string[], program: ts.Program, manifest: PackageManifest): ReachableSources {
  const reached = new Set<string>();
  const rootsByFile = new Map<string, Set<string>>();
  const commandReceiptsByFile = new Map<string, readonly EffectivenessCallReceipt[]>();
  const checker = program.getTypeChecker();
  const executionSymbols = importedExecutionSymbols(program, checker);
  const pending = roots.map((file) => ({ file, root: file, commands: [] as readonly EffectivenessCallReceipt[] }));
  while (pending.length > 0) {
    const { file, root: routeRoot, commands } = pending.shift()!;
    if (!existsSync(file)) continue;
    const knownRoots = rootsByFile.get(file) ?? new Set<string>();
    if (knownRoots.has(routeRoot)) continue;
    knownRoots.add(routeRoot);
    rootsByFile.set(file, knownRoots);
    if (reached.has(file)) continue;
    reached.add(file);
    commandReceiptsByFile.set(file, commands);
    const source = program.getSourceFile(file);
    if (!source) continue;
    for (const statement of source.statements) {
      const specifier = (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)
        ? statement.moduleSpecifier.text
        : undefined;
      if (!specifier) continue;
      const resolved = resolveLocalModule(root, repoRelative(root, file) ?? file, specifier);
      if (resolved) pending.push({ file: resolved, root: routeRoot, commands });
    }
    for (const target of commandTargets(root, source, checker, executionSymbols, manifest)) {
      const consumerFile = repoRelative(root, file);
      const targetFile = repoRelative(root, target);
      if (!consumerFile || !targetFile) continue;
      const receipt: EffectivenessCallReceipt = {
        id: `command:${consumerFile}->${targetFile}`,
        kind: "command",
        consumerFile,
        targetFile,
        targetSymbol: "<entrypoint>",
      };
      pending.push({ file: target, root: routeRoot, commands: [...commands, receipt] });
    }
  }
  return {
    files: reached,
    rootsByFile: new Map([...rootsByFile].map(([file, fileRoots]) => [file, [...fileRoots].sort(byText)])),
    commandReceiptsByFile,
  };
}

function canonicalSymbol(checker: ts.TypeChecker, symbol: ts.Symbol | undefined): ts.Symbol | undefined {
  if (!symbol) return undefined;
  if ((symbol.flags & ts.SymbolFlags.Alias) !== 0) {
    try {
      return checker.getAliasedSymbol(symbol);
    } catch {
      return symbol;
    }
  }
  return symbol;
}

function declarationSymbol(node: ts.Declaration): string | undefined {
  const name = (node as ts.NamedDeclaration).name;
  if (name && (ts.isIdentifier(name) || ts.isStringLiteralLike(name))) return name.text;
  if (ts.isSourceFile(node)) return "<module>";
  return undefined;
}

function symbolIdentity(root: string, checker: ts.TypeChecker, symbol: ts.Symbol | undefined): { file: string; symbol: string } | undefined {
  const resolved = canonicalSymbol(checker, symbol);
  if (!resolved) return undefined;
  for (const declaration of resolved.declarations ?? []) {
    const file = repoRelative(root, declaration.getSourceFile().fileName);
    const name = declarationSymbol(declaration) ?? resolved.getName();
    if (file && name && !name.startsWith("__")) return { file, symbol: name };
  }
  return undefined;
}

function expressionSymbol(checker: ts.TypeChecker, expression: ts.Expression): ts.Symbol | undefined {
  if (ts.isPropertyAccessExpression(expression)) {
    const property = canonicalSymbol(checker, checker.getSymbolAtLocation(expression.name));
    const initializer = property?.declarations?.find(ts.isPropertyAssignment)?.initializer;
    return initializer ? expressionSymbol(checker, initializer) : property;
  }
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression && ts.isStringLiteralLike(expression.argumentExpression)) {
    return canonicalSymbol(checker, checker.getTypeAtLocation(expression.expression).getProperty(expression.argumentExpression.text));
  }
  return canonicalSymbol(checker, checker.getSymbolAtLocation(expression));
}

function typeContainsFinding(checker: ts.TypeChecker, type: ts.Type, seen = new Set<ts.Type>()): boolean {
  if (seen.has(type)) return false;
  seen.add(type);
  if (type.isUnionOrIntersection()) return type.types.some((item) => typeContainsFinding(checker, item, seen));
  const arguments_ = checker.getTypeArguments(type as ts.TypeReference);
  if (arguments_.some((item) => item !== type && typeContainsFinding(checker, item, seen))) return true;
  const indexed = checker.getIndexTypeOfType(type, ts.IndexKind.Number);
  if (indexed && indexed !== type && typeContainsFinding(checker, indexed, seen)) return true;
  const properties = new Set(type.getProperties().map((property) => property.getName()));
  return properties.has("id") && properties.has("taxonomy") && properties.has("severity") && properties.has("location");
}

function programForSources(sources: readonly string[]): ts.Program {
  return ts.createProgram({
    rootNames: [...sources],
    options: { allowJs: true, checkJs: false, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2023, skipLibCheck: true },
  });
}

function isDeclarationReference(node: ts.Identifier): boolean {
  const parent = node.parent;
  return ("name" in parent && parent.name === node)
    || ts.isImportSpecifier(parent)
    || ts.isExportSpecifier(parent)
    || ts.isImportClause(parent)
    || ts.isNamespaceImport(parent);
}

function isDispatchReference(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (ts.isCallExpression(parent) && parent.arguments.includes(node))
    || (ts.isNewExpression(parent) && parent.arguments?.includes(node) === true);
}

export interface RouteGraphImplementation extends ProducerImplementation {
  readonly producerId: string;
  readonly deliveryKind?: "semantic-call" | "registry-dispatch" | "artifact-ingest" | "conservation";
  readonly endpoint?: EffectivenessRouteReceipt["endpoint"];
}

interface EffectivenessRouteGraph {
  readonly roots: readonly string[];
  readonly calls: readonly EffectivenessCallReceipt[];
  readonly consumers: readonly EffectivenessConsumerReceipt[];
  readonly routes: readonly EffectivenessRouteReceipt[];
  readonly unresolvedFindingDispatches: readonly string[];
  readonly corpusIds: readonly string[];
}

/**
 * Derive routes from the real TypeScript module closure. Declarations are identified by semantic
 * symbols, so aliases, re-exports and property calls retain the declaration identity instead of the
 * spelling used at the call site. A registry member counts only when its function value is referenced
 * from a reachable production module; imports and textual mentions do not.
 */
export function discoverEffectivenessRouteGraph(
  root: string,
  implementations: readonly RouteGraphImplementation[],
  requestedRoots?: readonly string[],
  options: { readonly detectUnknown?: boolean } = {},
): EffectivenessRouteGraph {
  const roots = (requestedRoots ?? productionRoots(root, implementations)).map((file) => resolve(root, file));
  const reachability = reachableSources(root, roots);
  const reachable = reachability.files;
  const program = programForSources([...reachable]);
  const checker = program.getTypeChecker();
  const implementationByIdentity = new Map(implementations.map((item) => [`${item.file}#${item.symbol}`, item]));
  const calls = new Map<string, EffectivenessCallReceipt>();
  for (const receipts of reachability.commandReceiptsByFile.values()) {
    for (const receipt of receipts) calls.set(receipt.id, receipt);
  }
  const live = new Map<string, { rootId: string; receiptId: string; callReceiptIds: readonly string[]; kind: "call" | "registry" }[]>();
  const unresolved = new Set<string>();
  const unresolvedCandidates: { message: string; consumerFile: string; targetFile?: string }[] = [];
  const corpusIds = new Set<string>();
  const rootIds = new Set(roots.map((entry) => repoRelative(root, entry)).filter((entry): entry is string => !!entry));
  const registeredFiles = new Set(implementations.map((item) => item.file));

  for (const source of program.getSourceFiles()) {
    if (!reachable.has(source.fileName)) continue;
    const consumerFile = repoRelative(root, source.fileName);
    if (!consumerFile) continue;
    const visit = (node: ts.Node): void => {
      if (ts.isPropertyAssignment(node)
        && (ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name))
        && node.name.text === "id"
        && ts.isStringLiteralLike(node.initializer)) corpusIds.add(node.initializer.text);
      if (ts.isCallExpression(node)) {
        const signature = checker.getResolvedSignature(node);
        const identity = symbolIdentity(root, checker, expressionSymbol(checker, node.expression))
          ?? (signature?.declaration ? symbolIdentity(root, checker, checker.getSymbolAtLocation((signature.declaration as ts.NamedDeclaration).name ?? signature.declaration)) : undefined);
        if (identity) {
          const target = `${identity.file}#${identity.symbol}`;
          const id = `call:${consumerFile}->${target}`;
          const implementation = implementationByIdentity.get(target);
          if (implementation) {
            calls.set(id, { id, kind: "call", consumerFile, targetFile: identity.file, targetSymbol: identity.symbol });
            const rootId = (reachability.rootsByFile.get(source.fileName) ?? [])
              .map((entry) => repoRelative(root, entry))
              .filter((entry): entry is string => !!entry)
              .sort(byText)[0] ?? consumerFile;
            const commandIds = (reachability.commandReceiptsByFile.get(source.fileName) ?? []).map((receipt) => receipt.id);
            live.set(target, [...(live.get(target) ?? []), { rootId, receiptId: id, callReceiptIds: [...commandIds, id], kind: "call" }]);
          } else if (options.detectUnknown !== false && !identity.file.startsWith("node_modules/") && (rootIds.has(consumerFile) || registeredFiles.has(consumerFile)) && typeContainsFinding(checker, checker.getTypeAtLocation(node))) {
            unresolvedCandidates.push({ message: `${consumerFile}#${identity.symbol}: finding-bearing call target ${target} is unregistered`, consumerFile, targetFile: identity.file });
          }
        } else if (options.detectUnknown !== false && rootIds.has(consumerFile) && typeContainsFinding(checker, checker.getTypeAtLocation(node))) {
          unresolvedCandidates.push({ message: `${consumerFile}: finding-bearing dispatch has no resolvable declaration`, consumerFile });
        }
      }
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node))
        && ((ts.isCallExpression(node.parent) && node.parent.arguments.includes(node))
          || (ts.isNewExpression(node.parent) && node.parent.arguments?.includes(node) === true))) {
        const identity = symbolIdentity(root, checker, expressionSymbol(checker, node));
        if (identity) {
          const target = `${identity.file}#${identity.symbol}`;
          if (implementationByIdentity.has(target)) {
            const id = `registry:${consumerFile}->${target}`;
            calls.set(id, { id, kind: "registry", consumerFile, targetFile: identity.file, targetSymbol: identity.symbol });
            const rootId = (reachability.rootsByFile.get(source.fileName) ?? [])
              .map((entry) => repoRelative(root, entry))
              .filter((entry): entry is string => !!entry)
              .sort(byText)[0] ?? consumerFile;
            const commandIds = (reachability.commandReceiptsByFile.get(source.fileName) ?? []).map((receipt) => receipt.id);
            live.set(target, [...(live.get(target) ?? []), { rootId, receiptId: id, callReceiptIds: [...commandIds, id], kind: "registry" }]);
          }
        }
      }
      if (ts.isIdentifier(node) && !isDeclarationReference(node) && isDispatchReference(node)) {
        const identity = symbolIdentity(root, checker, checker.getSymbolAtLocation(node));
        if (identity) {
          const target = `${identity.file}#${identity.symbol}`;
          const implementation = implementationByIdentity.get(target);
          if (implementation && !ts.isCallExpression(node.parent)) {
            const id = `registry:${consumerFile}->${target}`;
            calls.set(id, { id, kind: "registry", consumerFile, targetFile: identity.file, targetSymbol: identity.symbol });
            const rootId = (reachability.rootsByFile.get(source.fileName) ?? [])
              .map((entry) => repoRelative(root, entry))
              .filter((entry): entry is string => !!entry)
              .sort(byText)[0] ?? consumerFile;
            const commandIds = (reachability.commandReceiptsByFile.get(source.fileName) ?? []).map((receipt) => receipt.id);
            live.set(target, [...(live.get(target) ?? []), { rootId, receiptId: id, callReceiptIds: [...commandIds, id], kind: "registry" }]);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  const transportCache = new Map<string, boolean>();
  for (const candidate of unresolvedCandidates) {
    const isTransport = registeredFiles.has(candidate.consumerFile) || (!!candidate.targetFile && (() => {
      const cached = transportCache.get(candidate.targetFile!);
      if (cached !== undefined) return cached;
      const transportClosure = reachableSources(root, [join(root, candidate.targetFile!)]).files;
      const result = [...registeredFiles].some((file) => transportClosure.has(join(root, file)));
      transportCache.set(candidate.targetFile!, result);
      return result;
    })());
    if (!isTransport) unresolved.add(candidate.message);
  }

  const consumers: EffectivenessConsumerReceipt[] = [];
  const routes: EffectivenessRouteReceipt[] = [];
  const productionGraph = requestedRoots === undefined;
  for (const implementation of [...implementations].sort((a, b) => `${a.file}#${a.symbol}`.localeCompare(`${b.file}#${b.symbol}`))) {
    const identity = `${implementation.file}#${implementation.symbol}`;
    const discovered = [...new Map((live.get(identity) ?? []).map((receipt) => [receipt.receiptId, receipt])).values()].sort((a, b) => a.receiptId.localeCompare(b.receiptId));
    const declaredDispatchIsLive = implementation.deliveryKind === "registry-dispatch"
      ? productionGraph
        || reachable.has(join(root, implementation.file))
        || (implementation.kind === "rule" && reachable.has(join(root, "src", "scan", "semgrep.ts")))
      : productionGraph && (implementation.deliveryKind === "artifact-ingest" || implementation.deliveryKind === "conservation");
    const synthetic = discovered.length === 0 && declaredDispatchIsLive
      ? [{
          rootId: implementation.deliveryKind === "conservation" ? "src/cli/validate-conservation.ts" : implementation.file,
          receiptId: `${implementation.deliveryKind}:${implementation.producerId}:${identity}`,
          callReceiptIds: [`${implementation.deliveryKind}:${implementation.producerId}:${identity}`],
          kind: implementation.deliveryKind === "artifact-ingest" || implementation.deliveryKind === "conservation" ? "artifact" as const : "registry" as const,
        }]
      : [];
    const receipts = [...discovered, ...synthetic];
    for (const receipt of receipts) {
      if (!calls.has(receipt.receiptId)) calls.set(receipt.receiptId, {
        id: receipt.receiptId,
        kind: receipt.kind,
        consumerFile: receipt.rootId,
        targetFile: implementation.file,
        targetSymbol: implementation.symbol,
      });
      const consumerId = `consumer:${implementation.producerId}:${receipt.receiptId}`;
      consumers.push({ id: consumerId, producerId: implementation.producerId, implementationId: identity, callReceiptId: receipt.receiptId });
      routes.push({
        id: `route:${implementation.producerId}:${receipt.receiptId}`,
        producerId: implementation.producerId,
        implementationId: identity,
        rootId: receipt.rootId,
        callReceiptIds: [...receipt.callReceiptIds],
        consumerReceiptId: consumerId,
        endpoint: implementation.endpoint ?? "client-finding-delivery",
      });
    }
  }
  return {
    roots: roots.map((entry) => repoRelative(root, entry)).filter((entry): entry is string => !!entry).sort(byText),
    calls: [...calls.values()].sort((a, b) => a.id.localeCompare(b.id)),
    consumers: consumers.sort((a, b) => a.id.localeCompare(b.id)),
    routes: routes.sort((a, b) => a.id.localeCompare(b.id)),
    unresolvedFindingDispatches: [...unresolved].sort(byText),
    corpusIds: [...corpusIds].sort(byText),
  };
}
