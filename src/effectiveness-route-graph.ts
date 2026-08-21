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

function productionRoots(root: string): string[] {
  const roots = new Set<string>();
  const packagePath = join(root, "package.json");
  const runnerPath = join(root, "src", "audit-runners.ts");
  const runnerText = existsSync(runnerPath) ? readFileSync(runnerPath, "utf8") : "";
  if (existsSync(packagePath)) {
    const pkg = JSON.parse(readFileSync(packagePath, "utf8")) as { scripts?: Record<string, string> };
    for (const [script, command] of Object.entries(pkg.scripts ?? {})) {
      if (runnerText && !runnerText.includes(script) && !command.includes("tools/pii-classify.mjs")) continue;
      for (const match of command.matchAll(/(?:^|\s)((?:src|tools)\/[A-Za-z0-9_./-]+\.(?:ts|tsx|js|mjs|cjs))(?=\s|$)/g)) {
        const path = match[1] && join(root, match[1]);
        if (path && existsSync(path)) roots.add(path);
      }
    }
  }
  const auditRoot = join(root, "src", "cli", "run-audit.ts");
  if (existsSync(auditRoot)) roots.add(auditRoot);
  for (const match of runnerText.matchAll(/src\/cli\/[A-Za-z0-9_./-]+\.(?:ts|tsx|js|mjs|cjs)/g)) {
    const path = join(root, match[0]);
    if (existsSync(path)) roots.add(path);
  }
  return [...roots].sort(byText);
}

interface ReachableSources {
  readonly files: Set<string>;
  readonly rootsByFile: ReadonlyMap<string, readonly string[]>;
  readonly commandReceiptsByFile: ReadonlyMap<string, readonly EffectivenessCallReceipt[]>;
}

function commandTargets(root: string, source: ts.SourceFile): string[] {
  const result = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      for (const argument of node.arguments) {
        const values = ts.isArrayLiteralExpression(argument) ? argument.elements : [argument];
        for (const value of values) {
          if (!ts.isStringLiteralLike(value)) continue;
          if (!/^(?:src|tools)\/[A-Za-z0-9_./-]+\.(?:ts|tsx|js|mjs|cjs)$/.test(value.text)) continue;
          const target = join(root, value.text);
          if (existsSync(target)) result.add(target);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return [...result].sort(byText);
}

function reachableSources(root: string, roots: readonly string[]): ReachableSources {
  const reached = new Set<string>();
  const rootsByFile = new Map<string, Set<string>>();
  const commandReceiptsByFile = new Map<string, readonly EffectivenessCallReceipt[]>();
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
    const text = readFileSync(file, "utf8");
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, [".js", ".mjs", ".cjs"].includes(extname(file)) ? ts.ScriptKind.JS : ts.ScriptKind.TS);
    for (const statement of source.statements) {
      const specifier = (ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)
        ? statement.moduleSpecifier.text
        : undefined;
      if (!specifier) continue;
      const resolved = resolveLocalModule(root, repoRelative(root, file) ?? file, specifier);
      if (resolved) pending.push({ file: resolved, root: routeRoot, commands });
    }
    for (const target of commandTargets(root, source)) {
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
  const roots = (requestedRoots ?? productionRoots(root)).map((file) => resolve(root, file));
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
