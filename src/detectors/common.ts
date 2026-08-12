// Shared plumbing for the static AST detector modules (app-router.ts / perf-code.ts):
// source parsing, directive/location helpers, and call-chain walking. Extracted from
// app-router.ts when perf-code.ts (M7 code layer, #170) became a second consumer.

import { AsyncLocalStorage } from "node:async_hooks";
import ts from "typescript";

export interface SourceInput {
  /** Repo-relative path, e.g. "app/dashboard/page.tsx". Used for import resolution and location. */
  path: string;
  text: string;
}

export type NextId = () => string;

// #1065: plain .js/.mjs/.cjs parse as TSX, not TS. JSX in a `.js` file is the norm in React and
// Next (targets/vuln-seam-app's app/page.js is exactly that), and under ScriptKind.TS every `<div>`
// parses as a type assertion and the tree is garbage. The reverse risk does not exist: `<T>expr`
// type assertions aren't valid JavaScript, so nothing in a .js file needs the TS reading.
// .ts/.mts/.cts keep it, because there `<T>expr` IS a type assertion.
function isTsxPath(path: string): boolean {
  return /\.([jt]sx|[cm]?js)$/.test(path);
}

export interface CachedSourceFile {
  text: string;
  sourceFile: ts.SourceFile;
  onHit?: () => void;
}

const parseCache = new AsyncLocalStorage<ReadonlyMap<string, CachedSourceFile>>();

export function parseFresh(path: string, text: string): ts.SourceFile {
  return ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    isTsxPath(path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
}

/**
 * TypeScript's AST types are declared readonly but the runtime nodes are mutable.  A shared parse
 * cache therefore needs a runtime boundary: returning the raw SourceFile lets one detector change
 * a node and silently change every detector that runs after it.  This membrane keeps one canonical
 * tree (and stable proxy identity) while rejecting writes at every object reached through it.
 *
 * Method calls are applied to the underlying TypeScript object because several SourceFile methods
 * have internal receiver assumptions.  Arguments are unwrapped and object results are re-wrapped,
 * preserving recursive mutation protection for values returned by getChildren()/getSourceFile().
 */
export interface AstMembraneMetrics {
  objectsWrapped: number;
  methodWrappersCreated: number;
  callbacksWrapped: number;
  iteratorResultsWrapped: number;
  rejectedMutations: number;
}

export function readonlySourceFile(sourceFile: ts.SourceFile, metrics?: AstMembraneMetrics): ts.SourceFile {
  // TypeScript memoizes these public queries by writing private cache fields onto nodes. Materialize
  // them before the membrane is installed so later public API calls remain reads, not hidden writes.
  const warm = (node: ts.Node): void => {
    if (ts.canHaveModifiers(node)) void ts.getModifiers(node);
    if (ts.canHaveDecorators(node)) void ts.getDecorators(node);
    void ts.getJSDocCommentsAndTags(node);
    ts.forEachChild(node, warm);
  };
  warm(sourceFile);
  void sourceFile.getLineAndCharacterOfPosition(sourceFile.end);
  const proxies = new WeakMap<object, object>();
  const targets = new WeakMap<object, object>();
  const methods = new WeakMap<object, Map<PropertyKey, (...args: unknown[]) => unknown>>();
  const reject = (): never => {
    if (metrics) metrics.rejectedMutations += 1;
    throw new TypeError("shared TypeScript AST is immutable");
  };
  const unwrap = <T>(value: T): T => (value && typeof value === "object" && targets.has(value as object)
    ? targets.get(value as object) as T
    : value);
  const wrap = <T>(value: T): T => {
    if ((!value || (typeof value !== "object" && typeof value !== "function"))) return value;
    const target = value as object;
    const existing = proxies.get(target);
    if (existing) return existing as T;
    if (metrics) metrics.objectsWrapped += 1;
    const safeArguments = (args: readonly unknown[]): unknown[] => args.map((argument) => {
      if (typeof argument !== "function") return unwrap(argument);
      if (metrics) metrics.callbacksWrapped += 1;
      return function callbackMembrane(this: unknown, ...callbackArguments: unknown[]): unknown {
        return unwrap(Reflect.apply(argument, wrap(this), callbackArguments.map(wrap)));
      };
    });
    const proxy = new Proxy(target, {
      get(raw, property) {
        if ((raw instanceof Map || raw instanceof Set || raw instanceof WeakMap || raw instanceof WeakSet)
          && ["set", "add", "delete", "clear"].includes(String(property))) return reject;
        if (Array.isArray(raw)
          && ["copyWithin", "fill", "pop", "push", "reverse", "shift", "sort", "splice", "unshift"].includes(String(property))) return reject;
        const member = Reflect.get(raw, property, raw) as unknown;
        if (typeof member !== "function") return wrap(member);
        const byProperty = methods.get(raw) ?? new Map<PropertyKey, (...args: unknown[]) => unknown>();
        methods.set(raw, byProperty);
        const cached = byProperty.get(property);
        if (cached) return cached;
        const callable = (...args: unknown[]): unknown => {
          const result = Reflect.apply(member, raw, safeArguments(args));
          if (property === "next" && metrics) metrics.iteratorResultsWrapped += 1;
          return wrap(result);
        };
        if (metrics) metrics.methodWrappersCreated += 1;
        byProperty.set(property, callable);
        return callable;
      },
      getOwnPropertyDescriptor(raw, property) {
        const descriptor = Reflect.getOwnPropertyDescriptor(raw, property);
        if (!descriptor) return descriptor;
        if ("value" in descriptor) {
          if (descriptor.configurable === false && descriptor.writable === false
            && descriptor.value && (typeof descriptor.value === "object" || typeof descriptor.value === "function")) reject();
          return { ...descriptor, value: wrap(descriptor.value) };
        }
        return {
          ...descriptor,
          get: descriptor.get ? function readonlyDescriptorGet(this: unknown): unknown {
            return wrap(Reflect.apply(descriptor.get!, unwrap(this), []));
          } : undefined,
          set: descriptor.set ? reject : undefined,
        };
      },
      apply(raw, thisArgument, args) {
        return wrap(Reflect.apply(raw as (...values: unknown[]) => unknown, unwrap(thisArgument), safeArguments(args)));
      },
      set: reject,
      defineProperty: reject,
      deleteProperty: reject,
      preventExtensions: reject,
      setPrototypeOf: reject,
    });
    proxies.set(target, proxy);
    targets.set(proxy, target);
    return proxy as T;
  };
  return wrap(sourceFile);
}

export function parse(path: string, text: string): ts.SourceFile {
  const cached = parseCache.getStore()?.get(path);
  if (cached?.text === text) {
    cached.onHit?.();
    return cached.sourceFile;
  }
  return parseFresh(path, text);
}

export function withSourceParseCache<T>(cache: ReadonlyMap<string, CachedSourceFile>, run: () => T): T {
  return parseCache.run(cache, run);
}

export function leadingDirective(sf: ts.SourceFile): "use client" | "use server" | undefined {
  const first = sf.statements[0];
  if (first && ts.isExpressionStatement(first) && ts.isStringLiteral(first.expression)) {
    if (first.expression.text === "use client") return "use client";
    if (first.expression.text === "use server") return "use server";
  }
  return undefined;
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

export function loc(path: string, sf: ts.SourceFile, node: ts.Node): string {
  return `${path}:${lineOf(sf, node)}`;
}

// Walks a call chain (e.g. `supabase.from("x").select("y").single()`) and
// collects the method names invoked, innermost first.
export function callChainNames(node: ts.Expression): string[] {
  const names: string[] = [];
  let cur: ts.Expression = node;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    names.push(cur.expression.name.text);
    cur = cur.expression.expression;
  }
  return names;
}
