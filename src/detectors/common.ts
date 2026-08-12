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
