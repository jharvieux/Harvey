// Shared plumbing for the static AST detector modules (app-router.ts / perf-code.ts):
// source parsing, directive/location helpers, and call-chain walking. Extracted from
// app-router.ts when perf-code.ts (M7 code layer, #170) became a second consumer.

import ts from "typescript";

export interface SourceInput {
  /** Repo-relative path, e.g. "app/dashboard/page.tsx". Used for import resolution and location. */
  path: string;
  text: string;
}

export type NextId = () => string;

function isTsxPath(path: string): boolean {
  return path.endsWith(".tsx") || path.endsWith(".jsx");
}

export function parse(path: string, text: string): ts.SourceFile {
  return ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    isTsxPath(path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
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
