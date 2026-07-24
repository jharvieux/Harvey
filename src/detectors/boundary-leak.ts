// Shared server→client leak primitive for the return-value frameworks (#917/#918).
//
// Where Next's leak crosses the boundary as a JSX prop into a Client Component, Remix loaders and
// TanStack server functions serialise their RETURN VALUE to the client (`useLoaderData` /
// the server-function's resolved value). Given a return expression, report the whole raw DB row it
// carries — the leak — reusing the same raw-row bookkeeping the Next check uses (collectRawRowNames
// upstream; objectSpreadsRawRow/rowNameOf here). Matches the four real shapes:
//   - returned bare:            `return row;`
//   - spread whole:             `return { ...row };`
//   - carried as a property:    `return { user: row };`  /  `return { user };` (shorthand)
//   - wrapped in a Remix helper: `return json(row)` / `return json({ user })`
// A narrowing projection (`return { name: row.name }`) reports nothing — the safe shape.

import ts from "typescript";
import { objectSpreadsRawRow, rowNameOf } from "./app-router.js";

interface ReturnedRow {
  name: string;
  field?: string;
}

export function returnedRawRow(expr: ts.Expression, rawRowNames: ReadonlySet<string>): ReturnedRow | undefined {
  let e = expr;
  // Unwrap the Remix `json(...)` / `data(...)` response helpers around the payload.
  if (ts.isCallExpression(e) && e.arguments.length >= 1) {
    const callee = e.expression;
    const fn = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
    if ((fn === "json" || fn === "data") && e.arguments[0]) e = e.arguments[0];
  }
  if (ts.isIdentifier(e) && rawRowNames.has(e.text)) return { name: e.text };
  const topSpread = rowNameOf(e, rawRowNames); // `{ ...row }` at the top level
  if (topSpread) return { name: topSpread };
  if (ts.isObjectLiteralExpression(e)) {
    for (const p of e.properties) {
      if (ts.isShorthandPropertyAssignment(p) && rawRowNames.has(p.name.text)) return { name: p.name.text, field: p.name.text };
      if (ts.isPropertyAssignment(p)) {
        const field = ts.isIdentifier(p.name) || ts.isStringLiteralLike(p.name) ? p.name.text : undefined;
        if (ts.isIdentifier(p.initializer) && rawRowNames.has(p.initializer.text)) return { name: p.initializer.text, field };
        const nestedSpread = objectSpreadsRawRow(p.initializer, rawRowNames) ? rowNameOf(p.initializer, rawRowNames) : undefined;
        if (nestedSpread) return { name: nestedSpread, field };
      }
    }
  }
  return undefined;
}

// The `return` expressions reachable in a function body (skips nested function scopes, whose
// returns belong to a different callable).
export function returnExpressions(body: ts.Node): ts.Expression[] {
  const out: ts.Expression[] = [];
  const visit = (node: ts.Node) => {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    ) {
      if (node !== body) return; // don't descend into a nested callable's returns
    }
    if (ts.isReturnStatement(node) && node.expression) out.push(node.expression);
    ts.forEachChild(node, visit);
  };
  visit(body);
  return out;
}
