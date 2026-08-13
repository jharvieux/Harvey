// #1200 second half (OWASP Node.js Security CS, Application Security): "Set request size limits via
// middleware for different content types." harvey-body-parser-no-limit covers the middleware shape
// (`express.json()` with no `limit`); this covers the other one the issue scoped — a raw
// `req.on("data", …)` accumulator with no byte ceiling, which no body-parser option can bound
// because no body parser is involved.
//
// SINGLE-HANDLER HEURISTIC, disclosed in the finding itself: the ceiling is looked for in the
// function that wires up the listener (and therefore in the listener body), not across the module
// graph. A limit imposed by a middleware registered elsewhere, a reverse proxy, or a wrapper in
// another file is invisible to this pass — hence review tier, and hence the evidence text names the
// scope it actually searched instead of asserting the app has no limit.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

// Only request-shaped receivers. `.on("data", …)` on an arbitrary stream (a file read, a child
// process) accumulating into memory is not a request-size defect, and flagging it would put this
// rule on half of every build script.
const REQUEST_RECEIVER = /^_?(req|request|incoming|httpReq|httpRequest|nextReq|clientReq)$/i;

// Names that mean somebody is thinking about size. Deliberately generous: an over-eager clear is a
// false negative, an over-eager flag is a false positive on a handler that IS bounded.
const CEILING_NAME = /(limit|max|cap|threshold|quota|bytes?left|remaining)/i;
const CEILING_CALL = new Set(["destroy", "pause", "unpipe", "abort"]);
const RELATIONAL = new Set([
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.GreaterThanEqualsToken,
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
]);

function accumulates(cb: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    // `write`/`pipe` are deliberately absent: streaming a chunk straight out to a socket or a file
    // does not grow the heap, which is the whole defect here.
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ["push", "concat", "append"].includes(n.expression.name.text)) found = true;
    else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) found = true;
    if (!found) ts.forEachChild(n, visit);
  };
  visit(cb);
  return found;
}

function hasCeiling(scope: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isBinaryExpression(n) && RELATIONAL.has(n.operatorToken.kind)) found = true;
    else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && CEILING_CALL.has(n.expression.name.text)) found = true;
    else if (ts.isIdentifier(n) && CEILING_NAME.test(n.text)) found = true;
    else if (ts.isPropertyAccessExpression(n) && CEILING_NAME.test(n.name.text)) found = true;
    else if (ts.isStringLiteralLike(n) && /content-length/i.test(n.text)) found = true;
    if (!found) ts.forEachChild(n, visit);
  };
  visit(scope);
  return found;
}

// The function that wires up the listener — the widest scope this pass is willing to claim it read.
function enclosingScope(call: ts.Node, sf: ts.SourceFile): { node: ts.Node; label: string } {
  for (let n = call.parent; n; n = n.parent) {
    if (ts.isFunctionLike(n)) return { node: n, label: "the enclosing handler" };
    if (ts.isSourceFile(n)) break;
  }
  return { node: sf, label: "this module's top level" };
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (
      ts.isCallExpression(n) &&
      ts.isPropertyAccessExpression(n.expression) &&
      n.expression.name.text === "on" &&
      ts.isIdentifier(n.expression.expression) &&
      REQUEST_RECEIVER.test(n.expression.expression.text) &&
      n.arguments.length === 2 &&
      ts.isStringLiteralLike(n.arguments[0]!) &&
      (n.arguments[0] as ts.StringLiteralLike).text === "data" &&
      accumulates(n.arguments[1]!)
    ) {
      const receiver = n.expression.expression.text;
      const scope = enclosingScope(n, sf);
      if (!hasCeiling(scope.node)) {
        findings.push(
          mechanicalFinding({
            id: `SEC-RAW-BODY-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${n.getStart(sf)}`,
            title: `${receiver}.on("data", ...) accumulates the request body with no size limit`,
            severity: "Medium",
            category: "Denial of service",
            taxonomy: "Request body accumulated with no size limit",
            location: `${path}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`,
            evidence: `\`${n.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` buffers each chunk, and no byte ceiling — no running-total comparison, no \`${receiver}.destroy()\`/\`.pause()\`, no limit/max value — appears anywhere in ${scope.label} in ${path}. A ceiling imposed by middleware, a wrapper in another module, or a reverse proxy is OUTSIDE what this pass reads.`,
            impact: "One request with an arbitrarily large body is buffered whole in memory, so a single caller can exhaust the process heap — a denial of service that needs no authentication.",
            fix: `Track the accumulated byte count and reject past a ceiling sized to what the route legitimately needs (\`if (received > MAX_BYTES) { ${receiver}.destroy(); return; }\`), or read the body through a bounded parser (express.json({ limit: "100kb" }), raw-body's \`limit\` option).`,
            precisionTier: "review",
          }),
        );
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectRawBodyNoLimitFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
