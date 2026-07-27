// #1202 (OWASP Node.js Security CS, Error & Exception Handling): "Always listen to error events
// when using EventEmitter objects." An EventEmitter that emits 'error' with no registered
// listener throws synchronously and crashes the process — a remote DoS if the emit is reachable
// from a request path.
//
// SAME-FILE HEURISTIC ONLY, disclosed: proving no listener exists ANYWHERE needs cross-file
// reasoning (the listener may be attached by whatever module imports this emitter) — this walks
// one file, collects every `$E.emit("error", ...)` and every `$E.on("error", ...)`/
// `$E.once("error", ...)` by the emitter's local identifier name, and flags an emitter with no
// same-file listener. A listener registered on an imported instance from another module is
// invisible to this pass and will read as a false positive; review tier accounts for that.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

function errorArgLiteral(call: ts.CallExpression): boolean {
  const first = call.arguments[0];
  return !!first && ts.isStringLiteralLike(first) && first.text === "error";
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const emitters = new Map<string, ts.CallExpression>();
  const listened = new Set<string>();

  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) && errorArgLiteral(n)) {
      const method = n.expression.name.text;
      const receiver = n.expression.expression.text;
      if (method === "emit" && !emitters.has(receiver)) emitters.set(receiver, n);
      else if (method === "on" || method === "once") listened.add(receiver);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);

  const findings: Finding[] = [];
  for (const [receiver, node] of emitters) {
    if (listened.has(receiver)) continue;
    findings.push(
      mechanicalFinding({
        id: `SEC-EMITTER-ERR-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
        title: `${receiver}.emit("error", ...) has no same-file error listener`,
        severity: "High",
        category: "Error handling",
        taxonomy: "EventEmitter emits 'error' with no registered listener",
        location: `${path}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`,
        evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\` — no \`${receiver}.on("error", ...)\`/\`.once("error", ...)\` anywhere else in ${path}.`,
        impact: "Node re-throws an 'error' event with no listener, crashing the process — a remote denial of service if the emit is reachable from a request.",
        fix: `Register an error listener on ${receiver} (\`${receiver}.on("error", (err) => { ... })\`) before it can emit, or bind \`process.on("uncaughtException", ...)\` as a last-resort backstop.`,
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

export function detectEmitterUnhandledErrorFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanEmitterUnhandledError(projectDir: string): Finding[] {
  return detectEmitterUnhandledErrorFindings(walkSourceFiles(projectDir));
}
