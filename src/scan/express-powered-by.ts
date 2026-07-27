// #1204 (OWASP Node.js Security CS, Server Security): "Remove or obfuscate the X-Powered-By
// header." Express sets `X-Powered-By: Express` on every response unless the app turns it off, so
// an app that never disables it advertises its framework to any caller — free reconnaissance for
// matching a known Express/middleware CVE against the deployment.
//
// SAME-FILE HEURISTIC, disclosed in the finding itself rather than only here. This pass reads the
// module that CONSTRUCTS the app and looks there for the disable — `app.disable("x-powered-by")`,
// `app.set("x-powered-by", false)`, `res.removeHeader("X-Powered-By")`, an overwriting
// `setHeader("X-Powered-By", …)`, or helmet (whose hidePoweredBy strips it). A disable applied by
// another module that imports this app, or a header stripped at a reverse proxy / CDN / ingress in
// front of the app, is OUTSIDE what a static pass can read. Hence review tier, and hence the
// evidence text names the scope it actually searched instead of asserting the header ships.
//
// The clear is deliberately generous, same trade as raw-body-limit.ts: an over-eager clear is a
// false negative, an over-eager flag is a false positive on an app that is already correct — and
// #1204's ruling is explicit that an app handling this by hand must not be flagged.
//
// The companion half of that OWASP line — "use helmet middleware" — is DECLINED, not missing:
//
// REASON: Harvey does not flag an Express app for failing to adopt helmet; the response headers helmet sets are checked by their effect instead (b5-headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, cookie flags), so an app that sets them by hand is correct and is not flagged
// KIND: decisional
// PROVENANCE: MEASURED 2026-07-27 (the #1204 operator ruling; the by-design boundary is scored by P-OWASP-NODE-HELMET in src/scan/calibration/owasp-nodejs.entries.ts)
// OWNER: operator
// DECISION: #1204 — library adoption is not a defect; only the X-Powered-By half of the OWASP line is detected

import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const POWERED_BY_HEADER = /^x-powered-by$/i;

// Local bindings for the express factory: `import express from "express"`, `import * as express`,
// `const express = require("express")`. A named import (`import { Router }`) is not the factory.
function expressBindings(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node) => {
    if (ts.isImportDeclaration(n) && ts.isStringLiteralLike(n.moduleSpecifier) && n.moduleSpecifier.text === "express") {
      const clause = n.importClause;
      if (clause?.name) names.add(clause.name.text);
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) names.add(clause.namedBindings.name.text);
    }
    if (
      ts.isVariableDeclaration(n) &&
      ts.isIdentifier(n.name) &&
      n.initializer &&
      ts.isCallExpression(n.initializer) &&
      ts.isIdentifier(n.initializer.expression) &&
      n.initializer.expression.text === "require" &&
      n.initializer.arguments.length === 1 &&
      ts.isStringLiteralLike(n.initializer.arguments[0]!) &&
      (n.initializer.arguments[0] as ts.StringLiteralLike).text === "express"
    ) {
      names.add(n.name.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return names;
}

// Anything in this module that means somebody has already thought about the header. A string
// literal naming it (the disable, the `set(..., false)`, the removeHeader, an obfuscating
// overwrite) or any use of a `helmet` binding, whose hidePoweredBy default strips it.
function alreadyHandled(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isStringLiteralLike(n) && (POWERED_BY_HEADER.test(n.text) || n.text === "helmet")) found = true;
    else if (ts.isIdentifier(n) && n.text === "helmet") found = true;
    if (!found) ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

function appCreations(sf: ts.SourceFile, bindings: Set<string>): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && n.arguments.length === 0 && ts.isIdentifier(n.expression) && bindings.has(n.expression.text)) calls.push(n);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return calls;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const bindings = expressBindings(sf);
  if (bindings.size === 0) return [];
  const creations = appCreations(sf, bindings);
  if (creations.length === 0 || alreadyHandled(sf)) return [];

  // One row per module, not per `express()` call: the defect is "this app was never told to drop
  // the header", and a module that builds two routers has one such omission, not two.
  const node = creations[0]!;
  return [
    mechanicalFinding({
      id: `SEC-POWERED-BY-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
      title: "Express app never disables the X-Powered-By response header",
      severity: "Low",
      category: "Information disclosure",
      taxonomy: "Framework version disclosed via X-Powered-By",
      location: `${path}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`,
      evidence: `\`${node.getText(sf).replace(/\s+/g, " ").slice(0, 60)}\` builds an Express app, and no \`disable("x-powered-by")\`, \`set("x-powered-by", false)\`, \`removeHeader("X-Powered-By")\` or helmet use appears anywhere in ${path} — Express therefore sets \`X-Powered-By: Express\` on every response this app serves. SCOPE OF THIS CHECK: it reads the module that CONSTRUCTS the app and nothing else. A disable applied in another module that imports this app, or a header stripped at a reverse proxy, CDN or ingress in front of it, is OUTSIDE what this pass can see — so a live response may well not carry the header. Confirm against the deployed response before treating this as present.`,
      impact:
        "Every response names the server framework, which lets an attacker skip fingerprinting and go straight to Express- and middleware-specific exploits when a CVE lands. Low on its own; it is reconnaissance that shortens the path to a real finding.",
      fix: 'Call `app.disable("x-powered-by")` immediately after creating the app (or mount `helmet()`, whose hidePoweredBy default removes it). If the header is already stripped at a proxy or CDN, keep the app-level disable anyway so the app is not dependent on the edge staying configured.',
      precisionTier: "review",
    }),
  ];
}

export function detectExpressPoweredByFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanExpressPoweredBy(projectDir: string): Finding[] {
  return detectExpressPoweredByFindings(walkSourceFiles(projectDir));
}
