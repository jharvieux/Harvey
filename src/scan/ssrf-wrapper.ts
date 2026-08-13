// #1325 (#570 remainder) — the cross-file SSRF wrapper class beyond the curated name list.
//
// harvey-ssrf-fetch (src/scan/rules/semgrep/base.yml) keys its sink on a request-tainted URL
// reaching `fetch()`/`http(s).get|request()`/`axios(...)`/`request(...)`, OR reaching a call to a
// helper NAMED `fetchRemote`/`fetchUrl`/`fetchExternal`/`proxyFetch` — because OSS Semgrep's taint
// engine is single-file, and the real-world split ("tainted URL in the route, `fetch()` in a
// shared helper") puts the sink in a DIFFERENT file from the source. The curated-name list recovers
// that ONE shape. #1325 measured the cost of that: the fixture the same PR planted
// (`targets/calibration/lib/ar-fetch.ts`) exports a function named `fetchRemote` — one of the four
// — so the rule could never fail: fixture, allowlist and rule were written together. A real
// target's wrapper named `httpGet`/`getRemote`/`download`/anything else is completely dark.
//
// This detector is the COMPLEMENT, not a replacement: it resolves the actual cross-file import
// (rather than guessing by name) and checks the CALLEE's definition SHAPE — a function whose only
// use of its parameter is passing it straight to a fetch-family call, with nothing else touching
// it (no host check, no transformation) — so it fires on ANY thin-wrapper name, not just the four
// harvey-ssrf-fetch already covers. It deliberately EXCLUDES those four names (CURATED_WRAPPER_NAMES
// below) so the two checks never double-report the same call site.
//
// SCOPE (stated here so its silence elsewhere is not read as a clean bill of health):
//   - Only a ONE-HOP wrapper is recognised: `defined in file A, imported and called in file B`.
//     A wrapper re-exported through a third file, or called through a further layer of
//     indirection, is not resolved.
//   - The request-source vocabulary is a reduced subset of harvey-ssrf-fetch's `x-request-source`
//     anchor — req.query/body/params/cookies/headers (by req-like name), `searchParams`,
//     `await …json()`, `cookies()`, `headers()`. It does NOT cover the RSC destructured
//     `{ params }`/`{ searchParams }` parameter shape (#1240's class) — that needs the same
//     name-based reach as the semgrep rule uses, which is out of scope for a shape-only detector.
//   - The tainted argument is resolved ONE hop back at most: either inline at the call site, or via
//     a single preceding `const`/`let` in the SAME function. A value threaded through more
//     reassignments or a second helper is not traced.
//   - No sanitizer/allowlist recognition: harvey-ssrf-fetch's guard patterns are not reproduced
//     here. A wrapper call past a real host allowlist elsewhere in the caller will still fire.
// Any of these gaps is a real miss, not a false claim of completeness — the taxonomy and message
// say so, matching the disclosure discipline the -00 row family already uses for module-level gaps.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { collectPathAliases, resolveImport } from "../detectors/app-router.js";
import { mechanicalFinding } from "./common.js";

// Owned by harvey-ssrf-fetch's metavariable-regex (base.yml) — excluded here so the two checks
// never double-report the same call site.
const CURATED_WRAPPER_NAMES = new Set(["fetchRemote", "fetchUrl", "fetchExternal", "proxyFetch"]);

const SINK_CALLEE = /^(fetch|http\.get|http\.request|https\.get|https\.request|axios|axios\.get|axios\.post|request)$/;

// Reduced subset of base.yml's `x-request-source` anchor — see the SCOPE note above.
const REQ_NAME = /^_?(req|request|nextReq|nextRequest|httpReq|incoming)$/;
function looksRequestTainted(text: string): boolean {
  if (/\.searchParams\b/.test(text)) return true;
  if (/\bawait\s+[\w$.]*\.json\(\)/.test(text) || /\.json\(\)/.test(text)) return true;
  if (/\bcookies\(\)/.test(text) || /\bheaders\(\)/.test(text)) return true;
  const m = /([A-Za-z_$][\w$]*)\.(query|body|params|cookies|headers)\b/.exec(text);
  if (m && REQ_NAME.test(m[1]!)) return true;
  return false;
}

function calleeText(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression)) return `${expr.expression.text}.${expr.name.text}`;
  return undefined;
}

interface WrapperDef {
  file: string;
  param: string;
}

// A thin fetch-wrapper: exactly one parameter, and the SOLE occurrence of that parameter's name
// anywhere in the function body is as the first argument of a fetch-family call. That is the
// security-relevant shape the issue asks for ("a function whose body is a bare fetch($ARG)
// returning its result") stated as a property rather than a statement count, so it still matches a
// wrapper with a trailing `.text()`/`.json()` follow-up (the real calibration fixture has one).
function thinWrapperParam(fn: ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression): string | undefined {
  if (fn.parameters.length !== 1) return undefined;
  const p = fn.parameters[0]!.name;
  if (!ts.isIdentifier(p)) return undefined;
  const param = p.text;
  if (!fn.body) return undefined;

  let occurrences = 0;
  let sinkHit = false;
  const visit = (node: ts.Node) => {
    if (ts.isIdentifier(node) && node.text === param) {
      occurrences++;
      const call = node.parent;
      if (
        ts.isCallExpression(call) &&
        call.arguments[0] === node &&
        (ts.isIdentifier(call.expression) || ts.isPropertyAccessExpression(call.expression))
      ) {
        const callee = calleeText(call.expression);
        if (callee && SINK_CALLEE.test(callee)) sinkHit = true;
      }
      return; // an identifier has no children worth descending into
    }
    ts.forEachChild(node, visit);
  };
  visit(fn.body);
  return occurrences === 1 && sinkHit ? param : undefined;
}

function collectWrapperDefs(path: string, sf: ts.SourceFile): Map<string, WrapperDef> {
  const defs = new Map<string, WrapperDef>();
  for (const stmt of sf.statements) {
    const isExported = (n: ts.Node) => ts.canHaveModifiers(n) && ts.getModifiers(n)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body && isExported(stmt)) {
      const param = thinWrapperParam(stmt);
      if (param && !CURATED_WRAPPER_NAMES.has(stmt.name.text)) defs.set(stmt.name.text, { file: path, param });
    }
    if (ts.isVariableStatement(stmt) && isExported(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer || !ts.isArrowFunction(d.initializer)) continue;
        const param = thinWrapperParam(d.initializer);
        if (param && !CURATED_WRAPPER_NAMES.has(d.name.text)) defs.set(d.name.text, { file: path, param });
      }
    }
  }
  return defs;
}

// Walk up from `node` to the nearest enclosing function and, if `argExpr` is a bare identifier,
// find its nearest preceding `const`/`let` declaration in that function's top-level statement
// list — the one-hop local-variable case the calibration fixture (ar-ssrf/route.ts) exercises:
// `const url = new URL(req.url).searchParams.get(...) || ""; ...; fetchXYZ(url)`.
function resolvedArgText(sf: ts.SourceFile, call: ts.CallExpression, argExpr: ts.Expression): string {
  if (!ts.isIdentifier(argExpr)) return argExpr.getText(sf);
  let fn: ts.Node | undefined = call.parent;
  while (fn && !ts.isFunctionDeclaration(fn) && !ts.isArrowFunction(fn) && !ts.isFunctionExpression(fn)) fn = fn.parent;
  const body = fn && "body" in fn ? (fn as ts.FunctionLikeDeclaration).body : undefined;
  if (!body || !ts.isBlock(body)) return argExpr.getText(sf);
  for (const stmt of body.statements) {
    if (stmt.getStart(sf) >= call.getStart(sf)) break;
    if (!ts.isVariableStatement(stmt)) continue;
    for (const d of stmt.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.name.text === argExpr.text && d.initializer) return d.initializer.getText(sf);
    }
  }
  return argExpr.getText(sf);
}

interface CallSite {
  node: ts.CallExpression;
  wrapperName: string;
  argText: string;
}

function findWrapperCalls(sf: ts.SourceFile, wrapperAliases: Set<string>): CallSite[] {
  const sites: CallSite[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && wrapperAliases.has(node.expression.text) && node.arguments.length > 0) {
      const argExpr = node.arguments[0]!;
      sites.push({ node, wrapperName: node.expression.text, argText: resolvedArgText(sf, node, argExpr) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return sites;
}

export function detectSsrfWrapperFindings(files: SourceInput[], importGraph?: ReadonlyMap<string, readonly string[]>): Finding[] {
  const sources = new Map(files.map((f) => [f.path, parse(f.path, f.text)]));
  const allPaths = new Set(sources.keys());
  const aliases = collectPathAliases(files);

  const wrapperDefs = new Map<string, WrapperDef>();
  for (const [path, sf] of sources) for (const [name, def] of collectWrapperDefs(path, sf)) wrapperDefs.set(`${path}#${name}`, def);
  if (wrapperDefs.size === 0) return [];

  const findings: Finding[] = [];
  for (const [path, sf] of sources) {
    // Which imported local names are bound to a known wrapper? Resolve each import specifier to
    // its file, then check the file exported a wrapper by that name (aliasing: `as` renames it
    // locally, so the LOCAL name is what call sites use, but the wrapper def is keyed on the
    // EXPORTED name in its own file).
    const wrapperAliases = new Set<string>();
    const aliasToDef = new Map<string, WrapperDef>();
    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || !stmt.importClause?.namedBindings) continue;
      if (!ts.isNamedImports(stmt.importClause.namedBindings)) continue;
      const resolved = resolveImport(path, stmt.moduleSpecifier.text, allPaths, aliases);
      if (!resolved) continue;
      if (importGraph && !(importGraph.get(path) ?? []).includes(resolved)) continue;
      for (const el of stmt.importClause.namedBindings.elements) {
        const exportedName = (el.propertyName ?? el.name).text;
        const def = wrapperDefs.get(`${resolved}#${exportedName}`);
        if (def) {
          wrapperAliases.add(el.name.text);
          aliasToDef.set(el.name.text, def);
        }
      }
    }
    if (wrapperAliases.size === 0) continue;

    for (const site of findWrapperCalls(sf, wrapperAliases)) {
      if (!looksRequestTainted(site.argText)) continue;
      const def = aliasToDef.get(site.wrapperName)!;
      findings.push(
        mechanicalFinding({
          id: `SSRF-wrapper-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${site.node.getStart(sf)}`,
          title: `Request-controlled URL reaches \`${site.wrapperName}()\`, a cross-file fetch wrapper`,
          severity: "Medium",
          category: "Security",
          taxonomy: "M1 — SSRF via an uncurated cross-file fetch wrapper",
          location: loc(path, sf, site.node),
          evidence: `\`${site.wrapperName}\` is imported from ${def.file}, where its only use of its parameter \`${def.param}\` is passing it straight to a fetch-family call — a thin pass-through with no host check. Here it is called with \`${site.argText}\`, a request-derived value.`,
          impact: "SSRF: the server can be made to fetch an attacker-chosen URL, reaching internal services or cloud metadata endpoints depending on the deploy network.",
          fix: "Validate the host against an allowlist and block internal/link-local ranges before the value reaches the wrapper, or add that check inside the wrapper itself.",
          precisionTier: "review",
        }),
      );
    }
  }
  return findings;
}
