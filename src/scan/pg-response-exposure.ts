// #701 (#663 remainder) — Express + pg excessive data exposure: a handler sends a full
// internal row/object straight to res.json(...), exposing columns the client was never meant
// to see (password hashes, refresh tokens, secrets). #663 itself flags this as the least
// statically provable of its four sub-classes — "proving the object is a full sensitive row is
// not statically knowable single-file; res.json is ubiquitous and usually fine" — so this stays
// deliberately narrow: it never infers sensitivity from a value, only from a NAME the source
// itself writes down. Three curated, name-gated shapes, each chosen to keep false-fire near
// zero on ordinary DTOs:
//
//   1. direct: res.json({ ...password_hash: x... }) — a top-level property of the object
//      literal argument is literally named for a curated sensitive field (passwordHash,
//      refreshToken, ssn, ...). Catches the "forgot to strip a field" shape.
//   2. spread: res.json({ ...user }) where `user` is declared in the SAME function via an
//      object literal that itself names a curated sensitive field. Does not follow the value
//      across functions or files — "the value is derived from" is unprovable single-file, but
//      "the object literal that built this identifier names X" is a same-body AST fact.
//   3. select-star: res.json(row) / res.json(rows[0]) / res.json({ ...rows[0] }) where `row` /
//      `rows` is bound in the SAME function to the result of a `.query("SELECT * FROM ...")`
//      call — the classic "select * then hand the row straight back" flow named in #701. Gated
//      on the SQL string literal actually containing `select *`, not merely "any query result
//      reaches res.json" (which would fire on every narrowed, safe read too).
//
// A bare "token"/"secret"/"key" field name deliberately does NOT match — #701 calls out a CSRF
// token or a public share-link token as a legitimate field that must stay dark; only compound,
// unambiguous credential/PII names are curated in. Review tier, never free-count: the AST
// proves the name/shape, not that the field's runtime value is actually sensitive.

import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

// Curated, compound credential/PII field names only — normalized to lowercase alnum so
// passwordHash / password_hash / PASSWORD_HASH all match the same entry.
const SENSITIVE_FIELDS = new Set([
  "password",
  "passwordhash",
  "hashedpassword",
  "refreshtoken",
  "sessiontoken",
  "apikey",
  "secretkey",
  "privatekey",
  "ssn",
  "socialsecuritynumber",
  "creditcard",
  "creditcardnumber",
  "cardnumber",
  "cvv",
  "cvc",
  "salt",
]);

const SELECT_STAR = /select\s+\*\s+from/i;

type HandlerFn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

function normalizeKey(name: string): string {
  return name.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

function isExpressHandler(fn: HandlerFn): boolean {
  const names = ((fn as ts.SignatureDeclarationBase).parameters ?? [])
    .map((p) => (ts.isIdentifier(p.name) ? p.name.text : ""));
  const hasReq = names.some((n) => n === "req" || n === "request");
  const hasRes = names.some((n) => n === "res" || n === "response");
  return hasReq && hasRes;
}

function collectHandlers(sf: ts.SourceFile): HandlerFn[] {
  const handlers: HandlerFn[] = [];
  const visit = (node: ts.Node) => {
    if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) && node.body && isExpressHandler(node)) {
      handlers.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return handlers;
}

function propertyName(el: ts.ObjectLiteralElementLike): string | undefined {
  if ((ts.isPropertyAssignment(el) || ts.isShorthandPropertyAssignment(el)) && (ts.isIdentifier(el.name) || ts.isStringLiteral(el.name))) {
    return el.name.text;
  }
  return undefined;
}

// Direct hit: a top-level property of the object literal is literally named for a curated
// sensitive field.
function directSensitiveKey(obj: ts.ObjectLiteralExpression): string | undefined {
  for (const prop of obj.properties) {
    const name = propertyName(prop);
    if (name && SENSITIVE_FIELDS.has(normalizeKey(name))) return name;
  }
  return undefined;
}

// Spread hit: `...ident` where `ident` is declared in the same function via an object literal
// that itself names a curated sensitive field.
function spreadOfSensitiveVar(obj: ts.ObjectLiteralExpression, fn: ts.Node): string | undefined {
  const spreadNames = new Set<string>();
  for (const prop of obj.properties) {
    if (ts.isSpreadAssignment(prop) && ts.isIdentifier(prop.expression)) spreadNames.add(prop.expression.text);
  }
  if (spreadNames.size === 0) return undefined;

  let hit: string | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      spreadNames.has(node.name.text) &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      const field = directSensitiveKey(node.initializer);
      if (field) {
        hit = field;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return hit;
}

// Bindings, within one function, from a variable name to the exact expression text that
// refers to "the full result of a SELECT * query" (e.g. `result.rows[0]`, `rows`, `rows[0]`).
function collectSelectStarRowExprs(fn: ts.Node): Set<string> {
  const exprs = new Set<string>();
  const visit = (node: ts.Node) => {
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      isQueryCallWithSelectStar(node.initializer)
    ) {
      if (ts.isIdentifier(node.name)) {
        exprs.add(`${node.name.text}.rows[0]`);
        exprs.add(`${node.name.text}.rows`);
      } else if (ts.isObjectBindingPattern(node.name)) {
        for (const el of node.name.elements) {
          if (!ts.isIdentifier(el.name)) continue;
          const sourceKey = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
          if (sourceKey !== "rows") continue;
          exprs.add(`${el.name.text}[0]`);
          exprs.add(el.name.text);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return exprs;
}

// Unwraps `await <expr>` and checks for `<anything>.query(<sql with SELECT *>, ...)`.
function isQueryCallWithSelectStar(expr: ts.Expression): boolean {
  const inner = ts.isAwaitExpression(expr) ? expr.expression : expr;
  if (!ts.isCallExpression(inner) || !ts.isPropertyAccessExpression(inner.expression) || inner.expression.name.text !== "query") return false;
  const sql = inner.arguments[0];
  if (!sql) return false;
  if (ts.isStringLiteral(sql) || ts.isNoSubstitutionTemplateLiteral(sql)) return SELECT_STAR.test(sql.text);
  if (ts.isTemplateExpression(sql)) return SELECT_STAR.test(sql.head.text);
  return false;
}

interface ExposureHit {
  arg: ts.Expression;
  kind: "direct" | "spread" | "select-star";
  field: string;
}

function findExposure(fn: ts.Node, sf: ts.SourceFile): ExposureHit | undefined {
  const rowExprs = collectSelectStarRowExprs(fn);
  let hit: ExposureHit | undefined;

  const visit = (node: ts.Node) => {
    if (hit) return;
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "json" &&
      ts.isIdentifier(node.expression.expression) &&
      (node.expression.expression.text === "res" || node.expression.expression.text === "response") &&
      node.arguments.length === 1
    ) {
      const arg = node.arguments[0];
      if (!arg) return;

      if (ts.isObjectLiteralExpression(arg)) {
        const direct = directSensitiveKey(arg);
        if (direct) {
          hit = { arg, kind: "direct", field: direct };
          return;
        }
        const spread = spreadOfSensitiveVar(arg, fn);
        if (spread) {
          hit = { arg, kind: "spread", field: spread };
          return;
        }
        for (const prop of arg.properties) {
          if (ts.isSpreadAssignment(prop) && rowExprs.has(prop.expression.getText(sf))) {
            hit = { arg, kind: "select-star", field: prop.expression.getText(sf) };
            return;
          }
        }
      } else if (rowExprs.has(arg.getText(sf))) {
        hit = { arg, kind: "select-star", field: arg.getText(sf) };
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(fn);
  return hit;
}

const KIND_LABEL: Record<ExposureHit["kind"], string> = {
  direct: `names the curated-sensitive field "$FIELD" as a direct property of the object it returns`,
  spread: `spreads a same-function variable ("$FIELD" is one of its literal fields) into the object it returns`,
  "select-star": `hands the result of a same-function "SELECT *" query ($FIELD) straight back`,
};

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  for (const handler of collectHandlers(sf)) {
    const hit = findExposure(handler, sf);
    if (!hit) continue;

    const label = KIND_LABEL[hit.kind].replace("$FIELD", hit.field);
    findings.push(
      mechanicalFinding({
        id: `SEC-PG-RESJSON-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${hit.arg.getStart(sf)}`,
        title: `${path} — res.json(...) ${label}`,
        severity: hit.kind === "select-star" ? "Medium" : "High",
        category: "Sensitive data exposure",
        taxonomy: `Excessive data exposure: res.json(...) ${label} (pg-resjson-exposure-${hit.kind})`,
        location: loc(path, sf, hit.arg),
        evidence: `Heuristic "pg-resjson-exposure-${hit.kind}": an Express handler's res.json(...) ${label} instead of an explicit safe projection.`,
        impact: "The client receives internal columns it was never meant to see — credential material, tokens, or other PII riding along with the rest of the row.",
        fix: "Build an explicit response DTO that lists only the fields the client needs, rather than returning the fetched row/object (or a spread of it) as-is.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

export function detectPgResponseExposureFindings(files: SourceInput[]): Finding[] {
  return files.filter((f) => SOURCE_EXT.test(f.path)).flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

function walk(dir: string, root: string, out: SourceInput[]): void {
  for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (SKIP_DIRS.has(entry)) continue;
    if (isDirectory) walk(full, root, out);
    else if (SOURCE_EXT.test(entry)) out.push({ path: relative(root, full), text: readFileSync(full, "utf8") });
  }
}

export function scanPgResponseExposure(projectDir: string): Finding[] {
  const files: SourceInput[] = [];
  walk(projectDir, projectDir, files);
  return detectPgResponseExposureFindings(files);
}
