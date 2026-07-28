// #680 SECRET-ROTATION-PAIR — a static bearer/secret that is verified with a SINGLE equality or
// HMAC check and has NO dual-secret acceptance window. When a webhook/auth secret is checked with
// exactly `timingSafeEqual(sig, process.env.X)` or `header === process.env.X` and the codebase
// never reads a sibling rotation variant (`X_PREVIOUS`/`X_OLD`/`X_NEXT`/`X_CURRENT`/`X_2`) and the
// comparison does not already accept more than one secret, then rotating that secret is a hard
// cutover: the instant the new value is deployed, every request still signed with the old value is
// rejected. The rotation-safe form keeps a short window where BOTH the current and previous secret
// verify — a sibling env read or an "accepts more than one secret" comparison (an array `.some()`/
// `.includes()` of env values, or two `timingSafeEqual` calls OR'd).
//
// [when: an inbound secret-verify site exists] — inter-service seams only. The detector is inert
// (returns []) for a repo with zero secret-verify comparison sites: a plain app that never checks a
// webhook/bearer secret against process.env produces nothing. The AST shape is the primary gate,
// not the file path.
//
// Review tier, never free-count: the AST proves a single-secret verify with no sibling variant
// read, not that rotation is operationally impossible — the pair could live in a secret store the
// code never names. The `===`/`!==` shape additionally requires a secret-ish env name AND a
// non-literal other side, so config compares (`process.env.NODE_ENV === "production"`) never fire.

import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

// The `===`/`!==` verify shape needs a secret-ish name to distinguish a signature check from a
// config compare. timingSafeEqual is high-signal on its own and does not require this.
const SECRET_NAME = /(SECRET|TOKEN|SIGNATURE|SIGNING|WEBHOOK|HMAC|API[_-]?KEY|PASSWORD|PASSWD|BEARER|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|_KEY$)/i;

// Rotation-pair affixes: `WEBHOOK_SECRET` vs `WEBHOOK_SECRET_PREVIOUS` / `WEBHOOK_SECRET_2`.
const ROTATION_AFFIX_SUFFIX = /_(PREVIOUS|PREV|OLD|NEXT|CURRENT|CUR|2)$/i;
const ROTATION_AFFIX_PREFIX = /^(PREVIOUS|PREV|OLD|NEXT|CURRENT|CUR)_/i;

function baseName(name: string): string {
  return name.replace(ROTATION_AFFIX_SUFFIX, "").replace(ROTATION_AFFIX_PREFIX, "");
}

function isProcessEnv(node: ts.Expression): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "process" &&
    node.name.text === "env"
  );
}

// The env var name an expression's value derives from, unwrapping the wrappers that commonly sit
// around a secret read: `Buffer.from(process.env.X)`, `process.env.X ?? ""`, casts, parens.
function envNameOf(expr: ts.Expression, bindings: Map<string, string>): string | undefined {
  let e: ts.Expression = expr;
  for (;;) {
    if (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e)) {
      e = e.expression;
    } else if (ts.isBinaryExpression(e) && (e.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken || e.operatorToken.kind === ts.SyntaxKind.BarBarToken)) {
      e = e.left; // `process.env.X ?? ""` / `process.env.X || ""` — the env read is the left operand
    } else if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && e.expression.name.text === "from" && e.arguments[0]) {
      e = e.arguments[0]; // Buffer.from(process.env.X, "utf8")
    } else {
      break;
    }
  }
  if (ts.isPropertyAccessExpression(e) && isProcessEnv(e.expression)) return e.name.text;
  if (ts.isElementAccessExpression(e) && isProcessEnv(e.expression) && e.argumentExpression && ts.isStringLiteralLike(e.argumentExpression)) {
    return e.argumentExpression.text;
  }
  if (ts.isIdentifier(e)) return bindings.get(e.text);
  return undefined;
}

// Local `const secret = process.env.X` (with the usual fallback/wrapper) → { secret: "X" }.
function collectEnvBindings(sf: ts.SourceFile): Map<string, string> {
  const bindings = new Map<string, string>();
  const visit = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      const name = envNameOf(n.initializer, bindings);
      if (name) bindings.set(n.name.text, name);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return bindings;
}

function collectEnvReads(sf: ts.SourceFile, into: Set<string>): void {
  const visit = (n: ts.Node) => {
    if (ts.isPropertyAccessExpression(n) && isProcessEnv(n.expression)) into.add(n.name.text);
    else if (ts.isElementAccessExpression(n) && isProcessEnv(n.expression) && n.argumentExpression && ts.isStringLiteralLike(n.argumentExpression)) {
      into.add(n.argumentExpression.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}

function isTimingSafeEqual(node: ts.CallExpression): boolean {
  const callee = node.expression;
  if (ts.isIdentifier(callee)) return callee.text === "timingSafeEqual";
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text === "timingSafeEqual";
  return false;
}

// The file already accepts more than one secret (a rotation window in code): an array literal of
// two-or-more env reads (fed to `.some()`/`.includes()`), or a boolean expression OR-ing two
// timingSafeEqual calls.
function hasMultiSecretAcceptance(sf: ts.SourceFile, bindings: Map<string, string>): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isArrayLiteralExpression(n)) {
      const envCount = n.elements.filter((el) => envNameOf(el, bindings)).length;
      if (envCount >= 2) found = true;
    }
    if (ts.isBinaryExpression(n) && (n.operatorToken.kind === ts.SyntaxKind.BarBarToken || n.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken)) {
      let calls = 0;
      const count = (m: ts.Node) => {
        if (ts.isCallExpression(m) && isTimingSafeEqual(m)) calls++;
        ts.forEachChild(m, count);
      };
      count(n);
      if (calls >= 2) found = true;
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return found;
}

const EQUALITY_OPS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);

interface VerifySite {
  envName: string;
  node: ts.Node;
  kind: "timingSafeEqual" | "equality";
}

function collectVerifySites(sf: ts.SourceFile, bindings: Map<string, string>): VerifySite[] {
  const sites: VerifySite[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && isTimingSafeEqual(n)) {
      const names = n.arguments.map((a) => envNameOf(a, bindings)).filter((x): x is string => Boolean(x));
      // A single distinct env name is the single-secret shape; two distinct names IS a rotation
      // window in the same call, which hasMultiSecretAcceptance / distinctness below clears.
      const distinct = [...new Set(names)];
      if (distinct.length === 1) sites.push({ envName: distinct[0]!, node: n, kind: "timingSafeEqual" });
    } else if (ts.isBinaryExpression(n) && EQUALITY_OPS.has(n.operatorToken.kind)) {
      const leftEnv = envNameOf(n.left, bindings);
      const rightEnv = envNameOf(n.right, bindings);
      const envName = leftEnv ?? rightEnv;
      const other = leftEnv ? n.right : n.left;
      // A config compare (`process.env.NODE_ENV === "production"`) has a literal other side; a
      // signature check compares the secret against a runtime value. Require a secret-ish name too.
      if (envName && !(leftEnv && rightEnv) && SECRET_NAME.test(envName) && !ts.isStringLiteralLike(other) && !ts.isNumericLiteral(other)) {
        sites.push({ envName, node: n, kind: "equality" });
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return sites;
}

function hasRotationSibling(envName: string, allEnvNames: Set<string>): boolean {
  const base = baseName(envName);
  let count = 0;
  for (const n of allEnvNames) if (baseName(n) === base) count++;
  return count >= 2;
}

export function detectSecretRotationFindings(files: SourceInput[]): Finding[] {
  const sources = files.filter((f) => SOURCE_EXT.test(f.path)).map((f) => ({ path: f.path, sf: parse(f.path, f.text) }));

  // Rotation-pair siblings can live in any file (the verify reads X, the code reads X_PREVIOUS in a
  // config module), so the sibling set is collected across the WHOLE codebase first.
  const allEnvNames = new Set<string>();
  for (const { sf } of sources) collectEnvReads(sf, allEnvNames);

  const findings: Finding[] = [];
  for (const { path, sf } of sources) {
    const bindings = collectEnvBindings(sf);
    const sites = collectVerifySites(sf, bindings);
    if (sites.length === 0) continue;
    if (hasMultiSecretAcceptance(sf, bindings)) continue;

    const emitted = new Set<string>();
    for (const site of sites) {
      if (hasRotationSibling(site.envName, allEnvNames) || emitted.has(site.envName)) continue;
      emitted.add(site.envName);
      const how = site.kind === "timingSafeEqual" ? `timingSafeEqual(…, process.env.${site.envName})` : `=== process.env.${site.envName}`;
      findings.push(
        mechanicalFinding({
          id: `SECRET-rotation-pair-${site.envName}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
          title: `${path} — \`${site.envName}\` verified with no rotation-pair acceptance window`,
          severity: "Medium",
          category: "Secrets management",
          taxonomy: "Static secret verified with no rotation-pair acceptance window",
          location: loc(path, sf, site.node),
          evidence: `Heuristic "secret-rotation-pair": the secret \`process.env.${site.envName}\` is verified with a single ${how} and no sibling rotation variant (e.g. \`${baseName(site.envName)}_PREVIOUS\`) is read anywhere in the codebase, nor does the comparison accept more than one secret.`,
          impact: "Rotating this secret is a hard cutover: the moment the new value is deployed, every in-flight request still signed with the old value is rejected. A dual-secret window (accept current AND previous during rollover) removes that outage.",
          fix: `Accept both the current and a previous secret during rotation — read a \`${baseName(site.envName)}_PREVIOUS\` (or equivalent) alongside \`${site.envName}\` and pass the verify if EITHER matches, then retire the old value after the window.`,
          precisionTier: "review",
        }),
      );
    }
  }
  return findings;
}

function walk(dir: string, root: string, out: SourceInput[]): void {
  for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (SKIP_DIRS.has(entry)) continue;
    if (isDirectory) walk(full, root, out);
    else if (SOURCE_EXT.test(entry)) out.push({ path: relative(root, full), text: readFileSync(full, "utf8") });
  }
}

export function scanSecretRotation(projectDir: string): Finding[] {
  const files: SourceInput[] = [];
  walk(projectDir, projectDir, files);
  return detectSecretRotationFindings(files);
}
