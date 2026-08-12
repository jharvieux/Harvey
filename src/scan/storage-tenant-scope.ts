// #1198 STORAGE-TENANT-SCOPE — a Supabase storage object path built from the caller-supplied
// filename alone, with no tenant prefix or ownership check. OWASP Multi-Tenant Application
// Security Cheat Sheet section 6 ("Use tenant-prefixed paths for file storage", "Validate tenant
// ownership before serving files"). Found as a measured gap by that sheet's independent corpus
// (owasp-multitenant.entries.ts, P-OWASP-MT-STORAGE-PATH).
//
//   supabase.storage.from("attachments").upload(filename, file);    // no tenant prefix
//   supabase.storage.from("attachments").download(filename);       // no ownership check
//
// One tenant overwrites and reads another's objects in a shared bucket.
//
// DISTINCT FROM AUTH-upload-no-limit (leftover-auth.ts): that heuristic flags a storage .upload()
// with no size/MIME guard — an unrelated defect that also fires on this same fixture. Both can be
// true of the same call; this one is its own taxonomy so a reviewer does not mistake the adjacent
// High for coverage of the tenant-path class (the #1062 masking shape, in miniature — see the
// corpus entry note).
//
// The path is judged by NAME, not full taint: does the path expression's printed text mention a
// tenant/org discriminator or a session/auth accessor ANYWHERE? A bare parameter (`filename`) does
// not; `${tenantId}/${filename}` or `${session.user.tenantId}/${filename}` does. A plain string
// literal path (a fixed, non-caller-supplied name) is not this bug and is excluded.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// Clears the finding: the path mentions a tenant/org discriminator, or a verified-session accessor
// (the sheet's own remedy — "validate tenant ownership before serving files" via the session).
const TENANT_OR_SESSION_HINT = /(tenant|organi[sz]ation|\borg\b|workspace|session|auth|claims|jwt|principal|viewer|membership)/i;

const STORAGE_METHOD = /^(upload|download)$/;

// `<client>.storage.from("<bucket>").upload(...)` / `.download(...)` — the receiver one level down
// must be a `.from(...)` call whose OWN receiver mentions `.storage`.
function isStorageFromChain(expr: ts.Expression): boolean {
  if (!ts.isCallExpression(expr) || !ts.isPropertyAccessExpression(expr.expression)) return false;
  if (expr.expression.name.text !== "from") return false;
  return /\.storage\b/.test(expr.expression.expression.getText());
}

function isFunctionLike(n: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isConstructorDeclaration(n)
  );
}

function enclosingFunction(n: ts.Node): ts.Node | undefined {
  for (let cur: ts.Node | undefined = n.parent; cur; cur = cur.parent) if (isFunctionLike(cur)) return cur;
  return undefined;
}

// `const <name> = <initializer>` declared in the same function — so a path built once
// (`const path = \`${tenantId}/${filename}\`;`) and passed by name still reads its tenant wording.
function localBinding(fn: ts.Node, name: string): ts.Expression | undefined {
  let found: ts.Expression | undefined;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer) {
      found = node.initializer;
      return;
    }
    if (!isFunctionLike(node) || node === fn) ts.forEachChild(node, visit);
  };
  ts.forEachChild(fn, visit);
  return found;
}

// The expression whose text is judged for tenant/session wording: the argument itself, or — when
// it is a bare identifier — the local binding it resolves to in the enclosing function.
function resolvePathExpr(objectPath: ts.Expression, call: ts.CallExpression): ts.Expression {
  if (!ts.isIdentifier(objectPath)) return objectPath;
  const fn = enclosingFunction(call);
  return (fn && localBinding(fn, objectPath.text)) ?? objectPath;
}

// #1198/#1344: the path came OUT OF A ROW the caller already had to be entitled to fetch.
// `const { data: job } = await supabase.from("export_jobs").select("*").eq("id", id).single();
// storage.from("exports").download(job.storage_path)` is the SAFEST real-world spelling of this
// download, and the name test above scored it identically to the unguarded one — `job.storage_path`
// contains none of the tenant/session words, because a DB-derived path never does. Two detectors
// then disagreed about one route: harvey-path-traversal was deliberately taught to stay silent on
// exactly this shape (#1220), while this one reported High.
//
// Same reasoning #1220 encoded as its `$Q.eq(...)` sanitizer, expressed for an AST detector: the
// entitlement lives in the QUERY that produced the row, not in the path string. Scoped to the
// enclosing function, and to a binding whose initializer is a real `.from(...).select(...)` chain —
// a bare property access on an unresolved name still reports.
function rootIdentifier(expr: ts.Expression): string | undefined {
  let cur: ts.Expression = expr;
  while (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) ? cur.text : undefined;
}

function isDbReadChain(expr: ts.Expression): boolean {
  const call = ts.isAwaitExpression(expr) ? expr.expression : expr;
  if (!ts.isCallExpression(call)) return false;
  const names = callChainNames(call);
  return names.includes("from") && (names.includes("select") || names.includes("single"));
}

// Does `name` bind, in this function, to the result of a DB read? Handles both the plain
// `const row = await …` form and the destructured `const { data: row } = await …` Supabase idiom,
// which is the one that actually appears and which localBinding above cannot see.
function bindsToDbRead(fn: ts.Node, name: string): boolean {
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isVariableDeclaration(node) && node.initializer && isDbReadChain(node.initializer)) {
      if (ts.isIdentifier(node.name) && node.name.text === name) found = true;
      else if (ts.isObjectBindingPattern(node.name) && node.name.elements.some((el) => ts.isIdentifier(el.name) && el.name.text === name)) found = true;
      if (found) return;
    }
    if (!isFunctionLike(node) || node === fn) ts.forEachChild(node, visit);
  };
  ts.forEachChild(fn, visit);
  return found;
}

function pathIsDbDerived(objectPath: ts.Expression, call: ts.CallExpression): boolean {
  const root = rootIdentifier(objectPath);
  const fn = root === undefined ? undefined : enclosingFunction(call);
  return fn !== undefined && root !== undefined && bindsToDbRead(fn, root);
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && STORAGE_METHOD.test(n.expression.name.text)) {
      const method = n.expression.name.text;
      if (isStorageFromChain(n.expression.expression)) {
        const objectPath = n.arguments[0];
        if (
          objectPath &&
          !ts.isStringLiteralLike(objectPath) &&
          !TENANT_OR_SESSION_HINT.test(resolvePathExpr(objectPath, n).getText(sf)) &&
          !pathIsDbDerived(objectPath, n)
        ) {
          findings.push(
            mechanicalFinding({
              id: `STORAGE-path-no-tenant-${method}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${n.getStart(sf)}`,
              title: `${path} — storage ${method}() path has no tenant prefix or ownership check`,
              severity: "High",
              category: "Broken access control",
              taxonomy: "Storage object path without a tenant prefix (cross-tenant object read/overwrite)",
              location: loc(path, sf, n),
              evidence: `Heuristic "storage-tenant-scope" matched \`storage.from(...).${method}(${objectPath.getText(sf)}, …)\`, whose path does not mention a tenant/org discriminator or a session accessor.`,
              impact:
                "In a shared bucket, one tenant can overwrite or read another tenant's object by supplying the same filename — the path is the only isolation gate and it carries no tenant scope.",
              fix: "Prefix the object path with the tenant/org id from the verified session (e.g. `${session.user.tenantId}/${filename}`), and validate the caller owns that prefix before serving a download.",
              precisionTier: "review",
            }),
          );
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectStorageTenantScopeFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
