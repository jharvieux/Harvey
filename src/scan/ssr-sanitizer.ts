// #1239 P-OWASP-REACT-SSR-SANITIZER — a BROWSER-ONLY HTML sanitizer called in a server-rendered
// module. OWASP React Security CS (draft), SSR Security: "Use a Server-Compatible Sanitization
// Library for SSR HTML". `dompurify` needs a browser DOM; on the server it throws, or — behind a
// `window` shim or a permissive build — hands the input back untouched.
//
// The reason this was silent is the point. Every dangerouslySetInnerHTML rule we have EXCLUDES an
// import-bound sanitizer wrap (N-XSS-IMPORT-SANITIZE pins that exclusion deliberately, and it is
// correct in a browser), so a DOMPurify call in a Server Component is read as protection by exactly
// the rules that would otherwise fire on the line. That is #1066's no-op-sanitizer lesson reached
// through a different mechanism: there the sanitizer was locally defined and fake, here it is a
// genuine, well-regarded library running where it cannot work. Unsanitized HTML injected during SSR
// renders BEFORE hydration and before any client-side guard, which is what makes the server-side
// layer the more critical of the two.
//
// Deliberate precision boundaries — each is the correct form and must stay silent:
//   - `isomorphic-dompurify` / `sanitize-html` — the specifier must be exactly `dompurify`;
//   - a module that supplies its own DOM (`createDOMPurify(new JSDOM("").window)`) — the documented
//     server recipe, cleared by the jsdom/happy-dom/linkedom import;
//   - a `'use client'` module — DOMPurify's home, never a finding.
// SERVER-RENDERED is asserted from positive evidence, never from the absence of 'use client' (a
// Vite SPA emits no directive at all and its DOMPurify calls are fine): a 'use server' module, a
// `server-only` import, an App Router server route file, or an ASYNC component — React has no async
// Client Components, so an async function returning JSX renders on the server by construction.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { leadingDirective, loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const BROWSER_ONLY_PACKAGE = "dompurify";
const SERVER_DOM_PACKAGE = /^(jsdom|happy-dom|linkedom)$/;
const SERVER_ROUTE_FILE = /(^|\/)(page|layout|template|route|default|middleware)\.[cm]?[jt]sx?$/;

type FunctionLike = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

function importedFrom(sf: ts.SourceFile, matches: (specifier: string) => boolean): ts.ImportDeclaration[] {
  return sf.statements.filter(
    (s): s is ts.ImportDeclaration => ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier) && matches(s.moduleSpecifier.text),
  );
}

interface SanitizerBindings {
  /** `DOMPurify` in `DOMPurify.sanitize(html)` — default or namespace import. */
  objects: Set<string>;
  /** `sanitize` in `sanitize(html)` — the named export, imported directly. */
  calls: Set<string>;
}

function domPurifyBindings(sf: ts.SourceFile): SanitizerBindings {
  const objects = new Set<string>();
  const calls = new Set<string>();
  for (const decl of importedFrom(sf, (spec) => spec === BROWSER_ONLY_PACKAGE)) {
    const clause = decl.importClause;
    if (!clause) continue;
    if (clause.name) objects.add(clause.name.text);
    if (clause.namedBindings) {
      if (ts.isNamespaceImport(clause.namedBindings)) objects.add(clause.namedBindings.name.text);
      else for (const el of clause.namedBindings.elements) {
        const exported = (el.propertyName ?? el.name).text;
        if (exported === "sanitize") calls.add(el.name.text);
      }
    }
  }
  return { objects, calls };
}

function sanitizerCalls(sf: ts.SourceFile, bindings: SanitizerBindings): ts.CallExpression[] {
  const hits: ts.CallExpression[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === "sanitize" && ts.isIdentifier(callee.expression) && bindings.objects.has(callee.expression.text)) hits.push(node);
      else if (ts.isIdentifier(callee) && bindings.calls.has(callee.text)) hits.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hits;
}

function isFunctionLike(node: ts.Node): node is FunctionLike {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node);
}

function isJsx(expr: ts.Expression): boolean {
  return ts.isJsxElement(expr) || ts.isJsxSelfClosingElement(expr) || ts.isJsxFragment(expr);
}

// A function RENDERS when it hands JSX back — an arrow's concise body, or a `return` belonging to
// this function rather than to a nested callable.
function rendersJsx(fn: FunctionLike): boolean {
  if (!fn.body) return false;
  if (!ts.isBlock(fn.body)) return isJsx(fn.body);
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (isFunctionLike(node)) return;
    if (ts.isReturnStatement(node) && node.expression && isJsx(node.expression)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(fn.body);
  return found;
}

function functionName(fn: FunctionLike): string {
  if ((ts.isFunctionDeclaration(fn) || ts.isMethodDeclaration(fn)) && fn.name) return fn.name.getText();
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  return "an anonymous component";
}

function enclosingAsyncComponent(node: ts.Node): FunctionLike | undefined {
  for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) {
    if (isFunctionLike(cur) && cur.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword) && rendersJsx(cur)) return cur;
  }
  return undefined;
}

function serverContext(path: string, sf: ts.SourceFile, call: ts.CallExpression): string | undefined {
  if (leadingDirective(sf) === "use server") return "the module carries the `'use server'` directive";
  if (importedFrom(sf, (spec) => spec === "server-only").length > 0) return "the module imports `server-only`";
  if (SERVER_ROUTE_FILE.test(path)) return "the file is an App Router server module with no `'use client'` directive";
  const fn = enclosingAsyncComponent(call);
  return fn ? `\`${functionName(fn)}\` is an async component — React has no async Client Components, so it renders on the server` : undefined;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  if (leadingDirective(sf) === "use client") return [];
  const bindings = domPurifyBindings(sf);
  if (bindings.objects.size === 0 && bindings.calls.size === 0) return [];
  // The documented server recipe supplies the DOM itself; DOMPurify then works exactly as designed.
  if (importedFrom(sf, (spec) => SERVER_DOM_PACKAGE.test(spec)).length > 0) return [];

  const findings: Finding[] = [];
  for (const call of sanitizerCalls(sf, bindings)) {
    const why = serverContext(path, sf, call);
    if (!why) continue;
    const location = loc(path, sf, call);
    findings.push(
      mechanicalFinding({
        // Per CALL SITE, not per file: a module may hold both a DOMPurify component and a
        // server-safe sibling, and only the first is a finding.
        id: `XSS-ssr-browser-sanitizer-${location.replace(/[^a-zA-Z0-9]+/g, "-")}`,
        title: `${path} — browser-only sanitizer runs on the server`,
        severity: "High",
        category: "Next.js/web footgun",
        taxonomy: "Browser-only sanitizer in a server-rendered component",
        location,
        evidence: `\`${call.getText(sf).replace(/\s+/g, " ").slice(0, 120)}\` — \`dompurify\` is imported here and ${why}. DOMPurify depends on browser DOM APIs it does not have in Node.`,
        impact: "The sanitizer call reads as protection to reviewers and to every dangerouslySetInnerHTML rule (all of them exclude an import-bound sanitizer wrap), but on the server it throws or returns the input unchanged. The raw HTML renders during SSR — before hydration, and before any client-side guard can run.",
        fix: "Swap `dompurify` for a server-compatible sanitizer (`isomorphic-dompurify` or `sanitize-html`), or construct DOMPurify against a supplied DOM (`createDOMPurify(new JSDOM('').window)`).",
        precisionTier: "high",
        cwe: ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
        owasp: ["A03:2021 - Injection"],
      }),
    );
  }
  return findings;
}

export function detectSsrSanitizerFindings(files: SourceInput[]): Finding[] {
  return files.flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanSsrSanitizer(projectDir: string): Finding[] {
  return detectSsrSanitizerFindings(walkSourceFiles(projectDir));
}
