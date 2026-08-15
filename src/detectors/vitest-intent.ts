// M8 (test intent) — vitest-SPECIFIC test-quality detectors, the runner-gated complement to the
// jest/vitest-shared classes in src/detectors/test-intent.ts (#629). These match anti-patterns
// that only exist in a vitest suite, so every class is gated on vitest actually being the runner
// (jest has no `vi.*`, no `import.meta.vitest`, no `vi.hoisted`) — on a jest/mocha project the
// whole pass returns nothing rather than false-firing:
//
//   • UNRESTORED-SPY   — `vi.spyOn(...)` with no `mockRestore()`/`vi.restoreAllMocks()` anywhere
//                        in the file, so the spy's replacement implementation leaks into every
//                        later test that touches the same object (order-dependent flakiness).
//   • IN-SOURCE-TEST   — an `if (import.meta.vitest)` in-source test block living inside a PRODUCT
//                        module: its `it/expect` lines are counted as covered lines OF that module,
//                        inflating the module's own coverage unless the config excludes them.
//   • HOISTED-MISUSE   — a `vi.hoisted(() => …)` factory that references a module-scope binding
//                        (an import or a top-level const/let). `vi.hoisted` is lifted above all
//                        imports, so those bindings do not exist yet when the factory runs (TDZ /
//                        undefined) — the hoist guarantee is defeated.
//
// EXCLUDED (#660, the "vi.mock-factory hoisting reference" remainder split from #629): a static
// detector for a `vi.mock(spec, factory)` whose factory references a non-hoisted, non-`mock`-prefixed
// module binding was evaluated and DELIBERATELY NOT SHIPPED — no crisp signature clears the
// zero-false-fire precision bar. Empirically (vitest 4.1.10, same hoisting model as our 3.2):
// whether the reference throws "Cannot access X before initialization" depends on runtime IMPORT
// ORDER, not on the reference itself. A lazy closure ref (`() => ({ f: () => binding })`) always
// passes; an eager read (`() => binding` / `() => ({ ...binding })`) throws ONLY when the mocked
// module is pulled in by an EAGER static import before the binding initializes — and passes when the
// consumer is loaded via a later dynamic import. Our OWN `src/scan/mechanical.test.ts` eagerly reads
// two non-`mock`-prefixed top-level consts inside a `vi.mock` factory and is correct, so any
// single-file signature keying on the reference false-fires on the dogfood; distinguishing the
// erroring case needs cross-module import-ordering analysis, out of scope for an AST pass. #660 is
// left OPEN with this evidence; also, the modern-vitest static "must be `mock`-prefixed" rule the
// issue assumes no longer exists (Vite rewrites imports to hoisted `await import()`).
//
// Method mirrors test-intent.ts: TypeScript compiler API over SourceInput[], Finding[] out, every
// class gated by a positive+negative fixture pair (vitest-intent.test.ts, the #61 discipline).

import { posix } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import type { PathScopedClass } from "../scan/path-scope.js";
import { parse, type NextId, type SourceInput } from "./common.js";
import { isTestFile } from "./test-intent.js";

const PARSEABLE = /\.([cm]?[jt]s|[jt]sx)$/;

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function makeFinding(
  nextId: NextId,
  input: {
    title: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    taxonomy: string;
    location: string;
    evidence: string;
    impact: string;
    fix: string;
    value: number;
    ease: number;
    safety: number;
  },
): Finding {
  // Heuristic classes — review is the conservative precision floor; an untiered finding
  // silently mis-scores in a calibration scorer (#327, same default as perf-code/test-intent).
  return { id: nextId(), status: "Open", category: "Test quality", precisionTier: "review", ...input };
}

// --- vitest-runner gate ------------------------------------------------------------
// The classes below only make sense when vitest is the runner. `vi.*`/`import.meta.vitest` are
// vitest-only APIs, so their presence anywhere in the set — or a vitest dependency in a
// package.json — is proof enough; a jest/mocha project shows none of these and the pass is silent.
const VITEST_API = /\bfrom\s+['"]vitest['"]|import\.meta\.vitest|\bvi\.(spyOn|hoisted|mock|fn|mocked|stubGlobal|stubEnv)\b/;

function isVitestProject(files: readonly SourceInput[]): boolean {
  for (const f of files) {
    if (posix.basename(f.path) === "package.json") {
      try {
        const pkg = JSON.parse(f.text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
        if ((pkg.dependencies && "vitest" in pkg.dependencies) || (pkg.devDependencies && "vitest" in pkg.devDependencies)) return true;
      } catch {
        // malformed package.json — fall through to the API-signal check
      }
    }
    if (VITEST_API.test(f.text)) return true;
  }
  return false;
}

export function vitestTestFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => PARSEABLE.test(file.path) && isTestFile(file.path));
}

export function vitestInSourceFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => PARSEABLE.test(file.path) && !isTestFile(file.path));
}

const vitestClass = (
  rowId: string,
  classId: string,
  selectorSymbol: string,
  select: PathScopedClass["select"],
  convention: string,
  classes: string,
): PathScopedClass => ({
  rowId,
  detector: "vitest-intent",
  classId,
  ownerFile: "src/detectors/vitest-intent.ts",
  selectorSymbol,
  convention,
  select,
  applicable: (files) => isVitestProject(files),
  classes,
});

export const VITEST_INTENT_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [
  vitestClass(
    "M1-PATHSCOPE-M8-VITEST-UNRESTORED-SPY-00",
    "M8 — Unrestored vi.spyOn",
    "vitestTestFiles",
    vitestTestFiles,
    "parseable Vitest `*.test.*`, `*.spec.*`, and `__tests__/**` modules",
    "a Vitest spy whose replacement leaks into later tests",
  ),
  vitestClass(
    "M1-PATHSCOPE-M8-VITEST-IN-SOURCE-00",
    "M8 — In-source testing coverage-crediting",
    "vitestInSourceFiles",
    vitestInSourceFiles,
    "parseable non-test product modules in a Vitest project",
    "an in-source `import.meta.vitest` block that inflates its module's coverage",
  ),
  vitestClass(
    "M1-PATHSCOPE-M8-VITEST-HOISTED-00",
    "M8 — vi.hoisted misuse",
    "vitestTestFiles",
    vitestTestFiles,
    "parseable Vitest `*.test.*`, `*.spec.*`, and `__tests__/**` modules",
    "a `vi.hoisted` factory reading an uninitialized module-scope binding",
  ),
];

// --- UNRESTORED-SPY ----------------------------------------------------------------

function isViCall(node: ts.CallExpression, method: string): boolean {
  const callee = node.expression;
  return (
    ts.isPropertyAccessExpression(callee) &&
    ts.isIdentifier(callee.expression) &&
    callee.expression.text === "vi" &&
    callee.name.text === method
  );
}

// A file clears the leak if it restores mocks ANYWHERE: `vi.restoreAllMocks()`, a `.mockRestore()`
// on a spy handle, or a `restoreMocks` config token (the project-level auto-restore). Presence
// anywhere is intentionally lenient — the precision gate (zero false-fires on the dogfood and
// calibration) matters more than catching a spy that is restored in one test but leaks in another.
function hasRestoreEvidence(sf: ts.SourceFile, text: string): boolean {
  if (/\brestoreMocks\b/.test(text)) return true; // vitest config auto-restore
  let found = false;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isCallExpression(node)) {
      if (isViCall(node, "restoreAllMocks")) found = true;
      else if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "mockRestore") found = true;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

function detectUnrestoredSpy(file: SourceInput, sf: ts.SourceFile, nextId: NextId): Finding[] {
  if (hasRestoreEvidence(sf, file.text)) return [];
  let firstSpy: ts.CallExpression | undefined;
  const visit = (node: ts.Node) => {
    if (!firstSpy && ts.isCallExpression(node) && isViCall(node, "spyOn")) firstSpy = node;
    ts.forEachChild(node, visit);
  };
  visit(sf);
  if (!firstSpy) return [];
  return [
    makeFinding(nextId, {
      title: "Unrestored `vi.spyOn` leaks across tests",
      severity: "Medium",
      confidence: "Review",
      taxonomy: "M8 — Unrestored vi.spyOn",
      location: `${file.path}:${lineOf(sf, firstSpy)}`,
      evidence:
        "This file installs a `vi.spyOn(...)` but never calls `vi.restoreAllMocks()`/`mockRestore()` (no afterEach/afterAll restore, no `restoreMocks` config) — the spy's replacement implementation stays installed for every later test that touches the same object.",
      impact: "Later tests silently run against the spy's mock behavior instead of the real object, producing order-dependent passes and flaky failures that vanish when a test is run in isolation.",
      fix: "Restore the spy: add `afterEach(() => vi.restoreAllMocks())` (or call `.mockRestore()` on the returned handle), or enable `restoreMocks: true` in the vitest config.",
      value: 3,
      ease: 4,
      safety: 5,
    }),
  ];
}

// --- IN-SOURCE-TEST (coverage-crediting) -------------------------------------------

// `import.meta.vitest` — a vitest-only property that is `undefined` in a normal build and the
// test context only in a vitest run. Its use inside a PRODUCT module is vitest's in-source
// testing: the `it/expect` lines then count as covered lines of that very module.
function isImportMetaVitest(node: ts.Node): boolean {
  return (
    ts.isPropertyAccessExpression(node) &&
    node.name.text === "vitest" &&
    ts.isMetaProperty(node.expression) &&
    node.expression.keywordToken === ts.SyntaxKind.ImportKeyword
  );
}

function detectInSourceTest(file: SourceInput, sf: ts.SourceFile, nextId: NextId): Finding[] {
  let hit: ts.Node | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    if (isImportMetaVitest(node)) hit = node;
    ts.forEachChild(node, visit);
  };
  visit(sf);
  if (!hit) return [];
  return [
    makeFinding(nextId, {
      title: "In-source `import.meta.vitest` test block inflates module coverage",
      severity: "Low",
      confidence: "Review",
      taxonomy: "M8 — In-source testing coverage-crediting",
      location: `${file.path}:${lineOf(sf, hit)}`,
      evidence:
        "This product module contains an in-source `import.meta.vitest` test block — its `it/expect` lines are counted as covered lines of the module itself, so the module's coverage number reflects the tests living in it rather than the code they exercise.",
      impact: "Coverage for the module reads higher than the code is actually tested at, hiding untested branches behind the in-source test's own lines.",
      fix: "Exclude in-source test blocks from coverage (vitest `coverage.exclude` / `includeSource` remap), or move the tests into a sibling `*.test.ts` so the coverage credit tracks the code under test.",
      value: 2,
      ease: 3,
      safety: 5,
    }),
  ];
}

// --- HOISTED-MISUSE ----------------------------------------------------------------

// Module-scope bindings that a `vi.hoisted` factory must NOT reference: imports and top-level
// const/let. `vi.hoisted` is lifted above every import, so these do not exist when it runs.
// Function/class declarations are hoisted by JS itself, and a `const x = vi.hoisted(...)` binding
// is legitimately available — both are excluded so referencing them is not flagged.
function moduleScopeBindings(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && stmt.importClause) {
      const clause = stmt.importClause;
      if (clause.name) names.add(clause.name.text);
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) names.add(clause.namedBindings.name.text);
        else for (const el of clause.namedBindings.elements) names.add(el.name.text);
      }
    } else if (ts.isVariableStatement(stmt) && (stmt.declarationList.flags & ts.NodeFlags.Const || stmt.declarationList.flags & ts.NodeFlags.Let)) {
      for (const decl of stmt.declarationList.declarations) {
        // `const x = vi.hoisted(...)` IS hoisted — its binding is legitimately referenceable.
        if (decl.initializer && ts.isCallExpression(decl.initializer) && isViCall(decl.initializer, "hoisted")) continue;
        if (ts.isIdentifier(decl.name)) names.add(decl.name.text);
      }
    }
  }
  return names;
}

// Names declared INSIDE the factory (params + local const/let/var/function) — these shadow the
// module scope and are not the misuse.
function localFactoryNames(fn: ts.FunctionLikeDeclaration): Set<string> {
  const names = new Set<string>();
  for (const p of fn.parameters) if (ts.isIdentifier(p.name)) names.add(p.name.text);
  const visit = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) names.add(node.name.text);
    else if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) names.add(node.name.text);
    ts.forEachChild(node, visit);
  };
  if (fn.body) visit(fn.body);
  return names;
}

function referencedModuleBinding(fn: ts.FunctionLikeDeclaration, forbidden: Set<string>): string | undefined {
  const local = localFactoryNames(fn);
  let hit: string | undefined;
  const visit = (node: ts.Node) => {
    if (hit) return;
    // Skip the property-name side of `a.b` — only `a` is a real binding reference.
    if (ts.isPropertyAccessExpression(node)) {
      visit(node.expression);
      return;
    }
    if (ts.isIdentifier(node) && forbidden.has(node.text) && !local.has(node.text)) {
      hit = node.text;
      return;
    }
    ts.forEachChild(node, visit);
  };
  if (fn.body) visit(fn.body);
  return hit;
}

function detectHoistedMisuse(file: SourceInput, sf: ts.SourceFile, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const forbidden = moduleScopeBindings(sf);
  if (forbidden.size === 0) return findings;
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && isViCall(node, "hoisted")) {
      const factory = node.arguments[0];
      if (factory && (ts.isArrowFunction(factory) || ts.isFunctionExpression(factory))) {
        const ref = referencedModuleBinding(factory, forbidden);
        if (ref) {
          findings.push(
            makeFinding(nextId, {
              title: `\`vi.hoisted\` factory references non-hoisted binding \`${ref}\``,
              severity: "Medium",
              confidence: "Likely",
              taxonomy: "M8 — vi.hoisted misuse",
              location: `${file.path}:${lineOf(sf, node)}`,
              evidence: `The \`vi.hoisted(...)\` factory references \`${ref}\`, a module-scope binding (import or top-level const/let). \`vi.hoisted\` is lifted above all imports, so \`${ref}\` is uninitialized (TDZ) or undefined when the factory runs — the hoisting guarantee is defeated.`,
              impact: "The hoisted value is built from a binding that does not exist yet, so it silently reads `undefined` (or throws a ReferenceError) — the mock/setup it feeds is wrong, and any test relying on it is meaningless or crashes.",
              fix: "Make the factory self-contained: move the referenced value's construction INSIDE the `vi.hoisted` factory, or wrap that dependency in its own `vi.hoisted(...)` and read it from there.",
              value: 4,
              ease: 3,
              safety: 5,
            }),
          );
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// --- orchestrator ------------------------------------------------------------------

/**
 * Runs the vitest-specific M8 test-intent checks over the given source set. Returns [] unless the
 * project is a vitest project (jest/mocha suites show none of these APIs). Ids VITEST-*.
 */
export function detectVitestIntentFindings(files: SourceInput[]): Finding[] {
  const parseable = files.filter((f) => PARSEABLE.test(f.path));
  if (!isVitestProject(files)) return [];
  let n = 0;
  const nextId: NextId = () => `VITEST-${String(++n).padStart(2, "0")}`;
  const findings: Finding[] = [];
  const testPaths = new Set(vitestTestFiles(parseable).map((file) => file.path));
  const inSourcePaths = new Set(vitestInSourceFiles(parseable).map((file) => file.path));
  for (const file of parseable) {
    const sf = parse(file.path, file.text);
    if (testPaths.has(file.path)) {
      findings.push(...detectUnrestoredSpy(file, sf, nextId), ...detectHoistedMisuse(file, sf, nextId));
    } else if (inSourcePaths.has(file.path)) {
      findings.push(...detectInSourceTest(file, sf, nextId));
    }
  }
  return findings;
}
