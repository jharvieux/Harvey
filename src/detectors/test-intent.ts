// M8 (test intent) — mechanical detectors over TEST files for tests that are structurally
// unable to fail, the free/source-tier complement to the Stryker mutation scan
// (src/mutation-scan.ts). Stryker proves a test is WEAK (surviving mutants) but needs a fully
// configured target; these catch tests that are DEAD by construction from source alone (#372):
//
//   • MOCK-OF-SUBJECT   — vi.mock()/jest.mock() of the very module the test exercises, so the
//                         assertion checks the mock's canned return, not the real code.
//   • ASSERTION-FREE    — a test body that calls code but never asserts (coverage padding).
//   • TAUTOLOGICAL      — expect(x).toBe(x): the asserted value IS the expected value.
//   • SNAPSHOT-ONLY     — toMatchSnapshot() as the only assertion; "update snapshots" silently
//                         absorbs any regression it would ever catch (#372 comment).
//   • CALL-COUNT-ONLY   — toHaveBeenCalled/Times() as the only assertion; call count stands in
//                         for any claim about behavior (#372 comment).
//
// Method mirrors src/detectors/slop.ts: TypeScript compiler API over SourceInput[], Finding[]
// out, every class gated by a positive+negative fixture pair (test-intent.test.ts, the #61
// discipline). Complements — does not replace — the mutation scan: surviving mutants (#319)
// remain the ground truth for tests that are merely weak rather than structurally dead.

import { posix } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { parse, type NextId, type SourceInput } from "./common.js";

export function isTestFile(path: string): boolean {
  return /\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)__tests__\//.test(path);
}

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
  return { id: nextId(), status: "Open", category: "Test quality", ...input };
}

// --- test-block and assertion plumbing ---------------------------------------

// `it("...", fn)` / `test.each(rows)("...", fn)` / `describe("...", fn)` — the callable heads
// vitest/jest expose. skip/todo registrations can't fail by design, so they are exempt.
interface CallHead {
  base: string;
  mod?: string;
}

function callHead(node: ts.CallExpression): CallHead | undefined {
  const callee = node.expression;
  if (ts.isIdentifier(callee)) return { base: callee.text };
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
    return { base: callee.expression.text, mod: callee.name.text };
  }
  // it.each(table)("name", fn) — the registration call's callee is itself a call.
  if (ts.isCallExpression(callee)) return callHead(callee);
  return undefined;
}

const EXEMPT_MODS = new Set(["skip", "todo"]);
const TEST_HEADS = new Set(["it", "test"]);

function titleOf(node: ts.CallExpression, sf: ts.SourceFile): string {
  const arg = node.arguments[0];
  if (!arg) return "";
  if (ts.isStringLiteralLike(arg)) return arg.text;
  return arg.getText(sf);
}

function callbackOf(node: ts.CallExpression): ts.FunctionLikeDeclaration | undefined {
  for (const arg of node.arguments) {
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) return arg;
  }
  return undefined;
}

interface TestBlock {
  title: string;
  fullName: string; // enclosing describe titles + own title
  node: ts.CallExpression;
  fn: ts.FunctionLikeDeclaration;
  assertions: Assertion[];
}

interface Assertion {
  kind: "expect" | "assert" | "should";
  // Final matcher name of an expect chain (`toBe` in expect(x).not.toBe(y)); undefined for a
  // bare expect(x) that never invokes a matcher.
  matcher?: string;
  chain: string[]; // every property name in the chain (not, rejects, resolves, soft, ...)
  meta: boolean; // expect.assertions()/hasAssertions() — counting plumbing, not a value claim
  expectArg?: ts.Expression;
  matcherArg?: ts.Expression;
  node: ts.Node;
}

// expect roots are `expect(...)` and `expect.soft/poll/assertions/hasAssertions(...)` — a
// chained matcher call's callee is a CallExpression, not an identifier, so chains aren't
// double-counted.
function expectRoot(node: ts.CallExpression): { meta: boolean } | undefined {
  const callee = node.expression;
  if (ts.isIdentifier(callee) && callee.text === "expect") return { meta: false };
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === "expect") {
    return { meta: callee.name.text === "assertions" || callee.name.text === "hasAssertions" };
  }
  return undefined;
}

function buildExpectAssertion(root: ts.CallExpression, meta: boolean): Assertion {
  const chain: string[] = [];
  let matcher: string | undefined;
  let matcherArg: ts.Expression | undefined;
  let cur: ts.Node = root;
  let last: ts.Node = root;
  for (;;) {
    const parent: ts.Node | undefined = cur.parent;
    if (parent && ts.isPropertyAccessExpression(parent) && parent.expression === cur) {
      chain.push(parent.name.text);
      cur = parent;
    } else if (parent && ts.isCallExpression(parent) && parent.expression === cur) {
      matcher = chain[chain.length - 1];
      matcherArg = parent.arguments[0];
      cur = parent;
      last = parent;
    } else {
      break;
    }
  }
  return { kind: "expect", matcher, chain, meta, expectArg: root.arguments[0], matcherArg, node: last };
}

function collectAssertions(scope: ts.Node): Assertion[] {
  const out: Assertion[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const root = expectRoot(node);
      if (root) out.push(buildExpectAssertion(node, root.meta));
      const callee = node.expression;
      if (
        (ts.isIdentifier(callee) && callee.text === "assert") ||
        (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === "assert")
      ) {
        out.push({ kind: "assert", chain: [], meta: false, node });
      }
    }
    // chai's `value.should.equal(x)` — any .should property access is an assertion.
    if (ts.isPropertyAccessExpression(node) && node.name.text === "should") {
      out.push({ kind: "should", chain: [], meta: false, node });
    }
    ts.forEachChild(node, visit);
  };
  visit(scope);
  return out;
}

function collectTestBlocks(sf: ts.SourceFile): TestBlock[] {
  const blocks: TestBlock[] = [];
  const describeStack: string[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const head = callHead(node);
      if (head && !EXEMPT_MODS.has(head.mod ?? "")) {
        if (head.base === "describe") {
          const fn = callbackOf(node);
          if (fn && fn.body) {
            describeStack.push(titleOf(node, sf));
            visit(fn.body);
            describeStack.pop();
            return;
          }
        }
        if (TEST_HEADS.has(head.base)) {
          const fn = callbackOf(node);
          if (fn && fn.body) {
            const title = titleOf(node, sf);
            blocks.push({
              title,
              fullName: [...describeStack, title].filter(Boolean).join(" "),
              node,
              fn,
              assertions: collectAssertions(fn.body),
            });
            return;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return blocks;
}

// --- imports / mock plumbing --------------------------------------------------

interface ImportInfo {
  specifier: string;
  named: string[]; // default + named bindings
  namespace?: string; // `* as api`
}

function collectImports(sf: ts.SourceFile): ImportInfo[] {
  const out: ImportInfo[] = [];
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteralLike(stmt.moduleSpecifier)) continue;
    const info: ImportInfo = { specifier: stmt.moduleSpecifier.text, named: [] };
    const clause = stmt.importClause;
    if (clause?.name) info.named.push(clause.name.text);
    if (clause?.namedBindings) {
      if (ts.isNamespaceImport(clause.namedBindings)) info.namespace = clause.namedBindings.name.text;
      else for (const el of clause.namedBindings.elements) info.named.push(el.name.text);
    }
    out.push(info);
  }
  return out;
}

interface MockCall {
  specifier: string;
  node: ts.CallExpression;
  // A factory that re-imports the real module (importActual/requireActual) is a partial mock —
  // the real code still runs, so it is exempt from every mock-based class here.
  partial: boolean;
}

function collectModuleMocks(sf: ts.SourceFile): MockCall[] {
  const out: MockCall[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const { expression: obj, name } = node.expression;
      if (ts.isIdentifier(obj) && (obj.text === "vi" || obj.text === "jest") && (name.text === "mock" || name.text === "doMock")) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteralLike(arg)) {
          const factory = node.arguments[1];
          out.push({ specifier: arg.text, node, partial: !!factory && /importActual|requireActual|importOriginal/.test(factory.getText(sf)) });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function stripExt(p: string): string {
  return p.replace(/\.([cm]?[jt]s|[jt]sx)$/, "");
}

function subjectBasename(testPath: string): string {
  return stripExt(posix.basename(testPath)).replace(/\.(test|spec)$/, "");
}

// Resolves a relative or `@/`-alias import specifier to a file in the scanned source set.
// Bare package specifiers return undefined — they aren't in the set.
export function resolveModule(fromPath: string, specifier: string, byPath: ReadonlyMap<string, SourceInput>): SourceInput | undefined {
  let candidate: string;
  if (specifier.startsWith(".")) candidate = posix.normalize(posix.join(posix.dirname(fromPath), specifier));
  else if (specifier.startsWith("@/") || specifier.startsWith("~/")) candidate = specifier.slice(2);
  else return undefined;
  const base = stripExt(candidate);
  for (const p of [candidate, base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.mjs`, `${base}/index.ts`, `${base}/index.tsx`]) {
    const hit = byPath.get(p);
    if (hit) return hit;
  }
  return undefined;
}

// --- per-file context ----------------------------------------------------------

interface TestFileContext {
  file: SourceInput;
  sf: ts.SourceFile;
  blocks: TestBlock[];
  imports: ImportInfo[];
  mocks: MockCall[];
}

function contextFor(file: SourceInput): TestFileContext {
  const sf = parse(file.path, file.text);
  return { file, sf, blocks: collectTestBlocks(sf), imports: collectImports(sf), mocks: collectModuleMocks(sf) };
}

// --- MOCK-OF-SUBJECT (#372) -----------------------------------------------------

const MOCK_CONFIG_METHOD = /^mock/;

// The bindings a mock's module contributed that a test body actually INVOKES. Configuring the
// mock (`fn.mockReturnValue(...)`, `vi.mocked(fn)`) uses the binding as a receiver or argument,
// never as a direct call — so dependency mocks stay silent (the FP class #384 points out).
function invokesMockedBinding(ctx: TestFileContext, mock: MockCall): string | undefined {
  const imp = ctx.imports.find((i) => i.specifier === mock.specifier);
  if (!imp) return undefined;
  const named = new Set(imp.named);
  let hit: string | undefined;
  for (const block of ctx.blocks) {
    const visit = (node: ts.Node) => {
      if (hit) return;
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        if (ts.isIdentifier(callee) && named.has(callee.text)) hit = callee.text;
        else if (
          imp.namespace &&
          ts.isPropertyAccessExpression(callee) &&
          ts.isIdentifier(callee.expression) &&
          callee.expression.text === imp.namespace &&
          !MOCK_CONFIG_METHOD.test(callee.name.text)
        ) {
          hit = `${imp.namespace}.${callee.name.text}`;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(block.fn.body!);
    if (hit) break;
  }
  return hit;
}

function detectMockOfSubject(ctx: TestFileContext, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const subject = subjectBasename(ctx.file.path);
  for (const mock of ctx.mocks) {
    if (mock.partial) continue;
    const mockedBase = stripExt(posix.basename(mock.specifier));
    const basenameMatch = mockedBase === subject;
    const invoked = invokesMockedBinding(ctx, mock);
    if (!basenameMatch && !invoked) continue;
    findings.push(
      makeFinding(nextId, {
        title: "Test mocks the module it is testing",
        severity: "Medium",
        confidence: "Likely",
        taxonomy: "M8 — Mock of the subject under test",
        location: `${ctx.file.path}:${lineOf(ctx.sf, mock.node)}`,
        evidence: basenameMatch
          ? `\`mock("${mock.specifier}")\` mocks the module this test file is named after (\`${subject}\`) — every assertion checks the mock's canned return, not the real code.`
          : `\`mock("${mock.specifier}")\` is mocked, yet the test invokes \`${invoked}\` from that same module — the call hits the mock, so the assertion can never observe the real implementation.`,
        impact: "The test passes no matter what the real implementation does — false confidence with full coverage credit.",
        fix: "Un-mock the subject and mock only its dependencies (or use importActual for a partial mock of the parts that must stay real).",
        value: 4,
        ease: 3,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- ASSERTION-FREE (#372) -------------------------------------------------------

// A zero-assertion body that delegates to a local helper containing assertions (or to anything
// named like one) is NOT assertion-free — the classic FP class for this check.
const ASSERTION_HELPER_NAME = /^(assert|check|verify|expect|ensure)/i;

function localAssertionHelpers(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.body && collectAssertions(stmt.body).length > 0) {
      names.add(stmt.name.text);
    } else if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (
          ts.isIdentifier(decl.name) &&
          decl.initializer &&
          (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer)) &&
          decl.initializer.body &&
          collectAssertions(decl.initializer.body).length > 0
        ) {
          names.add(decl.name.text);
        }
      }
    }
  }
  return names;
}

function bodyCalls(block: TestBlock): string[] {
  const calls: string[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) calls.push(node.expression.text);
    else if (ts.isCallExpression(node)) calls.push(node.expression.getText());
    ts.forEachChild(node, visit);
  };
  visit(block.fn.body!);
  return calls;
}

function detectAssertionFree(ctx: TestFileContext, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  const helpers = localAssertionHelpers(ctx.sf);
  for (const block of ctx.blocks) {
    if (block.assertions.length > 0) continue;
    const calls = bodyCalls(block);
    if (calls.length === 0) continue; // empty body — dead weight, but it exercises nothing to miscredit
    if (calls.some((c) => helpers.has(c) || ASSERTION_HELPER_NAME.test(c))) continue;
    findings.push(
      makeFinding(nextId, {
        title: `Assertion-free test: "${block.title || "(unnamed)"}"`,
        severity: "Medium",
        confidence: "Likely",
        taxonomy: "M8 — Assertion-free test",
        location: `${ctx.file.path}:${lineOf(ctx.sf, block.node)}`,
        evidence: `The test body calls \`${calls[0]}\` but contains no expect/assert/should — it can only fail if the code throws, so it pads coverage while asserting nothing.`,
        impact: "Coverage numbers count this test, but no behavior regression short of a crash can ever fail it.",
        fix: "Assert on the call's observable result (return value, state change, emitted call args) — or delete the test.",
        value: 3,
        ease: 4,
        safety: 5,
      }),
    );
  }
  return findings;
}

// --- TAUTOLOGICAL / SNAPSHOT-ONLY / CALL-COUNT-ONLY (#372 + comment) ---------------

const EQUALITY_MATCHERS = new Set(["toBe", "toEqual", "toStrictEqual"]);
const SNAPSHOT_MATCHERS = new Set([
  "toMatchSnapshot",
  "toMatchInlineSnapshot",
  "toMatchFileSnapshot",
  "toThrowErrorMatchingSnapshot",
  "toThrowErrorMatchingInlineSnapshot",
]);
// Deliberately excludes toHaveBeenCalledWith and friends — asserting on call ARGUMENTS is a
// real behavioral claim; bare call-count is not.
const CALL_COUNT_MATCHERS = new Set(["toHaveBeenCalled", "toHaveBeenCalledTimes", "toBeCalled", "toBeCalledTimes", "toHaveBeenCalledOnce"]);

function isStableReference(e: ts.Expression | undefined): boolean {
  return !!e && (ts.isIdentifier(e) || ts.isPropertyAccessExpression(e));
}

function detectTautological(ctx: TestFileContext, nextId: NextId): Finding[] {
  const findings: Finding[] = [];
  for (const block of ctx.blocks) {
    for (const a of block.assertions) {
      if (a.kind !== "expect" || !a.matcher || !EQUALITY_MATCHERS.has(a.matcher) || a.chain.includes("not")) continue;
      if (!isStableReference(a.expectArg) || !isStableReference(a.matcherArg)) continue;
      const actual = a.expectArg!.getText(ctx.sf);
      if (actual !== a.matcherArg!.getText(ctx.sf)) continue;
      findings.push(
        makeFinding(nextId, {
          title: `Tautological assertion: \`expect(${actual}).${a.matcher}(${actual})\``,
          severity: "Medium",
          confidence: "Likely",
          taxonomy: "M8 — Tautological assertion",
          location: `${ctx.file.path}:${lineOf(ctx.sf, a.node)}`,
          evidence: `The asserted value and the expected value are the same expression (\`${actual}\`) — the comparison is true by definition and cannot fail.`,
          impact: "The test asserts nothing about the code under test; any regression passes.",
          fix: "Compare the actual result against an independently stated expected value (a literal or separately computed expectation).",
          value: 3,
          ease: 4,
          safety: 5,
        }),
      );
    }
  }
  return findings;
}

// SNAPSHOT-ONLY and CALL-COUNT-ONLY share one shape: every substantive assertion in the body
// belongs to one weak matcher family. A single value assertion alongside clears the test.
function detectOnlyClass(
  ctx: TestFileContext,
  nextId: NextId,
  matchers: ReadonlySet<string>,
  meta: { taxonomy: string; title: (t: string) => string; evidence: string; impact: string; fix: string; severity: Finding["severity"] },
): Finding[] {
  const findings: Finding[] = [];
  for (const block of ctx.blocks) {
    const substantive = block.assertions.filter((a) => !a.meta);
    if (substantive.length === 0) continue;
    if (!substantive.every((a) => a.kind === "expect" && !!a.matcher && matchers.has(a.matcher))) continue;
    findings.push(
      makeFinding(nextId, {
        title: meta.title(block.title || "(unnamed)"),
        severity: meta.severity,
        confidence: "Review",
        taxonomy: meta.taxonomy,
        location: `${ctx.file.path}:${lineOf(ctx.sf, block.node)}`,
        evidence: `Every assertion in the test is \`${substantive[0]?.matcher}\`-family. ${meta.evidence}`,
        impact: meta.impact,
        fix: meta.fix,
        value: 2,
        ease: 4,
        safety: 5,
      }),
    );
  }
  return findings;
}

function detectSnapshotOnly(ctx: TestFileContext, nextId: NextId): Finding[] {
  return detectOnlyClass(ctx, nextId, SNAPSHOT_MATCHERS, {
    taxonomy: "M8 — Snapshot-only test",
    title: (t) => `Snapshot-only test: "${t}"`,
    severity: "Low",
    evidence: "A snapshot pins WHAT the output was, not WHY it is correct — and `--update-snapshots` re-approves any regression wholesale.",
    impact: "Real regressions are silently absorbed the first time someone updates snapshots without reading the diff.",
    fix: "Add at least one specific assertion on the fields/behavior that matter; keep the snapshot as a supplement, not the proof.",
  });
}

function detectCallCountOnly(ctx: TestFileContext, nextId: NextId): Finding[] {
  return detectOnlyClass(ctx, nextId, CALL_COUNT_MATCHERS, {
    taxonomy: "M8 — Call-count-only test",
    title: (t) => `Call-count-only test: "${t}"`,
    severity: "Low",
    evidence: "Call count stands in for a claim about behavior — the test passes whatever the calls computed or returned.",
    impact: "Any regression that keeps the same call shape (wrong values, wrong branch, corrupted data) passes.",
    fix: "Assert on the call's arguments (`toHaveBeenCalledWith`) or on the observable result, not just that a call happened.",
  });
}

// --- orchestrator ------------------------------------------------------------------

/**
 * Runs the mechanical M8 test-intent checks over the given source set (pass BOTH test and
 * non-test files — cross-file classes resolve test imports against the rest of the set) and
 * returns Finding[] with taxonomy `M8 — …`, ids TESTINT-*.
 */
export function detectTestIntentFindings(files: SourceInput[]): Finding[] {
  let n = 0;
  const nextId: NextId = () => `TESTINT-${String(++n).padStart(2, "0")}`;
  const parseable = files.filter((f) => PARSEABLE.test(f.path));
  const findings: Finding[] = [];
  for (const file of parseable) {
    if (!isTestFile(file.path)) continue;
    const ctx = contextFor(file);
    findings.push(
      ...detectMockOfSubject(ctx, nextId),
      ...detectAssertionFree(ctx, nextId),
      ...detectTautological(ctx, nextId),
      ...detectSnapshotOnly(ctx, nextId),
      ...detectCallCountOnly(ctx, nextId),
    );
  }
  return findings;
}
