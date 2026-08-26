// M8 source-level classifier for assertions that can pass without observing production
// behavior (#1931). This deliberately remains distinct from mutation-scan.ts's file-level
// evidence: one fixed assertion in an otherwise useful test is still one source finding.

import ts from "typescript";
import type { Finding } from "../findings.js";
import type { PathScopedClass } from "../scan/path-scope.js";
import { parse, type SourceInput } from "./common.js";

export const M8_VACUOUS_ASSERTION_TAXONOMY = "M8 — Production-independent assertion";

export interface VacuousAssertionClassification {
  path: string;
  line: number;
  identity: string;
  language: "javascript/typescript" | "python";
  api: string;
  expression: string;
  reason: string;
}

type Primitive = string | number | bigint | boolean | null | undefined;
type Constant = { known: true; value: Primitive } | { known: false };

const UNKNOWN: Constant = { known: false };
const JS_TEST_PATH = /(?:^|\/)(?:__tests__\/.*|[^/]+\.(?:test|spec))\.[cm]?[jt]sx?$/;
const PYTHON_TEST_PATH = /(?:^|\/)(?:tests?\/.*\.py|test_[^/]+\.py|[^/]+_test\.py)$/;
const EXPECT_EQUALITY_MATCHERS = new Set(["toBe", "toEqual", "toStrictEqual", "equal", "equals", "eq", "eql"]);
const ASSERT_EQUALITY_MATCHERS = new Set(["equal", "strictEqual", "deepEqual", "deepStrictEqual"]);
const ASSERT_TRUTH_MATCHERS = new Set(["ok", "isOk", "isTrue"]);
const CHAI_PROPERTY_MATCHERS = new Set(["true", "false", "null", "undefined", "ok"]);

function known(value: Primitive): Constant {
  return { known: true, value };
}

function constantValue(node: ts.Expression | undefined): Constant {
  if (!node) return UNKNOWN;
  if (ts.isParenthesizedExpression(node)) return constantValue(node.expression);
  if (ts.isNumericLiteral(node)) return known(Number(node.text));
  if (ts.isBigIntLiteral(node)) return known(BigInt(node.text.slice(0, -1)));
  if (ts.isStringLiteralLike(node)) return known(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return known(true);
  if (node.kind === ts.SyntaxKind.FalseKeyword) return known(false);
  if (node.kind === ts.SyntaxKind.NullKeyword) return known(null);
  if (ts.isIdentifier(node)) {
    if (node.text === "undefined") return known(undefined);
    if (node.text === "NaN") return known(Number.NaN);
    if (node.text === "Infinity") return known(Number.POSITIVE_INFINITY);
    return UNKNOWN;
  }
  // Type assertions (`as`, `satisfies`, `<T>x`) are intentionally not unwrapped. They are
  // compile-time claims, one of #1931's explicit safe controls.
  if (ts.isPrefixUnaryExpression(node)) return prefixConstant(node);
  if (ts.isBinaryExpression(node)) return binaryConstant(node);
  return UNKNOWN;
}

function prefixConstant(node: ts.PrefixUnaryExpression): Constant {
  const operand = constantValue(node.operand);
  if (!operand.known) return UNKNOWN;
  switch (node.operator) {
    case ts.SyntaxKind.ExclamationToken:
      return known(!operand.value);
    case ts.SyntaxKind.PlusToken:
      return typeof operand.value === "number" ? known(+operand.value) : UNKNOWN;
    case ts.SyntaxKind.MinusToken:
      return typeof operand.value === "number" || typeof operand.value === "bigint" ? known(-operand.value) : UNKNOWN;
    case ts.SyntaxKind.TildeToken:
      return typeof operand.value === "number" || typeof operand.value === "bigint" ? known(~operand.value) : UNKNOWN;
    default:
      return UNKNOWN;
  }
}

function numericBinary(left: Primitive, right: Primitive, operator: ts.SyntaxKind): Constant {
  if (typeof left !== "number" || typeof right !== "number") return UNKNOWN;
  switch (operator) {
    case ts.SyntaxKind.PlusToken: return known(left + right);
    case ts.SyntaxKind.MinusToken: return known(left - right);
    case ts.SyntaxKind.AsteriskToken: return known(left * right);
    case ts.SyntaxKind.SlashToken: return known(left / right);
    case ts.SyntaxKind.PercentToken: return known(left % right);
    case ts.SyntaxKind.AsteriskAsteriskToken: return known(left ** right);
    case ts.SyntaxKind.LessThanToken: return known(left < right);
    case ts.SyntaxKind.LessThanEqualsToken: return known(left <= right);
    case ts.SyntaxKind.GreaterThanToken: return known(left > right);
    case ts.SyntaxKind.GreaterThanEqualsToken: return known(left >= right);
    default: return UNKNOWN;
  }
}

function binaryConstant(node: ts.BinaryExpression): Constant {
  const left = constantValue(node.left);
  const right = constantValue(node.right);
  if (!left.known || !right.known) return UNKNOWN;
  const operator = node.operatorToken.kind;
  if (operator === ts.SyntaxKind.EqualsEqualsEqualsToken || operator === ts.SyntaxKind.EqualsEqualsToken) {
    return known(Object.is(left.value, right.value));
  }
  if (operator === ts.SyntaxKind.ExclamationEqualsEqualsToken || operator === ts.SyntaxKind.ExclamationEqualsToken) {
    return known(!Object.is(left.value, right.value));
  }
  if (operator === ts.SyntaxKind.AmpersandAmpersandToken) return known(left.value ? right.value : left.value);
  if (operator === ts.SyntaxKind.BarBarToken) return known(left.value ? left.value : right.value);
  if (operator === ts.SyntaxKind.QuestionQuestionToken) return known(left.value === null || left.value === undefined ? right.value : left.value);
  if (operator === ts.SyntaxKind.PlusToken && (typeof left.value === "string" || typeof right.value === "string")) {
    return known(String(left.value) + String(right.value));
  }
  return numericBinary(left.value, right.value, operator);
}

function lineOf(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function smokeRationale(text: string): boolean {
  const lower = text.toLowerCase();
  const deliberate = /\b(deliberate|intentional|rationale)\b/.test(lower);
  const smoke = /\b(smoke|sanity|wiring|framework|runner)\b/.test(lower);
  const explanation = /\b(because|verify|verifies|ensure|ensures|document|documents)\b/.test(lower);
  return smoke && (deliberate || explanation);
}

function hasJsSmokeRationale(sf: ts.SourceFile, node: ts.Node): boolean {
  const ranges = ts.getLeadingCommentRanges(sf.text, node.getFullStart()) ?? [];
  return ranges.some((range) => smokeRationale(sf.text.slice(range.pos, range.end)));
}

interface ChainRoot {
  kind: "expect" | "should";
  observed: ts.Expression;
  properties: string[];
}

function chainRoot(node: ts.Expression): ChainRoot | undefined {
  const properties: string[] = [];
  let cursor: ts.Expression = node;
  while (ts.isPropertyAccessExpression(cursor)) {
    properties.unshift(cursor.name.text);
    if (cursor.name.text === "should") {
      return { kind: "should", observed: cursor.expression, properties };
    }
    cursor = cursor.expression;
  }
  if (
    ts.isCallExpression(cursor)
    && ts.isIdentifier(cursor.expression)
    && cursor.expression.text === "expect"
    && cursor.arguments[0]
  ) {
    return { kind: "expect", observed: cursor.arguments[0], properties };
  }
  return undefined;
}

function equalityPass(actual: Constant, expected: Constant): boolean {
  return actual.known && expected.known && Object.is(actual.value, expected.value);
}

function candidate(
  file: SourceInput,
  sf: ts.SourceFile,
  node: ts.Node,
  api: string,
  expression: string,
  reason: string,
): VacuousAssertionClassification | undefined {
  if (hasJsSmokeRationale(sf, node)) return undefined;
  const start = node.getStart(sf);
  return {
    path: file.path,
    line: lineOf(sf, node),
    identity: `${file.path}:${start}:${node.getEnd()}`,
    language: "javascript/typescript",
    api,
    expression,
    reason,
  };
}

function expectCallCandidate(file: SourceInput, sf: ts.SourceFile, node: ts.CallExpression): VacuousAssertionClassification | undefined {
  if (!ts.isPropertyAccessExpression(node.expression) || node.arguments.length === 0) return undefined;
  const matcher = node.expression.name.text;
  if (!EXPECT_EQUALITY_MATCHERS.has(matcher)) return undefined;
  const root = chainRoot(node.expression.expression);
  if (!root || root.properties.some((property) => property === "not")) return undefined;
  const actual = constantValue(root.observed);
  const expected = constantValue(node.arguments[0]);
  if (!equalityPass(actual, expected)) return undefined;
  const observedText = root.observed.getText(sf);
  const expectedText = node.arguments[0]!.getText(sf);
  const api = root.kind === "should" ? `Chai should.${matcher}` : `expect(...).${matcher}`;
  return candidate(
    file,
    sf,
    node,
    api,
    `${observedText} ${matcher} ${expectedText}`,
    `Both \`${observedText}\` and \`${expectedText}\` are fixed expressions; neither reads a production-derived value.`,
  );
}

function assertCallCandidate(file: SourceInput, sf: ts.SourceFile, node: ts.CallExpression): VacuousAssertionClassification | undefined {
  let api: string | undefined;
  let matcher: string | undefined;
  if (ts.isIdentifier(node.expression) && node.expression.text === "assert") {
    api = "Node assert(...)";
  } else if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
    const object = node.expression.expression.text;
    if (object !== "assert" && object !== "strict") return undefined;
    matcher = node.expression.name.text;
    api = `${object}.${matcher}`;
  } else {
    return undefined;
  }
  if (!matcher && node.arguments[0]) {
    const value = constantValue(node.arguments[0]);
    if (!value.known || !value.value) return undefined;
    const text = node.arguments[0].getText(sf);
    return candidate(file, sf, node, api, text, `\`${text}\` is a fixed truthy expression and does not read production behavior.`);
  }
  if (matcher && ASSERT_TRUTH_MATCHERS.has(matcher) && node.arguments[0]) {
    const value = constantValue(node.arguments[0]);
    const passes = value.known && (matcher === "isTrue" ? value.value === true : Boolean(value.value));
    if (!passes) return undefined;
    const text = node.arguments[0].getText(sf);
    return candidate(file, sf, node, api, text, `\`${text}\` is fixed before the test runs and is truthy without production behavior.`);
  }
  if (!matcher || !ASSERT_EQUALITY_MATCHERS.has(matcher) || node.arguments.length < 2) return undefined;
  const actual = constantValue(node.arguments[0]);
  const expected = constantValue(node.arguments[1]);
  if (!equalityPass(actual, expected)) return undefined;
  const actualText = node.arguments[0]!.getText(sf);
  const expectedText = node.arguments[1]!.getText(sf);
  return candidate(
    file,
    sf,
    node,
    api,
    `${actualText} ${matcher} ${expectedText}`,
    `Both \`${actualText}\` and \`${expectedText}\` are fixed expressions; the assertion is independent of production output.`,
  );
}

function chaiPropertyCandidate(file: SourceInput, sf: ts.SourceFile, node: ts.PropertyAccessExpression): VacuousAssertionClassification | undefined {
  if (!CHAI_PROPERTY_MATCHERS.has(node.name.text)) return undefined;
  if (ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node) return undefined;
  if (ts.isCallExpression(node.parent) && node.parent.expression === node) return undefined;
  const root = chainRoot(node.expression);
  if (!root || root.properties.some((property) => property === "not")) return undefined;
  const actual = constantValue(root.observed);
  if (!actual.known) return undefined;
  const matcher = node.name.text;
  const passes = matcher === "true" ? actual.value === true
    : matcher === "false" ? actual.value === false
      : matcher === "null" ? actual.value === null
        : matcher === "undefined" ? actual.value === undefined
          : Boolean(actual.value);
  if (!passes) return undefined;
  const observedText = root.observed.getText(sf);
  const api = root.kind === "should" ? `Chai should.be.${matcher}` : `Chai expect(...).to.be.${matcher}`;
  return candidate(file, sf, node, api, `${observedText} is ${matcher}`, `\`${observedText}\` is fixed and satisfies \`${matcher}\` without observing production behavior.`);
}

function classifyJsFile(file: SourceInput): VacuousAssertionClassification[] {
  if (!JS_TEST_PATH.test(file.path)) return [];
  const sf = parse(file.path, file.text);
  const byIdentity = new Map<string, VacuousAssertionClassification>();
  const visit = (node: ts.Node): void => {
    const hit = ts.isCallExpression(node)
      ? expectCallCandidate(file, sf, node) ?? assertCallCandidate(file, sf, node)
      : ts.isPropertyAccessExpression(node)
        ? chaiPropertyCandidate(file, sf, node)
        : undefined;
    if (hit) byIdentity.set(hit.identity, hit);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return [...byIdentity.values()];
}

interface PythonComment {
  start: number;
  end: number;
  text: string;
}

function maskPython(text: string): { code: string; comments: PythonComment[] } {
  const chars = [...text];
  const comments: PythonComment[] = [];
  let index = 0;
  const blank = (position: number): void => {
    if (chars[position] !== "\n" && chars[position] !== "\r") chars[position] = " ";
  };
  while (index < chars.length) {
    const char = chars[index];
    if (char === "#") {
      const start = index;
      while (index < chars.length && chars[index] !== "\n") {
        blank(index);
        index += 1;
      }
      comments.push({ start, end: index, text: text.slice(start, index) });
      continue;
    }
    if (char !== "'" && char !== '"') {
      index += 1;
      continue;
    }
    const quote = char;
    const triple = chars[index + 1] === quote && chars[index + 2] === quote;
    const width = triple ? 3 : 1;
    for (let offset = 0; offset < width; offset += 1) blank(index + offset);
    index += width;
    while (index < chars.length) {
      if (!triple && chars[index] === "\\") {
        blank(index);
        if (index + 1 < chars.length) blank(index + 1);
        index += 2;
        continue;
      }
      if (chars[index] === quote && (!triple || (chars[index + 1] === quote && chars[index + 2] === quote))) {
        for (let offset = 0; offset < width; offset += 1) blank(index + offset);
        index += width;
        break;
      }
      blank(index);
      index += 1;
    }
  }
  return { code: chars.join(""), comments };
}

function stripOuterParens(text: string): string {
  let current = text.trim();
  while (current.startsWith("(") && current.endsWith(")")) {
    let depth = 0;
    let wraps = true;
    for (let index = 0; index < current.length; index += 1) {
      if (current[index] === "(") depth += 1;
      else if (current[index] === ")") depth -= 1;
      if (depth === 0 && index < current.length - 1) {
        wraps = false;
        break;
      }
    }
    if (!wraps || depth !== 0) break;
    current = current.slice(1, -1).trim();
  }
  return current;
}

function pythonAtom(text: string): Constant {
  const expression = stripOuterParens(text);
  if (expression === "True") return known(true);
  if (expression === "False") return known(false);
  if (expression === "None") return known(null);
  if (/^[+-]?(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?$/.test(expression)) {
    return known(Number(expression.replaceAll("_", "")));
  }
  if (expression.startsWith("not ")) {
    const operand = pythonExpression(expression.slice(4));
    return operand.known ? known(!operand.value) : UNKNOWN;
  }
  return UNKNOWN;
}

function pythonExpression(text: string): Constant {
  const expression = stripOuterParens(text);
  const comparison = expression.match(/^(.*?)\s*(==|!=|<=|>=|<|>)\s*(.*?)$/);
  if (!comparison) return pythonAtom(expression);
  const left = pythonAtom(comparison[1] ?? "");
  const right = pythonAtom(comparison[3] ?? "");
  if (!left.known || !right.known) return UNKNOWN;
  switch (comparison[2]) {
    case "==": return known(Object.is(left.value, right.value));
    case "!=": return known(!Object.is(left.value, right.value));
    case "<": return typeof left.value === "number" && typeof right.value === "number" ? known(left.value < right.value) : UNKNOWN;
    case "<=": return typeof left.value === "number" && typeof right.value === "number" ? known(left.value <= right.value) : UNKNOWN;
    case ">": return typeof left.value === "number" && typeof right.value === "number" ? known(left.value > right.value) : UNKNOWN;
    case ">=": return typeof left.value === "number" && typeof right.value === "number" ? known(left.value >= right.value) : UNKNOWN;
    default: return UNKNOWN;
  }
}

function hasPythonSmokeRationale(comments: readonly PythonComment[], lineStart: number, lineEnd: number, previousLineStart: number): boolean {
  return comments.some((comment) => {
    const belongsToStatement = comment.start >= lineStart && comment.start <= lineEnd;
    const immediatelyPrecedes = comment.start >= previousLineStart && comment.end <= lineStart;
    return (belongsToStatement || immediatelyPrecedes) && smokeRationale(comment.text);
  });
}

function pythonCandidate(
  file: SourceInput,
  line: number,
  start: number,
  end: number,
  api: string,
  expression: string,
): VacuousAssertionClassification {
  return {
    path: file.path,
    line,
    identity: `${file.path}:${start}:${end}`,
    language: "python",
    api,
    expression,
    reason: `\`${expression}\` is a fixed passing condition and does not read a production-derived value.`,
  };
}

function classifyPythonLine(
  file: SourceInput,
  codeLine: string,
  line: number,
  start: number,
  end: number,
): VacuousAssertionClassification | undefined {
  const assertStatement = codeLine.match(/^\s*assert\s+(.+?)\s*$/);
  if (assertStatement) {
    const expression = (assertStatement[1] ?? "").split(",", 1)[0]!.trim();
    const value = pythonExpression(expression);
    return value.known && Boolean(value.value) ? pythonCandidate(file, line, start, end, "Python assert", expression) : undefined;
  }
  const unary = codeLine.match(/^\s*(?:self\.)?(assertTrue|assertFalse)\s*\((.*?)\)\s*$/);
  if (unary) {
    const expression = (unary[2] ?? "").trim();
    const value = pythonExpression(expression);
    const passes = value.known && (unary[1] === "assertTrue" ? Boolean(value.value) : !value.value);
    return passes ? pythonCandidate(file, line, start, end, `unittest.${unary[1]}`, expression) : undefined;
  }
  const equality = codeLine.match(/^\s*(?:self\.)?(assertEqual)\s*\((.*?),(.*?)\)\s*$/);
  if (!equality) return undefined;
  const actualText = (equality[2] ?? "").trim();
  const expectedText = (equality[3] ?? "").trim();
  const actual = pythonExpression(actualText);
  const expected = pythonExpression(expectedText);
  return equalityPass(actual, expected)
    ? pythonCandidate(file, line, start, end, "unittest.assertEqual", `${actualText} == ${expectedText}`)
    : undefined;
}

function classifyPythonFile(file: SourceInput): VacuousAssertionClassification[] {
  if (!PYTHON_TEST_PATH.test(file.path)) return [];
  const { code, comments } = maskPython(file.text);
  const findings: VacuousAssertionClassification[] = [];
  let start = 0;
  let previousLineStart = 0;
  let line = 1;
  while (start <= code.length) {
    const newline = code.indexOf("\n", start);
    const end = newline === -1 ? code.length : newline;
    const codeLine = code.slice(start, end);
    const hit = classifyPythonLine(file, codeLine, line, start, end);
    if (hit && !hasPythonSmokeRationale(comments, start, end, previousLineStart)) findings.push(hit);
    if (newline === -1) break;
    previousLineStart = start;
    start = newline + 1;
    line += 1;
  }
  return findings;
}

export function vacuousAssertionSourceFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => JS_TEST_PATH.test(file.path) || PYTHON_TEST_PATH.test(file.path));
}

export const M8_VACUOUS_ASSERTION_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [{
  rowId: "M1-PATHSCOPE-M8-VACUOUS-ASSERTION-00",
  detector: "m8-vacuous-assertion",
  classId: M8_VACUOUS_ASSERTION_TAXONOMY,
  ownerFile: "src/detectors/m8-vacuous-assertion.ts",
  selectorSymbol: "vacuousAssertionSourceFiles",
  inventory: "identified-sources",
  convention: "JavaScript/TypeScript test/spec files or __tests__ paths, and Python test directories or test_*.py / *_test.py filenames",
  select: vacuousAssertionSourceFiles,
  classes: "a test assertion that can pass without observing production behavior",
}];

export function classifyVacuousAssertions(files: readonly SourceInput[]): VacuousAssertionClassification[] {
  return vacuousAssertionSourceFiles(files).flatMap((file) => file.path.endsWith(".py") ? classifyPythonFile(file) : classifyJsFile(file));
}

export function detectM8VacuousAssertionFindings(files: readonly SourceInput[]): Finding[] {
  return classifyVacuousAssertions(files).map((classification, index) => ({
    id: `M8VAC-${String(index + 1).padStart(2, "0")}`,
    title: `Production-independent assertion: ${classification.api}`,
    severity: "Medium",
    confidence: "Review",
    category: "Test quality",
    taxonomy: M8_VACUOUS_ASSERTION_TAXONOMY,
    location: `${classification.path}:${classification.line}`,
    status: "Open",
    evidence: `${classification.api} uses ${classification.expression}. ${classification.reason}`,
    impact: "This assertion can keep passing after the production behavior it appears to cover changes or disappears.",
    fix: "Assert a production-derived return value, state change, emitted argument, or other observable behavior instead of a fixed condition.",
    value: 3,
    ease: 4,
    safety: 5,
    precisionTier: "review",
    mechanical: true,
  }));
}
