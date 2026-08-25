import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "./common.js";
import { SOURCE_FILE } from "./load-sources.js";

type ExceptionKind = "empty-catch" | "log-only-fallthrough" | "ambiguous-success";

interface ClassifiedCatch {
  catchClause: ts.CatchClause;
  kind: ExceptionKind;
  evidence: string;
}

const INTENTIONAL_IGNORE = /\b(best[- ]effort|intentionally (?:ignored?|swallow)|safe to ignore|non[- ]critical|optional (?:cleanup|telemetry)|cleanup only|telemetry only)\b/i;
const LOG_OBJECT = /^(console|logger?|logging|telemetry|sentry)$/i;
const LOG_HELPER = /^(log|logger|capture|report|record)(Error|Exception|Warning|Warn|Failure)?$/i;
const TERMINATING_CALL = /^(exit|abort|terminate|fatal)$/i;
const FAILURE_FACTORY = /^(err|error|failure|fail|left|reject)$/i;
const SENSITIVE_PATH_TOKENS = new Set([
  "auth",
  "authorization",
  "billing",
  "checkout",
  "guard",
  "middleware",
  "payment",
  "payments",
  "security",
  "webhook",
]);
const REQUEST_PATH_TOKENS = new Set(["api", "handler", "handlers", "route", "routes"]);
const HTTP_HANDLER = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$/;

function directChildren(node: ts.Node, visit: (node: ts.Node) => void): void {
  const walk = (child: ts.Node): void => {
    if (ts.isFunctionLike(child) || ts.isCatchClause(child)) return;
    visit(child);
    ts.forEachChild(child, walk);
  };
  ts.forEachChild(node, walk);
}

function hasIntentionalIgnoreRationale(block: ts.Block, sf: ts.SourceFile): boolean {
  const text = sf.text.slice(block.getStart(sf), block.end);
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, text);
  let token = scanner.scan();
  while (token !== ts.SyntaxKind.EndOfFileToken) {
    if ((token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia)
      && INTENTIONAL_IGNORE.test(scanner.getTokenText())) return true;
    token = scanner.scan();
  }
  return false;
}

function callName(call: ts.CallExpression): { object?: string; name: string } {
  if (ts.isIdentifier(call.expression)) return { name: call.expression.text };
  if (ts.isPropertyAccessExpression(call.expression)) {
    return { object: call.expression.expression.getText(), name: call.expression.name.text };
  }
  return { name: call.expression.getText() };
}

function isLogCall(call: ts.CallExpression): boolean {
  const { object, name } = callName(call);
  if (object && LOG_OBJECT.test(object.split(".").at(-1) ?? "")) {
    return /^(debug|error|exception|fatal|info|log|warn|warning|captureException)$/i.test(name);
  }
  return LOG_HELPER.test(name);
}

function isTerminatingCall(call: ts.CallExpression): boolean {
  const { object, name } = callName(call);
  return TERMINATING_CALL.test(name) && (!object || /^(process|Deno|Bun)$/i.test(object));
}

function isLogOnlyStatement(statement: ts.Statement): boolean {
  if (ts.isExpressionStatement(statement)) {
    const expression = ts.isAwaitExpression(statement.expression) ? statement.expression.expression : statement.expression;
    return ts.isCallExpression(expression) && isLogCall(expression);
  }
  if (ts.isVariableStatement(statement)) {
    return statement.declarationList.declarations.every((declaration) => {
      const initializer = declaration.initializer;
      if (!initializer) return true;
      let containsCall = false;
      directChildren(initializer, (node) => {
        if (ts.isCallExpression(node)) containsCall = true;
      });
      return !containsCall && !ts.isCallExpression(initializer);
    });
  }
  if (ts.isBlock(statement)) return statement.statements.every(isLogOnlyStatement);
  if (ts.isIfStatement(statement)) {
    return isLogOnlyStatement(statement.thenStatement)
      && (!statement.elseStatement || isLogOnlyStatement(statement.elseStatement));
  }
  return false;
}

function literalBoolean(expression: ts.Expression): boolean | undefined {
  if (expression.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (expression.kind === ts.SyntaxKind.FalseKeyword) return false;
  return undefined;
}

function isTypedFailure(expression: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(expression)) return isTypedFailure(expression.expression);
  if (ts.isNewExpression(expression)) return /Error$/.test(expression.expression.getText());
  if (ts.isCallExpression(expression)) return FAILURE_FACTORY.test(callName(expression).name);
  if (!ts.isObjectLiteralExpression(expression)) return false;

  let explicitFailure = false;
  let carriesFailure = false;
  for (const property of expression.properties) {
    if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
    const name = property.name?.getText().replace(/["']/g, "") ?? "";
    if (ts.isPropertyAssignment(property) && /^(ok|success)$/.test(name)) {
      explicitFailure ||= literalBoolean(property.initializer) === false;
    }
    carriesFailure ||= /^(error|err|failure|cause)$/.test(name);
  }
  return explicitFailure || carriesFailure;
}

function isAmbiguousSuccess(expression: ts.Expression | undefined): boolean {
  if (!expression) return true;
  if (isTypedFailure(expression)) return false;
  if (expression.kind === ts.SyntaxKind.NullKeyword || expression.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (ts.isIdentifier(expression) && expression.text === "undefined") return true;
  if (ts.isArrayLiteralExpression(expression) && expression.elements.length === 0) return true;
  if (ts.isObjectLiteralExpression(expression)) {
    if (expression.properties.length === 0) return true;
    return expression.properties.some((property) => ts.isPropertyAssignment(property)
      && /^(ok|success)$/.test(property.name.getText().replace(/["']/g, ""))
      && literalBoolean(property.initializer) === true);
  }
  if (ts.isCallExpression(expression)) {
    const { object, name } = callName(expression);
    return object === "Promise" && name === "resolve"
      && (expression.arguments.length === 0 || isAmbiguousSuccess(expression.arguments[0]));
  }
  return false;
}

function definitelyTerminates(statement: ts.Statement): boolean {
  if (ts.isThrowStatement(statement)) return true;
  if (ts.isReturnStatement(statement)) return !isAmbiguousSuccess(statement.expression);
  if (ts.isExpressionStatement(statement)) {
    const expression = ts.isAwaitExpression(statement.expression) ? statement.expression.expression : statement.expression;
    return ts.isCallExpression(expression) && isTerminatingCall(expression);
  }
  if (ts.isBlock(statement)) {
    const last = statement.statements.at(-1);
    return last ? definitelyTerminates(last) : false;
  }
  if (ts.isIfStatement(statement) && statement.elseStatement) {
    return definitelyTerminates(statement.thenStatement) && definitelyTerminates(statement.elseStatement);
  }
  return false;
}

function bareReturnFollowsResponse(catchClause: ts.CatchClause, statement: ts.ReturnStatement, sf: ts.SourceFile): boolean {
  if (statement.expression) return false;
  const preceding = catchClause.block.getText(sf).slice(0, statement.getStart(sf) - catchClause.block.getStart(sf));
  return /\b(?:res|response)\s*\.\s*(?:status|json|send|end|redirect)\s*\(/.test(preceding);
}

function classifyCatch(catchClause: ts.CatchClause, sf: ts.SourceFile, enabled: ReadonlySet<ExceptionKind>): ClassifiedCatch | undefined {
  const block = catchClause.block;
  if (hasIntentionalIgnoreRationale(block, sf)) return undefined;

  if (enabled.has("empty-catch") && block.statements.length === 0) {
    return {
      catchClause,
      kind: "empty-catch",
      evidence: "the catch body is empty and contains no explicit ignored-error rationale",
    };
  }

  if (enabled.has("ambiguous-success")) {
    let ambiguous: ts.ReturnStatement | undefined;
    directChildren(block, (node) => {
      if (!ambiguous && ts.isReturnStatement(node) && isAmbiguousSuccess(node.expression)) ambiguous = node;
    });
    if (ambiguous && !bareReturnFollowsResponse(catchClause, ambiguous, sf)) {
      return {
        catchClause,
        kind: "ambiguous-success",
        evidence: `caught failure becomes ambiguous success via \`${ambiguous.getText(sf).replace(/\s+/g, " ").slice(0, 100)}\``,
      };
    }
  }

  const last = block.statements.at(-1);
  if (enabled.has("log-only-fallthrough")
    && block.statements.length > 0
    && block.statements.every(isLogOnlyStatement)
    && (!last || !definitelyTerminates(last))) {
    return {
      catchClause,
      kind: "log-only-fallthrough",
      evidence: "the catch only records the error and then falls through without recovery or a typed failure",
    };
  }
  return undefined;
}

function pathTokens(path: string): Set<string> {
  return new Set(path.split(/[^a-zA-Z0-9]+|(?<=[a-z0-9])(?=[A-Z])/).filter(Boolean).map((token) => token.toLowerCase()));
}

function isExecutableFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node)
    || ts.isFunctionExpression(node)
    || ts.isArrowFunction(node)
    || ts.isMethodDeclaration(node)
    || ts.isConstructorDeclaration(node)
    || ts.isGetAccessorDeclaration(node)
    || ts.isSetAccessorDeclaration(node);
}

function enclosingFunction(catchClause: ts.CatchClause): ts.FunctionLikeDeclaration | undefined {
  let current: ts.Node | undefined = catchClause.parent;
  while (current) {
    if (isExecutableFunction(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function functionName(fn: ts.FunctionLikeDeclaration | undefined): string | undefined {
  if (!fn) return undefined;
  if ("name" in fn && fn.name && ts.isIdentifier(fn.name)) return fn.name.text;
  if (ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)) return fn.parent.name.text;
  return undefined;
}

function boundaryKind(path: string, catchClause: ts.CatchClause): "auth/security" | "billing/payment" | "request" | undefined {
  const tokens = pathTokens(path);
  if (["auth", "authorization", "guard", "middleware", "security"].some((token) => tokens.has(token))) return "auth/security";
  if (["billing", "checkout", "payment", "payments"].some((token) => tokens.has(token))) return "billing/payment";
  if ([...REQUEST_PATH_TOKENS, "webhook"].some((token) => tokens.has(token))) return "request";

  const fn = enclosingFunction(catchClause);
  const name = functionName(fn);
  if (name && HTTP_HANDLER.test(name)) return "request";
  if (fn?.parameters.some((parameter) => ts.isIdentifier(parameter.name) && /^(req|request)$/.test(parameter.name.text))) return "request";
  if ([...SENSITIVE_PATH_TOKENS].some((token) => tokens.has(token))) return "auth/security";
  return undefined;
}

function collectClassified(
  files: SourceInput[],
  enabled: ReadonlySet<ExceptionKind>,
): Array<{ path: string; sf: ts.SourceFile; classified: ClassifiedCatch; boundary?: ReturnType<typeof boundaryKind> }> {
  const rows: Array<{ path: string; sf: ts.SourceFile; classified: ClassifiedCatch; boundary?: ReturnType<typeof boundaryKind> }> = [];
  for (const file of files) {
    if (!SOURCE_FILE.test(file.path)) continue;
    const sf = parse(file.path, file.text);
    const visit = (node: ts.Node): void => {
      if (ts.isCatchClause(node)) {
        const classified = classifyCatch(node, sf, enabled);
        if (classified) rows.push({ path: file.path, sf, classified, boundary: boundaryKind(file.path, node) });
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return rows;
}

export function m5ExceptionFlowSources(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => SOURCE_FILE.test(file.path));
}

function makeFinding(
  id: string,
  path: string,
  sf: ts.SourceFile,
  classified: ClassifiedCatch,
  boundary?: "auth/security" | "billing/payment" | "request",
): Finding {
  const caught = classified.catchClause.variableDeclaration?.name.getText(sf) ?? "the caught error";
  const security = boundary !== undefined;
  const kindTitle: Record<ExceptionKind, string> = {
    "empty-catch": "Empty catch silently discards a failure",
    "log-only-fallthrough": "Log-only catch continues after a failure",
    "ambiguous-success": "Catch converts a failure into ambiguous success",
  };
  const taxonomy = security
    ? `M1 — Swallowed exception at ${boundary} boundary`
    : `M5 — ${classified.kind === "empty-catch" ? "Empty catch" : classified.kind === "log-only-fallthrough" ? "Log-only catch" : "Ambiguous exception success"}`;
  return {
    id,
    title: security ? `${kindTitle[classified.kind]} at a ${boundary} boundary` : kindTitle[classified.kind],
    severity: security ? "Medium" : "Low",
    confidence: "Review",
    category: security ? "Security" : "Maintainability",
    taxonomy,
    location: loc(path, sf, classified.catchClause),
    status: "Open",
    evidence: `\`catch (${caught})\`: ${classified.evidence}.`,
    impact: security
      ? "A failed security- or request-boundary operation can continue as though it succeeded, weakening denial and transaction guarantees."
      : "Callers cannot distinguish the failed operation from success, so state can drift while the original cause is hidden.",
    fix: "Propagate or wrap the error, return an explicit typed failure, terminate the path, or perform a documented compensating action.",
    value: security ? 5 : 3,
    ease: 4,
    safety: 4,
    okWhen: "The catch has an explicit ignored-error rationale for genuinely best-effort work, or it rethrows, returns typed failure, compensates, or terminates.",
    notOkWhen: "The catch is empty, only logs and continues, or returns a value indistinguishable from success.",
    mechanical: true,
    precisionTier: "review",
  };
}

function enabledKinds(options: { emptyCatch?: boolean; logOnlyFallthrough?: boolean; ambiguousSuccess?: boolean }): ReadonlySet<ExceptionKind> {
  const enabled = new Set<ExceptionKind>();
  if (options.emptyCatch !== false) enabled.add("empty-catch");
  if (options.logOnlyFallthrough !== false) enabled.add("log-only-fallthrough");
  if (options.ambiguousSuccess !== false) enabled.add("ambiguous-success");
  return enabled;
}

export function detectM5ExceptionFlowFindings(
  files: SourceInput[],
  classifiers: { emptyCatch?: boolean; logOnlyFallthrough?: boolean; ambiguousSuccess?: boolean } = {},
): Finding[] {
  let id = 0;
  return collectClassified(m5ExceptionFlowSources(files), enabledKinds(classifiers))
    .filter((row) => row.boundary === undefined)
    .map((row) => makeFinding(`M5EXC-${String(++id).padStart(2, "0")}`, row.path, row.sf, row.classified));
}

export function detectM1ExceptionFlowFindings(
  files: SourceInput[],
  classifiers: { emptyCatch?: boolean; logOnlyFallthrough?: boolean; ambiguousSuccess?: boolean } = {},
): Finding[] {
  let id = 0;
  return collectClassified(m5ExceptionFlowSources(files), enabledKinds(classifiers))
    .filter((row): row is typeof row & { boundary: "auth/security" | "billing/payment" | "request" } => row.boundary !== undefined)
    .map((row) => makeFinding(`M1EXC-${String(++id).padStart(2, "0")}`, row.path, row.sf, row.classified, row.boundary));
}
