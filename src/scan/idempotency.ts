// #1230 / D-091 items 10, 22, 24 and (since #1352) 27 — four retry-safety shapes that share one
// question: what does a RETRY of this code do? #1230 filed them as "cross-statement or cross-time
// dataflow, a poor fit for the mechanical tier". Re-checked against the catalog: the cross-TIME
// part is the failure
// mode (a crash, a retry, an overlapping run), but the DEFECT is an ordering fact between two
// statements in one function body, which is exactly what an AST can read. What no AST can read is
// whether the retry actually happens — hence `review`, never free-count.
//
// (22) CLAIM-BEFORE-SEND — inside a loop, the row is stamped `sent_at` AFTER the send. A retry
//      re-sends every row whose stamp had not landed. The fix is a CAS claim BEFORE the send, so
//      the ordering IS the finding: stamp-after-send in a loop, with no earlier claim.
//
// (10) IDEMPOTENCY-ROW-BEFORE-DISPATCH — a dedup row inserted before the handler it guards. A crash
//      in between makes the provider's genuine retry look like a duplicate, so the work never
//      completes. The row's existence must mean "fully processed", not "received".
//
// (24) EXTERNAL-SEND-NO-IDEMPOTENCY-KEY — a call to an external API that supports idempotency keys,
//      from a retryable context, without one. Scoped two ways so it does not fire on every outbound
//      call in the codebase: the FILE must be a retryable context (an Inngest/cron/queue/worker/
//      webhook path — where the platform, not the user, decides to run the code again), and the
//      call must be to an API whose idempotency contract we can name, either the Stripe SDK's
//      `idempotencyKey` request option or one of the REST hosts below. An unrecognised host is
//      silent: we do not know whether it dedups, and guessing would be noise.
//
// (27) WEBHOOK-ORDERING (#1352) — event-derived state written with no comparison against the last
//      applied ordering field, so a STALE delivery overwrites newer state. Full rationale, and the
//      corpus measurement that decided it, sit above `webhookOrdering` at the bottom of this file.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

const SEND_CALLEE = /^(send|dispatch|deliver|notify|email|publish|enqueue|post|fire)[A-Za-z0-9_]*$/i;
const STAMP_FIELD = /^(sent|delivered|notified|emailed|dispatched|published|fired|processed)_at$/i;
const DEDUP_TABLE = /(webhook_events?|processed_events?|idempotency|idempotent|dedup|deduplication|seen_events?|event_log|handled_events?)/i;
const DISPATCH_CALLEE = /^(handle|dispatch|process|apply|route|execute|perform|on)[A-Z][A-Za-z0-9_]*$/;
const RETRYABLE_PATH = /(^|\/)(inngest|cron|crons|queue|queues|worker|workers|jobs?|tasks?|webhooks?|scheduler|schedules?)(\/|\.|$)/i;
const IDEMPOTENT_HOST = /https?:\/\/api\.(stripe|resend|apify|sendgrid|postmarkapp|mailgun|twilio|adyen|square(?:up)?)\.com/i;
const IDEMPOTENCY_KEY_TAXONOMY = "Idempotency key does not identify a stable scoped operation";
const TENANT_IDENTITY = /(?:^|_)(tenant|org(?:anization)?|workspace|team|account)_?(?:id|key|ref)?$/i;
const ENTITY_IDENTITY = /(?:id|uuid|key|ref|reference)$/i;
const ATTEMPT_IDENTITY = /(?:^|_)(?:attempt|retry|nonce|timestamp|time|now)(?:_|$)/i;
const OPERATION_WORD = /[a-z][a-z0-9_-]{2,}/i;

type KeySlot =
  | { kind: "absent" }
  | { kind: "unknown"; detail: string }
  | { kind: "present"; expression: ts.Expression };

interface ExternalSendTarget {
  api: string;
  call: ts.CallExpression;
  key: KeySlot;
}

interface KeyAnalysis {
  safe: boolean;
  classification: string;
  detail: string;
  falsifier: string;
}

type BindingKind =
  | "variable"
  | "parameter"
  | "catch"
  | "import"
  | "function"
  | "class"
  | "enum"
  | "module"
  | "function-self"
  | "class-self"
  | "enum-member";

interface IndexedBinding {
  name: string;
  identifier: ts.Identifier;
  declaration: ts.Node;
  owner: ts.Node;
  kind: BindingKind;
  simple: boolean;
  variable?: ts.VariableDeclaration;
}

type BindingLookup =
  | { kind: "resolved"; binding: IndexedBinding }
  | { kind: "unknown"; detail: string }
  | { kind: "unbound" };

type ObjectResolution =
  | { kind: "object"; object: ts.ObjectLiteralExpression }
  | { kind: "unknown"; detail: string };

type AliasEligibility =
  | { kind: "eligible"; initializer: ts.Expression }
  | { kind: "ineligible"; detail: string };

function isLoop(n: ts.Node): boolean {
  return ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isWhileStatement(n) || ts.isDoStatement(n);
}

function calleeName(node: ts.CallExpression): string | undefined {
  if (ts.isIdentifier(node.expression)) return node.expression.text;
  if (ts.isPropertyAccessExpression(node.expression)) return node.expression.name.text;
  return undefined;
}

// The `.from("<t>")` table anywhere in this call's chain — same walk counter-race.ts uses.
function tableOf(node: ts.Node): string | undefined {
  let cur: ts.Node = node;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "from") {
      const arg = cur.arguments[0];
      if (arg && ts.isStringLiteralLike(arg)) return arg.text;
    }
    cur = cur.expression.expression;
  }
  return undefined;
}

function calls(root: ts.Node): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n)) out.push(n);
    ts.forEachChild(n, visit);
  };
  visit(root);
  return out;
}

// (22) A stamp-update that lands after a send, in the same loop body.
function claimBeforeSend(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isLoop(n)) {
      const inLoop = calls(n);
      const sends = inLoop.filter((c) => {
        const name = calleeName(c);
        return name !== undefined && SEND_CALLEE.test(name) && tableOf(c) === undefined;
      });
      const stamps = inLoop.filter((c) => {
        if (calleeName(c) !== "update" || tableOf(c) === undefined) return false;
        const payload = c.arguments[0];
        return (
          payload !== undefined &&
          ts.isObjectLiteralExpression(payload) &&
          payload.properties.some((p) => p.name !== undefined && STAMP_FIELD.test(p.name.getText(sf).replace(/['"`]/g, "")))
        );
      });
      for (const stamp of stamps) {
        const earlierSend = sends.find((s) => s.getStart(sf) < stamp.getStart(sf));
        if (!earlierSend) continue;
        findings.push(
          mechanicalFinding({
            id: `RETRY-stamp-after-send-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${stamp.getStart(sf)}`,
            title: `${path} — batch job stamps the row after sending, not before`,
            severity: "Medium",
            category: "Business logic",
            taxonomy: "Batch send stamped after dispatch instead of claimed before",
            location: loc(path, sf, stamp),
            evidence: `Heuristic "claim-before-send" matched \`${calleeName(earlierSend)}(…)\` inside a loop, followed by an \`.update()\` setting a sent-style timestamp on \`${tableOf(stamp)}\` — the row is marked sent only after the send returns.`,
            impact:
              "A retry, or a second overlapping run of the same job, re-sends every row whose stamp had not yet landed. A single-run test passes: the double send needs a crash inside the send window or two concurrent runs.",
            fix: "CAS-claim the row before sending — `.update({ sent_at: … }).is('sent_at', null).select('id')` — and skip the send when zero rows were claimed.",
            precisionTier: "review",
          }),
        );
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

// (10) A dedup-table insert that precedes, IN THE SAME FUNCTION BODY, the handler it is supposed
// to guard. Function-scoped on purpose: file-wide, an insert in one function and an unrelated
// handler call in the next one down would read as this bug.
function dedupBeforeDispatch(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const inFunction = (fn: ts.Node): void => {
    const all = calls(fn);
    const inserts = all.filter((c) => {
      if (calleeName(c) !== "insert") return false;
      const table = tableOf(c);
      return table !== undefined && DEDUP_TABLE.test(table);
    });
    for (const insert of inserts) {
      const dispatch = all.find((c) => {
        const name = calleeName(c);
        return name !== undefined && DISPATCH_CALLEE.test(name) && c.getStart(sf) > insert.getEnd();
      });
      if (!dispatch) continue;
      findings.push(
        mechanicalFinding({
          id: `RETRY-dedup-before-dispatch-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${insert.getStart(sf)}`,
          title: `${path} — idempotency row written before the handler it guards`,
          severity: "Medium",
          category: "Business logic",
          taxonomy: "Idempotency row written before the dispatched handler",
          location: loc(path, sf, insert),
          evidence: `Heuristic "dedup-before-dispatch" matched an insert into \`${tableOf(insert)}\` followed by \`${calleeName(dispatch)}(…)\` — the dedup row lands before the work it guards runs.`,
          impact:
            "A crash between the insert and the handler makes the provider's genuine retry look like a duplicate, so the work never completes and nothing reports it: the row says 'processed' when it means 'received'.",
          fix: "Write the idempotency row AFTER the dispatched handler completes, so its existence means 'fully processed'. Track in-flight work with a separate `processing_started_at` if reconciliation needs it.",
          precisionTier: "review",
        }),
      );
    }
  };
  const visit = (n: ts.Node) => {
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n)) {
      inFunction(n);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

function propertyName(property: ts.ObjectLiteralElementLike, sf: ts.SourceFile): string | undefined {
  if (!property.name) return undefined;
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) || ts.isNumericLiteral(property.name)) return property.name.text;
  if (ts.isComputedPropertyName(property.name) && ts.isStringLiteralLike(property.name.expression)) return property.name.expression.text;
  return property.name.getText(sf).replace(/["'`]/g, "");
}

function unwrapExpression(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function isRuntimeFunctionLike(node: ts.Node): node is ts.SignatureDeclarationBase & ts.Node {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function isForEnvironment(node: ts.Node): boolean {
  return ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node);
}

function isEnvironmentOwner(node: ts.Node): boolean {
  return (
    ts.isSourceFile(node) ||
    ts.isModuleDeclaration(node) ||
    isRuntimeFunctionLike(node) ||
    ts.isClassStaticBlockDeclaration(node) ||
    ts.isBlock(node) ||
    ts.isCatchClause(node) ||
    isForEnvironment(node) ||
    ts.isCaseBlock(node) ||
    ts.isFunctionExpression(node) ||
    ts.isClassExpression(node) ||
    ts.isEnumDeclaration(node)
  );
}

function lexicalOwner(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isModuleBlock(current)) return current.parent;
    if (
      ts.isSourceFile(current) ||
      ts.isBlock(current) ||
      ts.isCatchClause(current) ||
      isForEnvironment(current) ||
      ts.isCaseBlock(current) ||
      isRuntimeFunctionLike(current) ||
      ts.isClassStaticBlockDeclaration(current) ||
      ts.isModuleDeclaration(current)
    ) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

function variableOwner(declaration: ts.VariableDeclaration): ts.Node | undefined {
  const list = declaration.parent;
  if (!ts.isVariableDeclarationList(list)) return undefined;
  const blockScoped = (list.flags & ts.NodeFlags.BlockScoped) !== 0;
  if (blockScoped) return lexicalOwner(list);
  let current: ts.Node | undefined = list.parent;
  while (current) {
    if (ts.isModuleBlock(current)) return current.parent;
    if (
      ts.isSourceFile(current) ||
      ts.isModuleDeclaration(current) ||
      isRuntimeFunctionLike(current) ||
      ts.isClassStaticBlockDeclaration(current)
    ) {
      return current;
    }
    current = current.parent;
  }
  return undefined;
}

function forEachBindingIdentifier(name: ts.BindingName, visit: (identifier: ts.Identifier) => void): void {
  if (ts.isIdentifier(name)) {
    visit(name);
    return;
  }
  for (const element of name.elements) {
    if (!ts.isOmittedExpression(element)) forEachBindingIdentifier(element.name, visit);
  }
}

function declarationNameIdentifier(node: ts.DeclarationName | undefined): ts.Identifier | undefined {
  return node && ts.isIdentifier(node) ? node : undefined;
}

class SourceFileBindingIndex {
  private readonly environments = new Map<ts.Node, Map<string, IndexedBinding[]>>();
  private readonly lookupCache = new WeakMap<ts.Identifier, BindingLookup>();

  constructor(private readonly sf: ts.SourceFile) {
    this.build(sf);
  }

  lookup(identifier: ts.Identifier): BindingLookup {
    const cached = this.lookupCache.get(identifier);
    if (cached) return cached;
    for (const owner of this.visibleOwners(identifier)) {
      const bindings = this.environments.get(owner)?.get(identifier.text);
      if (!bindings) continue;
      const result: BindingLookup =
        bindings.length === 1
          ? { kind: "resolved", binding: bindings[0]! }
          : {
              kind: "unknown",
              detail: `the visible environment contains ${bindings.length} declarations named \`${identifier.text}\``,
            };
      this.lookupCache.set(identifier, result);
      return result;
    }
    const result: BindingLookup = { kind: "unbound" };
    this.lookupCache.set(identifier, result);
    return result;
  }

  private visibleOwners(identifier: ts.Identifier): ts.Node[] {
    const owners: ts.Node[] = [];
    let current: ts.Node | undefined = identifier.parent;
    while (current) {
      if (ts.isModuleBlock(current)) {
        owners.push(current.parent);
      } else if (isEnvironmentOwner(current)) {
        owners.push(current);
      }
      current = current.parent;
    }
    return owners;
  }

  private add(binding: IndexedBinding): void {
    let names = this.environments.get(binding.owner);
    if (!names) {
      names = new Map();
      this.environments.set(binding.owner, names);
    }
    const bindings = names.get(binding.name) ?? [];
    bindings.push(binding);
    names.set(binding.name, bindings);
  }

  private addBindingName(
    name: ts.BindingName,
    declaration: ts.Node,
    owner: ts.Node | undefined,
    kind: BindingKind,
    variable?: ts.VariableDeclaration,
  ): void {
    if (!owner) return;
    forEachBindingIdentifier(name, (identifier) => {
      this.add({
        name: identifier.text,
        identifier,
        declaration,
        owner,
        kind,
        simple: ts.isIdentifier(name),
        variable,
      });
    });
  }

  private addNamedDeclaration(node: ts.Declaration & { name?: ts.DeclarationName }, kind: BindingKind): void {
    const identifier = declarationNameIdentifier(node.name);
    const owner = lexicalOwner(node);
    if (!identifier || !owner) return;
    this.add({ name: identifier.text, identifier, declaration: node, owner, kind, simple: true });
  }

  private addImportBindings(node: ts.ImportDeclaration): void {
    const owner = lexicalOwner(node);
    const clause = node.importClause;
    if (!owner || !clause) return;
    if (clause.name) this.add({ name: clause.name.text, identifier: clause.name, declaration: clause, owner, kind: "import", simple: true });
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) {
      this.add({ name: bindings.name.text, identifier: bindings.name, declaration: bindings, owner, kind: "import", simple: true });
    } else if (bindings && ts.isNamedImports(bindings)) {
      for (const specifier of bindings.elements) {
        this.add({ name: specifier.name.text, identifier: specifier.name, declaration: specifier, owner, kind: "import", simple: true });
      }
    }
  }

  private build(root: ts.Node): void {
    const visit = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node) && ts.isVariableDeclarationList(node.parent)) {
        this.addBindingName(node.name, node, variableOwner(node), "variable", node);
      } else if (ts.isParameter(node)) {
        let owner: ts.Node | undefined = node.parent;
        while (owner && !isRuntimeFunctionLike(owner)) owner = owner.parent;
        this.addBindingName(node.name, node, owner, "parameter");
      } else if (ts.isCatchClause(node) && node.variableDeclaration) {
        this.addBindingName(node.variableDeclaration.name, node.variableDeclaration, node, "catch");
      } else if (ts.isImportDeclaration(node)) {
        this.addImportBindings(node);
      } else if (ts.isImportEqualsDeclaration(node)) {
        const owner = lexicalOwner(node);
        if (owner) this.add({ name: node.name.text, identifier: node.name, declaration: node, owner, kind: "import", simple: true });
      } else if (ts.isFunctionDeclaration(node)) {
        this.addNamedDeclaration(node, "function");
      } else if (ts.isClassDeclaration(node)) {
        this.addNamedDeclaration(node, "class");
      } else if (ts.isEnumDeclaration(node)) {
        this.addNamedDeclaration(node, "enum");
        for (const member of node.members) {
          const identifier = declarationNameIdentifier(member.name);
          if (identifier) this.add({ name: identifier.text, identifier, declaration: member, owner: node, kind: "enum-member", simple: true });
        }
      } else if (ts.isModuleDeclaration(node)) {
        this.addNamedDeclaration(node, "module");
      } else if (ts.isFunctionExpression(node) && node.name) {
        this.add({ name: node.name.text, identifier: node.name, declaration: node, owner: node, kind: "function-self", simple: true });
      } else if (ts.isClassExpression(node) && node.name) {
        this.add({ name: node.name.text, identifier: node.name, declaration: node, owner: node, kind: "class-self", simple: true });
      }
      ts.forEachChild(node, visit);
    };
    visit(root);
  }
}

function eagerRegion(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node;
  while (current) {
    if (isRuntimeFunctionLike(current) || ts.isClassStaticBlockDeclaration(current) || ts.isModuleDeclaration(current)) return current;
    if (ts.isSourceFile(current)) return current;
    current = current.parent;
  }
  return node.getSourceFile();
}

function nearestCaseClause(node: ts.Node): ts.CaseOrDefaultClause | undefined {
  let current: ts.Node | undefined = node;
  while (current) {
    if (ts.isCaseClause(current) || ts.isDefaultClause(current)) return current;
    if (isRuntimeFunctionLike(current) || ts.isSourceFile(current)) return undefined;
    current = current.parent;
  }
  return undefined;
}

function containsConditionalEvaluation(node: ts.Node): boolean {
  let conditional = false;
  const visit = (current: ts.Node): void => {
    if (conditional) return;
    if (
      ts.isConditionalExpression(current) ||
      (ts.isBinaryExpression(current) &&
        (current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
          current.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          current.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken))
    ) {
      conditional = true;
      return;
    }
    if (current !== node && isRuntimeFunctionLike(current)) return;
    ts.forEachChild(current, visit);
  };
  visit(node);
  return conditional;
}

function isWriteTarget(node: ts.Node): boolean {
  const parent = node.parent;
  if (ts.isBinaryExpression(parent) && parent.left === node) {
    return parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment;
  }
  return (
    (ts.isPrefixUnaryExpression(parent) &&
      (parent.operator === ts.SyntaxKind.PlusPlusToken || parent.operator === ts.SyntaxKind.MinusMinusToken)) ||
    ts.isDeleteExpression(parent) ||
    (ts.isPostfixUnaryExpression(parent) && (parent.operator === ts.SyntaxKind.PlusPlusToken || parent.operator === ts.SyntaxKind.MinusMinusToken))
  );
}

function rootOfAccess(node: ts.Expression): ts.Expression {
  let current = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) current = current.expression;
  return current;
}

function initializerMayBeMutable(initializer: ts.Expression): boolean {
  const value = unwrapExpression(initializer);
  return (
    ts.isObjectLiteralExpression(value) ||
    ts.isArrayLiteralExpression(value) ||
    ts.isNewExpression(value) ||
    ts.isFunctionExpression(value) ||
    ts.isArrowFunction(value) ||
    ts.isClassExpression(value)
  );
}

function hasObservableMutationOrEscape(
  binding: IndexedBinding,
  use: ts.Identifier,
  observation: ts.Node,
  bindings: SourceFileBindingIndex,
): boolean {
  const initializer = binding.variable?.initializer;
  if (!initializer) return false;
  const mutableValue = initializerMayBeMutable(initializer);
  const start = initializer.getEnd();
  const end = observation.getStart(observation.getSourceFile());
  let unsafe = false;
  const visit = (node: ts.Node): void => {
    if (unsafe || node.getEnd() <= start || node.getStart(node.getSourceFile()) >= end) return;
    if (ts.isIdentifier(node) && node !== use && node.text === binding.name) {
      const lookup = bindings.lookup(node);
      if (lookup.kind !== "resolved" || lookup.binding !== binding) return;
      let access: ts.Expression = node;
      while (
        (ts.isPropertyAccessExpression(access.parent) || ts.isElementAccessExpression(access.parent)) &&
        access.parent.expression === access
      ) {
        access = access.parent;
      }
      const parent = access.parent;
      if (
        isWriteTarget(access) ||
        (mutableValue &&
          ((ts.isCallExpression(parent) && (parent.expression === access || parent.arguments.includes(access))) ||
            (ts.isNewExpression(parent) && parent.arguments?.includes(access)) ||
            ts.isReturnStatement(parent) ||
            ts.isYieldExpression(parent) ||
            (ts.isPropertyAssignment(parent) && parent.initializer === access) ||
            (ts.isArrayLiteralExpression(parent) && parent.elements.includes(access)) ||
            (ts.isVariableDeclaration(parent) && parent.initializer === access) ||
            (ts.isBinaryExpression(parent) && parent.right === access)))
      ) {
        unsafe = true;
        return;
      }
      if (access !== node && rootOfAccess(access) === node && isWriteTarget(access)) unsafe = true;
    }
    ts.forEachChild(node, visit);
  };
  visit(observation.getSourceFile());
  return unsafe;
}

function eligibleConstInitializer(
  binding: IndexedBinding,
  use: ts.Identifier,
  observation: ts.Node,
  bindings: SourceFileBindingIndex,
): AliasEligibility {
  const declaration = binding.variable;
  if (binding.kind !== "variable" || !declaration || !binding.simple || !ts.isIdentifier(declaration.name)) {
    return { kind: "ineligible", detail: `\`${binding.name}\` is a ${binding.kind} binding, not a simple local const` };
  }
  const list = declaration.parent;
  if (
    !ts.isVariableDeclarationList(list) ||
    (list.flags & ts.NodeFlags.Const) === 0 ||
    (list.flags & ts.NodeFlags.Using) !== 0
  ) {
    return { kind: "ineligible", detail: `\`${binding.name}\` is mutable or resource-managed rather than a simple const` };
  }
  if (!declaration.initializer) return { kind: "ineligible", detail: `\`${binding.name}\` has no initializer` };
  if (eagerRegion(declaration) !== eagerRegion(use)) {
    return { kind: "ineligible", detail: `\`${binding.name}\` crosses an eager-execution/function boundary` };
  }
  if (declaration.getStart(declaration.getSourceFile()) >= use.getStart(use.getSourceFile())) {
    return { kind: "ineligible", detail: `\`${binding.name}\` is read before its initializer structurally dominates the use` };
  }
  const declarationClause = nearestCaseClause(declaration);
  const useClause = nearestCaseClause(use);
  if (ts.isCaseBlock(binding.owner) && declarationClause !== useClause) {
    return { kind: "ineligible", detail: `\`${binding.name}\` is not initialized earlier in this same switch clause` };
  }
  if (containsConditionalEvaluation(declaration.initializer)) {
    return { kind: "ineligible", detail: `\`${binding.name}\` has a conditionally evaluated initializer` };
  }
  if (hasObservableMutationOrEscape(binding, use, observation, bindings)) {
    return { kind: "ineligible", detail: `\`${binding.name}\` is observably mutated or escapes before the provider call` };
  }
  return { kind: "eligible", initializer: declaration.initializer };
}

function isUnshadowedGlobal(identifier: ts.Identifier, name: string, bindings: SourceFileBindingIndex): boolean {
  return identifier.text === name && bindings.lookup(identifier).kind === "unbound";
}

function objectLiteralOf(
  expression: ts.Expression,
  observation: ts.Node,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
  aliasBudget = 1,
  seen = new Set<IndexedBinding>(),
): ObjectResolution {
  const value = unwrapExpression(expression);
  if (ts.isObjectLiteralExpression(value)) return { kind: "object", object: value };
  if (ts.isNewExpression(value) && ts.isIdentifier(value.expression) && isUnshadowedGlobal(value.expression, "Headers", bindings)) {
    const argument = value.arguments?.[0];
    return argument
      ? objectLiteralOf(argument, observation, sf, bindings, aliasBudget, seen)
      : { kind: "unknown", detail: "the Headers constructor has no statically readable initializer" };
  }
  if (!ts.isIdentifier(value)) return { kind: "unknown", detail: "the expression is not a local object literal" };
  const lookup = bindings.lookup(value);
  if (lookup.kind === "unbound") return { kind: "unknown", detail: `\`${value.text}\` has no visible local binding` };
  if (lookup.kind === "unknown") return { kind: "unknown", detail: lookup.detail };
  if (seen.has(lookup.binding)) return { kind: "unknown", detail: `the \`${value.text}\` object alias is cyclic` };
  if (aliasBudget <= 0) return { kind: "unknown", detail: `the \`${value.text}\` object uses more than one local alias hop` };
  const eligibility = eligibleConstInitializer(lookup.binding, value, observation, bindings);
  if (eligibility.kind === "ineligible") return { kind: "unknown", detail: eligibility.detail };
  seen.add(lookup.binding);
  return objectLiteralOf(eligibility.initializer, observation, sf, bindings, aliasBudget - 1, seen);
}

function keyInObject(object: ts.ObjectLiteralExpression, keyName: string, sf: ts.SourceFile): KeySlot {
  for (const property of object.properties) {
    if (propertyName(property, sf)?.toLowerCase() !== keyName.toLowerCase()) continue;
    if (ts.isPropertyAssignment(property)) return { kind: "present", expression: property.initializer };
    if (ts.isShorthandPropertyAssignment(property)) return { kind: "present", expression: property.name };
    return { kind: "unknown", detail: `the \`${keyName}\` property is not a statically readable value` };
  }
  return object.properties.some(ts.isSpreadAssignment)
    ? { kind: "unknown", detail: `the object uses a spread, so the \`${keyName}\` slot cannot be proven present or absent` }
    : { kind: "absent" };
}

function stripeKey(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): KeySlot {
  const options = node.arguments[1];
  if (!options) return { kind: "absent" };
  const resolved = objectLiteralOf(options, node, sf, bindings);
  return resolved.kind === "object"
    ? keyInObject(resolved.object, "idempotencyKey", sf)
    : { kind: "unknown", detail: `the Stripe request-options expression is not a local object literal (${resolved.detail})` };
}

function fetchKey(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): KeySlot {
  const options = node.arguments[1];
  if (!options) return { kind: "absent" };
  const resolved = objectLiteralOf(options, node, sf, bindings);
  if (resolved.kind === "unknown") return { kind: "unknown", detail: `the fetch options expression is not a local object literal (${resolved.detail})` };
  const headersProperty = resolved.object.properties.find((property) => propertyName(property, sf)?.toLowerCase() === "headers");
  if (!headersProperty) {
    return resolved.object.properties.some(ts.isSpreadAssignment)
      ? { kind: "unknown", detail: "the fetch options use a spread, so the headers cannot be proven" }
      : { kind: "absent" };
  }
  if (!ts.isPropertyAssignment(headersProperty) && !ts.isShorthandPropertyAssignment(headersProperty)) {
    return { kind: "unknown", detail: "the fetch headers are not a statically readable value" };
  }
  const headersExpression = ts.isPropertyAssignment(headersProperty) ? headersProperty.initializer : headersProperty.name;
  const headers = objectLiteralOf(headersExpression, node, sf, bindings);
  return headers.kind === "object"
    ? keyInObject(headers.object, "Idempotency-Key", sf)
    : { kind: "unknown", detail: `the fetch headers expression is unproven: ${headers.detail}` };
}

function isInsideWithBody(node: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current?.parent) {
    if (ts.isWithStatement(current.parent) && current !== current.parent.expression) return true;
    current = current.parent;
  }
  return false;
}

// (24) An external send from a retryable path. Provider-specific extraction returns the exact key
// slot rather than accepting any idempotency-looking text elsewhere in request options.
function externalSendTarget(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): ExternalSendTarget | undefined {
  if (ts.isIdentifier(node.expression) && node.expression.text === "fetch") {
    const url = node.arguments[0];
    const host = url && ts.isStringLiteralLike(url) ? IDEMPOTENT_HOST.exec(url.text) : null;
    return host
      ? {
          call: node,
          key: isInsideWithBody(node)
            ? { kind: "unknown", detail: "the provider call is inside JavaScript `with`, so dynamic name resolution is unproven" }
            : fetchKey(node, sf, bindings),
          api: host[0],
        }
      : undefined;
  }
  // stripe.<resource>.create(params, options)
  if (
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "create" &&
    ts.isPropertyAccessExpression(node.expression.expression) &&
    /stripe/i.test(node.expression.expression.expression.getText(sf))
  ) {
    return {
      call: node,
      key: isInsideWithBody(node)
        ? { kind: "unknown", detail: "the provider call is inside JavaScript `with`, so dynamic name resolution is unproven" }
        : stripeKey(node, sf, bindings),
      api: `Stripe ${node.expression.expression.name.text}.create`,
    };
  }
  return undefined;
}

function enclosingFunction(node: ts.Node): ts.SignatureDeclarationBase | undefined {
  let current = node.parent;
  while (current) {
    if (isRuntimeFunctionLike(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function parameterBindingNames(fn: ts.SignatureDeclarationBase | undefined): string[] {
  const names: string[] = [];
  for (const parameter of fn?.parameters ?? []) forEachBindingIdentifier(parameter.name, (identifier) => names.push(identifier.text));
  return names;
}

function boundedNodeText(node: ts.Node, sf: ts.SourceFile): string {
  const text = node.getText(sf).replace(/\s+/g, " ");
  return text.length <= 180 ? text : `${text.slice(0, 177)}…`;
}

function analyzeKey(
  expression: ts.Expression,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): KeyAnalysis {
  const text = boundedNodeText(expression, sf);
  const contributorNames = new Set<string>();
  const identityNames = new Set<string>();
  const literals: string[] = [];
  let unknownCall: string | undefined;
  let volatile: string | undefined;
  const opaque = new Set<string>();
  const expansionStack = new Set<IndexedBinding>();
  const fn = enclosingFunction(call);

  const visit = (node: ts.Node): boolean => {
    if (
      ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isTypeAssertionExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isSatisfiesExpression(node)
    ) {
      return visit(node.expression);
    }
    const nodeText = boundedNodeText(node, sf);
    if (!volatile && ts.isCallExpression(node) && /(?:Math\.random|randomUUID|randomBytes|uuid(?:\.v4)?|nanoid)\s*\(/i.test(nodeText)) {
      volatile = "random-per-attempt";
    } else if (
      !volatile &&
      ((ts.isCallExpression(node) && /(?:Date\.now|performance\.now|process\.hrtime)\s*\(/.test(nodeText)) ||
        (ts.isNewExpression(node) && /^new\s+Date\s*\(/.test(nodeText)))
    ) {
      volatile = "clock-derived";
    }
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(sf);
      const volatileCall = /(?:Math\.random|randomUUID|randomBytes|uuid(?:\.v4)?|nanoid|Date\.now|performance\.now|process\.hrtime)$/i.test(callee);
      const pureWrapper = /^(?:String|encodeURIComponent|sha(?:1|256|512)|hash)$/i.test(callee);
      if (!volatileCall && !pureWrapper) {
        unknownCall ??= callee;
      }
      let origin = false;
      for (const argument of node.arguments) if (visit(argument)) origin = true;
      return pureWrapper && origin;
    }
    if (ts.isNewExpression(node)) {
      for (const argument of node.arguments ?? []) visit(argument);
      if (!/^new\s+Date\s*\(/.test(nodeText)) opaque.add(`constructor expression \`${boundedNodeText(node.expression, sf)}\` is not a proven immutable key transform`);
      return false;
    }
    if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      literals.push(node.text);
      return false;
    }
    if (ts.isPropertyAccessExpression(node)) {
      const origin = visit(node.expression);
      if (origin) {
        contributorNames.add(node.name.text);
        identityNames.add(node.name.text);
      }
      return origin;
    }
    if (ts.isElementAccessExpression(node)) {
      const origin = visit(node.expression);
      if (node.argumentExpression) visit(node.argumentExpression);
      return origin;
    }
    if (ts.isIdentifier(node)) {
      const lookup = bindings.lookup(node);
      if (lookup.kind === "unbound") {
        opaque.add(`identifier \`${node.text}\` has no visible lexical binding`);
        return false;
      }
      if (lookup.kind === "unknown") {
        opaque.add(lookup.detail);
        return false;
      }
      const binding = lookup.binding;
      if (binding.kind === "parameter" && binding.owner === fn) {
        contributorNames.add(binding.name);
        identityNames.add(binding.name);
        return true;
      }
      if (binding.kind !== "variable") {
        opaque.add(`\`${binding.name}\` resolves to a ${binding.kind} binding instead of an enclosing-function parameter or immutable local alias`);
        return false;
      }
      if (expansionStack.has(binding)) {
        opaque.add(`local key alias \`${binding.name}\` is cyclic`);
        return false;
      }
      const eligibility = eligibleConstInitializer(binding, node, call, bindings);
      if (eligibility.kind === "ineligible") {
        opaque.add(eligibility.detail);
        return false;
      }
      expansionStack.add(binding);
      const origin = visit(unwrapExpression(eligibility.initializer));
      expansionStack.delete(binding);
      return origin;
    }
    if (node.kind === ts.SyntaxKind.ThisKeyword || node.kind === ts.SyntaxKind.SuperKeyword) {
      opaque.add(`\`${nodeText}\` is not an enclosing-function parameter or immutable local alias`);
      return false;
    }
    if (node !== expression && isRuntimeFunctionLike(node)) {
      opaque.add("a nested function value is not a statically proven idempotency key");
      return false;
    }
    if (ts.isPropertyAssignment(node)) return visit(node.initializer);
    if (ts.isShorthandPropertyAssignment(node)) return visit(node.name);
    let origin = false;
    ts.forEachChild(node, (child) => {
      if (visit(child)) origin = true;
    });
    return origin;
  };
  visit(unwrapExpression(expression));

  if (volatile === "random-per-attempt") {
    return {
      safe: false,
      classification: volatile,
      detail: `\`${text}\` creates a new value on each attempt, so one logical operation cannot reproduce its key`,
      falsifier: "replace the random source with immutable tenant/entity/operation identifiers and show two evaluations for the same operation are equal",
    };
  }
  if (volatile === "clock-derived" || [...identityNames].some((name) => ATTEMPT_IDENTITY.test(name))) {
    return {
      safe: false,
      classification: "clock-or-attempt-derived",
      detail: `\`${text}\` depends on time or attempt-local state, so a retry changes the key`,
      falsifier: "evaluate the key for two retry attempts of the same logical operation and show byte-for-byte equality",
    };
  }

  if (unknownCall) {
    return {
      safe: false,
      classification: "mechanically-unproven-key-helper",
      detail: `the helper call \`${unknownCall}(…)\` hides whether \`${text}\` is retry-stable and collision-safe`,
      falsifier: "inline or expose the helper's deterministic tenant/entity/operation composition so this pass can verify it",
    };
  }

  if (opaque.size > 0) {
    return {
      safe: false,
      classification: "mechanically-unproven-key-binding",
      detail: [...opaque][0]!,
      falsifier: "replace the opaque binding with a dominating immutable local const derived only from this function's tenant/entity parameters and a literal operation discriminator",
    };
  }

  const entityNames = [...identityNames].filter((name) => ENTITY_IDENTITY.test(name));
  if (entityNames.length === 0) {
    return {
      safe: false,
      classification: contributorNames.size === 0 ? "unsafe-global-constant" : "missing-entity-scope",
      detail:
        contributorNames.size === 0
          ? `\`${text}\` has no immutable operation identity and can collide across every call site execution`
          : `\`${text}\` does not include a recognisable immutable entity/operation identifier`,
      falsifier: "evaluate the key for two different entities in the same scope and show the values differ",
    };
  }

  const parameterNames = parameterBindingNames(fn);
  const tenantRequired = parameterNames.some((name) => TENANT_IDENTITY.test(name));
  const tenantPresent = [...identityNames].some((name) => TENANT_IDENTITY.test(name));
  if (tenantRequired && !tenantPresent) {
    return {
      safe: false,
      classification: "missing-tenant-scope",
      detail: `\`${text}\` omits the tenant-like identity available to this function (\`${parameterNames.join(", ")}\`)`,
      falsifier: "evaluate the key for the same entity identifier in two tenants and show the values differ",
    };
  }

  if (!literals.some((literal) => OPERATION_WORD.test(literal))) {
    return {
      safe: false,
      classification: "missing-operation-scope",
      detail: `\`${text}\` has an entity identity but no stable operation discriminator`,
      falsifier: "evaluate two different operations for the same tenant/entity and show their keys differ",
    };
  }

  return {
    safe: true,
    classification: "stable-scoped-operation-key",
    detail: `\`${text}\` combines an immutable identity with an operation discriminator${tenantRequired ? " and the available tenant identity" : ""}`,
    falsifier: "change any tenant, entity, or operation input and observe a collision, or retry unchanged inputs and observe a different key",
  };
}

function externalSendNoIdempotencyKey(path: string, sf: ts.SourceFile, bindings: SourceFileBindingIndex): Finding[] {
  if (!RETRYABLE_PATH.test(path)) return [];
  const findings: Finding[] = [];
  for (const call of calls(sf)) {
    const target = externalSendTarget(call, sf, bindings);
    if (!target) continue;
    if (target.key.kind === "present") {
      const analysis = analyzeKey(target.key.expression, call, sf, bindings);
      if (analysis.safe) continue;
      findings.push(
        mechanicalFinding({
          id: `RETRY-unsafe-idempotency-key-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${target.key.expression.getStart(sf)}`,
          title: `${path} — idempotency key does not identify one stable scoped operation`,
          severity: "Medium",
          category: "Business logic",
          taxonomy: IDEMPOTENCY_KEY_TAXONOMY,
          location: loc(path, sf, target.key.expression),
          evidence: `Heuristic "external-send-idempotency-key" classified the ${target.api} key as ${analysis.classification}: ${analysis.detail}. SCOPE OF THIS CHECK: it reads the provider's exact key option and local expression bindings in THIS FILE only. FALSIFIER: ${analysis.falsifier}.`,
          impact:
            "If a retry changes the key, the provider performs the logical operation twice. If different tenant/entity/operation tuples share the key, the provider suppresses legitimate work as a duplicate.",
          fix:
            "Derive the key from the domain's immutable tenant/entity/operation identity so identical logical operations reproduce one key and different scoped operations cannot collide. Payload hashing is optional, not a universal requirement.",
          precisionTier: "review",
        }),
      );
      continue;
    }
    if (target.key.kind === "unknown") {
      findings.push(
        mechanicalFinding({
          id: `RETRY-unproven-idempotency-key-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${target.call.getStart(sf)}`,
          title: `${path} — external send's idempotency key cannot be verified mechanically`,
          severity: "Medium",
          category: "Business logic",
          taxonomy: IDEMPOTENCY_KEY_TAXONOMY,
          location: loc(path, sf, target.call),
          evidence: `Heuristic "external-send-idempotency-key" inspected ${target.api}, but ${target.key.detail}. SCOPE OF THIS CHECK: local provider options in THIS FILE only. FALSIFIER: expose the exact key expression locally and show immutable tenant/entity/operation inputs that are equal across retries and distinct across different operations.`,
          impact:
            "The visible code cannot establish whether retries deduplicate or whether distinct scoped operations collide; treating an opaque option as safe would silently suppress review of both failure modes.",
          fix:
            "Make the provider's exact key option statically visible, derived from the domain's immutable tenant/entity/operation identity. Do not add a payload hash unless that is the domain invariant.",
          precisionTier: "review",
        }),
      );
      continue;
    }
    findings.push(
      mechanicalFinding({
        id: `RETRY-no-idempotency-key-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${call.getStart(sf)}`,
        title: `${path} — external send from a retryable job carries no idempotency key`,
        severity: "Medium",
        category: "Business logic",
        taxonomy: "External send without a deterministic idempotency key",
        location: loc(path, sf, call),
        evidence: `Heuristic "external-send-idempotency" matched a call to ${target.api} from a retryable path (\`${path}\`) whose exact provider option carries no idempotency key. Unrelated idempotency-looking metadata does not satisfy this check.`,
        impact:
          "The platform retries this step on any failure after the call was already accepted, so the operation lands twice. The provider's dedup window is minutes to hours and single-run tests never retry, so the duplicate only appears in production.",
        fix: "Pass an idempotency key derived from the domain's immutable tenant/entity/operation identity — the Stripe SDK's `idempotencyKey` request option, or an `Idempotency-Key` header on the REST call. Hashing is optional; stable scoped identity is the invariant.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

// (27) WEBHOOK-ORDERING — #1352. Replay dedup stops the SAME delivery twice; it does nothing about
// a STALE delivery arriving after a fresher one under at-least-once, unordered delivery. The bug is
// a handler that writes event-derived state without ever comparing the event's own ordering field
// against what was last applied, so an older delivery overwrites newer state.
//
// #1230 declined this `by-design` on a REACH argument — an ordering comparison might live in an
// imported wrapper, so the absence proof is out of an AST's range. #1350/#1352 falsified that
// argument (see briefs/anti-patterns.md item 27 for the full record): the three checks above, plus
// express-powered-by.ts / raw-body-limit.ts / gha-permissions.ts, prove an absence with the very
// same range problem and answer it the same way — review tier, bound stated in the finding.
//
// The production predicate has NO webhook-path prefilter; detectIdempotencyFindings applies it to
// every admitted shipping TS/JS source. FIELD PRECISION IS UNMEASURED, and that is the real bound.
// MEASURED 2026-08-15 with the production registry command
// `pnpm corpus-drift --install --shard N/3 --json corpus-drift-shardN.json
// --baseline-findings prior-drift/corpus-drift.json` for N=1,2,3 in Actions run 31873008063: the
// `idempotency` detector ledger reports 17 pinned targets, 13,104 `unitsExamined` source units, and
// 0 findings. The merged `corpus-drift.json` has SHA-256
// `5eaeb965920aacf2e83c1f78def674691b2f214935990d8ffb85b3d7f73311ff`. Zero firings means the FP
// rate is undefined, not zero, and the finding says so rather than implying a clean field reading.
// The write target remains a Supabase `.from(…)` chain or a `prisma`-style model call, never a bare
// `.update(...)`, excluding signature-digest methods from the candidate population.
const ORDERING_FIELD = /^(created|created_at|createdAt|timestamp|version|sequence|event_time|eventTime|occurred_at|occurredAt)$/;
const ORM_ROOT = /^(prisma|db|tx|client)$/i;
const RELATIONAL_FILTER = /^(gt|gte|lt|lte)$/;

function orderingFieldOfParam(fn: ts.SignatureDeclarationBase, param: string): string | undefined {
  const declared = fn.parameters[0]?.type;
  if (declared && ts.isTypeLiteralNode(declared)) {
    for (const m of declared.members) {
      if (ts.isPropertySignature(m) && m.name && ts.isIdentifier(m.name) && ORDERING_FIELD.test(m.name.text)) return m.name.text;
    }
  }
  let read: string | undefined;
  const visit = (n: ts.Node) => {
    if (read) return;
    if (ts.isPropertyAccessExpression(n) && ORDERING_FIELD.test(n.name.text)) {
      let base: ts.Node = n.expression;
      while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) base = base.expression;
      if (ts.isIdentifier(base) && base.text === param) read = n.name.text;
    }
    ts.forEachChild(n, visit);
  };
  visit(fn);
  return read;
}

// A write to a data store, not any method that happens to be called `update` — see the createHmac
// rows the corpus measurement turned up.
function writeTarget(call: ts.CallExpression): string | undefined {
  const table = tableOf(call);
  if (table) return table;
  if (ts.isPropertyAccessExpression(call.expression) && ts.isPropertyAccessExpression(call.expression.expression)) {
    const model = call.expression.expression;
    if (ts.isIdentifier(model.expression) && ORM_ROOT.test(model.expression.text)) return `${model.expression.text}.${model.name.text}`;
  }
  return undefined;
}

// The absence proof, scoped to the function body and disclosed as such in the finding.
function comparesOrdering(fn: ts.Node): boolean {
  const REL = new Set([ts.SyntaxKind.LessThanToken, ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken]);
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isBinaryExpression(n) && REL.has(n.operatorToken.kind)) found = true;
    else if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && RELATIONAL_FILTER.test(n.expression.name.text)) found = true;
    else if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && RELATIONAL_FILTER.test(n.name.text)) found = true;
    ts.forEachChild(n, visit);
  };
  visit(fn);
  return found;
}

function webhookOrdering(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const inFunction = (fn: ts.SignatureDeclarationBase & ts.Node): void => {
    const first = fn.parameters[0];
    if (!first || !ts.isIdentifier(first.name)) return;
    const param = first.name.text;
    const write = calls(fn).find(
      (c) =>
        ts.isPropertyAccessExpression(c.expression) &&
        /^(update|updateMany|upsert)$/.test(c.expression.name.text) &&
        writeTarget(c) !== undefined &&
        c.arguments.some((a) => referencesBinding(a, param)),
    );
    if (!write) return;
    const field = orderingFieldOfParam(fn, param);
    if (!field || comparesOrdering(fn)) return;
    findings.push(
      mechanicalFinding({
        id: `RETRY-webhook-ordering-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${write.getStart(sf)}`,
        title: `${path} — webhook state applied with no ordering guard`,
        severity: "Medium",
        category: "Business logic",
        taxonomy: "Webhook state applied without an ordering guard",
        location: loc(path, sf, write),
        evidence: `Heuristic "webhook-ordering" matched a handler whose event parameter \`${param}\` carries the ordering field \`${field}\`, writing event-derived state into \`${writeTarget(write)}\`, with no comparison against a stored last-applied value anywhere in this function. SCOPE OF THIS CHECK: it reads THIS FUNCTION BODY only, with NO webhook-path prefilter. A comparison performed inside a wrapper in another module, a database trigger, or a conditional \`WHERE ${field} > …\` built elsewhere is OUTSIDE what this pass can see. FIELD PRECISION IS UNMEASURED: MEASURED 2026-08-15 with \`pnpm corpus-drift --install --shard N/3 --json corpus-drift-shardN.json --baseline-findings prior-drift/corpus-drift.json\` for N=1,2,3 in Actions run 31873008063, the production \`idempotency\` registry ledger examined 13,104 source units across 17 pinned targets and emitted ZERO findings (merged artifact SHA-256 \`5eaeb965920aacf2e83c1f78def674691b2f214935990d8ffb85b3d7f73311ff\`). Zero firings leave the false-positive rate undefined — treat this as a prompt to check, not as a confirmed defect.`,
        impact:
          "Under at-least-once, unordered delivery a stale event arriving after a fresher one overwrites newer state — a cancelled subscription reactivated by a late `updated` delivery, a downgraded plan restored. Replay dedup does not prevent it: the two deliveries are genuinely different events.",
        fix: `Compare the event's \`${field}\` against the last-applied value on the row and skip the write when it is not newer — a conditional update (\`... .gt("${field}", stored)\`, or \`WHERE ${field} < $new\`) keeps the check atomic with the write.`,
        precisionTier: "review",
      }),
    );
  };
  const visit = (n: ts.Node) => {
    if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n)) inFunction(n);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

function referencesBinding(root: ts.Node, name: string): boolean {
  if (ts.isIdentifier(root) && root.text === name) return true;
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isIdentifier(n) && n.text === name) found = true;
    else ts.forEachChild(n, visit);
  };
  visit(root);
  return found;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const bindings = new SourceFileBindingIndex(sf);
  return [
    ...claimBeforeSend(path, sf),
    ...dedupBeforeDispatch(path, sf),
    ...externalSendNoIdempotencyKey(path, sf, bindings),
    ...webhookOrdering(path, sf),
  ];
}

export function detectIdempotencyFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
