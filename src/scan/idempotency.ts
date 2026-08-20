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
import type { PathScopedClass } from "./path-scope.js";

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
  logicalOperation: string;
  operationDetail?: string;
  payload?: ts.Expression;
  providerDomain: string;
}

interface KeyAnalysis {
  safe: boolean;
  classification: string;
  detail: string;
  falsifier: string;
  contract?: ProvenOperationKeyContract;
}

type IdentityRole = "tenant" | "entity" | "other";
type JsonPrimitiveType = "string" | "number" | "boolean";

interface ValueOrigin {
  display: string;
  key: string;
  parameter: ts.ParameterDeclaration;
  path: string[];
  primitiveType?: JsonPrimitiveType;
  role: IdentityRole;
  semanticName: string;
}

interface ProvenOperationKeyContract {
  framing: "canonical-json-tuple" | "encoded-terms";
  operationDiscriminator: string;
  originKeys: Set<string>;
  signature: string;
}

type LogicalOperationContext =
  | { kind: "named"; display: string; fingerprint: string }
  | { kind: "unknown"; detail: string };

interface ExternalOperationRecord {
  analysis: KeyAnalysis;
  operationContext: LogicalOperationContext;
  path: string;
  sf: ts.SourceFile;
  target: ExternalSendTarget;
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

/** Generic shipping-source filter shared by all four idempotency classes. */
function idempotencySourceFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter((file) => SOURCE_EXT.test(file.path) && !NON_SHIPPING_PATH.test(file.path) && !NON_SHIPPING_FILE.test(file.path));
}

function isRetryableExternalSendPath(path: string): boolean {
  return RETRYABLE_PATH.test(path);
}

/** The actual class population for external sends that need a deterministic idempotency key. */
export function retryableExternalSendFiles(files: readonly SourceInput[]): SourceInput[] {
  return idempotencySourceFiles(files).filter((file) => isRetryableExternalSendPath(file.path));
}

export const IDEMPOTENCY_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [
  {
    rowId: "M1-PATHSCOPE-IDEMPOTENCY-EXTERNAL-SEND-00",
    detector: "idempotency",
    classId: "External send without a deterministic idempotency key",
    ownerFile: "src/scan/idempotency.ts",
    selectorSymbol: "retryableExternalSendFiles",
    convention: "shipping source under Inngest, cron, queue, worker, job, task, webhook, or scheduler path segments",
    select: retryableExternalSendFiles,
    classes: "an external provider send from a retryable execution context without an idempotency key",
  },
];

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

function isStructuredTupleWrapper(call: ts.CallExpression, bindings: SourceFileBindingIndex): boolean {
  return (
    call.arguments.length === 1 &&
    ts.isArrayLiteralExpression(unwrapExpression(call.arguments[0]!)) &&
    ts.isPropertyAccessExpression(call.expression) &&
    call.expression.name.text === "stringify" &&
    ts.isIdentifier(call.expression.expression) &&
    isUnshadowedGlobal(call.expression.expression, "JSON", bindings)
  );
}

function isPureBuiltinKeyWrapper(call: ts.CallExpression, bindings: SourceFileBindingIndex): boolean {
  if (isStructuredTupleWrapper(call, bindings)) return true;
  return (
    call.arguments.length === 1 &&
    ts.isIdentifier(call.expression) &&
    (isUnshadowedGlobal(call.expression, "String", bindings) || isUnshadowedGlobal(call.expression, "encodeURIComponent", bindings))
  );
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

function keyInObject(
  object: ts.ObjectLiteralExpression,
  keyName: string,
  observation: ts.Node,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
  seen = new Set<ts.ObjectLiteralExpression>(),
): KeySlot {
  if (seen.has(object)) return { kind: "unknown", detail: `the object spread graph for \`${keyName}\` is cyclic` };
  const nextSeen = new Set(seen);
  nextSeen.add(object);
  for (let index = object.properties.length - 1; index >= 0; index -= 1) {
    const property = object.properties[index]!;
    if (ts.isSpreadAssignment(property)) {
      const spread = objectLiteralOf(property.expression, observation, sf, bindings);
      if (spread.kind === "unknown") {
        return { kind: "unknown", detail: `a later object spread may overwrite \`${keyName}\` (${spread.detail})` };
      }
      const spreadSlot = keyInObject(spread.object, keyName, observation, sf, bindings, nextSeen);
      if (spreadSlot.kind !== "absent") return spreadSlot;
      continue;
    }
    if (ts.isComputedPropertyName(property.name) && !ts.isStringLiteralLike(property.name.expression)) {
      return { kind: "unknown", detail: `a computed property may overwrite \`${keyName}\`` };
    }
    if (propertyName(property, sf)?.toLowerCase() !== keyName.toLowerCase()) continue;
    if (ts.isPropertyAssignment(property)) return { kind: "present", expression: property.initializer };
    if (ts.isShorthandPropertyAssignment(property)) return { kind: "present", expression: property.name };
    return { kind: "unknown", detail: `the \`${keyName}\` property is not a statically readable value` };
  }
  return { kind: "absent" };
}

function stripeKey(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): KeySlot {
  const options = node.arguments[1];
  if (!options) return { kind: "absent" };
  const resolved = objectLiteralOf(options, node, sf, bindings);
  return resolved.kind === "object"
    ? keyInObject(resolved.object, "idempotencyKey", node, sf, bindings)
    : { kind: "unknown", detail: `the Stripe request-options expression is not a local object literal (${resolved.detail})` };
}

function fetchKey(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): KeySlot {
  const options = node.arguments[1];
  if (!options) return { kind: "absent" };
  const resolved = objectLiteralOf(options, node, sf, bindings);
  if (resolved.kind === "unknown") return { kind: "unknown", detail: `the fetch options expression is not a local object literal (${resolved.detail})` };
  const headersSlot = keyInObject(resolved.object, "headers", node, sf, bindings);
  if (headersSlot.kind !== "present") return headersSlot;
  const headersExpression = headersSlot.expression;
  const headers = objectLiteralOf(headersExpression, node, sf, bindings);
  return headers.kind === "object"
    ? keyInObject(headers.object, "Idempotency-Key", node, sf, bindings)
    : { kind: "unknown", detail: `the fetch headers expression is unproven: ${headers.detail}` };
}

function fetchPayload(node: ts.CallExpression, sf: ts.SourceFile, bindings: SourceFileBindingIndex): ts.Expression | undefined {
  const options = node.arguments[1];
  if (!options) return undefined;
  const resolved = objectLiteralOf(options, node, sf, bindings);
  if (resolved.kind === "unknown") return undefined;
  const body = keyInObject(resolved.object, "body", node, sf, bindings);
  return body.kind === "present" ? body.expression : undefined;
}

function staticFetchMethod(
  node: ts.CallExpression,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): { method?: string; detail?: string } {
  const options = node.arguments[1];
  if (!options) return { method: "GET" };
  const resolved = objectLiteralOf(options, node, sf, bindings);
  if (resolved.kind === "unknown") return { detail: resolved.detail };
  const method = keyInObject(resolved.object, "method", node, sf, bindings);
  if (method.kind === "absent") return { method: "GET" };
  if (method.kind === "unknown") return { detail: method.detail };
  const expression = unwrapExpression(method.expression);
  return ts.isStringLiteralLike(expression)
    ? { method: expression.text.toUpperCase() }
    : { detail: `the fetch method '${boundedNodeText(expression, sf)}' is not a static string` };
}

function normalizedUrlPath(url: string): string {
  const path = /^https?:\/\/[^/]+(\/[^?#]*)/i.exec(url)?.[1] ?? "/";
  return path.length > 1 ? path.replace(/\/+$/, "") : path;
}

function normalizedProviderDomain(provider: string): string {
  const normalized = provider.toLowerCase();
  if (normalized === "squareup") return "square";
  if (normalized === "postmarkapp") return "postmark";
  return normalized;
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
    if (!host || !url || !ts.isStringLiteralLike(url)) return undefined;
    const operation = staticFetchMethod(node, sf, bindings);
    const path = normalizedUrlPath(url.text);
    return {
      call: node,
      key: isInsideWithBody(node)
        ? { kind: "unknown", detail: "the provider call is inside JavaScript `with`, so dynamic name resolution is unproven" }
        : fetchKey(node, sf, bindings),
      api: host[0],
      logicalOperation: operation.method ? `${operation.method} ${path}` : `unknown-method ${path}`,
      operationDetail: operation.detail,
      payload: fetchPayload(node, sf, bindings),
      providerDomain: normalizedProviderDomain(host[1]!),
    };
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
      logicalOperation: `${node.expression.expression.name.text}.create`,
      payload: node.arguments[0],
      providerDomain: "stripe",
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

function logicalOperationContext(node: ts.Node): LogicalOperationContext {
  const fn = enclosingFunction(node);
  if (!fn) return { kind: "unknown", detail: "the provider call has no enclosing named operation" };

  const directName = declarationPropertyName((fn as ts.SignatureDeclarationBase & { name?: ts.PropertyName }).name);
  const parentName =
    !directName && ts.isVariableDeclaration(fn.parent) && ts.isIdentifier(fn.parent.name)
      ? fn.parent.name.text
      : !directName && ts.isPropertyAssignment(fn.parent)
        ? declarationPropertyName(fn.parent.name)
        : undefined;
  const display = directName ?? parentName;
  if (!display) return { kind: "unknown", detail: "the provider call's enclosing function has no static name" };

  const terms = display
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  const wrapperPrefixes = new Set(["do", "execute", "handle", "perform", "process", "retry", "run"]);
  const wrapperSuffixes = new Set(["handler", "job", "task", "worker"]);
  while (terms.length > 1 && wrapperPrefixes.has(terms[0]!)) terms.shift();
  while (terms.length > 1 && wrapperSuffixes.has(terms.at(-1)!)) terms.pop();
  const implementationQualifier = terms.findIndex((term) => ["by", "from", "using", "via", "with"].includes(term));
  if (implementationQualifier > 0) terms.splice(implementationQualifier);
  if (terms.length === 0) return { kind: "unknown", detail: `the enclosing function \`${display}\` has no operation-bearing name` };
  return { kind: "named", display, fingerprint: terms.join("-") };
}

function declarationPropertyName(name: ts.PropertyName | undefined): string | undefined {
  if (!name) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return name.text;
  if (ts.isComputedPropertyName(name) && ts.isStringLiteralLike(name.expression)) return name.expression.text;
  return undefined;
}

function identityRole(name: string): IdentityRole {
  if (TENANT_IDENTITY.test(name)) return "tenant";
  if (ENTITY_IDENTITY.test(name)) return "entity";
  return "other";
}

function bindingPath(identifier: ts.Identifier, parameter: ts.ParameterDeclaration): string[] {
  const path: string[] = [];
  let current: ts.Node = identifier;
  while (current.parent && current.parent !== parameter) {
    if (ts.isBindingElement(current.parent)) {
      const element = current.parent;
      const segment = declarationPropertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
      if (segment) path.unshift(segment);
    }
    current = current.parent;
  }
  return path;
}

function localTypeDeclaration(sf: ts.SourceFile, name: string): ts.InterfaceDeclaration | ts.TypeAliasDeclaration | undefined {
  return sf.statements.find(
    (statement): statement is ts.InterfaceDeclaration | ts.TypeAliasDeclaration =>
      (ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement)) && statement.name.text === name,
  );
}

interface ResolvedPropertyType {
  optional: boolean;
  type: ts.TypeNode;
}

function propertyType(
  type: ts.TypeNode,
  name: string,
  sf: ts.SourceFile,
  seen = new Set<string>(),
): ResolvedPropertyType | undefined {
  if (ts.isParenthesizedTypeNode(type)) return propertyType(type.type, name, sf, seen);
  if (ts.isIntersectionTypeNode(type)) {
    for (const member of type.types) {
      const resolved = propertyType(member, name, sf, seen);
      if (resolved) return resolved;
    }
    return undefined;
  }
  if (ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)) {
    const typeName = type.typeName.text;
    if (seen.has(typeName)) return undefined;
    const declaration = localTypeDeclaration(sf, typeName);
    if (!declaration) return undefined;
    const nextSeen = new Set(seen);
    nextSeen.add(typeName);
    if (ts.isTypeAliasDeclaration(declaration)) return propertyType(declaration.type, name, sf, nextSeen);
    for (const member of declaration.members) {
      if (!ts.isPropertySignature(member) || declarationPropertyName(member.name) !== name || !member.type) continue;
      return { type: member.type, optional: member.questionToken !== undefined };
    }
    for (const clause of declaration.heritageClauses ?? []) {
      for (const inherited of clause.types) {
        if (!ts.isIdentifier(inherited.expression)) continue;
        const inheritedDeclaration = localTypeDeclaration(sf, inherited.expression.text);
        if (!inheritedDeclaration) continue;
        const inheritedType = ts.isTypeAliasDeclaration(inheritedDeclaration)
          ? inheritedDeclaration.type
          : ts.factory.createTypeReferenceNode(inheritedDeclaration.name.text, undefined);
        const resolved = propertyType(inheritedType, name, sf, nextSeen);
        if (resolved) return resolved;
      }
    }
    return undefined;
  }
  if (!ts.isTypeLiteralNode(type)) return undefined;
  for (const member of type.members) {
    if (!ts.isPropertySignature(member) || declarationPropertyName(member.name) !== name || !member.type) continue;
    return { type: member.type, optional: member.questionToken !== undefined };
  }
  return undefined;
}

function primitiveType(type: ts.TypeNode | undefined, sf: ts.SourceFile, seen = new Set<string>()): JsonPrimitiveType | undefined {
  if (!type) return undefined;
  if (ts.isParenthesizedTypeNode(type)) return primitiveType(type.type, sf, seen);
  if (type.kind === ts.SyntaxKind.StringKeyword) return "string";
  if (type.kind === ts.SyntaxKind.NumberKeyword) return "number";
  if (type.kind === ts.SyntaxKind.BooleanKeyword) return "boolean";
  if (ts.isLiteralTypeNode(type)) {
    if (ts.isStringLiteral(type.literal)) return "string";
    if (ts.isNumericLiteral(type.literal)) return "number";
    if (type.literal.kind === ts.SyntaxKind.TrueKeyword || type.literal.kind === ts.SyntaxKind.FalseKeyword) return "boolean";
    return undefined;
  }
  if (ts.isUnionTypeNode(type)) {
    const members = type.types.map((member) => primitiveType(member, sf, new Set(seen)));
    const first = members[0];
    return first && members.every((member) => member === first) ? first : undefined;
  }
  if (ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)) {
    const name = type.typeName.text;
    if (seen.has(name)) return undefined;
    const declaration = localTypeDeclaration(sf, name);
    if (!declaration || ts.isInterfaceDeclaration(declaration)) return undefined;
    const nextSeen = new Set(seen);
    nextSeen.add(name);
    return primitiveType(declaration.type, sf, nextSeen);
  }
  return undefined;
}

function primitiveTypeAt(parameter: ts.ParameterDeclaration, path: string[], sf: ts.SourceFile): JsonPrimitiveType | undefined {
  let type = parameter.type;
  if (path.length === 0) return primitiveType(type, sf);
  for (const segment of path) {
    if (!type) return undefined;
    const resolved = propertyType(type, segment, sf);
    if (!resolved || resolved.optional) return undefined;
    type = resolved.type;
  }
  return primitiveType(type, sf);
}

function parameterOrigin(
  parameter: ts.ParameterDeclaration,
  path: string[],
  semanticName: string,
  display: string,
  sf: ts.SourceFile,
): ValueOrigin {
  return {
    display,
    key: `${parameter.getStart(sf)}:${path.length > 0 ? path.join(".") : "$"}`,
    parameter,
    path,
    primitiveType: primitiveTypeAt(parameter, path, sf),
    role: identityRole(semanticName),
    semanticName,
  };
}

type OriginResolution = { kind: "resolved"; origin: ValueOrigin } | { kind: "unknown"; detail: string };

function resolveValueOrigin(
  expression: ts.Expression,
  use: ts.Node,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
  seen = new Set<IndexedBinding>(),
): OriginResolution {
  const node = unwrapExpression(expression);
  if (ts.isPropertyAccessExpression(node)) {
    const base = resolveValueOrigin(node.expression, use, call, sf, bindings, seen);
    if (base.kind === "unknown") return base;
    const path = [...base.origin.path, node.name.text];
    return {
      kind: "resolved",
      origin: parameterOrigin(base.origin.parameter, path, node.name.text, boundedNodeText(node, sf), sf),
    };
  }
  if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression)) {
    const base = resolveValueOrigin(node.expression, use, call, sf, bindings, seen);
    if (base.kind === "unknown") return base;
    const path = [...base.origin.path, node.argumentExpression.text];
    return {
      kind: "resolved",
      origin: parameterOrigin(base.origin.parameter, path, node.argumentExpression.text, boundedNodeText(node, sf), sf),
    };
  }
  if (!ts.isIdentifier(node)) return { kind: "unknown", detail: `'${boundedNodeText(node, sf)}' is not a parameter value origin` };
  const lookup = bindings.lookup(node);
  if (lookup.kind === "unbound") return { kind: "unknown", detail: `identifier '${node.text}' has no visible lexical binding` };
  if (lookup.kind === "unknown") return { kind: "unknown", detail: lookup.detail };
  const binding = lookup.binding;
  const fn = enclosingFunction(call);
  if (binding.kind === "parameter") {
    if (binding.owner !== fn || !ts.isParameter(binding.declaration)) {
      return { kind: "unknown", detail: `'${binding.name}' is not a parameter of the provider call's enclosing function` };
    }
    const path = bindingPath(binding.identifier, binding.declaration);
    const semanticName = path.at(-1) ?? binding.name;
    return {
      kind: "resolved",
      origin: parameterOrigin(binding.declaration, path, semanticName, node.text, sf),
    };
  }
  if (binding.kind !== "variable") {
    return { kind: "unknown", detail: `'${binding.name}' resolves to a ${binding.kind} binding instead of immutable parameter provenance` };
  }
  if (seen.has(binding)) return { kind: "unknown", detail: `local key alias '${binding.name}' is cyclic` };
  const eligibility = eligibleConstInitializer(binding, node, use, bindings);
  if (eligibility.kind === "ineligible") return { kind: "unknown", detail: eligibility.detail };
  const nextSeen = new Set(seen);
  nextSeen.add(binding);
  return resolveValueOrigin(eligibility.initializer, use, call, sf, bindings, nextSeen);
}

function typeIdentityPaths(
  type: ts.TypeNode | undefined,
  sf: ts.SourceFile,
  prefix: string[] = [],
  seen = new Set<string>(),
  depth = 0,
): string[][] {
  if (!type || depth > 5) return [];
  if (ts.isParenthesizedTypeNode(type)) return typeIdentityPaths(type.type, sf, prefix, seen, depth);
  if (ts.isIntersectionTypeNode(type)) return type.types.flatMap((member) => typeIdentityPaths(member, sf, prefix, new Set(seen), depth));
  if (ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)) {
    const name = type.typeName.text;
    if (seen.has(name)) return [];
    const declaration = localTypeDeclaration(sf, name);
    if (!declaration) return [];
    const nextSeen = new Set(seen);
    nextSeen.add(name);
    if (ts.isTypeAliasDeclaration(declaration)) return typeIdentityPaths(declaration.type, sf, prefix, nextSeen, depth + 1);
    const ownPaths = declaration.members.flatMap((member) => {
      if (!ts.isPropertySignature(member) || !member.type) return [];
      const memberName = declarationPropertyName(member.name);
      if (!memberName) return [];
      const path = [...prefix, memberName];
      const own = identityRole(memberName) === "other" || primitiveType(member.type, sf) === undefined ? [] : [path];
      return [...own, ...typeIdentityPaths(member.type, sf, path, new Set(nextSeen), depth + 1)];
    });
    const inheritedPaths = (declaration.heritageClauses ?? []).flatMap((clause) =>
      clause.types.flatMap((inherited) =>
        ts.isIdentifier(inherited.expression)
          ? typeIdentityPaths(ts.factory.createTypeReferenceNode(inherited.expression.text, undefined), sf, prefix, new Set(nextSeen), depth + 1)
          : [],
      ),
    );
    return [...ownPaths, ...inheritedPaths];
  }
  if (!ts.isTypeLiteralNode(type)) return [];
  return type.members.flatMap((member) => {
    if (!ts.isPropertySignature(member) || !member.type) return [];
    const name = declarationPropertyName(member.name);
    if (!name) return [];
    const path = [...prefix, name];
    const own = identityRole(name) === "other" || primitiveType(member.type, sf) === undefined ? [] : [path];
    return [...own, ...typeIdentityPaths(member.type, sf, path, new Set(seen), depth + 1)];
  });
}

function declaredIdentityOrigins(fn: ts.SignatureDeclarationBase | undefined, sf: ts.SourceFile): ValueOrigin[] {
  const origins = new Map<string, ValueOrigin>();
  for (const parameter of fn?.parameters ?? []) {
    if (ts.isIdentifier(parameter.name) && identityRole(parameter.name.text) !== "other") {
      const origin = parameterOrigin(parameter, [], parameter.name.text, parameter.name.text, sf);
      origins.set(origin.key, origin);
    }
    forEachBindingIdentifier(parameter.name, (identifier) => {
      const path = bindingPath(identifier, parameter);
      const semanticName = path.at(-1) ?? identifier.text;
      if (identityRole(semanticName) === "other") return;
      const origin = parameterOrigin(parameter, path, semanticName, identifier.text, sf);
      origins.set(origin.key, origin);
    });
    for (const path of typeIdentityPaths(parameter.type, sf)) {
      const semanticName = path.at(-1)!;
      const root = ts.isIdentifier(parameter.name) ? parameter.name.text : "parameter";
      const origin = parameterOrigin(parameter, path, semanticName, `${root}.${path.join(".")}`, sf);
      origins.set(origin.key, origin);
    }
  }
  return [...origins.values()];
}

function expressionIdentityOrigins(
  expression: ts.Expression | undefined,
  call: ts.CallExpression,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): ValueOrigin[] {
  if (!expression) return [];
  const origins = new Map<string, ValueOrigin>();
  const visit = (node: ts.Node, expansionStack = new Set<IndexedBinding>()): void => {
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node) || ts.isIdentifier(node)) {
      const resolved = resolveValueOrigin(node as ts.Expression, node, call, sf, bindings);
      if (resolved.kind === "resolved" && resolved.origin.role !== "other") {
        origins.set(resolved.origin.key, resolved.origin);
        return;
      }
      if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        visit(node.expression, expansionStack);
        return;
      }
      const lookup = bindings.lookup(node);
      if (lookup.kind === "resolved" && lookup.binding.kind === "variable" && !expansionStack.has(lookup.binding)) {
        const eligibility = eligibleConstInitializer(lookup.binding, node, call, bindings);
        if (eligibility.kind === "eligible") {
          const nextStack = new Set(expansionStack);
          nextStack.add(lookup.binding);
          visit(eligibility.initializer, nextStack);
        }
      }
      return;
    }
    if (ts.isCallExpression(node)) {
      for (const argument of node.arguments) visit(argument, expansionStack);
      return;
    }
    if (node !== expression && isRuntimeFunctionLike(node)) return;
    ts.forEachChild(node, (child) => visit(child, expansionStack));
  };
  visit(expression);
  return [...origins.values()];
}

interface ScopeRequirement {
  ambiguity?: string;
  entity: ValueOrigin[];
  tenant: ValueOrigin[];
}

function scopeRequirement(
  target: ExternalSendTarget,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): ScopeRequirement {
  const fn = enclosingFunction(target.call);
  const available = declaredIdentityOrigins(fn, sf);
  const payload = expressionIdentityOrigins(target.payload, target.call, sf, bindings);
  const select = (role: Exclude<IdentityRole, "other">): { origins: ValueOrigin[]; ambiguity?: string } => {
    const payloadOrigins = payload.filter((origin) => origin.role === role);
    if (payloadOrigins.length > 0) return { origins: payloadOrigins };
    const availableOrigins = available.filter((origin) => origin.role === role);
    if (availableOrigins.length <= 1) return { origins: availableOrigins };
    return {
      origins: [],
      ambiguity: `the provider payload does not identify which of ${availableOrigins.length} available ${role} identities defines this operation`,
    };
  };
  const tenant = select("tenant");
  const entity = select("entity");
  return {
    tenant: tenant.origins,
    entity: entity.origins,
    ambiguity: tenant.ambiguity ?? entity.ambiguity,
  };
}

function boundedNodeText(node: ts.Node, sf: ts.SourceFile): string {
  const text = node.getText(sf).replace(/\s+/g, " ");
  return text.length <= 180 ? text : `${text.slice(0, 177)}…`;
}

function analyzeKey(
  expression: ts.Expression,
  target: ExternalSendTarget,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): KeyAnalysis {
  const call = target.call;
  const text = boundedNodeText(expression, sf);
  const keyOrigins = new Map<string, ValueOrigin>();
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
      const pureWrapper = isPureBuiltinKeyWrapper(node, bindings);
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
    if (
      ts.isStringLiteralLike(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      return false;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const resolution = resolveValueOrigin(node, node, call, sf, bindings);
      if (resolution.kind === "resolved") {
        keyOrigins.set(resolution.origin.key, resolution.origin);
        return true;
      }
      opaque.add(resolution.detail);
      return false;
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
        const resolution = resolveValueOrigin(node, node, call, sf, bindings);
        if (resolution.kind === "resolved") {
          keyOrigins.set(resolution.origin.key, resolution.origin);
          return true;
        }
        opaque.add(resolution.detail);
        return false;
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

  type CompositionPart =
    | { kind: "literal"; value: string }
    | { encoded: boolean; kind: "dynamic"; origin: ValueOrigin };
  type Composition =
    | { framing: "json-tuple" | "raw"; kind: "known"; parts: CompositionPart[] }
    | { detail: string; kind: "unknown" };
  const compositionStack = new Set<IndexedBinding>();
  const compositionOf = (raw: ts.Expression): Composition => {
    const node = unwrapExpression(raw);
    if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node)) {
      return { kind: "known", parts: [{ kind: "literal", value: node.text }], framing: "raw" };
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword || node.kind === ts.SyntaxKind.FalseKeyword || node.kind === ts.SyntaxKind.NullKeyword) {
      return { kind: "known", parts: [{ kind: "literal", value: node.getText(sf) }], framing: "raw" };
    }
    if (ts.isTemplateExpression(node)) {
      const parts: CompositionPart[] = [{ kind: "literal", value: node.head.text }];
      for (const span of node.templateSpans) {
        const expressionPart = compositionOf(span.expression);
        if (expressionPart.kind === "unknown") return expressionPart;
        if (expressionPart.framing === "json-tuple") {
          return { kind: "unknown", detail: "a JSON tuple is nested inside string interpolation" };
        }
        parts.push(...expressionPart.parts, { kind: "literal", value: span.literal.text });
      }
      return { kind: "known", parts, framing: "raw" };
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = compositionOf(node.left);
      const right = compositionOf(node.right);
      if (left.kind === "unknown") return left;
      if (right.kind === "unknown") return right;
      if (left.framing === "json-tuple" || right.framing === "json-tuple") {
        return { kind: "unknown", detail: "a JSON tuple is concatenated with another value" };
      }
      return { kind: "known", parts: [...left.parts, ...right.parts], framing: "raw" };
    }
    if (ts.isCallExpression(node) && isStructuredTupleWrapper(node, bindings)) {
      const tuple = unwrapExpression(node.arguments[0]!);
      if (!ts.isArrayLiteralExpression(tuple)) return { kind: "unknown", detail: "JSON.stringify does not wrap an array literal" };
      const parts: CompositionPart[] = [];
      for (const element of tuple.elements) {
        if (ts.isSpreadElement(element)) return { kind: "unknown", detail: "the JSON tuple contains a spread element" };
        const value = unwrapExpression(element);
        if (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value)) {
          parts.push({ kind: "literal", value: value.text });
          continue;
        }
        if (value.kind === ts.SyntaxKind.TrueKeyword || value.kind === ts.SyntaxKind.FalseKeyword || value.kind === ts.SyntaxKind.NullKeyword) {
          parts.push({ kind: "literal", value: value.getText(sf) });
          continue;
        }
        const resolution = resolveValueOrigin(value, value, call, sf, bindings);
        if (resolution.kind === "unknown") return { kind: "unknown", detail: resolution.detail };
        parts.push({ kind: "dynamic", origin: resolution.origin, encoded: false });
      }
      return { kind: "known", parts, framing: "json-tuple" };
    }
    if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isIdentifier(node.expression) &&
      isUnshadowedGlobal(node.expression, "encodeURIComponent", bindings)
    ) {
      const resolution = resolveValueOrigin(node.arguments[0]!, node, call, sf, bindings);
      return resolution.kind === "resolved"
        ? { kind: "known", parts: [{ kind: "dynamic", origin: resolution.origin, encoded: true }], framing: "raw" }
        : { kind: "unknown", detail: resolution.detail };
    }
    if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isIdentifier(node.expression) &&
      isUnshadowedGlobal(node.expression, "String", bindings)
    ) {
      return compositionOf(node.arguments[0]!);
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const resolution = resolveValueOrigin(node, node, call, sf, bindings);
      return resolution.kind === "resolved"
        ? { kind: "known", parts: [{ kind: "dynamic", origin: resolution.origin, encoded: false }], framing: "raw" }
        : { kind: "unknown", detail: resolution.detail };
    }
    if (ts.isIdentifier(node)) {
      const resolution = resolveValueOrigin(node, node, call, sf, bindings);
      if (resolution.kind === "resolved") {
        return { kind: "known", parts: [{ kind: "dynamic", origin: resolution.origin, encoded: false }], framing: "raw" };
      }
      const lookup = bindings.lookup(node);
      if (lookup.kind !== "resolved") return { kind: "unknown", detail: resolution.detail };
      const binding = lookup.binding;
      if (binding.kind !== "variable" || compositionStack.has(binding)) return { kind: "unknown", detail: resolution.detail };
      const eligibility = eligibleConstInitializer(binding, node, call, bindings);
      if (eligibility.kind === "ineligible") return { kind: "unknown", detail: eligibility.detail };
      compositionStack.add(binding);
      const composition = compositionOf(eligibility.initializer);
      compositionStack.delete(binding);
      return composition;
    }
    return { kind: "unknown", detail: `'${boundedNodeText(node, sf)}' is not a canonical key composition` };
  };

  const normalizeComposition = (parts: CompositionPart[]): CompositionPart[] => {
    const normalized: CompositionPart[] = [];
    for (const part of parts) {
      const prior = normalized.at(-1);
      if (part.kind === "literal" && prior?.kind === "literal") prior.value += part.value;
      else normalized.push(part.kind === "literal" ? { ...part } : { ...part, origin: { ...part.origin, path: [...part.origin.path] } });
    }
    return normalized;
  };

  const hasEncodedTermFraming = (parts: CompositionPart[]): boolean => {
    const dynamicIndexes = parts.flatMap((part, index) => (part.kind === "dynamic" ? [index] : []));
    if (dynamicIndexes.length === 0 || !dynamicIndexes.every((index) => parts[index]!.kind === "dynamic" && parts[index]!.encoded)) return false;
    for (let index = 1; index < dynamicIndexes.length; index += 1) {
      const between = parts.slice(dynamicIndexes[index - 1]! + 1, dynamicIndexes[index]);
      if (!between.some((part) => part.kind === "literal" && /[:/|,;=@#$?&+]/.test(part.value))) return false;
    }
    return true;
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
  if (volatile === "clock-derived" || [...keyOrigins.values()].some((origin) => ATTEMPT_IDENTITY.test(origin.semanticName))) {
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

  if (target.operationDetail) {
    return {
      safe: false,
      classification: "mechanically-unproven-provider-operation",
      detail: `${target.operationDetail}, so this pass cannot bind the key to one provider effect`,
      falsifier: "make the provider method and effect statically visible, then show one consistent key contract for that logical operation",
    };
  }

  const composition = compositionOf(expression);
  if (composition.kind === "unknown") {
    return {
      safe: false,
      classification: "collision-prone-key-framing",
      detail: `\`${text}\` is not a mechanically decodable key composition (${composition.detail})`,
      falsifier: "use a typed JSON array tuple or encode every dynamic term separately with the unshadowed encodeURIComponent builtin",
    };
  }

  const parts = normalizeComposition(composition.parts);
  const dynamicParts = parts.filter((part): part is Extract<CompositionPart, { kind: "dynamic" }> => part.kind === "dynamic");
  if (dynamicParts.length === 0) {
    return {
      safe: false,
      classification: "unsafe-global-constant",
      detail: `\`${text}\` has no immutable operation identity and can collide across every call site execution`,
      falsifier: "evaluate the key for two different entities in the same scope and show the values differ",
    };
  }

  const requirement = scopeRequirement(target, sf, bindings);
  if (requirement.ambiguity) {
    return {
      safe: false,
      classification: "mechanically-unproven-scope-domain",
      detail: `${requirement.ambiguity}; declaration spellings alone cannot select the logical operation's identity`,
      falsifier: "make the provider payload's tenant/entity provenance explicit and show the key uses those exact immutable origins",
    };
  }

  const origins = new Map(dynamicParts.map((part) => [part.origin.key, part.origin]));
  const entityOrigins = [...origins.values()].filter((origin) => origin.role === "entity");
  const missingEntities = requirement.entity.filter((origin) => !origins.has(origin.key));
  if (entityOrigins.length === 0 || missingEntities.length > 0) {
    return {
      safe: false,
      classification: "missing-entity-scope",
      detail:
        missingEntities.length > 0
          ? `\`${text}\` omits provider-payload entity provenance (${missingEntities.map((origin) => `\`${origin.display}\``).join(", ")})`
          : `\`${text}\` has no entity identity distinct from tenant provenance`,
      falsifier: "evaluate the key for two different entities in the same tenant scope and show the values differ",
    };
  }

  const missingTenants = requirement.tenant.filter((origin) => !origins.has(origin.key));
  if (missingTenants.length > 0) {
    return {
      safe: false,
      classification: "missing-tenant-scope",
      detail: `\`${text}\` omits provider-payload or typed tenant provenance (${missingTenants.map((origin) => `\`${origin.display}\``).join(", ")})`,
      falsifier: "evaluate the key for the same entity identifier in two tenants and show the values differ",
    };
  }

  const operationLiterals = parts
    .filter((part): part is Extract<CompositionPart, { kind: "literal" }> => part.kind === "literal")
    .map((part) => part.value)
    .filter((literal) => OPERATION_WORD.test(literal));
  if (operationLiterals.length === 0) {
    return {
      safe: false,
      classification: "missing-operation-scope",
      detail: `\`${text}\` has entity provenance but no stable operation discriminator`,
      falsifier: "evaluate two different provider effects for the same tenant/entity and show their keys differ",
    };
  }
  const operationDiscriminator = OPERATION_WORD.exec(operationLiterals[0]!)![0]!.toLowerCase();

  const untyped = dynamicParts.find((part) => part.origin.primitiveType === undefined);
  if (untyped) {
    return {
      safe: false,
      classification: "mechanically-unproven-key-origin-type",
      detail: `\`${untyped.origin.display}\` is not a required string/number/boolean origin, so its serialization can collapse distinct values`,
      falsifier: "give every dynamic key term a required primitive type and demonstrate distinct typed values serialize distinctly",
    };
  }

  const framing: ProvenOperationKeyContract["framing"] | undefined =
    composition.framing === "json-tuple"
      ? "canonical-json-tuple"
      : hasEncodedTermFraming(parts)
        ? "encoded-terms"
        : undefined;
  if (!framing) {
    return {
      safe: false,
      classification: "collision-prone-key-framing",
      detail: `\`${text}\` is not a typed JSON tuple and does not separately encode every dynamic term, so distinct identity tuples can share one byte string`,
      falsifier: "evaluate shifted-boundary tuples and either use a typed JSON array or individually encode every term with separators outside the encoded values",
    };
  }

  const signature = [
    framing,
    ...parts.map((part) => {
      if (part.kind === "literal") return `L:${JSON.stringify(part.value)}`;
      const sameRoleCount = dynamicParts.filter((candidate) => candidate.origin.role === part.origin.role).length;
      const semanticRole =
        part.origin.role === "other" || sameRoleCount > 1
          ? `${part.origin.role}:${part.origin.semanticName.toLowerCase()}`
          : part.origin.role;
      return `D:${semanticRole}`;
    }),
  ].join("|");

  return {
    safe: true,
    classification: "stable-scoped-operation-key",
    detail: `\`${text}\` proves disjoint tenant/entity provenance, ${framing}, and a stable discriminator for ${target.logicalOperation}`,
    falsifier: "change any required tenant/entity or provider effect and observe a collision, or retry unchanged inputs and observe a different key",
    contract: { framing, operationDiscriminator, originKeys: new Set(origins.keys()), signature },
  };
}

function externalOperationRecords(
  path: string,
  sf: ts.SourceFile,
  bindings: SourceFileBindingIndex,
): { findings: Finding[]; records: ExternalOperationRecord[] } {
  if (!isRetryableExternalSendPath(path)) return { findings: [], records: [] };
  const findings: Finding[] = [];
  const records: ExternalOperationRecord[] = [];
  for (const call of calls(sf)) {
    const target = externalSendTarget(call, sf, bindings);
    if (!target) continue;
    if (target.key.kind === "present") {
      const analysis = analyzeKey(target.key.expression, target, sf, bindings);
      if (analysis.safe && analysis.contract) {
        records.push({ analysis, operationContext: logicalOperationContext(target.call), path, sf, target });
        continue;
      }
      if (analysis.safe) continue;
      findings.push(
        mechanicalFinding({
          id: `RETRY-unsafe-idempotency-key-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${target.key.expression.getStart(sf)}`,
          title: `${path} — idempotency key does not identify one stable scoped operation`,
          severity: "Medium",
          category: "Business logic",
          taxonomy: IDEMPOTENCY_KEY_TAXONOMY,
          location: loc(path, sf, target.key.expression),
          evidence: `Heuristic "external-send-idempotency-key" classified the ${target.api} key as ${analysis.classification}: ${analysis.detail}. PROVIDER COLLISION DOMAIN: ${target.providerDomain}. LOGICAL OPERATION: ${target.logicalOperation}. SCOPE OF THIS CHECK: it reads exact provider slots and immutable provenance in THIS FILE only, then compares proven contracts across ALL ADMITTED PROJECT FILES. FALSIFIER: ${analysis.falsifier}.`,
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
  return { findings, records };
}

function projectWideOperationContractFindings(records: ExternalOperationRecord[]): Finding[] {
  const findings: Finding[] = [];
  const contextsProveSameOperation = (
    left: LogicalOperationContext,
    right: LogicalOperationContext,
    operationDiscriminator: string,
  ): boolean => {
    if (left.kind === "unknown" || right.kind === "unknown") return false;
    if (left.fingerprint === right.fingerprint) return true;
    const discriminatorTerms = operationDiscriminator.split(/[^a-z0-9]+/).filter(Boolean);
    const namesDiscriminator = (context: Extract<LogicalOperationContext, { kind: "named" }>): boolean => {
      const nameTerms = new Set(context.fingerprint.split("-"));
      return discriminatorTerms.length > 0 && discriminatorTerms.every((term) => nameTerms.has(term));
    };
    return namesDiscriminator(left) && namesDiscriminator(right);
  };
  const domains = new Map<
    string,
    { byOperation: Map<string, ExternalOperationRecord>; bySignature: Map<string, ExternalOperationRecord> }
  >();
  for (const record of records) {
    const contract = record.analysis.contract;
    if (!contract) continue;
    const operationIdentity = `${record.target.logicalOperation}::${contract.operationDiscriminator}`;
    const domain = domains.get(record.target.providerDomain) ?? {
      byOperation: new Map<string, ExternalOperationRecord>(),
      bySignature: new Map<string, ExternalOperationRecord>(),
    };
    domains.set(record.target.providerDomain, domain);
    const sameOperation = domain.byOperation.get(operationIdentity);
    const sameSignature = domain.bySignature.get(contract.signature);
    let classification:
      | "cross-operation-key-collision"
      | "inconsistent-logical-operation-key-contract"
      | "mechanically-unproven-logical-operation-collision"
      | undefined;
    let prior: ExternalOperationRecord | undefined;
    if (sameSignature && sameSignature.target.logicalOperation !== record.target.logicalOperation) {
      classification = "cross-operation-key-collision";
      prior = sameSignature;
    } else if (
      sameSignature &&
      !contextsProveSameOperation(
        sameSignature.operationContext,
        record.operationContext,
        contract.operationDiscriminator,
      )
    ) {
      classification = "mechanically-unproven-logical-operation-collision";
      prior = sameSignature;
    } else if (sameOperation?.analysis.contract?.signature !== undefined && sameOperation.analysis.contract.signature !== contract.signature) {
      classification = "inconsistent-logical-operation-key-contract";
      prior = sameOperation;
    }
    if (classification && prior && record.target.key.kind === "present") {
      const collision = classification !== "inconsistent-logical-operation-key-contract";
      const contextEvidence = (candidate: ExternalOperationRecord): string =>
        candidate.operationContext.kind === "named"
          ? `enclosing operation \`${candidate.operationContext.display}\``
          : candidate.operationContext.detail;
      findings.push(
        mechanicalFinding({
          id: `RETRY-project-idempotency-contract-${record.path.replace(/[^a-zA-Z0-9]+/g, "-")}-${record.target.key.expression.getStart(record.sf)}`,
          title:
            classification === "mechanically-unproven-logical-operation-collision"
              ? `${record.path} — distinct logical-operation contexts share one idempotency-key contract`
              : collision
                ? `${record.path} — different provider effects share one idempotency-key contract`
                : `${record.path} — one provider effect uses inconsistent idempotency-key contracts`,
          severity: "Medium",
          category: "Business logic",
          taxonomy: IDEMPOTENCY_KEY_TAXONOMY,
          location: loc(record.path, record.sf, record.target.key.expression),
          evidence: collision
            ? `Heuristic "external-send-idempotency-key" classified this as ${classification}: ${record.target.logicalOperation} in \`${record.path}\` (${contextEvidence(record)}) and ${prior.target.logicalOperation} in \`${prior.path}\` (${contextEvidence(prior)}) map to the same proven contract inside provider collision domain \`${record.target.providerDomain}\`. SCOPE OF THIS CHECK: ALL ADMITTED PROJECT FILES, partitioned by provider collision domain. FALSIFIER: prove the named call-site operations are retry entry points for the same logical effect, or give distinct effects disjoint stable operation discriminators and show their keys differ for one shared tenant/entity tuple.`
            : `Heuristic "external-send-idempotency-key" classified this as ${classification}: ${record.target.logicalOperation} uses a different proven encoding in \`${record.path}\` than in \`${prior.path}\` inside provider collision domain \`${record.target.providerDomain}\`. SCOPE OF THIS CHECK: ALL ADMITTED PROJECT FILES, partitioned by provider collision domain. FALSIFIER: show both call sites implement different provider effects, or make every site for this logical operation use one stable decodable contract.`,
          impact: collision
            ? "A provider may suppress one distinct external effect as a retry of another because both effects occupy the same key namespace."
            : "Retries routed through different call sites can produce different keys for the same provider effect, defeating deduplication.",
          fix: collision
            ? "Give each provider effect a disjoint stable operation discriminator while preserving required tenant/entity provenance."
            : "Use one canonical typed or per-term-encoded contract for this logical provider operation at every call site.",
          precisionTier: "review",
        }),
      );
    }
    if (!sameOperation) domain.byOperation.set(operationIdentity, record);
    if (!sameSignature) domain.bySignature.set(contract.signature, record);
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
  return [
    ...claimBeforeSend(path, sf),
    ...dedupBeforeDispatch(path, sf),
    ...webhookOrdering(path, sf),
  ];
}

export function detectIdempotencyFindings(files: SourceInput[]): Finding[] {
  const admittedSources = idempotencySourceFiles(files);
  const admitted = admittedSources
    .map((file) => ({ path: file.path, sf: parse(file.path, file.text) }));
  const findings = admitted.flatMap((file) => detectFile(file.path, file.sf));
  const records: ExternalOperationRecord[] = [];
  const retryablePaths = new Set(retryableExternalSendFiles(admittedSources).map((file) => file.path));
  for (const file of admitted.filter((candidate) => retryablePaths.has(candidate.path))) {
    const external = externalOperationRecords(file.path, file.sf, new SourceFileBindingIndex(file.sf));
    findings.push(...external.findings);
    records.push(...external.records);
  }
  findings.push(...projectWideOperationContractFindings(records));
  return findings;
}
