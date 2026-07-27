// #1230 / D-091 items 10, 22 and 24 — three retry-safety shapes that share one question: what does
// a RETRY of this code do? #1230 filed all three as "cross-statement or cross-time dataflow, a poor
// fit for the mechanical tier". Re-checked against the catalog: the cross-TIME part is the failure
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

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

const SEND_CALLEE = /^(send|dispatch|deliver|notify|email|publish|enqueue|post|fire)[A-Za-z0-9_]*$/i;
const STAMP_FIELD = /^(sent|delivered|notified|emailed|dispatched|published|fired|processed)_at$/i;
const DEDUP_TABLE = /(webhook_events?|processed_events?|idempotency|idempotent|dedup|deduplication|seen_events?|event_log|handled_events?)/i;
const DISPATCH_CALLEE = /^(handle|dispatch|process|apply|route|execute|perform|on)[A-Z][A-Za-z0-9_]*$/;
const RETRYABLE_PATH = /(^|\/)(inngest|cron|crons|queue|queues|worker|workers|jobs?|tasks?|webhooks?|scheduler|schedules?)(\/|\.|$)/i;
const IDEMPOTENT_HOST = /https?:\/\/api\.(stripe|resend|apify|sendgrid|postmarkapp|mailgun|twilio|adyen|square(?:up)?)\.com/i;
const IDEMPOTENCY_OPTION = /idempotenc/i;

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

// (24) An external send from a retryable path with no idempotency key. `optionsOf` returns the
// argument that would carry the key, or undefined when the call is not one we can speak to.
function optionsOf(node: ts.CallExpression, sf: ts.SourceFile): { arg: ts.Expression | undefined; api: string } | undefined {
  if (ts.isIdentifier(node.expression) && node.expression.text === "fetch") {
    const url = node.arguments[0];
    const host = url && ts.isStringLiteralLike(url) ? IDEMPOTENT_HOST.exec(url.text) : null;
    return host ? { arg: node.arguments[1], api: host[0] } : undefined;
  }
  // stripe.<resource>.create(params, options)
  if (
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === "create" &&
    ts.isPropertyAccessExpression(node.expression.expression) &&
    /stripe/i.test(node.expression.expression.expression.getText(sf))
  ) {
    return { arg: node.arguments[1], api: `Stripe ${node.expression.expression.name.text}.create` };
  }
  return undefined;
}

function externalSendNoIdempotencyKey(path: string, sf: ts.SourceFile): Finding[] {
  if (!RETRYABLE_PATH.test(path)) return [];
  const findings: Finding[] = [];
  for (const call of calls(sf)) {
    const target = optionsOf(call, sf);
    if (!target) continue;
    if (target.arg && IDEMPOTENCY_OPTION.test(target.arg.getText(sf))) continue;
    findings.push(
      mechanicalFinding({
        id: `RETRY-no-idempotency-key-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${call.getStart(sf)}`,
        title: `${path} — external send from a retryable job carries no idempotency key`,
        severity: "Medium",
        category: "Business logic",
        taxonomy: "External send without a deterministic idempotency key",
        location: loc(path, sf, call),
        evidence: `Heuristic "external-send-idempotency" matched a call to ${target.api} from a retryable path (\`${path}\`) whose options carry no idempotency key.`,
        impact:
          "The platform retries this step on any failure after the call was already accepted, so the operation lands twice. The provider's dedup window is minutes to hours and single-run tests never retry, so the duplicate only appears in production.",
        fix: "Pass an idempotency key derived from immutable identifiers (`sha256(tenant_id|entity_id|operation|version)`) — the Stripe SDK's `idempotencyKey` request option, or an `Idempotency-Key` header on the REST call.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  return [...claimBeforeSend(path, sf), ...dedupBeforeDispatch(path, sf), ...externalSendNoIdempotencyKey(path, sf)];
}

export function detectIdempotencyFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanIdempotency(projectDir: string): Finding[] {
  return detectIdempotencyFindings(walkSourceFiles(projectDir));
}
