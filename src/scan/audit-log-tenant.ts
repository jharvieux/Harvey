// #1242 AUDIT-LOG-TENANT — an audit record that names WHO and WHAT but not WHICH TENANT. OWASP
// Multi-Tenant Application Security Cheat Sheet section 8 ("Include tenant context in all log
// entries", "Implement tenant-isolated audit trails"). Found as a measured gap by that sheet's
// independent corpus (owasp-multitenant.entries.ts, P-OWASP-MT-LOG-TENANT) and the last of its
// eight gaps to get an owner.
//
//   export function recordDeletion(userId: string, invoiceId: string) {
//     logger.info(`user ${userId} deleted invoice ${invoiceId}`);
//   }
//
// The sheet asks elsewhere for monitoring and alerting on cross-tenant access attempts; that
// guidance is unenforceable against a trail whose entries carry no discriminator to group by.
//
// FP DISCIPLINE — the issue's own doubt was whether this is shippable at all, because "this log
// line omits a field" needs to know which fields matter for the app. cache-tenant-scope.ts narrows
// by requiring a tenant identifier already in scope; that narrowing is UNAVAILABLE here (the whole
// shape is a logging site with no tenant anywhere), so the substitute is to require the entry to
// be AUDIT-SHAPED — all four of:
//   1. the receiver reads as a logger/audit sink (never `console`, which is diagnostics, not a
//      trail — a console line is nobody's detective control);
//   2. the enclosing function takes an ACTOR identifier parameter (`userId`/`actorId`/…) and the
//      logged arguments mention it, so this is a per-actor record and not a debug breadcrumb;
//   3. the logged arguments name a security-relevant MUTATION verb (deleted/granted/exported/…) —
//      the sheet's concern is reconstructing an access, not tracing control flow;
//   4. nothing in the logged arguments mentions a tenant/org/workspace discriminator.
// What survives all four is narrow, but the residual FP is real and NAMED IN THE EVIDENCE rather
// than engineered away: a single-tenant application has no discriminator to log, and this pass
// cannot see whether the sink injects one (a pino/winston child logger bound with `tenant_id`
// upstream is invisible here). That is why it is `review`, never free-count.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// Deliberately excludes `account`/`company`, which read as tenant words in TENANT_TOKEN below.
const ACTOR_PARAM = /^(user|actor|member|principal|caller|admin|editor|author|operator)_?id$/i;
const TENANT_TOKEN = /\b(tenant|org|orgs|organisation|organization|workspace|company|account)/i;

// A logging/audit sink. `console` is excluded on purpose — see FP DISCIPLINE (1).
const LOG_RECEIVER = /^(logger|log|audit|auditLog|auditLogger|auditTrail|trail|events?)$/i;
const LOG_METHOD = /^(info|warn|warning|error|debug|log|trace|event|record|write|audit|emit)$/;

// Security-relevant state changes — the events an audit trail exists to reconstruct.
const MUTATION_VERB =
  /\b(created?|deleted?|removed?|updated?|modified|granted?|revoked?|approved?|rejected?|exported?|downloaded?|uploaded?|disabled?|enabled?|impersonated?|transferred?|invited?|assigned?|archived?|restored?|purged?|rotated?)\b/i;

function isFunctionLike(n: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n)
  );
}

function actorParamNames(fn: ts.SignatureDeclaration): string[] {
  const names: string[] = [];
  const collect = (name: ts.BindingName) => {
    if (ts.isIdentifier(name)) {
      if (ACTOR_PARAM.test(name.text)) names.push(name.text);
    } else if (ts.isObjectBindingPattern(name)) {
      for (const el of name.elements) if (ts.isBindingElement(el)) collect(el.name);
    }
  };
  for (const p of fn.parameters) collect(p.name);
  return names;
}

// A `<sink>.<method>(...)` call on a logger-like receiver, or `<sink>.<a>.<method>(...)` for the
// namespaced form (`ctx.logger.info`). Returns the printed text of every argument.
function logCall(node: ts.CallExpression, sf: ts.SourceFile): { sink: string; args: string } | undefined {
  if (!ts.isPropertyAccessExpression(node.expression)) return undefined;
  if (!LOG_METHOD.test(node.expression.name.text)) return undefined;
  const receiver = node.expression.expression;
  const sink = ts.isIdentifier(receiver)
    ? receiver.text
    : ts.isPropertyAccessExpression(receiver)
      ? receiver.name.text
      : undefined;
  if (!sink || !LOG_RECEIVER.test(sink)) return undefined;
  if (node.arguments.length === 0) return undefined;
  return { sink, args: node.arguments.map((a) => a.getText(sf)).join(", ") };
}

function detectFunction(fn: ts.SignatureDeclaration & ts.Node, sf: ts.SourceFile, path: string): Finding[] {
  const actors = actorParamNames(fn);
  if (actors.length === 0) return [];

  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n)) {
      const call = logCall(n, sf);
      if (call) {
        const namesActor = actors.some((a) => new RegExp(`\\b${a}\\b`).test(call.args));
        if (namesActor && MUTATION_VERB.test(call.args) && !TENANT_TOKEN.test(call.args)) {
          findings.push(
            mechanicalFinding({
              id: `AUDIT-log-no-tenant-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${n.getStart(sf)}`,
              title: `${path} — audit log entry records the actor but no tenant`,
              severity: "Medium",
              category: "Logging and monitoring",
              taxonomy: "Audit log entry without a tenant discriminator",
              location: loc(path, sf, n),
              evidence:
                `Heuristic "audit-log-tenant" matched a \`${call.sink}\` entry that names the actor \`${actors[0]}\` and a state change, ` +
                `with no tenant/organisation/workspace discriminator in its arguments. ` +
                `Assumes a multi-tenant target and a sink that does not inject the tenant upstream — a bound child logger is invisible to a static pass, so confirm before acting.`,
              impact:
                "A cross-tenant access cannot be reconstructed or alerted on after the fact: the trail records who and what, but not which tenant's data was touched, so entries cannot be grouped or scoped per tenant during an investigation.",
              fix: "Include the tenant identifier in every audit entry — as a structured field (`logger.info({ tenantId, userId, action })`) or via a per-request child logger bound with the tenant — and keep audit trails tenant-isolated.",
              precisionTier: "review",
            }),
          );
        }
      }
    }
    if (!isFunctionLike(n) || n === fn) ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);
  return findings;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (n: ts.Node) => {
    if (isFunctionLike(n)) findings.push(...detectFunction(n as ts.SignatureDeclaration & ts.Node, sf, path));
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return findings;
}

export function detectAuditLogTenantFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
