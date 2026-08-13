// #760 (part of #756) PRISMA-TENANT-SCOPE — the Prisma-idiom of the cross-tenant BOLA class the
// pg/Supabase detectors (src/scan/bola-owner.ts, src/scan/job-tenant-scope.ts) already catch. A
// Prisma app has NO database-level tenant enforcement — it lost the RLS safety net — so a query
// filtered ONLY by a primary key (`prisma.<model>.<verb>({ where: { id } })`) with no tenant/owner
// column reads or mutates whichever tenant owns that id: any authenticated user who substitutes
// another tenant's id gets that tenant's row. This is the exact shape that made proposit Critical
// (a service-role/ORM query with no organisation scope) and is endemic in Prisma-on-Next SaaS.
//
// Gates — each a deliberate precision boundary (boxyhq, a real Prisma app, had zero RLS-detector
// false positives; keep it that way):
//   - the call must be the Prisma model-delegate shape `<client>.<model>.<verb>(<object>)`, where
//     the client segment is named like a Prisma client (`prisma`/`db`/`tx`/`client`, bare or as
//     `this.prisma`/`ctx.prisma`) — a Drizzle `db.query.users.findFirst` or a Supabase
//     `.from(...).update().eq(...)` chain does not match this shape;
//   - the verb reads or mutates a specific row by filter (`update`/`updateMany`/`delete`/
//     `deleteMany`/`findUnique`/`findUniqueOrThrow`/`findFirst`/`findFirstOrThrow`) — `create`
//     names the tenant in its payload, `findMany` with no `where` is a different (list-all) class;
//   - the `where` object filters by a primary key (`id`) yet carries NO tenant/owner column
//     ANYWHERE in it (recursively, so a relational or `AND`/`OR`-nested scope clears the finding).
// Review tier, never free-count: the AST proves the where clause carries no tenant column, not that
// an ownership check in a wrapper/middleware it can't see is absent.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";

// Shared with the Drizzle idiom of this same cross-tenant BOLA class (#901,
// src/scan/drizzle-tenant-scope.ts): the source-extension gate, the tenant/owner column vocabulary,
// and the non-shipping-path filter are the same question asked of a different query shape, so the
// two detectors stay in lockstep by importing these rather than drifting apart.
export const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

// The read/write verbs whose filter, if unscoped, selects WHOSE row comes back or is mutated.
// `create`/`createMany` name the tenant in the payload; `findMany`/`count` are the list-all class.
const SCOPED_VERBS = new Set([
  "update",
  "updateMany",
  "delete",
  "deleteMany",
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
]);

// A Prisma client binding, by conventional name — bare (`prisma.user…`, `db.user…`) or as a
// property (`this.prisma.user…`, `ctx.prisma.user…`, `ctx.db.user…`). The `.model.verb({ where })`
// shape below is already Prisma-specific; this name gate keeps a same-shaped call on some other
// object (a plain data holder) from matching.
const CLIENT_NAME = /^(prisma|prismaclient|db|tx|client)$/i;

// A tenant/owner scoping column, in Prisma's idiom. The shared OWNERSHIP_COLUMN (owner-id.ts) only
// admits snake_case/`_id`, but Prisma schemas are overwhelmingly camelCase (`organizationId`,
// `tenantId`, `teamId`, `userId`) and Prisma also scopes through named RELATIONS (`where: { id,
// organization: { members: { some: { userId } } } }`), so this admits camelCase, `Id`/`_id`
// suffixes, and bare relation names, and adds `team`/`company` which the SaaS idiom uses.
export const TENANT_SCOPE_COLUMN =
  /^(user|owner|tenant|account|org|organisation|organization|customer|workspace|member|profile|team|company|createdby|created_by|author)(id|_id)?$/i;

function propertyKeyName(prop: ts.ObjectLiteralElementLike): string | undefined {
  if ((ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) && prop.name) {
    if (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)) return prop.name.text;
  }
  return undefined;
}

// Any key ANYWHERE in the where object (descending through nested objects and `AND`/`OR` arrays)
// that names a tenant/owner column. Recursion fails SAFE toward silence: a scope nested under a
// relation or a boolean combinator still clears the finding.
function hasTenantScopeKey(node: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isObjectLiteralExpression(n)) {
      for (const prop of n.properties) {
        const key = propertyKeyName(prop);
        if (key && TENANT_SCOPE_COLUMN.test(key)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

function hasIdKey(where: ts.ObjectLiteralExpression): boolean {
  return where.properties.some((p) => propertyKeyName(p) === "id");
}

// The `prisma.<model>.<verb>` shape: a call whose callee is `<clientAccess>.<model>.<verb>`, with a
// client-named root. Returns the model and verb when it matches, else undefined. NO verb filter —
// which verbs count is the caller's question: this detector wants the row-selecting ones
// (SCOPED_VERBS), while client-supplied-tenant.ts (#1194) wants any verb that takes a `where`,
// `findMany` included.
export function prismaModelCall(node: ts.CallExpression): { model: string; verb: string } | undefined {
  const verbAccess = node.expression;
  if (!ts.isPropertyAccessExpression(verbAccess)) return undefined;
  const verb = verbAccess.name.text;

  const modelAccess = verbAccess.expression;
  if (!ts.isPropertyAccessExpression(modelAccess)) return undefined;
  const model = modelAccess.name.text;
  if (model.startsWith("$")) return undefined; // prisma.$transaction / $queryRaw are not models

  const client = modelAccess.expression;
  const clientName = ts.isIdentifier(client) ? client.text : ts.isPropertyAccessExpression(client) ? client.name.text : undefined;
  if (!clientName || !CLIENT_NAME.test(clientName)) return undefined;

  return { model, verb };
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const call = prismaModelCall(node);
      const shape = call && SCOPED_VERBS.has(call.verb) ? call : undefined;
      const arg = node.arguments[0];
      if (shape && arg && ts.isObjectLiteralExpression(arg)) {
        const whereProp = arg.properties.find((p) => propertyKeyName(p) === "where");
        if (whereProp && ts.isPropertyAssignment(whereProp) && ts.isObjectLiteralExpression(whereProp.initializer)) {
          const where = whereProp.initializer;
          if (hasIdKey(where) && !hasTenantScopeKey(where)) {
            findings.push(
              mechanicalFinding({
                id: `AUTH-prisma-tenant-scope-${shape.model}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
                title: `${path} — \`prisma.${shape.model}.${shape.verb}\` filters by \`id\` alone, with no tenant/owner scope`,
                severity: "High",
                category: "Broken access control",
                taxonomy: "Object-level authorization gap: Prisma query filtered by primary key with no tenant scope",
                location: loc(path, sf, node),
                evidence: `Heuristic "prisma-tenant-scope": \`prisma.${shape.model}.${shape.verb}({ where: { id, … } })\` filters by the primary key alone — no tenant/owner column (organizationId/tenantId/teamId/userId/…) appears anywhere in the where clause.`,
                impact: "A Prisma app has no database-level tenant enforcement (no RLS), so this query's where clause is the only isolation gate. Filtered by id alone, any authenticated user who substitutes another tenant's id reads or mutates that tenant's row — the cross-tenant BOLA/IDOR that made proposit Critical.",
                fix: `Add the caller's tenant/owner to the filter (e.g. \`where: { id, organizationId }\` scoped from the verified session), or compare the fetched row's owner against the session and reject a mismatch before returning/mutating it. Prefer \`findFirst\`/\`updateMany\`/\`deleteMany\` for a non-unique tenant predicate.`,
                precisionTier: "review",
              }),
            );
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// #896 — non-shipping code, which this detector must not report on. MEASURED 2026-07-23 over three
// MIT tenant-scoping libraries (s1owjke/prisma-rls, zenstackhq/zenstack, Errorname/prisma-multi-
// tenant): 1031 findings, EVERY ONE of them in a test, example, playground or doc path, and zero in
// any library's shipping source. An ORM test suite is wall-to-wall `prisma.post.update({ where: {
// id } })` by construction — that is the fixture setting up the case, not an authorization gap, and
// briefs/fp-rules.txt already rules test/fixture/seed/dev-script code out of scope.
//
// Broader than the shared NON_PRODUCT (detectors/load-sources.ts), which keys off the `.test.`/
// `.spec.` suffix and `__tests__/` and would still have passed 1031 → ~20 of these through:
// zenstack's `tests/**/typecheck.ts` and `.test-d.ts`, prisma-multi-tenant's `docs/examples/**` and
// `tests/playground/**`. Kept local to this detector rather than widening NON_PRODUCT, because that
// constant also feeds M6/M7/M9, whose external-corpus baselines are measured against its current
// meaning — widening it there is a re-measurement, not a precision fix.
export const NON_SHIPPING_PATH = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|spec|specs|e2e|fixtures?|examples?|playground|docs?|samples?|benchmarks?)\//i;
export const NON_SHIPPING_FILE = /\.(test|spec)([.-]|$)|\.stories\./i;

// #911: an APPLICATION built on a tenant-scoping wrapper library still draws findings from this
// detector, because the wrapper injects the tenant predicate at runtime — a `db.post.findUnique({
// where: { id } })` call site is safe when `db` is a prisma-rls/ZenStack-enhanced client, but the
// AST at the call site is identical to the genuinely-unscoped case (#896 measured this as an open
// question: the three library repos it scanned are not applications, so no such call site existed
// to measure there). Rather than try to tell an enhanced client binding apart from a raw one at
// each call site — which the AST cannot do reliably — this gates the WHOLE detector off for a
// target that shows either recognized signal, matching the dependency-gated precedent in
// framework-detect.ts's detectOrm/recogniseDataLayer:
//   - a package.json dependency on a known wrapper package (prisma-rls, ZenStack's runtime); or
//   - an in-tree Prisma client extension using the `$extends(...).$allOperations` idiom those
//     wrappers are built on, vendored rather than imported (prisma-rls's own shape, see
//     extension-scoping-negative).
// This is a coarser gate than per-call-site precision: a target that depends on the wrapper but
// doesn't route every query through it has its unscoped call sites withheld too. #1067 made that
// cost visible instead of silent — the gate no longer returns an empty result, it returns
// M1-WRAPPER-00 naming the signal that fired and counting exactly what was withheld, so the
// deliverable never shows a wrapper-using target as an assessed-and-clean one.
const TENANT_SCOPING_WRAPPER_DEPS = ["prisma-rls", "@zenstackhq/runtime", "zenstack"];

function wrapperDependencies(pkgText: string | undefined): string[] {
  if (!pkgText) return [];
  let pkg: unknown;
  try {
    pkg = JSON.parse(pkgText);
  } catch {
    return [];
  }
  if (typeof pkg !== "object" || pkg === null) return [];
  const p = pkg as Record<string, Record<string, unknown> | undefined>;
  const sections = { dependencies: p.dependencies, devDependencies: p.devDependencies, peerDependencies: p.peerDependencies };
  const hits: string[] = [];
  for (const [section, deps] of Object.entries(sections)) {
    for (const d of TENANT_SCOPING_WRAPPER_DEPS) if (deps && d in deps) hits.push(`${d} (${section})`);
  }
  return hits;
}

const EXTENDS_CALL = /\$extends\s*\(/;
const ALL_OPERATIONS = /\$allOperations\b/;

// Which signals fired, in the deliverable's words. Empty means the detector reports normally.
function tenantScopingWrapperSignals(files: SourceInput[]): string[] {
  const signals = wrapperDependencies(files.find((f) => f.path === "package.json")?.text).map((d) => `package.json declares ${d}`);
  for (const f of files) {
    if (SOURCE_EXT.test(f.path) && EXTENDS_CALL.test(f.text) && ALL_OPERATIONS.test(f.text)) {
      signals.push(`${f.path} vendors the $extends(...).$allOperations wrapper idiom in-tree`);
    }
  }
  return signals;
}

// #1067: the wrapper gate used to `return []`, which is indistinguishable in every deliverable
// from "assessed, nothing found". This states what was gated off and how many call sites it cost.
function wrapperDisclosure(signals: string[], withheld: Finding[]): Finding {
  const locations = withheld.length > 0 ? ` Withheld: ${withheld.map((f) => f.location).join("; ")}.` : "";
  return {
    id: "M1-WRAPPER-00",
    title: `Prisma tenant-scope detector gated off by a tenant-scoping wrapper (${withheld.length} call site${withheld.length === 1 ? "" : "s"} withheld)`,
    severity: "Info",
    confidence: "N/A",
    category: "Multi-tenant isolation",
    taxonomy: "Coverage — Prisma tenant-scope not assessed (wrapper-gated)",
    location: "(repo-wide)",
    status: "Open",
    evidence: `Recognised tenant-scoping wrapper signals: ${signals.join("; ")}. Because such a wrapper injects the tenant predicate at runtime, an unscoped-looking \`prisma.<model>.<verb>({ where: { id } })\` is indistinguishable at the AST from a genuinely unscoped one, so the whole detector is gated off for this target. It matched ${withheld.length} call site${withheld.length === 1 ? "" : "s"} that were withheld as a result.${locations}`,
    impact:
      "Prisma tenant-scope coverage for this target is NOT ASSESSED, not clean. The signal can be a devDependency or a vendored extension the production query path never uses — in which case the withheld call sites are real cross-tenant BOLA exposure that no other mechanical detector covers (a Prisma app has no database-level RLS).",
    fix: "Confirm every Prisma query in this codebase actually routes through the enhanced/wrapped client. Review the withheld call sites above by hand — each must be reached only via the wrapper, or must carry its own tenant/owner predicate.",
    value: 1,
    ease: 4,
    safety: 5,
    mechanical: true,
  };
}

export function detectPrismaTenantScopeFindings(files: SourceInput[]): Finding[] {
  const matches = files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
  const signals = tenantScopingWrapperSignals(files);
  return signals.length > 0 ? [wrapperDisclosure(signals, matches)] : matches;
}
