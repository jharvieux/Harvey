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
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

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
const TENANT_SCOPE_COLUMN =
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
// client-named root. Returns the model name when it matches, else undefined.
function prismaModelVerb(node: ts.CallExpression): { model: string; verb: string } | undefined {
  const verbAccess = node.expression;
  if (!ts.isPropertyAccessExpression(verbAccess)) return undefined;
  const verb = verbAccess.name.text;
  if (!SCOPED_VERBS.has(verb)) return undefined;

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
      const shape = prismaModelVerb(node);
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

export function detectPrismaTenantScopeFindings(files: SourceInput[]): Finding[] {
  return files.filter((f) => SOURCE_EXT.test(f.path)).flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

export function scanPrismaTenantScope(projectDir: string): Finding[] {
  return detectPrismaTenantScopeFindings(walkSourceFiles(projectDir));
}
