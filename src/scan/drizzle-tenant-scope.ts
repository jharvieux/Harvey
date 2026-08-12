// #901 (remainder of #869) DRIZZLE-TENANT-SCOPE — the Drizzle query-builder idiom of the same
// cross-tenant BOLA class the Prisma detector (src/scan/prisma-tenant-scope.ts, #760) catches. A
// Drizzle-on-Postgres app has NO database-level tenant enforcement (it never had the Supabase RLS
// safety net), so a query whose `.where(...)` filters ONLY by a primary key
// (`db.select().from(table).where(eq(table.id, id))`, or the `update`/`delete` equivalents) with no
// tenant/owner column reads or mutates whichever tenant owns that id: any authenticated user who
// substitutes another tenant's id gets that tenant's row. Same shape, same Critical, different ORM.
//
// Gates — mirrors #760's precision posture:
//   - the call must be a Drizzle builder chain terminating in `.where(<expr>)`, whose root is a
//     client-named binding (`db`/`tx`/`client`/`drizzle`/`database`, bare or as `this.db`/`ctx.db`)
//     and whose innermost verb is `select().from(...)`, `update(...).set(...)`, or `delete(...)` —
//     a Prisma `prisma.task.update({ where })` object shape does not match this method-chain shape;
//   - the filter columns come ONLY from the FIRST argument of a Drizzle comparison operator
//     (`eq`/`gt`/`inArray`/…) inside the where expression — so a Knex `.where({ id })` object, which
//     carries no `eq(col, …)` call, yields no columns and never matches, and a tenant id appearing
//     on the VALUE side of a comparison can't spuriously clear the finding;
//   - the filtered columns include `id` yet carry NO tenant/owner column anywhere in the where.
// Review tier, never free-count: the AST proves the where clause carries no tenant column, not that
// an ownership check in a wrapper/middleware it can't see is absent.

import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { mechanicalFinding } from "./common.js";
import { NON_SHIPPING_FILE, NON_SHIPPING_PATH, SOURCE_EXT, TENANT_SCOPE_COLUMN } from "./prisma-tenant-scope.js";

// A Drizzle client binding, by conventional name — bare (`db.select()…`) or as a property
// (`this.db.select()…`, `ctx.db.select()…`). The builder-chain shape below is already Drizzle-ish;
// this name gate keeps a same-named `.select().from().where()` chain on some unrelated object out.
const CLIENT_NAME = /^(db|tx|client|drizzle|database)$/i;

// Drizzle comparison operators — the column being filtered is always their FIRST argument. `and`/
// `or`/`not` are combinators (no direct column) and are descended THROUGH by the tree walk below,
// not listed here.
export const COMPARISON_OPS = new Set([
  "eq",
  "ne",
  "gt",
  "gte",
  "lt",
  "lte",
  "like",
  "ilike",
  "notlike",
  "notilike",
  "inarray",
  "notinarray",
  "isnull",
  "isnotnull",
  "between",
  "notbetween",
]);

// The columns a where expression filters on: the first argument of every comparison-operator call
// anywhere in it (recursing through `and`/`or`/`not`). A column is a `table.column` property access;
// its `.name` is the column. Value-side property accesses are ignored, so `eq(t.id, ctx.orgId)` does
// NOT read as tenant-scoped (that would be a false clear — a missed bug).
function filteredColumns(where: ts.Node): string[] {
  const cols: string[] = [];
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && COMPARISON_OPS.has(n.expression.text.toLowerCase())) {
      const col = n.arguments[0];
      if (col && ts.isPropertyAccessExpression(col)) cols.push(col.name.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(where);
  return cols;
}

// Walk a `.where(...)` call down its method chain to the root. Returns the matched verb (the label
// used in the finding) and the client-name root when the chain is a scoped Drizzle read/write, else
// undefined. `select` requires a `.from`; `update` requires a `.set`; `delete` stands alone.
function drizzleWhereChain(whereCall: ts.CallExpression): { verb: string } | undefined {
  const methods: string[] = [];
  let current: ts.Expression = whereCall;
  while (ts.isCallExpression(current)) {
    const callee = current.expression;
    if (!ts.isPropertyAccessExpression(callee)) return undefined;
    methods.push(callee.name.text);
    current = callee.expression;
  }
  // `current` is the chain root: `db` (identifier) or `this.db`/`ctx.db` (property access).
  const rootName = ts.isIdentifier(current)
    ? current.text
    : ts.isPropertyAccessExpression(current)
      ? current.name.text
      : undefined;
  if (!rootName || !CLIENT_NAME.test(rootName)) return undefined;

  const has = (m: string) => methods.includes(m);
  if (has("select") && has("from")) return { verb: "select" };
  if (has("update") && has("set")) return { verb: "update" };
  if (has("delete")) return { verb: "delete" };
  return undefined;
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "where") {
      const chain = drizzleWhereChain(node);
      const whereArg = node.arguments[0];
      if (chain && whereArg) {
        const cols = filteredColumns(whereArg);
        const hasId = cols.some((c) => c === "id");
        const hasTenant = cols.some((c) => TENANT_SCOPE_COLUMN.test(c));
        if (hasId && !hasTenant) {
          findings.push(
            mechanicalFinding({
              id: `AUTH-drizzle-tenant-scope-${chain.verb}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
              title: `${path} — Drizzle \`${chain.verb}\` filters by \`id\` alone, with no tenant/owner scope`,
              severity: "High",
              category: "Broken access control",
              taxonomy: "Object-level authorization gap: Drizzle query filtered by primary key with no tenant scope",
              location: loc(path, sf, node),
              evidence: `Heuristic "drizzle-tenant-scope": a Drizzle \`${chain.verb}\` chain's \`.where(...)\` filters by the primary key alone (\`eq(table.id, …)\`) — no tenant/owner column (organizationId/tenantId/teamId/userId/…) appears in any comparison in the where clause.`,
              impact: "A Drizzle app has no database-level tenant enforcement (no RLS), so this query's where clause is the only isolation gate. Filtered by id alone, any authenticated user who substitutes another tenant's id reads or mutates that tenant's row — the cross-tenant BOLA/IDOR that made proposit Critical.",
              fix: `Add the caller's tenant/owner to the filter (e.g. \`.where(and(eq(table.id, id), eq(table.organizationId, orgId)))\` scoped from the verified session), or compare the fetched row's owner against the session and reject a mismatch before returning/mutating it.`,
              precisionTier: "review",
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

export function detectDrizzleTenantScopeFindings(files: SourceInput[]): Finding[] {
  return files
    .filter((f) => SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path))
    .flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}
