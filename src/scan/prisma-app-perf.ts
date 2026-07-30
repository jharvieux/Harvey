// #793 (part of #756, the remainder split from #761/#756) M7 — the two app-code
// cross-referencing Prisma perf heuristics #761 deliberately deferred: schema.prisma alone can't
// see (1) a query issued once per loop iteration (N+1) or (2) a `where` filter on a column with no
// covering index — both need the app source AND the schema. Noisier by construction than #761's
// pure schema parse, so both are precision-gated and review-tier; each gate below exists because a
// naive version of it produced a specific false positive during design.
//
// Local mirror of prisma-schema-perf.ts's (#761) MODEL_START/readBalancedBraces scan and its
// covered-index regexes, and of prisma-schema-parse.ts's (#758) scalar-vs-relation field
// classification — duplicated rather than imported, matching prisma-schema-perf.ts's own
// precedent (its header mirrors prisma-schema-parse.ts's readBalancedBraces the same way) so these
// small independent parsers don't couple to each other's internals. Deliberately NOT importing
// prisma-schema-parse.ts's parsePrismaSchema directly: its output is keyed by @@map/@map DB names
// (built for the M10 SQL-column shape), but app code always addresses a Prisma field by its SCHEMA
// name, never a remapped DB column name (see the shared fixture's Customer.paymentMethod
// @map("payment_method")) — reusing it here would silently mismatch any @map'd field.

import { existsSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { loc, parse, type SourceInput } from "../detectors/common.js";
import { devToolingModules } from "../detectors/perf-code.js";
import { readEntriesSafe } from "../fs-walk.js";
import { mechanicalFinding, walkSourceFiles } from "./common.js";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

function stripLineComments(text: string): string {
  return text
    .split("\n")
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join("\n");
}

function readBalancedBraces(text: string, open: number): { body: string; end: number } | null {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return { body: text.slice(open + 1, i), end: i };
    }
  }
  return null; // unterminated block — under-extract, don't guess where it ends
}

const MODEL_START = /\bmodel\s+(\w+)\s*\{/g;
const BLOCK_ATTR_LINE = /^\s*@@/;
const FIELD_LINE = /^\s*(\w+)\s+(\w+)(?:\?|\[\])?/;
const ID_OR_UNIQUE_ATTR = /(^|\s)@(id|unique)(\s|\(|$)/;
const BLOCK_COVERING_ATTR = /@@(?:id|unique|index)\(\s*\[([^\]]*)\]/g;
// Prisma's own scalar field types (schema reference §Model field scalar types) — mirrors
// prisma-schema-parse.ts's SCALAR_TYPE_MAP keys. Any other capitalized type name is a relation to
// another model (or an enum this parser doesn't resolve), which this heuristic must NOT treat as
// an indexable column: a relation field (e.g. `user User @relation(...)`) is never itself an
// `@index` target (its backing scalar FK field is, already covered by #761), so counting it as a
// "filter column" would flag ordinary relation filtering (`where: { user: { id } }`) as unindexed.
const SCALAR_TYPES = new Set(["String", "Boolean", "Int", "BigInt", "Float", "Decimal", "DateTime", "Json", "Bytes"]);

interface ModelFilterInfo {
  /** the model name as declared in schema.prisma, for display (e.g. "Note"). */
  displayName: string;
  /** scalar (non-relation) field names declared on the model. */
  scalarFields: Set<string>;
  /** field names covered by @id/@unique on the field, or named in @@id/@@unique/@@index. */
  indexedFields: Set<string>;
}

// Prisma's generated client property is the model name with only its FIRST letter
// lowercased (`model OAuthToken` → `prisma.oAuthToken`), never a full-string lowercase — the
// schema map below is keyed by this form so a `prisma.<model>.<verb>` call site's `model` segment
// (already in this form) looks the map up directly, with no per-lookup transform at the call site.
function clientPropertyName(modelName: string): string {
  return modelName.charAt(0).toLowerCase() + modelName.slice(1);
}

/** Per-model scalar-field/index info, parsed straight from schema.prisma text and keyed by the
 * Prisma-client property name (see clientPropertyName) so it matches app code directly. */
function parseModelFilterInfo(schema: string): Map<string, ModelFilterInfo> {
  const clean = stripLineComments(schema);
  const out = new Map<string, ModelFilterInfo>();
  MODEL_START.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MODEL_START.exec(clean))) {
    const modelName = m[1]!;
    const open = clean.indexOf("{", m.index);
    const block = readBalancedBraces(clean, open);
    if (!block) break; // unterminated model block — nothing after it can be trusted either
    MODEL_START.lastIndex = block.end + 1;

    const scalarFields = new Set<string>();
    const indexedFields = new Set<string>();
    for (const bm of block.body.matchAll(BLOCK_COVERING_ATTR)) {
      for (const raw of bm[1]!.split(",")) {
        const name = raw.trim().split(/[\s(]/)[0];
        if (name) indexedFields.add(name);
      }
    }
    for (const line of block.body.split("\n")) {
      if (BLOCK_ATTR_LINE.test(line)) continue; // @@map/@@index/@@id/… — not a field declaration
      const fm = FIELD_LINE.exec(line);
      if (!fm) continue;
      const [, fieldName, baseType] = fm;
      if (SCALAR_TYPES.has(baseType!)) scalarFields.add(fieldName!);
      if (ID_OR_UNIQUE_ATTR.test(line)) indexedFields.add(fieldName!);
    }
    out.set(clientPropertyName(modelName), { displayName: modelName, scalarFields, indexedFields });
  }
  return out;
}

const PRISMA_SCHEMA_PATHS = ["schema.prisma", join("prisma", "schema.prisma")];

// package.json manifests across the tree, as SourceInput[] — the dev-tooling gate's script arm
// needs them and walkSourceFiles is deliberately source-only.
function loadManifests(dir: string, root: string = dir, out: SourceInput[] = []): SourceInput[] {
  for (const { name, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (MANIFEST_SKIP_DIRS.has(name)) continue;
    if (isDirectory) loadManifests(full, root, out);
    else if (name === "package.json") out.push({ path: relative(root, full).split(sep).join("/"), text: readFileSync(full, "utf8") });
  }
  return out;
}
const MANIFEST_SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

function readSchema(dir: string): string | undefined {
  const relPath = PRISMA_SCHEMA_PATHS.find((p) => existsSync(join(dir, p)));
  return relPath ? readFileSync(join(dir, relPath), "utf8") : undefined;
}

// ---------------------------------------------------------------------------------------------
// Shared call-shape gate: `<client>.<model>.<verb>(...)` — mirrors prisma-tenant-scope.ts's (#760)
// prismaModelVerb, generalized to a caller-supplied verb set (each heuristic below cares about a
// different verb class). Duplicated rather than imported for the same independent-parser reason as
// the schema scan above.
const CLIENT_NAME = /^(prisma|prismaclient|db|tx|client)$/i;

function prismaCallShape(node: ts.CallExpression, verbs: Set<string>): { model: string; verb: string } | undefined {
  const verbAccess = node.expression;
  if (!ts.isPropertyAccessExpression(verbAccess)) return undefined;
  const verb = verbAccess.name.text;
  if (!verbs.has(verb)) return undefined;

  const modelAccess = verbAccess.expression;
  if (!ts.isPropertyAccessExpression(modelAccess)) return undefined;
  const model = modelAccess.name.text;
  if (model.startsWith("$")) return undefined; // prisma.$transaction / $queryRaw are not models

  const client = modelAccess.expression;
  const clientName = ts.isIdentifier(client) ? client.text : ts.isPropertyAccessExpression(client) ? client.name.text : undefined;
  if (!clientName || !CLIENT_NAME.test(clientName)) return undefined;

  return { model, verb };
}

function propertyKeyName(prop: ts.ObjectLiteralElementLike): string | undefined {
  if ((ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) && prop.name) {
    if (ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)) return prop.name.text;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// Heuristic 1: N+1 query pattern — a `prisma.<model>.<verb>(...)` read call reached by walking
// straight up from inside a loop, with no intervening function definition, is "one query per
// iteration" by construction.
//
// Scoped to the READ verbs only (find*/count/aggregate) — the textbook N+1 is a list fetched once
// then a FURTHER read issued per item instead of a single batched query (`findMany({ where: { id:
// { in: ids } } })` or an `include`). A mutation-per-iteration loop (create/update/delete) is a
// different, far more debatable perf smell: Prisma has no bulk conditional update/delete/upsert, so
// a per-item mutation loop is frequently the only implementation available — flagging it would be
// exactly the noisy first cut #761/#793 warn against.
const N1_READ_VERBS = new Set(["findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany", "count", "aggregate"]);

function isLoopStatement(node: ts.Node): boolean {
  return ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node);
}

// Is `fn` the callback argument of a `.map`/`.forEach` call — the other loop shape besides a
// literal for/while statement.
function isMapOrForEachCallback(fn: ts.Node): boolean {
  const call = fn.parent;
  if (!call || !ts.isCallExpression(call) || !ts.isPropertyAccessExpression(call.expression)) return false;
  if (call.expression.name.text !== "map" && call.expression.name.text !== "forEach") return false;
  return call.arguments.includes(fn as ts.Expression);
}

// Walks upward from a query call looking for the nearest enclosing loop. Stops at the first
// function boundary that ISN'T itself a `.map`/`.forEach` callback: a query in an ordinary helper
// function isn't "in a loop" just because some caller, elsewhere, happens to invoke it in one —
// this under-reports a real but unprovable-by-syntax case rather than risk the false positive #793
// calls out by name (a single query that merely uses `.map` on ITS OWN already-fetched results has
// no Prisma call inside the `.map` callback at all, so it never reaches this function).
function enclosingLoop(node: ts.Node): "loop" | "map/forEach" | undefined {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (isLoopStatement(cur)) return "loop";
    if (ts.isFunctionLike(cur)) return isMapOrForEachCallback(cur) ? "map/forEach" : undefined;
    cur = cur.parent;
  }
  return undefined;
}

function buildN1Finding(path: string, sf: ts.SourceFile, node: ts.CallExpression, model: string, verb: string, kind: "loop" | "map/forEach"): Finding {
  return mechanicalFinding({
    id: `PRISMA-M7-N1-${model}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}-${node.getStart(sf)}`,
    title: `${path} — \`prisma.${model}.${verb}\` called once per iteration (N+1)`,
    severity: "Perf",
    category: "Performance",
    taxonomy: "M7 — Prisma N+1 query pattern",
    location: loc(path, sf, node),
    evidence: `Heuristic "prisma-n1": \`prisma.${model}.${verb}(...)\` sits directly inside a ${kind === "loop" ? "for/while loop" : "`.map`/`.forEach` callback"} — a separate query is issued per iteration instead of one batched query for the whole list.`,
    impact: "Query count scales linearly with the list size instead of staying constant — fine on a dev seed, a production-sized page turns into dozens-to-thousands of round trips and the endpoint's latency becomes proportional to row count.",
    fix: `Replace with a single batched query outside the loop — \`findMany({ where: { id: { in: [...] } } })\` for a re-fetch by id, or an \`include\`/\`select\` on the original query if the per-item data is a relation of it.`,
    precisionTier: "review",
  });
}

function detectN1(path: string, sf: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const shape = prismaCallShape(node, N1_READ_VERBS);
      if (shape) {
        const loop = enclosingLoop(node);
        if (loop) findings.push(buildN1Finding(path, sf, node, shape.model, shape.verb, loop));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

// ---------------------------------------------------------------------------------------------
// Heuristic 2: filter-column-without-index — a `where` on a scalar column with no covering index
// ANYWHERE in schema.prisma, cross-referenced against app source.
//
// Scoped to the verbs whose `where` filters a NON-unique predicate (findMany/findFirst(OrThrow)/
// count/aggregate/groupBy/updateMany/deleteMany): `findUnique`/`update`/`delete`/`upsert` require a
// WhereUniqueInput by Prisma's own type system, so their `where` is already guaranteed unique —
// any "unindexed" hit there would be this parser failing to recognize a compound-unique key name,
// not a real gap.
//
// Only flags when NONE of a call's top-level scalar filter keys have any covering index — a
// composite/leading-column index on a SIBLING key in the same filter (e.g. `where: { tenantId,
// status }` with `tenantId` indexed) still lets Postgres prune most rows before checking the
// unindexed column, so that's a materially smaller, noisier finding this heuristic deliberately
// skips per #793's "prefer under-reporting" gate.
const FILTER_VERBS = new Set(["findFirst", "findFirstOrThrow", "findMany", "count", "aggregate", "groupBy", "updateMany", "deleteMany"]);

function whereObjectOf(node: ts.CallExpression): ts.ObjectLiteralExpression | undefined {
  const arg = node.arguments[0];
  if (!arg || !ts.isObjectLiteralExpression(arg)) return undefined;
  const whereProp = arg.properties.find((p) => propertyKeyName(p) === "where");
  if (!whereProp || !ts.isPropertyAssignment(whereProp) || !ts.isObjectLiteralExpression(whereProp.initializer)) return undefined;
  return whereProp.initializer;
}

// #1081: cap on how many call sites a collapsed finding cites by name — the callSiteCount itself
// is always exact, this only bounds how long the evidence string gets (mirrors
// dep-reachability.ts's FILES_CITED / diverged-clones.ts's MAX_MEMBERS_SHOWN convention).
const MAX_LOCATIONS_SHOWN = 5;

interface UnindexedFilterHit {
  clientModel: string;
  displayModel: string;
  verb: string;
  columns: string[];
  locations: string[];
}

function buildFilterFinding(hit: UnindexedFilterHit): Finding {
  const { clientModel, displayModel, verb, columns, locations } = hit;
  const cols = columns.join(", ");
  const shown = locations.slice(0, MAX_LOCATIONS_SHOWN);
  const overflow = locations.length > MAX_LOCATIONS_SHOWN ? `, +${locations.length - MAX_LOCATIONS_SHOWN} more` : "";
  return mechanicalFinding({
    id: `PRISMA-M7-UNINDEXED-FILTER-${displayModel}-${columns.join("-")}`,
    title: `${displayModel}.${cols} — filtered with no covering index`,
    severity: "Perf",
    category: "Performance",
    taxonomy: "M7 — Prisma filter column without index",
    location: shown[0]!,
    evidence: `Heuristic "prisma-unindexed-filter": \`prisma.${clientModel}.${verb}({ where: { ${cols} } })\` filters on \`${cols}\`, but ${displayModel} has no \`@unique\`/\`@id\` on ${columns.length > 1 ? "any of these fields" : "that field"} and no \`@@id\`/\`@@unique\`/\`@@index\` naming ${columns.length > 1 ? "any of them" : "it"} in schema.prisma — this filter has no index to use at all. Found at ${locations.length} call site${locations.length === 1 ? "" : "s"} across this scan: ${shown.join(", ")}${overflow}.`,
    impact: `Every one of the ${locations.length} call site${locations.length === 1 ? "" : "s"} above forces a sequential scan of the table; latency degrades linearly as the table grows and is invisible in a dev-sized seed.`,
    fix: `Add \`@@index([${cols}])\` on model ${displayModel} — one index fixes every call site listed above (a single-column index if only one field is filtered together, composite if they're always queried together).`,
    precisionTier: "review",
  });
}

function collectUnindexedFilters(
  path: string,
  sf: ts.SourceFile,
  schemaModels: Map<string, ModelFilterInfo>,
  hits: Map<string, UnindexedFilterHit>, // one finding per (model, sorted column set) across the whole scan — repeated call sites accumulate here instead of being dropped
): void {
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const shape = prismaCallShape(node, FILTER_VERBS);
      const info = shape && schemaModels.get(shape.model);
      const where = shape && whereObjectOf(node);
      if (shape && info && where) {
        const scalarKeys = where.properties
          .map(propertyKeyName)
          .filter((k): k is string => k !== undefined && k !== "id" && info.scalarFields.has(k));
        const uncovered = scalarKeys.filter((k) => !info.indexedFields.has(k));
        // Flag only when EVERY scalar filter key is uncovered — see the module-header gate.
        if (scalarKeys.length > 0 && uncovered.length === scalarKeys.length) {
          const key = `${shape.model}:${[...uncovered].sort().join(",")}`;
          const hit = hits.get(key) ?? { clientModel: shape.model, displayModel: info.displayName, verb: shape.verb, columns: uncovered, locations: [] };
          hit.locations.push(loc(path, sf, node));
          hits.set(key, hit);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

export function detectPrismaAppPerfFindings(files: SourceInput[], schema: string): Finding[] {
  const schemaModels = parseModelFilterInfo(schema);
  const filterHits = new Map<string, UnindexedFilterHit>();
  const findings: Finding[] = [];
  const sources = new Map(files.filter((f) => SOURCE_EXT.test(f.path)).map((f) => [f.path, parse(f.path, f.text)]));
  // #1476: this detector reported boxyhq's `delete-team.js` — an interactive `readline` admin CLI
  // wired to `npm run delete-team` — as an N+1, a SECOND false row on a file the generic
  // await-in-loop class was already flagging. The corpus note that recorded this detector's
  // arrival as "a precision fix" was measuring a duplicate false positive. Same gate as the
  // generic tier, so a later widening of one keeps the other in step.
  const tooling = devToolingModules(files, sources);
  for (const [path, sf] of sources) {
    if (tooling.has(path)) continue; // #1528: request-reachable modules are subtracted in devToolingModules
    findings.push(...detectN1(path, sf));
    collectUnindexedFilters(path, sf, schemaModels, filterHits);
  }
  for (const hit of filterHits.values()) findings.push(buildFilterFinding(hit));
  return findings;
}

/** Locates the target's schema.prisma (same conventional paths as scanPrismaSchemaPerf) and walks
 * its source tree, cross-referencing app code against the schema's index set. Empty when no
 * schema.prisma is found (nothing to cross-reference against). */
export function scanPrismaAppPerf(dir: string): Finding[] {
  const schema = readSchema(dir);
  if (!schema) return [];
  // The manifests come along because the dev-tooling gate reads `scripts`/`bin`/`prisma.seed` to
  // recognise a file the project runs as a script (#1476); walkSourceFiles is source-only.
  return detectPrismaAppPerfFindings([...walkSourceFiles(dir), ...loadManifests(dir)], schema);
}
