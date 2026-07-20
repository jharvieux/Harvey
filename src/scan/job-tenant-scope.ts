// #681 JOB-TENANT-SCOPE — a service-role DB query in a BACKGROUND-JOB path (Inngest/cron/queue/
// worker) that reads or writes a table with NO tenant-scoping predicate. Distinct from the
// request-handler classes (src/scan/bola-owner.ts, src/detectors/app-router.ts): a job has no
// request and no session, so there is no client-supplied owner id to reason about — the defect is
// the MISSING predicate itself. A service-role `.from(X).select/update/delete(...)` with no
// `.eq/.in/.filter/.match` on a tenant/owner column returns or mutates rows across every tenant,
// and the RLS-bypassing client is the only thing that would have gated it. This is the shape ATC
// finding #2003 (import-pipeline service-role read of gmail_inbound_messages) hit — caught only by
// the LLM semantic pass until now.
//
// Review tier, never free-count: the AST proves the query has no in-chain tenant filter, not that
// a wrapper/RPC/job-runtime enforces scoping out of view. An in-source escape hatch
// (`// d091-allow:service-role-tenant`, mirroring the target's D-091 allow convention) suppresses
// a site whose tenancy is enforced elsewhere.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { collectServiceClientNames, isServiceRooted, OWNERSHIP_COLUMN } from "../detectors/owner-id.js";
import { mechanicalFinding } from "./common.js";

// Background-job paths, by conventional location. `src/inngest`, `src/jobs`, and the bare
// `inngest`/`jobs`/`queues`/`workers` segments cover the common Inngest/queue/worker layouts;
// `app/api/cron` is the Next.js App Router cron surface. A named const so the scope is
// discoverable and extendable in one place.
const JOB_PATH = /(^|\/)(inngest|jobs|queues|workers)\/|(^|\/)app\/api\/cron\//;

// Mirrors the target's D-091 allow convention: a leading or trailing comment on the query's
// enclosing statement suppresses the finding (tenancy enforced by a wrapper/RPC the AST can't see).
const ALLOW_ANNOTATION = "d091-allow:service-role-tenant";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);

// The read/write verbs whose absence of a tenant predicate is a cross-tenant exposure. `.insert`
// is excluded: an insert names the tenant in its payload, it does not select WHOSE rows come back.
const SCOPED_VERBS = new Set(["select", "update", "delete"]);

// The string table name in the `.from("<table>")` call of a chain, if any.
function tableOf(top: ts.CallExpression): string | undefined {
  let cur: ts.Node = top;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    if (cur.expression.name.text === "from") {
      const arg = cur.arguments[0];
      if (arg && ts.isStringLiteralLike(arg)) return arg.text;
    }
    cur = cur.expression.expression;
  }
  return undefined;
}

// The chain's outermost call and every call inside it, so we can inspect each method + args.
function chainCalls(top: ts.CallExpression): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  let cur: ts.Expression = top;
  while (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
    calls.push(cur);
    cur = cur.expression.expression;
  }
  return calls;
}

// Any in-chain filter on a tenant/owner column: `.eq(col,…)`, `.in(col,…)`, `.filter(col,…)`, or
// `.match({ col: … })`. This is the predicate whose absence is the finding.
function hasTenantPredicate(top: ts.CallExpression): boolean {
  for (const call of chainCalls(top)) {
    const method = (call.expression as ts.PropertyAccessExpression).name.text;
    const first = call.arguments[0];
    if ((method === "eq" || method === "in" || method === "filter") && first && ts.isStringLiteralLike(first)) {
      if (OWNERSHIP_COLUMN.test(first.text)) return true;
    } else if (method === "match" && first && ts.isObjectLiteralExpression(first)) {
      for (const prop of first.properties) {
        const key = prop.name;
        if (key && (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) && OWNERSHIP_COLUMN.test(key.text)) return true;
      }
    }
  }
  return false;
}

// A CallExpression is the top of its Supabase chain when it is not itself the receiver of a
// further `.method()` call — i.e. its parent is not a property access reading off it.
function isChainTop(n: ts.CallExpression): boolean {
  const p = n.parent;
  return !(p && ts.isPropertyAccessExpression(p) && p.expression === n);
}

function enclosingStatement(node: ts.Node): ts.Node {
  let cur: ts.Node = node;
  while (cur.parent && !ts.isStatement(cur)) cur = cur.parent;
  return cur;
}

function isAllowAnnotated(sf: ts.SourceFile, node: ts.Node): boolean {
  const stmt = enclosingStatement(node);
  const ranges = [
    ...(ts.getLeadingCommentRanges(sf.text, stmt.getFullStart()) ?? []),
    ...(ts.getTrailingCommentRanges(sf.text, stmt.end) ?? []),
  ];
  return ranges.some((r) => sf.text.slice(r.pos, r.end).includes(ALLOW_ANNOTATION));
}

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const serviceNames = collectServiceClientNames(sf, sf);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isChainTop(node)) {
      const names = callChainNames(node);
      const verb = [...SCOPED_VERBS].find((v) => names.includes(v));
      if (verb && names.includes("from") && isServiceRooted(node, serviceNames)) {
        const table = tableOf(node);
        if (table && !seen.has(table) && !hasTenantPredicate(node) && !isAllowAnnotated(sf, node)) {
          seen.add(table);
          findings.push(
            mechanicalFinding({
              id: `AUTH-job-tenant-scope-${table}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
              title: `${path} — service-role \`${verb}\` on \`${table}\` in a background-job path with no tenant predicate`,
              severity: "High",
              category: "Broken access control",
              taxonomy: "Service-role query in a background-job path with no tenant predicate",
              location: loc(path, sf, node),
              evidence: `Heuristic "job-tenant-scope": a service-role \`.${verb}()\` on \`.from("${table}")\` in a background-job path (${path}) carries no tenant-scoping predicate (\`.eq\`/\`.in\`/\`.filter\`/\`.match\` on a tenant/owner column). Annotate the site \`// ${ALLOW_ANNOTATION}\` if a wrapper or RPC enforces scoping the AST can't see.`,
              impact: "A background job runs with no request or session, so the service-role client bypasses RLS and this query reads (or writes) rows across every tenant. With no explicit tenant filter, one tenant's job can expose or mutate another tenant's data — exactly the class of ATC finding #2003.",
              fix: `Scope the query to the job's tenant (e.g. \`.eq("tenant_id", tenantId)\` from the job payload/context), or if a wrapper/RPC already enforces tenancy, annotate the site \`// ${ALLOW_ANNOTATION}\`.`,
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

export function detectJobTenantScopeFindings(files: SourceInput[]): Finding[] {
  return files.filter((f) => JOB_PATH.test(f.path) && SOURCE_EXT.test(f.path)).flatMap((f) => detectFile(f.path, parse(f.path, f.text)));
}

function walk(dir: string, root: string, out: SourceInput[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, root, out);
    else if (SOURCE_EXT.test(entry)) out.push({ path: relative(root, full), text: readFileSync(full, "utf8") });
  }
}

export function scanJobTenantScope(projectDir: string): Finding[] {
  const files: SourceInput[] = [];
  walk(projectDir, projectDir, files);
  return detectJobTenantScopeFindings(files);
}
