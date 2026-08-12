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

import ts from "typescript";
import type { Finding } from "../findings.js";
import { callChainNames, loc, parse, type SourceInput } from "../detectors/common.js";
import { collectServiceClientNames, isServiceRooted, OWNERSHIP_COLUMN } from "../detectors/owner-id.js";
import { NON_SHIPPING_FILE, NON_SHIPPING_PATH } from "./prisma-tenant-scope.js";
import { mechanicalFinding } from "./common.js";

// Background-job paths, by conventional location. `src/inngest`, `src/jobs`, and the bare
// `inngest`/`jobs`/`queues`/`workers` segments cover the common Inngest/queue/worker layouts;
// `app/api/cron` is the Next.js App Router cron surface. A named const so the scope is
// discoverable and extendable in one place.
const JOB_PATH = /(^|\/)(inngest|jobs|queues|workers)\/|(^|\/)app\/api\/cron\//;

// #1281 — the coverage-disclosure half. JOB_PATH is a CONVENTION, and a target whose jobs live in
// `src/tasks/`, `functions/` or `workers-v2/` was previously scanned by nothing and told nothing:
// MEASURED 2026-07-31, `scanJobTenantScope` over a fixture with an unscoped service-role read in
// `src/tasks/import-inbound.ts` returned 0 findings and 0 rows. Silence is the one answer the
// coverage doctrine forbids, so the unmatched directories are now COUNTED and named.
//
// The candidate set is derived, not guessed: a file is job-like when it imports a background-job
// runtime. Naming a directory "tasks" is a hunch; importing `inngest`/`bullmq`/`node-cron` is
// evidence, and it is the same evidence a human triager would use.
const JOB_RUNTIME_IMPORT =
  /\b(?:from|require\()\s*["'](inngest|bullmq|bull|bee-queue|kue|agenda|agenda-rest|bree|node-cron|croner|cron|pg-boss|graphile-worker|quirrel|@upstash\/qstash|@trigger\.dev\/[^"']+)["']/;

// Mirrors the target's D-091 allow convention: a leading or trailing comment on the query's
// enclosing statement suppresses the finding (tenancy enforced by a wrapper/RPC the AST can't see).
const ALLOW_ANNOTATION = "d091-allow:service-role-tenant";

const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

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

// #1081: cap on how many call-site locations a collapsed finding cites by name — the count itself
// is always exact, this only bounds how long the evidence string gets (mirrors dep-reachability.ts's
// FILES_CITED / diverged-clones.ts's MAX_MEMBERS_SHOWN convention).
const MAX_LOCATIONS_SHOWN = 5;

function detectFile(path: string, sf: ts.SourceFile): Finding[] {
  const serviceNames = collectServiceClientNames(sf, sf);
  // #1081: one file could carry several unscoped call sites on the SAME table (twelve unscoped
  // `.from("orders")` calls in one cron handler) — dedup key (one finding per file+table) stays
  // exactly as before, but every matching site is now collected instead of dropped after the first,
  // so the collapsed finding can disclose how many were dropped and where.
  const hits = new Map<string, { verbs: Set<string>; locations: string[] }>();

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isChainTop(node)) {
      const names = callChainNames(node);
      const verb = [...SCOPED_VERBS].find((v) => names.includes(v));
      if (verb && names.includes("from") && isServiceRooted(node, serviceNames)) {
        const table = tableOf(node);
        if (table && !hasTenantPredicate(node) && !isAllowAnnotated(sf, node)) {
          const entry = hits.get(table) ?? { verbs: new Set<string>(), locations: [] };
          entry.verbs.add(verb);
          entry.locations.push(loc(path, sf, node));
          hits.set(table, entry);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  const findings: Finding[] = [];
  for (const [table, { verbs, locations }] of hits) {
    const verbList = [...verbs].join("/");
    const shown = locations.slice(0, MAX_LOCATIONS_SHOWN);
    const overflow = locations.length > MAX_LOCATIONS_SHOWN ? ` (+${locations.length - MAX_LOCATIONS_SHOWN} more)` : "";
    const siteCount = locations.length > 1 ? ` Found at ${locations.length} call site(s) in this file: ${shown.join(", ")}${overflow}.` : "";
    findings.push(
      mechanicalFinding({
        id: `AUTH-job-tenant-scope-${table}-${path.replace(/[^a-zA-Z0-9]+/g, "-")}`,
        title: `${path} — service-role \`${verbList}\` on \`${table}\` in a background-job path with no tenant predicate`,
        severity: "High",
        category: "Broken access control",
        taxonomy: "Service-role query in a background-job path with no tenant predicate",
        location: locations[0]!,
        evidence: `Heuristic "job-tenant-scope": a service-role \`.${verbList}()\` on \`.from("${table}")\` in a background-job path (${path}) carries no tenant-scoping predicate (\`.eq\`/\`.in\`/\`.filter\`/\`.match\` on a tenant/owner column).${siteCount} Annotate a site \`// ${ALLOW_ANNOTATION}\` if a wrapper or RPC enforces scoping the AST can't see.`,
        impact:
          "A background job runs with no request or session, so the service-role client bypasses RLS and this query reads (or writes) rows across every tenant. With no explicit tenant filter, one tenant's job can expose or mutate another tenant's data — exactly the class of ATC finding #2003." +
          (locations.length > 1 ? ` Every one of the ${locations.length} call sites above needs the same fix — patching only the cited line leaves the rest exposed.` : ""),
        fix: `Scope the query to the job's tenant (e.g. \`.eq("tenant_id", tenantId)\` from the job payload/context) at every cited call site, or if a wrapper/RPC already enforces tenancy, annotate each site \`// ${ALLOW_ANNOTATION}\`.`,
        precisionTier: "review",
      }),
    );
  }
  return findings;
}

const dirOf = (path: string): string => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "(repo root)");

// #1281: which directories hold background-job code, and which of those JOB_PATH reaches. Returns
// the unmatched ones so the caller can disclose them rather than silently skipping them.
function jobDirectories(files: SourceInput[]): { matched: Map<string, number>; unmatched: Map<string, number> } {
  const matched = new Map<string, number>();
  const unmatched = new Map<string, number>();
  for (const f of files) {
    if (!SOURCE_EXT.test(f.path) || NON_SHIPPING_PATH.test(f.path) || NON_SHIPPING_FILE.test(f.path)) continue;
    const inScope = JOB_PATH.test(f.path);
    if (!inScope && !JOB_RUNTIME_IMPORT.test(f.text)) continue;
    const bucket = inScope ? matched : unmatched;
    bucket.set(dirOf(f.path), (bucket.get(dirOf(f.path)) ?? 0) + 1);
  }
  return { matched, unmatched };
}

const dirSummary = (dirs: Map<string, number>): string =>
  [...dirs.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([d, n]) => `${d}/ (${n} file${n === 1 ? "" : "s"})`).join("; ");

function jobPathScopeRow(files: SourceInput[]): Finding[] {
  const { matched, unmatched } = jobDirectories(files);
  if (unmatched.size === 0) return [];
  const unmatchedFiles = [...unmatched.values()].reduce((a, b) => a + b, 0);
  return [
    {
      id: "M1-JOBPATH-00",
      title: `Background-job code outside the scanned job paths: ${unmatchedFiles} file(s) in ${unmatched.size} director${unmatched.size === 1 ? "y" : "ies"}`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — background-job directories outside the job-tenant-scope path convention",
      location: "(repo-wide)",
      status: "Open",
      evidence: `The job-tenant-scope check reads only conventional background-job locations (\`inngest/\`, \`jobs/\`, \`queues/\`, \`workers/\`, \`app/api/cron/\`). Matched and assessed: ${matched.size ? dirSummary(matched) : "none"}. NOT assessed — these directories import a background-job runtime but do not match that convention: ${dirSummary(unmatched)}.`,
      impact:
        "A service-role query with no tenant predicate in one of the unassessed directories reads or writes rows across every tenant, and this check did not look at it. Recorded so that the absence of a JOB-TENANT-SCOPE finding for those files reads as 'not assessed', not 'assessed and clean'.",
      fix: "Review the listed files by hand for service-role queries with no tenant-scoping predicate, or move them under a conventional job directory (`jobs/`, `queues/`, `workers/`, `inngest/`) so the check reaches them on the next run.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}

// #1269: the non-shipping exclusion prisma-tenant-scope carries since #896. `tests/jobs/…` and
// `examples/inngest/…` both match JOB_PATH, and MEASURED 2026-07-31 the detector fired on the
// planted shape at each of them exactly as it does in `src/inngest/`.
//
// #1689 — exported so the zero-population disclosure row and the pinned-corpus census read this
// detector's scope through the SAME predicate the detector scans with.
export function jobTenantScopeScannedFiles(files: readonly SourceInput[]): SourceInput[] {
  return files.filter(
    (f) => JOB_PATH.test(f.path) && SOURCE_EXT.test(f.path) && !NON_SHIPPING_PATH.test(f.path) && !NON_SHIPPING_FILE.test(f.path),
  );
}

export function detectJobTenantScopeFindings(files: SourceInput[]): Finding[] {
  return [...jobTenantScopeScannedFiles(files).flatMap((f) => detectFile(f.path, parse(f.path, f.text))), ...jobPathScopeRow(files)];
}
