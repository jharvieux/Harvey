// #1503 — the IMPORT-GRAPH member of the coverage-disclosure family. `M1-EXT-00` says how many
// source files the passes read; `M1-PATHSCOPE-*` says a path-scoped detector read none. Neither
// answers this one: the files were all read, and the EDGES BETWEEN THEM were not resolved.
//
// The defect this exists for (#1479/#1490): `collectPathAliases` fell back to a bare `@/` default on
// any Nx-style monorepo shipping its `paths` map in `tsconfig.base.json` with no root
// `tsconfig.json`. Every cross-file edge on such a target silently failed to resolve — and the pass
// emitted NOTHING. Worse, the corpus then recorded those degraded numbers as the correct baselines,
// so `corpus-drift` was green throughout. A regression that lands BEFORE a baseline is taken becomes
// the baseline. This row is what makes that condition visible in the deliverable instead of
// inferable only from a number nobody can check.
//
// CONSUMER AUDIT (#1503 criterion 3), enumerated by `git grep -n "resolveImport\|buildImportGraph\|
// collectPathAliases" -- src` on 2026-08-01 rather than from the two the issue names. SIX modules
// read this resolver and every one of them drops the edge with a bare `continue`/`undefined`, so a
// partial graph produces silence in all six:
//   - src/detectors/app-router.ts — M9's server→client leak, the server-only guard, #1263's gate
//     resolution, #1502's cross-file SSR helper, and #1344's request-reachability closure
//     (`collectValueImports`);
//   - src/detectors/perf-code.ts — M7 bundle/sync-I/O reachability (two `buildImportGraph` calls);
//   - src/detectors/slop.ts — M5's cross-file async-caller purity check (#1533);
//   - src/scan/service-role-literal.ts — M1's cross-file service-role JWT literal (#664);
//   - src/scan/ssrf-wrapper.ts — M1's SSRF sink behind a wrapper;
//   - src/scan/bola-cross-file.ts — M1's BOLA where the unscoped query lives in an imported repo.
// The issue named M7, M9 and #1344; the other three were affected identically and unrecorded.
//
// The predicate below is the SHIPPED one, not a re-implementation: same `resolveImport`, same
// `collectPathAliases`, and the same `ImportDeclaration` + string-literal + not-type-only filter
// `buildImportGraph` applies, so a specifier this file calls unresolved is exactly an edge the graph
// does not have.
//
// MEASURED 2026-08-01 over the 17 pinned EXTERNAL_CORPUS commits (`scratch/census-1503.ts`, the
// production loader + this census). It fires on 14 and is SILENT on 3 (multi-tenant-starter,
// launch-mvp, supabase-security-labs), so it has a real failing direction rather than being a
// status line: boxyhq 125 dropped of 644 (its tsconfig sets `baseUrl: "."` plus two unrelated
// `paths` wildcards, so `import "hooks/useTeam"` was a resolution shape this repo had never
// modelled — found BY this row),
// inbox-zero 239 of 6,623 (`@/generated/prisma/*`, output not in the checkout), tanstack-com 42,
// documenso 28, ghostfolio 12, carbon 12.
// #1812 re-measured the same 17 clean pins on 2026-08-20: boxyhq is now 4 dropped of 644 (640
// resolved), documenso 27 of 8,516, inbox-zero 238 of 6,623, and subscription-payments 1 of 92;
// the other 13 targets' resolved/dropped counts are unchanged. The remaining rows stay disclosed.
// NEGATIVE CONTROL, same command with `collectPathAliases` stubbed to its bare default — i.e. the
// #1479 regression re-created: ghostfolio 12 -> 2,128 dropped (2,577 -> 461 resolved), carbon
// 12 -> 7,494, inbox-zero 239 -> 6,284. The row that was absent when this actually happened now
// moves by two orders of magnitude.

import ts from "typescript";
import { builtinModules } from "node:module";
import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { collectPathAliases, resolveImport, type PathAlias } from "../detectors/app-router.js";

// Imports the graph deliberately does not model: an asset is not a module edge, and counting one as
// a dropped edge would make the row fire on every target that imports a stylesheet.
const ASSET_SPECIFIER = /\.(css|scss|sass|less|styl|svg|png|jpe?g|gif|webp|avif|ico|json|graphql|gql|txt|md|mdx|wasm|ya?ml|sql|node)($|\?)/;

// The bare `@/` -> repo-root row `collectPathAliases` pushes when NO tsconfig/jsconfig in the tree
// declared a wildcard `paths` entry, MARKED at the push (`fallback: true`) rather than recognised
// by its shape: proposit really declares `"@/*": ["./*"]` with `baseUrl: "."`, which produces a
// byte-identical row, and a shape test read that genuine alias as a degradation.
const isBuiltInDefault = (a: PathAlias): boolean => a.fallback === true;
const isBaseUrlRoot = (a: PathAlias): boolean => a.kind === "base-url";

const BUILTINS = new Set(builtinModules);
const isBuiltinModule = (specifier: string): boolean => BUILTINS.has(specifier.split("/")[0] ?? specifier);

// A specifier that names something other than a file: a bundler virtual module
// (`virtual:react-router/server-build`), a Deno URL import, a data URL. The graph is a filesystem
// graph, so these are correctly outside it rather than edges it failed to find.
const NON_FILESYSTEM_SCHEME = /^(virtual|https?|data|node|bun|npm|jsr):/;

/** `@scope/name/sub` -> `@scope/name`; `pkg/sub` -> `pkg`. The unit a manifest declares. */
function packageNameOf(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? specifier);
}

/**
 * Every package name the target's manifests declare as a DEPENDENCY, plus Node's own builtins.
 *
 * This is the yardstick, and it is deliberately independent of the alias table — the same
 * construction #1065 used for M1-EXT-00, and for the same reason. Classifying "is this specifier
 * repo-local?" by asking the alias table is circular: MEASURED 2026-08-01 by stubbing
 * `collectPathAliases` to its bare default over the ghostfolio pin, an alias-table-based classifier
 * reported ghostfolio SILENT while 2,116 of its edges had just vanished, because with no aliases
 * declared `@ghostfolio/common` stops looking aliased and reads as a third-party package. That is
 * #1503's own defect, reproduced inside the check written to detect it.
 */
function declaredDependencies(manifests: readonly SourceInput[]): Set<string> {
  const names = new Set<string>();
  for (const m of manifests) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(m.text);
    } catch {
      continue; // a manifest that fails to parse contributes no names; its specifiers stay repo-local, which is the loud direction
    }
    const pkg = parsed as Record<string, unknown>;
    for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
      const block = pkg[field];
      if (block && typeof block === "object") for (const name of Object.keys(block)) names.add(name);
    }
  }
  return names;
}

interface ImportGraphCensus {
  /**
   * Alias prefixes the resolver can use, excluding the built-in fallback — tsconfig/jsconfig
   * `paths` entries and workspace-member subpaths together. NOT split by origin: a workspace
   * member's subpath alias and a tsconfig one are the same record with the same fields, so any
   * split would be a guess dressed as a count.
   */
  aliasPrefixes: number;
  /** Configuration-scoped compilerOptions.baseUrl roots available to the production resolver. */
  baseUrlRoots: number;
  /** Of those, the workspace-member package names matched EXACTLY as whole specifiers (#1353). */
  workspacePackages: number;
  /** True when `collectPathAliases` declared nothing and fell back to the built-in `@/` default. */
  builtInDefaultOnly: boolean;
  /** The target's manifests imply a workspace — so a `paths` map was expected and none was found. */
  workspaceImplied: boolean;
  edgesResolved: number;
  /** A `./x` / `../x` specifier that resolved to nothing (assets excluded). */
  unresolvedRelative: number;
  /** A bare specifier no manifest declares as a dependency — repo-local, and it resolved to nothing. */
  unresolvedAliased: number;
  /** A declared dependency or a Node builtin. Correctly outside the repo's own graph. */
  externalSpecifiers: number;
  examples: string[];
}

export function importGraphCensus(files: readonly SourceInput[]): ImportGraphCensus {
  const mutable = [...files];
  const aliases = collectPathAliases(mutable);
  const allPaths = new Set(mutable.map((f) => f.path));
  const manifests = mutable.filter((f) => f.path === "package.json" || f.path.endsWith("/package.json"));
  const external = declaredDependencies(manifests);
  const baseUrlRoots = aliases.filter(isBaseUrlRoot).length;
  const census: ImportGraphCensus = {
    aliasPrefixes: aliases.filter((a) => a.kind === "paths" || a.kind === "workspace").length,
    baseUrlRoots,
    workspacePackages: aliases.filter((a) => a.entryBases !== undefined).length,
    builtInDefaultOnly: aliases.some(isBuiltInDefault) && baseUrlRoots === 0,
    workspaceImplied: manifests.length > 1 || mutable.some((f) => f.path === "pnpm-workspace.yaml") || manifests.some((f) => /"workspaces"\s*:/.test(f.text)),
    edgesResolved: 0,
    unresolvedRelative: 0,
    unresolvedAliased: 0,
    externalSpecifiers: 0,
    examples: [],
  };

  for (const f of mutable) {
    if (!/\.[cm]?[jt]sx?$/.test(f.path)) continue;
    const sf = ts.createSourceFile(f.path, f.text, ts.ScriptTarget.Latest, true, f.path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    for (const stmt of sf.statements) {
      // Exactly buildImportGraph's filter — a specifier it never asks about is not a missing edge.
      if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.importClause?.isTypeOnly) continue;
      const spec = stmt.moduleSpecifier.text;
      if (resolveImport(f.path, spec, allPaths, aliases) !== undefined) {
        census.edgesResolved++;
        continue;
      }
      if (ASSET_SPECIFIER.test(spec)) continue;
      if (!spec.startsWith(".") && (external.has(packageNameOf(spec)) || NON_FILESYSTEM_SCHEME.test(spec) || isBuiltinModule(spec))) {
        census.externalSpecifiers++;
        continue;
      }
      const repoLocal = spec.startsWith(".") ? "unresolvedRelative" : "unresolvedAliased";
      census[repoLocal]++;
      if (census.examples.length < 5) census.examples.push(`${f.path} imports "${spec}"`);
    }
  }
  return census;
}

/**
 * One counted not-assessed row when the cross-file import graph is PARTIAL.
 *
 * Fires on either half of #1503's condition: an alias table that degraded to the built-in default on
 * a target whose manifests imply a workspace (the ghostfolio shape, which had a real unresolved
 * population of zero only because nothing checked), or any repo-local specifier that resolved to
 * nothing. Silent when the graph is whole — the family discloses a limitation, not a status, and a
 * "0 dropped edges" row on every target would dilute it into a status line.
 */
export function importGraphNotAssessedRows(files: readonly SourceInput[]): Finding[] {
  if (files.length === 0) return [];
  const c = importGraphCensus(files);
  const dropped = c.unresolvedRelative + c.unresolvedAliased;
  const degraded = c.builtInDefaultOnly && c.workspaceImplied;
  if (dropped === 0 && !degraded) return [];

  const aliasSource = c.builtInDefaultOnly
    ? `NO tsconfig/jsconfig in this target declares a wildcard \`paths\` alias, so alias resolution fell back to the built-in \`@/\` → repo-root default${c.workspaceImplied ? " — on a target whose manifests declare a workspace, which is the shape that silently disconnected an entire Nx monorepo's graph (#1479/#1490)" : ""}`
    : `${c.baseUrlRoots > 0 ? `${c.baseUrlRoots} configuration-scoped \`baseUrl\` root(s) and ` : ""}${c.aliasPrefixes} alias prefix(es) were resolvable (tsconfig/jsconfig \`paths\` entries plus workspace-member subpaths), ${c.workspacePackages} of the prefixes workspace-member package names`;
  // Stated as what was MEASURED, not as a diagnosis. A dropped bare specifier is either a repo-local
  // module the resolver could not reach OR a package no manifest in this checkout declares; the
  // check does not separate those two, and both mean the same thing here — the edge is not in the graph.
  const droppedDetail =
    dropped === 0
      ? "Every import specifier this run examined did resolve, so the degradation above cost no edge that this check can see"
      : `${dropped} import specifier(s) resolved to nothing and are therefore ABSENT from the graph: ${c.unresolvedRelative} relative (\`./x\`, \`../x\`) and ${c.unresolvedAliased} bare specifier(s) that no manifest in this checkout declares as a dependency. Excluded from that count by design: ${c.externalSpecifiers} declared dependency/Node-builtin/virtual-module specifier(s), and asset imports (.css/.svg/.json), which are not module edges`;

  return [
    {
      id: "M1-IMPORTGRAPH-00",
      title: `Cross-file import graph partially resolved: ${dropped} dropped edge${dropped === 1 ? "" : "s"} of ${c.edgesResolved + dropped}`,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
      taxonomy: "Coverage — cross-file import graph partially resolved",
      location: "(repo-wide)",
      status: "Open",
      evidence: `${aliasSource}. ${c.edgesResolved} import edge(s) resolved. ${droppedDetail}.${c.examples.length ? ` e.g. ${c.examples.join("; ")}.` : ""}`,
      impact:
        "Six checks read this graph and all of them answer by silence when an edge is missing: M7's bundle and blocking-sync-I/O reachability, M9's server→client data leak and server-only-guard resolution, the request-reachability closure that decides whether a route can reach a sink, M5's cross-file async-caller check, M1's cross-file service-role-key literal, and M1's BOLA-through-an-imported-repository check. For the edges listed here every one of those passes saw an UNCONNECTED module. Recorded so their absence reads as 'not assessed', not 'assessed and clean'.",
      fix: "Read the examples above. If they point at generated code (a Prisma client, compiled protobufs) or at a dependency that is installed but undeclared, that is expected and this row is the record of it. If they point at real committed source, the mapping is declared somewhere Harvey does not read — a bundler config (`vite.config`, `webpack.resolve.alias`), a tsconfig `extends` chain, or a package `exports` condition — so declare it as a tsconfig `paths` wildcard and re-run to connect those edges.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}
