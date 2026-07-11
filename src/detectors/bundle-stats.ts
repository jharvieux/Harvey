// M7 [B] tier (#170) — ground-truth shipped-bundle findings from a real `next build`
// artifact (the `.next` directory). This is the optional build-input tier: deterministic,
// but it needs the artifact — the client runs `next build` (or grants repo access and we
// run it), same trust class as the connected DB advisor.
//
// Metric: first-load JS, gzipped — the same number `next build` prints.
//
// Two manifest layouts exist in the wild (validated against a fresh ATC build, 2026-07-10):
// - webpack builds (Next ≤ 15 default, and 16 with webpack): app-build-manifest.json /
//   build-manifest.json map every route to its client chunks → full per-route findings.
// - Turbopack builds (Next 16 default): NO app-build-manifest.json anywhere; the top-level
//   build-manifest.json carries only rootMainFiles. We can still measure the shared
//   baseline every route pays, but per-route attribution is impossible from manifests
//   alone — that gap is DISCLOSED as an Info finding, not silently skipped (the fail-loud
//   doctrine), and needs @next/bundle-analyzer as the follow-up input.
//
// [B] depth tier (#179) — duplicate-modules-across-chunks, dependency attribution, and
// per-route first-load on Turbopack builds all need the @next/bundle-analyzer / webpack-stats
// JSON (a separate artifact from `.next` — `generateStatsFile: true` writes it via
// webpack-bundle-analyzer, standard webpack Stats.toJson() shape: `modules[]` with
// `identifier`/`name`/`size`/`chunks[]`, `namedChunkGroups{}` with `assets[]`). UNVERIFIED
// against a live @next/bundle-analyzer run — package.json is a supervised path for this repo,
// so the shape below is built from webpack's documented stats format, not a real sample.
// Sizes in this JSON are parsed (pre-gzip) bytes; there's no gzip step over already-emitted
// JSON, so the budgets here are independently calibrated on uncompressed bytes and are NOT
// directly comparable to the gzip-based M7B-01/02 budgets above.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { Finding } from "../findings.js";

interface AppBuildManifest {
  pages?: Record<string, string[]>;
}

interface BuildManifest {
  pages?: Record<string, string[]>;
  rootMainFiles?: string[];
}

interface BundleStatsOptions {
  /** Per-route first-load JS budget, gzipped bytes. Default 250 KB. */
  routeBudgetBytes?: number;
  /** Budget for the chunks shared by every route, gzipped bytes. Default 150 KB. */
  sharedBudgetBytes?: number;
}

const INSTANCE_CAP = 10;

function kb(bytes: number): string {
  return `${Math.round(bytes / 1024)} KB`;
}

// Gzipped size per chunk, memoized — shared chunks appear in every route's list.
function chunkSizer(buildDir: string): (chunk: string) => number {
  const cache = new Map<string, number>();
  return (chunk) => {
    const cached = cache.get(chunk);
    if (cached !== undefined) return cached;
    let size = 0;
    const path = join(buildDir, chunk);
    if (chunk.endsWith(".js") && existsSync(path)) size = gzipSync(readFileSync(path)).length;
    cache.set(chunk, size);
    return size;
  };
}

function readJson<T>(path: string): T | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

// Human route from a manifest key: app manifest keys look like "/(admin)/dashboard/page",
// pages manifest keys like "/dashboard".
function routeLabel(key: string): string {
  return key.replace(/\/(page|route)$/, "") || "/";
}

function baselineFinding(shared: string[], sharedBytes: number, sharedBudget: number): Finding {
  return {
    id: "M7B-02",
    status: "Open",
    category: "Performance",
    title: `Shared first-load baseline is ${kb(sharedBytes)} (budget ${kb(sharedBudget)}) — every route pays it`,
    severity: "Perf",
    confidence: "Confirmed", // measured from the build artifact, not inferred from source
    taxonomy: "M7 — Shared bundle baseline over budget",
    location: shared.slice(0, 3).join(", "),
    evidence: `${shared.length} chunks ship on every route, ${kb(sharedBytes)} gzipped in total — this is the floor under every page's first-load number.`,
    impact: "A heavy shared baseline caps how fast ANY page can get; per-route code-splitting can't recover it.",
    fix: "Find the shared-chunk residents (bundle-analyzer) — usually a provider/layout importing a heavy lib app-wide; move it behind `next/dynamic` or into the routes that use it.",
    value: 4,
    ease: 2,
    safety: 4,
  };
}

export function parseBundleStats(buildDir: string, options?: BundleStatsOptions): Finding[] {
  const routeBudget = options?.routeBudgetBytes ?? 250 * 1024;
  const sharedBudget = options?.sharedBudgetBytes ?? 150 * 1024;

  const appManifest = readJson<AppBuildManifest>(join(buildDir, "app-build-manifest.json"));
  const pagesManifest = readJson<BuildManifest>(join(buildDir, "build-manifest.json"));
  if (!appManifest && !pagesManifest) return [];

  const sizeOf = chunkSizer(buildDir);
  const routes: Record<string, string[]> = { ...pagesManifest?.pages, ...appManifest?.pages };
  delete routes["/_app"];
  delete routes["/_error"];
  delete routes["/_document"];

  // Turbopack layout: no per-route chunk mapping at all. Measure what we can (the shared
  // baseline from rootMainFiles) and disclose what we can't.
  if (Object.keys(routes).length === 0) {
    const shared = pagesManifest?.rootMainFiles ?? [];
    const sharedBytes = shared.reduce((sum, c) => sum + sizeOf(c), 0);
    const findings: Finding[] = [];
    if (sharedBytes > sharedBudget) findings.push(baselineFinding(shared, sharedBytes, sharedBudget));

    const appRoutes = readJson<Record<string, string>>(join(buildDir, "app-path-routes-manifest.json"));
    const pageRoutes = Object.keys(appRoutes ?? {}).filter((k) => k.endsWith("/page"));
    if (pageRoutes.length > 0) {
      findings.push({
        id: "M7B-03",
        status: "Open",
        category: "Performance",
        title: `Per-route bundle attribution unavailable (Turbopack build) — ${pageRoutes.length} page route${pageRoutes.length === 1 ? "" : "s"} unmeasured`,
        severity: "Info",
        confidence: "N/A",
        taxonomy: "M7 — Bundle route attribution unavailable",
        location: buildDir,
        evidence: `This .next was produced by a Turbopack build, which emits no app-build-manifest.json — the shared baseline above is measurable (${kb(sharedBytes)}), but per-route first-load JS is not.`,
        impact: "The audit cannot rank routes by shipped JS from this artifact alone — a coverage disclosure, not a defect.",
        fix: "Re-build with @next/bundle-analyzer enabled (or `next build --webpack` where supported) and re-run this pass for per-route numbers.",
        value: 1,
        ease: 3,
        safety: 5,
      });
    }
    return findings;
  }

  // Webpack layout: full per-route measurement.
  const routeChunkSets = Object.values(routes).map((chunks) => new Set(chunks));
  const firstSet = routeChunkSets[0];
  const shared = firstSet ? [...firstSet].filter((c) => routeChunkSets.every((s) => s.has(c))) : [];
  for (const c of pagesManifest?.rootMainFiles ?? []) if (!shared.includes(c)) shared.push(c);
  const sharedBytes = shared.reduce((sum, c) => sum + sizeOf(c), 0);

  const weights = Object.entries(routes)
    .map(([key, chunks]) => ({
      route: routeLabel(key),
      bytes: [...new Set(chunks)].reduce((sum, c) => sum + sizeOf(c), 0),
    }))
    .filter((w) => w.bytes > routeBudget)
    .sort((a, b) => b.bytes - a.bytes);

  const findings: Finding[] = [];
  if (weights.length) {
    const shown = weights.slice(0, INSTANCE_CAP);
    const worst = shown[0];
    findings.push({
      id: "M7B-01",
      status: "Open",
      category: "Performance",
      title: `${weights.length} route${weights.length === 1 ? "" : "s"} over the ${kb(routeBudget)} first-load JS budget (worst: ${worst ? kb(worst.bytes) : ""})`,
      severity: "Perf",
      confidence: "Confirmed",
      taxonomy: "M7 — First-load JS over budget",
      location: worst?.route ?? "",
      evidence:
        `Gzipped first-load JS per route (from ${appManifest ? "app-build-manifest.json" : "build-manifest.json"}), worst-first: ` +
        shown.map((w) => `${w.route} (${kb(w.bytes)})`).join(", ") +
        (weights.length > shown.length ? ` … and ${weights.length - shown.length} more` : ""),
      impact: "Every visitor downloads, parses, and executes this JS before the route is interactive — the single largest controllable input to INP/TTI on mid-range devices.",
      fix: "Split the heaviest routes with `next/dynamic` for below-the-fold/rarely-used components, and check the whole-library / heavy-client-import M7C findings for the likely culprits.",
      value: 4,
      ease: 3,
      safety: 4,
    });
  }
  if (sharedBytes > sharedBudget) findings.push(baselineFinding(shared, sharedBytes, sharedBudget));
  return findings;
}

// --- bundle-analyzer stats JSON tier (#179) ---------------------------------------------

interface StatsModule {
  name?: string;
  identifier?: string;
  size: number;
  chunks?: (string | number)[];
}

interface StatsChunkGroup {
  assets?: { name: string; size: number }[];
}

interface WebpackBundleStats {
  modules?: StatsModule[];
  namedChunkGroups?: Record<string, StatsChunkGroup>;
}

interface BundleAnalyzerOptions {
  /** Per-route first-load JS budget, parsed (pre-gzip) bytes. Default ~750 KB (rule-of-thumb
   *  3x the gzip route budget for JS text — not a verified compression ratio). */
  routeBudgetBytes?: number;
  /** Minimum per-module size (bytes) before a chunk-duplicate is worth flagging. Default 1 KB. */
  dupModuleFloorBytes?: number;
  /** Minimum summed per-package size (bytes) before a dependency is worth flagging. Default 100 KB. */
  depBudgetBytes?: number;
}

function moduleLabel(m: StatsModule): string {
  return m.name ?? m.identifier ?? "(unknown module)";
}

// pnpm nests the resolved package under node_modules/.pnpm/<pkg>@ver/node_modules/<pkg>/... —
// the LAST node_modules/<pkg> segment in the identifier is the one that actually ships.
function packageOf(m: StatsModule): string | undefined {
  const id = m.identifier ?? m.name ?? "";
  const matches = [...id.matchAll(/node_modules\/(@[^/]+\/[^/]+|[^/]+)/g)];
  return matches.at(-1)?.[1];
}

function duplicateModulesFinding(modules: StatsModule[], floorBytes: number): Finding | undefined {
  const dups = modules
    .filter((m) => (m.chunks?.length ?? 0) > 1 && m.size > floorBytes)
    .map((m) => ({ label: moduleLabel(m), size: m.size, copies: m.chunks!.length, wasted: m.size * (m.chunks!.length - 1) }))
    .sort((a, b) => b.wasted - a.wasted);
  if (!dups.length) return undefined;

  const shown = dups.slice(0, INSTANCE_CAP);
  const worst = shown[0]!;
  const totalWasted = dups.reduce((sum, d) => sum + d.wasted, 0);
  return {
    id: "M7B-04",
    status: "Open",
    category: "Performance",
    title: `${dups.length} module${dups.length === 1 ? "" : "s"} duplicated across chunks (~${kb(totalWasted)} wasted, worst: ${worst.label})`,
    severity: "Perf",
    confidence: "Confirmed",
    taxonomy: "M7 — Duplicate modules across chunks",
    location: worst.label,
    evidence:
      `Worst-first (module, copies, size each, bytes wasted beyond the first copy): ` +
      shown.map((d) => `${d.label} (${d.copies}×, ${kb(d.size)} each, ${kb(d.wasted)} wasted)`).join(", ") +
      (dups.length > shown.length ? ` … and ${dups.length - shown.length} more` : ""),
    impact: "Each duplicate copy re-ships and re-parses the same code on every route that pulls it in, instead of loading it once from a shared chunk — a code-splitting boundary problem, not a source-level one.",
    fix: "Pull these modules into a shared chunk (webpack `splitChunks` cache groups, or a shared layout-level import) so every route references one copy instead of bundling its own.",
    value: 3,
    ease: 3,
    safety: 4,
  };
}

function dependencyAttributionFinding(modules: StatsModule[], depBudgetBytes: number): Finding | undefined {
  const totals = new Map<string, number>();
  for (const m of modules) {
    const pkg = packageOf(m);
    if (pkg) totals.set(pkg, (totals.get(pkg) ?? 0) + m.size);
  }
  const ranked = [...totals.entries()]
    .map(([pkg, bytes]) => ({ pkg, bytes }))
    .filter((d) => d.bytes > depBudgetBytes)
    .sort((a, b) => b.bytes - a.bytes);
  if (!ranked.length) return undefined;

  const shown = ranked.slice(0, INSTANCE_CAP);
  const worst = shown[0]!;
  return {
    id: "M7B-05",
    status: "Open",
    category: "Performance",
    title: `${ranked.length} dependenc${ranked.length === 1 ? "y" : "ies"} over ${kb(depBudgetBytes)} of shipped module weight (worst: ${worst.pkg}, ${kb(worst.bytes)})`,
    severity: "Perf",
    confidence: "Confirmed",
    taxonomy: "M7 — Dependency attribution over budget",
    location: worst.pkg,
    evidence:
      `Worst-first, summed module size per npm package across analyzed chunks: ` +
      shown.map((d) => `${d.pkg} (${kb(d.bytes)})`).join(", ") +
      (ranked.length > shown.length ? ` … and ${ranked.length - shown.length} more` : ""),
    impact: "Attributes shipped weight to specific packages — including a server-only dependency that has leaked into a client chunk, which shows up here as unexpected client-side weight tied to its name.",
    fix: "Confirm each package's client-side presence is intentional; swap for a lighter alternative, lazy-load it behind the route/component that needs it, or exclude it from the client bundle if it's server-only.",
    value: 4,
    ease: 3,
    safety: 4,
  };
}

// Next.js webpack entry names look like "app/dashboard/page" / "pages/dashboard" — strip the
// entry-type prefix so routeLabel's "/page" | "/route" suffix stripping lands on a real route.
function statsRouteLabel(entryName: string): string {
  return routeLabel(`/${entryName.replace(/^(app|pages)\//, "")}`);
}

function statsRouteAttributionFinding(groups: Record<string, StatsChunkGroup>, routeBudget: number): Finding | undefined {
  const weights = Object.entries(groups)
    .map(([name, g]) => ({ route: statsRouteLabel(name), bytes: (g.assets ?? []).reduce((sum, a) => sum + a.size, 0) }))
    .filter((w) => w.bytes > routeBudget)
    .sort((a, b) => b.bytes - a.bytes);
  if (!weights.length) return undefined;

  const shown = weights.slice(0, INSTANCE_CAP);
  const worst = shown[0]!;
  return {
    id: "M7B-06",
    status: "Open",
    category: "Performance",
    title: `${weights.length} route${weights.length === 1 ? "" : "s"} over the ${kb(routeBudget)} first-load JS budget per bundle-analyzer stats (worst: ${kb(worst.bytes)})`,
    severity: "Perf",
    confidence: "Confirmed",
    taxonomy: "M7 — First-load JS over budget (bundle-analyzer stats)",
    location: worst.route,
    evidence:
      `Parsed (pre-gzip) first-load JS per route from the stats JSON's chunk groups, worst-first: ` +
      shown.map((w) => `${w.route} (${kb(w.bytes)})`).join(", ") +
      (weights.length > shown.length ? ` … and ${weights.length - shown.length} more` : ""),
    impact: "On Turbopack builds this is the only per-route attribution available — no app-build-manifest.json exists to derive it from the primary build artifact (see M7B-03).",
    fix: "Split the heaviest routes with `next/dynamic`; cross-check against the M7B-04/M7B-05 findings for which duplicated modules or dependencies are driving the weight.",
    value: 4,
    ease: 3,
    safety: 4,
  };
}

// `statsPath` points at a webpack/bundle-analyzer stats JSON (e.g. `.next/analyze/client.json`
// from `@next/bundle-analyzer`'s `generateStatsFile: true`) — a separate, optional input from
// the `.next` build directory `parseBundleStats` reads above. Closes three gaps that manifest
// parsing can't: duplicate modules across chunks, per-package dependency attribution, and
// per-route first-load on Turbopack builds (which emit no app-build-manifest.json).
export function parseBundleAnalyzerStats(statsPath: string, options?: BundleAnalyzerOptions): Finding[] {
  const stats = readJson<WebpackBundleStats>(statsPath);
  if (!stats) return [];

  const routeBudget = options?.routeBudgetBytes ?? 750 * 1024;
  const dupFloor = options?.dupModuleFloorBytes ?? 1024;
  const depBudget = options?.depBudgetBytes ?? 100 * 1024;

  const modules = stats.modules ?? [];
  const groups = stats.namedChunkGroups ?? {};

  const findings: Finding[] = [];
  const dup = duplicateModulesFinding(modules, dupFloor);
  if (dup) findings.push(dup);
  const dep = dependencyAttributionFinding(modules, depBudget);
  if (dep) findings.push(dep);
  const route = statsRouteAttributionFinding(groups, routeBudget);
  if (route) findings.push(route);
  return findings;
}
