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
// Deliberately not here: duplicate-modules-across-chunks and which-dependency-ships-where —
// webpack-stats territory (@next/bundle-analyzer), still deferred on #170.

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
