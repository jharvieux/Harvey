// Runs the static AST detector modules — M9 App Router (src/detectors/app-router.ts) and
// M7 code-level performance (src/detectors/perf-code.ts) — over a target repo and writes
// the merged Finding[]. This is the engagement entry point for both detector sets (they
// take in-memory sources, so tests never needed a CLI; audits do).
//
//   pnpm detect-static <target-dir> [--out findings.static.json] [--build <path-to-.next>]...
//     [--stats <path-to-bundle-analyzer-stats.json>]...
//
// `--build` points at a `next build` artifact for the [B] bundle tier (repeatable for
// monorepos); with no flag, <target>/.next and <target>/apps/*/.next are auto-detected.
// `--stats` points at a webpack/bundle-analyzer stats JSON (repeatable) for the [B] depth
// tier — duplicate-modules-across-chunks, dependency attribution, and per-route first-load
// on Turbopack builds; optional, no auto-detection (the artifact isn't part of `.next`).
//
// Thin untested I/O wrapper per the repo convention — the detectors themselves are the
// tested pure transforms. Test/story/fixture files are excluded from the product-code
// detectors (perf and boundary findings in test code aren't audit findings) but ARE loaded
// for the M8 test-intent pass (#372) — its subject matter is the test files themselves.

import { existsSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import type { Finding } from "../findings.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { scanAssetWeight } from "../detectors/asset-weight.js";
import { parseBundleAnalyzerStats, parseBundleStats, parseViteBundleStats } from "../detectors/bundle-stats.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { detectHookDepFindings } from "../detectors/hook-deps.js";
import { CONFIG_FILE, loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import { detectSlopFindings } from "../detectors/slop.js";
import { detectTestIntentFindings } from "../detectors/test-intent.js";
import { detectVitestIntentFindings } from "../detectors/vitest-intent.js";
import { detectOrm, detectTargetFramework, isViteTooling, nonNextWorkspaces } from "../scan/framework-detect.js";
import { scanPrismaAppPerf } from "../scan/prisma-app-perf.js";
import { scanPrismaSchemaPerf } from "../scan/prisma-schema-perf.js";
import { resolveScanScope } from "../scan/scan-scope.js";
import { checkUnreadSourceExtensions } from "../scan/ext-coverage.js";
import { checkUnassessedSfcFiles } from "../scan/sfc-coverage.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm detect-static <target-dir> [--out findings.static.json]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const { scanDir, cleanup } = resolveScanScope(targetDir);
try {
  const allSources = loadSources(scanDir);
  // Product-code detectors skip test/story/fixture files; the M8 test-intent pass reads the
  // full set (test files are its subject; non-test files feed its cross-file resolution).
  const sources = allSources.filter((f) => !NON_PRODUCT.test(f.path));
  // #1065: the orchestrator's anti-silent-skip guard reads the PRODUCT SOURCE count, not the total
  // — package.json and next.config.js are loaded on every target (for `paths` alias resolution),
  // so a total-file guard can never reach 0 and never fired.
  const productSources = sources.filter((f) => !CONFIG_FILE.test(basename(f.path)));
  console.log(
    `loaded ${allSources.length} source files (${productSources.length} product source, ${sources.length - productSources.length} config, ${allSources.length - sources.length} test/story) from ${targetDir}`,
  );

  // M9 assumes a Next.js App Router shape; on a Vite/SPA target it is N/A (see detectAppRouterFindings).
  // M7's client-JS tiers and bundle reader also branch on it (#577).
  const framework = detectTargetFramework(scanDir);
  const orm = detectOrm(scanDir);
  // #872: every recognised non-Next framework builds on Vite and has no App Router surface, so both
  // the M9 suppression and M7's Vite-mode tiers key on that, not on the `vite` value alone.
  const isVite = isViteTooling(framework);
  console.log(`target framework: ${framework}${isVite ? " — M9 App Router checks N/A (not Next); M7 in Vite mode" : ""}`);

  // #597: at a monorepo root the root verdict is `other` (vite.config lives in apps/*), so the
  // whole-target Vite short-circuit above never fires. Resolve a framework per workspace so M9
  // suppresses the SSR family for each Vite app's files rather than false-firing on them.
  const nonNextWs = isVite ? [] : nonNextWorkspaces(scanDir);
  if (nonNextWs.length) {
    console.log(`non-Next workspaces (M9 App Router checks N/A): ${nonNextWs.map((w) => `${w.rel} (${w.framework})`).join(", ")}`);
  }

  // Bundle tier: explicit --build flags, or auto-detected build dirs. Build artifacts live in the
  // REAL target dir — they're gitignored, so the scoped copy never contains them. A Next target's
  // artifact is `.next/` (build-manifest.json); a Vite target's is `dist/` (index.html).
  const explicitBuilds = args.flatMap((a, i) => {
    const next = args[i + 1];
    return a === "--build" && next ? [resolve(next)] : [];
  });
  const buildDirs = [...explicitBuilds];
  if (buildDirs.length === 0) {
    const marker = isVite ? "index.html" : "build-manifest.json";
    const candidates = [join(targetDir, isVite ? "dist" : ".next")];
    const appsDir = join(targetDir, "apps");
    if (existsSync(appsDir)) {
      for (const app of readdirSync(appsDir)) candidates.push(join(appsDir, app, isVite ? "dist" : ".next"));
    }
    buildDirs.push(...candidates.filter((c) => existsSync(join(c, marker))));
  }

  // Stats tier: explicit --stats flags only — the artifact isn't part of `.next` so there's
  // nothing to auto-detect it from. Next-only (webpack/bundle-analyzer shape).
  const statsPaths = args.flatMap((a, i) => {
    const next = args[i + 1];
    return a === "--stats" && next ? [resolve(next)] : [];
  });

  const findings: Finding[] = [
    ...detectAppRouterFindings(sources, framework, nonNextWs, orm),
    ...detectPerfCodeFindings(sources, framework),
    ...detectHookDepFindings(sources),
    ...detectSlopFindings(sources),
    ...detectHandrolledFindings(sources), // M6 free-tier indicators — Info-only, non-grading (#267)
    ...detectTestIntentFindings(allSources), // M8 free tier (#372) — needs the test files too
    ...detectVitestIntentFindings(allSources), // M8 vitest-specific (#629) — runner-gated
    ...scanAssetWeight(scanDir), // scoped copy = committed files only
    ...buildDirs.flatMap((b) => (isVite ? parseViteBundleStats(b) : parseBundleStats(b))),
    ...statsPaths.flatMap((p) => parseBundleAnalyzerStats(p)),
    // #761 (part of #756): M7's Prisma-schema equivalent of the Supabase connected-tier
    // "unindexed foreign keys" advisor — static schema.prisma parse, no live DB needed.
    // #793 (the #761 remainder): the two app-code cross-referencing heuristics — N+1 query
    // pattern and a `where` filter with no covering index — schema.prisma alone can't see either.
    ...(orm === "prisma" ? [...scanPrismaSchemaPerf(scanDir), ...scanPrismaAppPerf(scanDir)] : []),
    // #919 — .svelte/.vue/.astro source is invisible to every detector call above (all load
    // sources via loadSources, JS/TS only); disclose it rather than let a SvelteKit/
    // Nuxt/Astro target's M5/M6/M7/M9 rows read as a clean scan of a codebase barely read.
    ...checkUnassessedSfcFiles(scanDir),
    // #1065 — the extension half of the same doctrine: what the loader DID read vs. what is there
    // to read. Independent of the loader's own filter, so a future narrowing fires this row instead
    // of silently shrinking the scan.
    ...checkUnreadSourceExtensions(
      scanDir,
      allSources.map((f) => f.path),
    ),
  ];
  if (buildDirs.length === 0) {
    console.log(
      isVite
        ? "bundle tier: no Vite dist/ build found (pass --build <path-to-dist>) — first-load JS unmeasured"
        : "bundle tier: no next build artifact found (pass --build <path-to-.next>) — [B] findings skipped",
    );
  }
  if (statsPaths.length === 0 && !isVite) {
    console.log("bundle-analyzer tier: no --stats path provided — M7B-04/05/06 findings skipped");
  }

  const byTaxonomy = new Map<string, number>();
  for (const f of findings) byTaxonomy.set(f.taxonomy, (byTaxonomy.get(f.taxonomy) ?? 0) + 1);
  console.log(`\n${findings.length} findings across ${byTaxonomy.size} classes:`);
  for (const [tax, count] of [...byTaxonomy.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(count).padStart(4)}  ${tax}`);
  }

  if (outPath) {
    writeFileSync(outPath, `${JSON.stringify(findings, null, 2)}\n`);
    console.log(`\nwritten to ${outPath} — merge into the engagement findings.json and \`pnpm validate:findings\``);
  }
} finally {
  cleanup();
}
