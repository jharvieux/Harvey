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
// tested pure transforms. Test/story/fixture files are excluded: perf and boundary findings
// in test code aren't audit findings.

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import type { Finding } from "../findings.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { scanAssetWeight } from "../detectors/asset-weight.js";
import { parseBundleAnalyzerStats, parseBundleStats } from "../detectors/bundle-stats.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { detectHookDepFindings } from "../detectors/hook-deps.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import { detectSlopFindings } from "../detectors/slop.js";
import type { SourceInput } from "../detectors/common.js";
import { resolveScanScope } from "../scan/scan-scope.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm detect-static <target-dir> [--out findings.static.json]");
  process.exit(2);
}

const SOURCE_FILE = /\.(ts|tsx|jsx|mjs)$/;
const CONFIG_FILE = /^(next\.config\.(js|mjs|cjs|ts)|\.babelrc|\.babelrc\.json|babel\.config\.(js|json|mjs|cjs)|package\.json)$/;
const EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out)$/;
const NON_PRODUCT = /\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)(__tests__|__mocks__|__fixtures__|__snapshots__)\/|\.stories\./;

function loadSources(root: string): SourceInput[] {
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
      } else if (SOURCE_FILE.test(entry) || CONFIG_FILE.test(entry)) {
        const path = relative(root, full).split(sep).join("/");
        if (NON_PRODUCT.test(path)) continue;
        files.push({ path, text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

const targetDir = resolve(targetArg);
const { scanDir, cleanup } = resolveScanScope(targetDir);
try {
  const sources = loadSources(scanDir);
  console.log(`loaded ${sources.length} source files from ${targetDir}`);

  // Bundle tier: explicit --build flags, or auto-detected .next dirs (root + apps/*).
  // Build artifacts live in the REAL target dir — they're gitignored, so the scoped copy
  // never contains them.
  const buildDirs = args.flatMap((a, i) => {
    const next = args[i + 1];
    return a === "--build" && next ? [resolve(next)] : [];
  });
  if (buildDirs.length === 0) {
    const candidates = [join(targetDir, ".next")];
    const appsDir = join(targetDir, "apps");
    if (existsSync(appsDir)) {
      for (const app of readdirSync(appsDir)) candidates.push(join(appsDir, app, ".next"));
    }
    buildDirs.push(...candidates.filter((c) => existsSync(join(c, "build-manifest.json"))));
  }

  // Stats tier: explicit --stats flags only — the artifact isn't part of `.next` so there's
  // nothing to auto-detect it from.
  const statsPaths = args.flatMap((a, i) => {
    const next = args[i + 1];
    return a === "--stats" && next ? [resolve(next)] : [];
  });

  const findings: Finding[] = [
    ...detectAppRouterFindings(sources),
    ...detectPerfCodeFindings(sources),
    ...detectHookDepFindings(sources),
    ...detectSlopFindings(sources),
    ...detectHandrolledFindings(sources), // M6 free-tier indicators — Info-only, non-grading (#267)
    ...scanAssetWeight(scanDir), // scoped copy = committed files only
    ...buildDirs.flatMap((b) => parseBundleStats(b)),
    ...statsPaths.flatMap((p) => parseBundleAnalyzerStats(p)),
  ];
  if (buildDirs.length === 0) {
    console.log("bundle tier: no next build artifact found (pass --build <path-to-.next>) — [B] findings skipped");
  }
  if (statsPaths.length === 0) {
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
