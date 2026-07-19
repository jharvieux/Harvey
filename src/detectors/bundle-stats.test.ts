// Bundle-stats calibration (#170 [B] tier): fixtures are synthetic .next dirs generated at
// runtime (randomBytes chunks — incompressible, so gzip size ≈ raw size and the thresholds
// are predictable). Two layouts: webpack (per-route manifests) and Turbopack (baseline only,
// attribution gap disclosed). Also validated once against a real Next 16 build (ATC rag).

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseBundleAnalyzerStats, parseBundleStats, parseViteBundleStats } from "./bundle-stats.js";

let webpackDir: string;
let turboDir: string;
let statsPath: string;
let statsDir: string;
let viteDir: string;

beforeAll(() => {
  // Webpack layout: shared framework chunk (100 KB) + heavy route chunk (300 KB) + light (5 KB).
  webpackDir = mkdtempSync(join(tmpdir(), "harvey-bundle-wp-"));
  mkdirSync(join(webpackDir, "static", "chunks"), { recursive: true });
  writeFileSync(join(webpackDir, "static", "chunks", "framework.js"), randomBytes(100 * 1024));
  writeFileSync(join(webpackDir, "static", "chunks", "heavy-route.js"), randomBytes(300 * 1024));
  writeFileSync(join(webpackDir, "static", "chunks", "light-route.js"), randomBytes(5 * 1024));
  writeFileSync(
    join(webpackDir, "app-build-manifest.json"),
    JSON.stringify({
      pages: {
        "/dashboard/page": ["static/chunks/framework.js", "static/chunks/heavy-route.js"],
        "/about/page": ["static/chunks/framework.js", "static/chunks/light-route.js"],
      },
    }),
  );

  // Turbopack layout: rootMainFiles only, no app-build-manifest, page routes present.
  turboDir = mkdtempSync(join(tmpdir(), "harvey-bundle-tp-"));
  mkdirSync(join(turboDir, "static", "chunks"), { recursive: true });
  writeFileSync(join(turboDir, "static", "chunks", "main.js"), randomBytes(200 * 1024));
  writeFileSync(
    join(turboDir, "build-manifest.json"),
    JSON.stringify({ pages: { "/_app": [] }, rootMainFiles: ["static/chunks/main.js"] }),
  );
  writeFileSync(join(turboDir, "app-path-routes-manifest.json"), JSON.stringify({ "/page": "/", "/api/health/route": "/api/health" }));

  // Synthetic webpack-stats JSON (#179): the shape @next/bundle-analyzer's `generateStatsFile`
  // writes (webpack Stats.toJson()) — no real analyzer run, since installing the dependency
  // is out of scope (package.json is supervised).
  statsDir = mkdtempSync(join(tmpdir(), "harvey-bundle-stats-"));
  statsPath = join(statsDir, "client-stats.json");
  writeFileSync(
    statsPath,
    JSON.stringify({
      modules: [
        // duplicated into two chunks, over the 1 KB floor → M7B-04
        { identifier: "/repo/node_modules/lodash/lodash.js", size: 50 * 1024, chunks: ["dashboard", "about"] },
        // duplicated but under the floor → filtered out of M7B-04
        { identifier: "/repo/node_modules/tiny-pkg/index.js", size: 500, chunks: ["dashboard", "about"] },
        // pnpm-nested identifier; two modules from the same package sum past the dep budget → M7B-05
        { identifier: "/repo/node_modules/.pnpm/heavy-chart-lib@2.0.0/node_modules/heavy-chart-lib/index.js", size: 120 * 1024, chunks: ["dashboard"] },
        { identifier: "/repo/node_modules/heavy-chart-lib/utils.js", size: 60 * 1024, chunks: ["dashboard"] },
        // app source, not a dependency — excluded from M7B-05
        { identifier: "/repo/src/app/dashboard/page.tsx", size: 5 * 1024, chunks: ["dashboard"] },
      ],
      namedChunkGroups: {
        "app/dashboard/page": { assets: [{ name: "dashboard.js", size: 900 * 1024 }] },
        "app/about/page": { assets: [{ name: "about.js", size: 100 * 1024 }] },
      },
    }),
  );

  // Vite (Rollup) dist layout (#577): index.html references the entry chunk (<script type=module>)
  // and a modulepreload vendor chunk; a lazy chunk sits in assets/ but is NOT referenced by the HTML,
  // so it must be excluded from first-load. randomBytes → incompressible → gzip ≈ raw, so budgets are
  // predictable (250 KB budget; entry 200 + vendor 100 = 300 KB first-load; lazy 500 KB excluded).
  viteDir = mkdtempSync(join(tmpdir(), "harvey-bundle-vite-"));
  mkdirSync(join(viteDir, "assets"), { recursive: true });
  writeFileSync(join(viteDir, "assets", "index-abc123.js"), randomBytes(200 * 1024));
  writeFileSync(join(viteDir, "assets", "vendor-def456.js"), randomBytes(100 * 1024));
  writeFileSync(join(viteDir, "assets", "SettingsPage-lazy789.js"), randomBytes(500 * 1024));
  writeFileSync(
    join(viteDir, "index.html"),
    `<!doctype html><html><head>
      <link rel="modulepreload" crossorigin href="/assets/vendor-def456.js">
      <script type="module" crossorigin src="/assets/index-abc123.js"></script>
    </head><body><div id="root"></div></body></html>`,
  );
});

afterAll(() => {
  rmSync(webpackDir, { recursive: true, force: true });
  rmSync(turboDir, { recursive: true, force: true });
  rmSync(statsDir, { recursive: true, force: true });
  rmSync(viteDir, { recursive: true, force: true });
});

describe("webpack-layout builds (per-route manifests)", () => {
  it("flags the route over budget with measured gzip weight, Confirmed confidence", () => {
    const findings = parseBundleStats(webpackDir, { routeBudgetBytes: 250 * 1024, sharedBudgetBytes: 150 * 1024 });
    const route = findings.find((f) => f.taxonomy === "M7 — First-load JS over budget");
    expect(route).toBeDefined();
    expect(route?.location).toBe("/dashboard");
    expect(route?.title).toContain("1 route");
    expect(route).toMatchObject({ confidence: "Confirmed", severity: "Perf", id: "M7B-01" });
    expect(route?.evidence).not.toContain("/about"); // the light route is under budget
  });

  it("flags the shared baseline when it exceeds its own budget", () => {
    const findings = parseBundleStats(webpackDir, { routeBudgetBytes: 999 * 1024, sharedBudgetBytes: 50 * 1024 });
    const baseline = findings.find((f) => f.taxonomy === "M7 — Shared bundle baseline over budget");
    expect(baseline?.location).toContain("framework.js");
    expect(baseline?.id).toBe("M7B-02");
  });

  it("stays silent when everything is under budget", () => {
    expect(parseBundleStats(webpackDir, { routeBudgetBytes: 999 * 1024, sharedBudgetBytes: 999 * 1024 })).toHaveLength(0);
  });
});

describe("Turbopack-layout builds (no per-route manifest)", () => {
  it("measures the shared baseline and DISCLOSES the attribution gap instead of silently skipping", () => {
    const findings = parseBundleStats(turboDir, { sharedBudgetBytes: 100 * 1024 });
    const baseline = findings.find((f) => f.taxonomy === "M7 — Shared bundle baseline over budget");
    expect(baseline).toBeDefined();
    const gap = findings.find((f) => f.taxonomy === "M7 — Bundle route attribution unavailable");
    expect(gap).toMatchObject({ severity: "Info", confidence: "N/A", id: "M7B-03" });
    expect(gap?.title).toContain("1 page route"); // /api/health is not a page
  });
});

describe("no build artifact", () => {
  it("returns nothing for a directory with no manifests", () => {
    const empty = mkdtempSync(join(tmpdir(), "harvey-bundle-empty-"));
    try {
      expect(parseBundleStats(empty)).toHaveLength(0);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});

describe("Vite (Rollup) dist reader (#577)", () => {
  it("measures first-load JS from the index.html entry + modulepreload set, excluding lazy chunks", () => {
    const findings = parseViteBundleStats(viteDir);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f).toMatchObject({ id: "M7B-V1", confidence: "Confirmed", severity: "Perf" });
    expect(f.taxonomy).toBe("M7 — First-load JS over budget (Vite)");
    expect(f.title).toContain("300 KB"); // 200 entry + 100 vendor, gzip ≈ raw (incompressible)
    expect(f.title).toContain("2 entry chunks");
    expect(f.evidence).toContain("index-abc123.js");
    expect(f.evidence).toContain("vendor-def456.js");
    expect(f.evidence).not.toContain("SettingsPage-lazy789.js"); // lazy chunk not in first-load
  });

  it("stays silent when first-load is under budget", () => {
    expect(parseViteBundleStats(viteDir, { firstLoadBudgetBytes: 999 * 1024 })).toHaveLength(0);
  });

  it("returns nothing for a directory with no dist/index.html and no assets", () => {
    const empty = mkdtempSync(join(tmpdir(), "harvey-vite-empty-"));
    try {
      expect(parseViteBundleStats(empty)).toHaveLength(0);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it("discloses the first-load attribution gap (M7B-V0) when assets exist but index.html is absent", () => {
    const noHtml = mkdtempSync(join(tmpdir(), "harvey-vite-nohtml-"));
    try {
      mkdirSync(join(noHtml, "assets"), { recursive: true });
      writeFileSync(join(noHtml, "assets", "chunk.js"), randomBytes(80 * 1024));
      const findings = parseViteBundleStats(noHtml);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ id: "M7B-V0", severity: "Info", confidence: "N/A" });
    } finally {
      rmSync(noHtml, { recursive: true, force: true });
    }
  });
});

describe("bundle-analyzer stats JSON (#179)", () => {
  it("flags modules duplicated across chunks above the per-module floor", () => {
    const findings = parseBundleAnalyzerStats(statsPath);
    const dup = findings.find((f) => f.taxonomy === "M7 — Duplicate modules across chunks");
    expect(dup).toMatchObject({ id: "M7B-04", confidence: "Confirmed", severity: "Perf" });
    expect(dup?.evidence).toContain("lodash.js");
    expect(dup?.evidence).not.toContain("tiny-pkg"); // below the 1 KB floor
  });

  it("attributes shipped weight to npm packages, summing across resolved module copies", () => {
    const findings = parseBundleAnalyzerStats(statsPath);
    const dep = findings.find((f) => f.taxonomy === "M7 — Dependency attribution over budget");
    expect(dep).toMatchObject({ id: "M7B-05", confidence: "Confirmed", location: "heavy-chart-lib" });
    expect(dep?.evidence).toContain("heavy-chart-lib (180 KB)"); // 120 KB + 60 KB, pnpm-nested identifier resolved
  });

  it("measures per-route first-load from namedChunkGroups — the Turbopack gap closer", () => {
    const findings = parseBundleAnalyzerStats(statsPath, { routeBudgetBytes: 750 * 1024 });
    const route = findings.find((f) => f.taxonomy === "M7 — First-load JS over budget (bundle-analyzer stats)");
    expect(route).toMatchObject({ id: "M7B-06", confidence: "Confirmed", location: "/dashboard" });
    expect(route?.evidence).not.toContain("/about"); // under budget
  });

  it("returns nothing for a missing or unparsable stats file", () => {
    expect(parseBundleAnalyzerStats(join(statsDir, "does-not-exist.json"))).toHaveLength(0);
  });
});
