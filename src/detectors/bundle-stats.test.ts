// Bundle-stats calibration (#170 [B] tier): fixtures are synthetic .next dirs generated at
// runtime (randomBytes chunks — incompressible, so gzip size ≈ raw size and the thresholds
// are predictable). Two layouts: webpack (per-route manifests) and Turbopack (baseline only,
// attribution gap disclosed). Also validated once against a real Next 16 build (ATC rag).

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseBundleStats } from "./bundle-stats.js";

let webpackDir: string;
let turboDir: string;

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
});

afterAll(() => {
  rmSync(webpackDir, { recursive: true, force: true });
  rmSync(turboDir, { recursive: true, force: true });
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
