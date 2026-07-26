// #1065 — the loader's extension filter is the single point through which M5/M6/M7/M8/M9 and the
// M1 AST detectors see a codebase. It omitted `.js`/`.cjs` until 2026-07-25, so a plain-JavaScript
// app was scanned by nobody and the report said nothing. These tests pin the two halves that make
// that class of failure loud: the extensions actually loaded, and that a `.js`-only tree produces
// real findings rather than silence.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectHandrolledFindings } from "./handrolled.js";
import { loadSources, NON_PRODUCT } from "./load-sources.js";
import { detectPerfCodeFindings } from "./perf-code.js";
import { detectSlopFindings } from "./slop.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-load-sources-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("loadSources extension coverage (#1065)", () => {
  it("loads the whole JS/TS family, not just the TypeScript half", () => {
    const dir = makeTarget({
      "app/route.js": "export const GET = () => null;\n",
      "lib/legacy.cjs": "module.exports = {};\n",
      "lib/esm.mjs": "export const a = 1;\n",
      "lib/typed.mts": "export const b: number = 1;\n",
      "lib/typed.cts": "export const c: number = 1;\n",
      "app/page.tsx": "export default function P() { return null; }\n",
      "app/legacy.jsx": "export default function L() { return null; }\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    const loaded = loadSources(dir)
      .map((f) => f.path)
      .sort();
    expect(loaded).toEqual(["app/legacy.jsx", "app/page.tsx", "app/route.js", "lib/db.ts", "lib/esm.mjs", "lib/legacy.cjs", "lib/typed.cts", "lib/typed.mts"]);
  });

  it("skips minified/generated JavaScript — machine output is not auditable source", () => {
    const dir = makeTarget({
      "public/vendor.min.js": "var a=1;\n",
      "public/bundle.js": `var x=1;${"/* padding */".repeat(200)}\n`,
      "app/route.js": "export const GET = () => null;\n",
    });
    expect(loadSources(dir).map((f) => f.path)).toEqual(["app/route.js"]);
  });

  it("still recognises test files as non-product when they are plain .js", () => {
    const dir = makeTarget({
      "lib/util.js": "export const u = 1;\n",
      "lib/util.test.js": "it('works', () => {});\n",
      "lib/util.spec.cjs": "it('works', () => {});\n",
    });
    const paths = loadSources(dir).map((f) => f.path);
    expect(paths).toHaveLength(3);
    expect(paths.filter((p) => !NON_PRODUCT.test(p))).toEqual(["lib/util.js"]);
  });
});

describe("a .js-only target produces real findings (#1065)", () => {
  it("fires the M6 and M7 detectors on plain JavaScript, where it previously found nothing", () => {
    const dir = makeTarget({
      "package.json": '{"name":"js-only","dependencies":{"zod":"^3"}}\n',
      "lib/validate.js": "export function isEmail(value) {\n  return /^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(value);\n}\n",
      "lib/report.js": "import { supabase } from './db.js';\nexport async function all() {\n  const { data } = await supabase.from('events').select('*');\n  return data;\n}\n",
    });
    const sources = loadSources(dir).filter((f) => !NON_PRODUCT.test(f.path));

    const findings = [...detectHandrolledFindings(sources), ...detectPerfCodeFindings(sources, "next")];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.map((f) => f.taxonomy)).toEqual(expect.arrayContaining(["M6 — Indicator: email-shape regex", "M7 — Unbounded select"]));
    expect(findings.every((f) => f.location.includes(".js:"))).toBe(true);
  });

  it("reads and reports on the standing vuln-seam-app fixture, which is entirely .js", () => {
    // The fixture that made #1065 visible: 12 authored .js files, of which the loader saw 2
    // (next.config.js and package.json). `pnpm detect-static targets/vuln-seam-app` printed
    // "loaded 2 source files … 0 findings across 0 classes" while every app/api/**/route.js was
    // invisible — a standing offline regression fixture reporting a clean bill of health.
    const sources = loadSources(resolve(process.cwd(), "targets/vuln-seam-app"));
    const routes = sources.filter((f) => f.path.startsWith("app/api/") && f.path.endsWith("/route.js"));
    expect(routes.length).toBeGreaterThanOrEqual(10);
    expect(sources.map((f) => f.path)).toContain("app/page.js");

    const product = sources.filter((f) => !NON_PRODUCT.test(f.path));
    const findings = [...detectSlopFindings(product), ...detectHandrolledFindings(product)];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.location.includes(".js:"))).toBe(true);
  });
});
