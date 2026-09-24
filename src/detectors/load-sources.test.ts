// #1065 — the loader's extension filter is the single point through which M5/M6/M7/M8/M9 and the
// M1 AST detectors see a codebase. It omitted `.js`/`.cjs` until 2026-07-25, so a plain-JavaScript
// app was scanned by nobody and the report said nothing. These tests pin the two halves that make
// that class of failure loud: the extensions actually loaded, and that a `.js`-only tree produces
// real findings rather than silence.

import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectHandrolledFindings } from "./handrolled.js";
import { isProductJavaScriptTypeScriptSource, loadSourceInventory, loadSources, NON_PRODUCT } from "./load-sources.js";
import { detectPerfCodeFindings } from "./perf-code.js";
import { detectSlopFindings } from "./slop.js";
import { productSourceInventoryForScope, productSourceInventoryForTarget } from "../source-inventory.js";

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
  it("preserves source populations and canonical aliases with a caller's current scope inventory", () => {
    const root = makeTarget({
      "tsconfig.json": JSON.stringify({ files: ["src/main.ts"] }),
      "src/main.ts": "export const value = 1;\n",
      "src/main.js": "exports.value = 1;\n",
      "src/app/api/reports/route.ts": "export const GET = () => null;\n",
      "tool.py": "value = 1\n",
    });
    const alias = `${root}-alias`;
    symlinkSync(root, alias);
    dirs.push(alias);
    const scope = { root: realpathSync(root), inventory: productSourceInventoryForTarget(root) };
    expect(loadSources(alias, scope)).toEqual(loadSources(root));
    expect(loadSourceInventory(alias, scope)).toEqual(loadSourceInventory(root));
    const paths = loadSources(root, scope).map((file) => file.path);
    expect(paths).toContain("src/main.ts");
    expect(paths).toContain("src/app/api/reports/route.ts");
    expect(paths).not.toContain("src/main.js");
  });

  it("rejects a supplied inventory bound to another scope", () => {
    const root = makeTarget({ "main.ts": "export const live = true;\n" });
    const other = makeTarget({ "main.ts": "export const other = true;\n" });
    const scope = { root: other, inventory: productSourceInventoryForTarget(other) };
    expect(() => loadSources(root, scope)).toThrow("different scope");
    expect(() => loadSourceInventory(root, scope)).toThrow("different scope");
  });

  it("keeps complete ordered source contents with a rebased member inventory", () => {
    const root = makeTarget({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "tsconfig.json": JSON.stringify({ files: ["apps/web/src/main.ts"] }),
      "apps/web/package.json": JSON.stringify({ name: "web" }),
      "apps/web/src/main.ts": "export const live = true;\n",
      "apps/web/src/main.js": "exports.live = true;\n",
      "apps/web/src/dist/authored.ts": "export const authored = true;\n",
      "apps/web/src/main.test.ts": "test('live', () => expect(true).toBe(true));\n",
      "apps/web/report.py": "def report():\n    return 1\n",
    });
    const member = join(root, "apps/web");
    const inventory = productSourceInventoryForTarget(root);
    const scope = { root: member, inventory: productSourceInventoryForScope(root, member, inventory) };
    expect(loadSources(member, scope)).toEqual(loadSources(member));
    expect(loadSourceInventory(member, scope)).toEqual(loadSourceInventory(member));
    expect(loadSources(member, scope).map((file) => file.path)).toEqual([
      "package.json", "src/dist/authored.ts", "src/main.test.ts", "src/main.ts",
    ]);
    expect(loadSourceInventory(member, scope).map((file) => file.path)).toContain("report.py");
  });

  it("refreshes compiler-live source after dependency preparation on a later standalone call", () => {
    const root = makeTarget({
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "build", moduleResolution: "node" }, files: ["main.ts"] }),
      "main.ts": 'import "prepared";\n',
      "build/authored.ts": "export interface Value { value: number }\n",
    });
    expect(loadSources(root).map((file) => file.path)).not.toContain("build/authored.ts");
    mkdirSync(join(root, "node_modules/prepared"), { recursive: true });
    writeFileSync(join(root, "node_modules/prepared/index.d.ts"), 'export type Value = import("../../build/authored").Value;\n');
    expect(loadSources(root).map((file) => file.path)).toContain("build/authored.ts");
  });

  it("keeps authored reports/dist paths while excluding a pnpm store from every loader consumer (#2132/#2125)", () => {
    const dir = makeTarget({
      "package.json": JSON.stringify({ packageManager: "pnpm@9.0.0" }),
      "src/app/api/reports/route.ts": "export const GET = () => null;\n",
      "src/dist/handwritten.ts": "export const authored = true;\n",
      ".pnpm-store/v3/pkg/index.ts": "export const dependency = true;\n",
    });
    expect(loadSources(dir).map((file) => file.path).sort()).toEqual([
      "package.json",
      "src/app/api/reports/route.ts",
      "src/dist/handwritten.ts",
    ]);
  });

  it("excludes flat and nested files when an ancestor config marks the whole workspace as output", () => {
    const root = makeTarget({
      "package.json": JSON.stringify({ private: true, workspaces: ["apps/*"] }),
      "tsconfig.json": JSON.stringify({ compilerOptions: { outDir: "apps" } }),
      "apps/web/package.json": JSON.stringify({ name: "web", private: true }),
      "apps/web/generated.ts": "export const direct = true;\n",
      "apps/web/src/generated.ts": "export const nested = true;\n",
    });
    const app = join(root, "apps/web");
    expect(loadSourceInventory(app)).toEqual([]);
    expect(loadSources(app)).toEqual([]);
  });

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

  it("defines the M6 product population across every supported suffix while preserving explicit exclusions (#2105)", () => {
    const supported = ["ts", "tsx", "jsx", "mjs", "js", "cjs", "mts", "cts"];
    expect(supported.map((suffix) => `src/shape.${suffix}`).filter(isProductJavaScriptTypeScriptSource)).toEqual(
      supported.map((suffix) => `src/shape.${suffix}`),
    );
    expect(isProductJavaScriptTypeScriptSource("src/shape.test.js")).toBe(false);
    expect(isProductJavaScriptTypeScriptSource("src/__fixtures__/shape.mts")).toBe(false);
    expect(isProductJavaScriptTypeScriptSource("scripts/generate.py")).toBe(false);
  });

  it("skips minified/generated JavaScript — machine output is not auditable source", () => {
    const dir = makeTarget({
      "public/vendor.min.js": "var a=1;\n",
      "public/bundle.js": `var x=1;${"/* padding */".repeat(200)}\n`,
      "app/route.js": "export const GET = () => null;\n",
    });
    expect(loadSources(dir).map((f) => f.path)).toEqual(["app/route.js"]);
  });

  it("#1136: does NOT drop real source that merely carries one long string literal", () => {
    // Mirrors the false exclusion measured against inbox-zero's update-rule-tool.ts (605 lines,
    // one 1081-char line, that line is 5.7% of the file's bytes): many ordinary short lines plus
    // one long outlier is real source, not a minified/generated bundle.
    const normalLines = Array.from({ length: 300 }, (_, i) => `export const line${i} = ${i};`).join("\n");
    const longStringLiteral = `export const TOOL_DESCRIPTION = "${"x".repeat(1200)}";`;
    const dir = makeTarget({ "lib/ai-tool.ts": `${normalLines}\n${longStringLiteral}\n` });
    expect(loadSources(dir).map((f) => f.path)).toEqual(["lib/ai-tool.ts"]);
  });

  it("#1136: still excludes a file whose bulk (not an aside) is packed onto long lines", () => {
    // Mirrors carbon's onshape/config.tsx and paperless-parts/config.tsx (SVG icon-path-data
    // tables): most of the file's bytes sit on long lines, not one outlier amid ordinary code.
    const longLines = Array.from({ length: 8 }, (_, i) => `export const path${i} = "M${"1".repeat(1100)}Z";`).join("\n");
    const dir = makeTarget({ "components/icons.tsx": `${longLines}\n` });
    expect(loadSources(dir).map((f) => f.path)).toEqual([]);
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
