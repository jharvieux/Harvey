// #919 — .svelte/.vue/.astro single-file-component source is invisible to every static/AST pass
// (the shared source loader only reads .ts/.tsx/.jsx/.mjs) and, before this file, was uncounted
// too. Mirrors language-coverage.test.ts's (#871) shape for the sibling gap.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkUnassessedSfcFiles } from "./sfc-coverage.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-sfc-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("checkUnassessedSfcFiles (#919)", () => {
  it("names every SFC format with its file count, an example path, and the affected modules", () => {
    const dir = makeTarget({
      "src/routes/+page.svelte": "<script>export let data;</script>\n<h1>{data.title}</h1>\n",
      "src/lib/Widget.svelte": "<script>export let count = 0;</script>\n<button>{count}</button>\n",
      "src/lib/util.ts": "export function add(a: number, b: number): number { return a + b; }\n",
    });
    const [finding] = checkUnassessedSfcFiles(dir);
    expect(finding).toMatchObject({ id: "M1-SFC-00", severity: "Info", confidence: "N/A" });
    expect(finding?.evidence).toContain("Svelte (2 files");
    expect(finding?.evidence).toMatch(/src\/lib\/Widget\.svelte|src\/routes\/\+page\.svelte/);
    // Proportion is DERIVED (1 analysable .ts file vs. 3 total source-like files), not asserted.
    expect(finding?.evidence).toContain("analysed 1 of 3 source files (33%)");
    expect(finding?.evidence).toMatch(/M5\/M6\/M7\/M9/);
    expect(finding?.impact).toMatch(/M5 \(dead code\)/);
    expect(finding?.impact).toMatch(/M9 \(App Router boundaries\)/);
  });

  it("names Vue and Astro too, ranked worst-format-first", () => {
    const dir = makeTarget({
      "src/App.vue": "<template><div/></template>\n",
      "src/pages/index.astro": "<h1>hi</h1>\n",
      "src/pages/about.astro": "<h1>about</h1>\n",
    });
    const [finding] = checkUnassessedSfcFiles(dir);
    expect(finding?.title).toBe("Single-file-component source not analysed: Astro/Vue");
    expect(finding?.evidence).toContain("Astro (2 files");
    expect(finding?.evidence).toContain("Vue (1 file,");
  });

  it("emits nothing for a pure JS/TS target (no SFC files present)", () => {
    const dir = makeTarget({
      "app/page.tsx": "export default function Page() { return null; }\n",
      "lib/db.ts": "export const q = 1;\n",
    });
    expect(checkUnassessedSfcFiles(dir)).toEqual([]);
  });

  it("ignores vendored/installed trees — a target's own source is the subject", () => {
    const dir = makeTarget({
      "node_modules/some-pkg/Component.svelte": "<script></script>\n",
      "src/lib/util.ts": "export const x = 1;\n",
    });
    expect(checkUnassessedSfcFiles(dir)).toEqual([]);
  });
});
