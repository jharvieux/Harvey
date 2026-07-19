// M8 vitest-specific test-intent calibration gate (#629): every class ships with a caught
// positive AND a cleared benign negative — the #61 fixture discipline (same shape as
// test-intent.test.ts). Runs in `pnpm verify`.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { SourceInput } from "./common.js";
import { detectVitestIntentFindings } from "./vitest-intent.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/vitest-intent/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".txt")) files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
    }
  };
  walk(root);
  return files;
}

function byTaxonomy(relDir: string, taxonomy: string) {
  return detectVitestIntentFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
  severity: string;
  confidence: string;
}

const CASES: Case[] = [
  { name: "unrestored vi.spyOn", dir: "unrestored-spy", taxonomy: "M8 — Unrestored vi.spyOn", posCount: 1, severity: "Medium", confidence: "Review" },
  { name: "in-source testing coverage-crediting", dir: "in-source-test", taxonomy: "M8 — In-source testing coverage-crediting", posCount: 1, severity: "Low", confidence: "Review" },
  { name: "vi.hoisted misuse", dir: "vi-hoisted-misuse", taxonomy: "M8 — vi.hoisted misuse", posCount: 2, severity: "Medium", confidence: "Likely" },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count, severity, confidence, and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Test quality", status: "Open", severity: c.severity, confidence: c.confidence });
        expect(h.location).toMatch(/[^:]:\d+$/); // `path:line` — catches a detector that loses its line
      }
    });
    it("clears the benign negative (incl. the discrimination boundaries)", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

// The runner gate is the load-bearing discrimination: a jest/mocha project shows none of the
// vitest-only APIs, so the whole pass must be silent rather than false-firing on `jest.spyOn`.
describe("vitest-runner gate (regression lock)", () => {
  it("returns nothing on a jest project even with an unrestored jest.spyOn", () => {
    const jestFile: SourceInput = {
      path: "widget.test.ts",
      text: [
        'import { describe, expect, it, jest } from "@jest/globals";',
        'import { render } from "./widget.js";',
        'describe("widget", () => {',
        '  it("renders", () => {',
        '    jest.spyOn(console, "warn").mockImplementation(() => {});',
        "    render();",
        "    expect(true).toBe(true);",
        "  });",
        "});",
      ].join("\n"),
    };
    expect(detectVitestIntentFindings([jestFile])).toHaveLength(0);
  });

  it("runs when a package.json declares vitest even if no test file imports it", () => {
    const files: SourceInput[] = [
      { path: "package.json", text: JSON.stringify({ devDependencies: { vitest: "^2.0.0" } }) },
      {
        path: "src/thing.ts",
        text: ["export const x = 1;", "if (import.meta.vitest) {", "  const { it, expect } = import.meta.vitest;", '  it("x", () => expect(x).toBe(1));', "}"].join("\n"),
      },
    ];
    expect(detectVitestIntentFindings(files)).toHaveLength(1);
  });
});
