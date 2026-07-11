// M5 slop calibration gate: every AI-slop class ships only with a caught positive AND a
// cleared benign negative — the #61 fixture discipline, applied to the slop detectors.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectSlopFindings } from "./slop.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/slop/", import.meta.url));

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
  return detectSlopFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

const CASES: { name: string; dir: string; taxonomy: string; posCount?: number }[] = [
  // Ported from ATC slop-check.
  { name: "orphan TODO", dir: "orphan-todo", taxonomy: "M5 — Orphan TODO", posCount: 1 },
  { name: "narrating comment", dir: "narrating-comment", taxonomy: "M5 — Narrating comment", posCount: 1 },
  { name: "rethrow catch", dir: "rethrow-catch", taxonomy: "M5 — Rethrow catch", posCount: 1 },
  { name: "single-call wrapper", dir: "single-call-wrapper", taxonomy: "M5 — Single-call wrapper", posCount: 1 },
  // Additional researched classes.
  { name: "placeholder stub", dir: "placeholder", taxonomy: "M5 — Placeholder stub", posCount: 2 },
  { name: "elision placeholder", dir: "elision", taxonomy: "M5 — Elision placeholder", posCount: 1 },
  { name: "AI comment phrasing", dir: "ai-phrasing", taxonomy: "M5 — AI comment phrasing", posCount: 1 },
  { name: "redundant boolean", dir: "redundant-boolean", taxonomy: "M5 — Redundant boolean", posCount: 2 },
  { name: "else after return", dir: "else-after-return", taxonomy: "M5 — Else after return", posCount: 1 },
  { name: "decorative emoji", dir: "emoji", taxonomy: "M5 — Decorative emoji", posCount: 2 },
  { name: "redundant JSDoc", dir: "redundant-jsdoc", taxonomy: "M5 — Redundant JSDoc", posCount: 1 },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits.length).toBeGreaterThanOrEqual(1);
      if (c.posCount !== undefined) expect(hits.length).toBe(c.posCount);
      expect(hits[0]).toMatchObject({ category: "Maintainability", status: "Open" });
    });
    it("clears the benign negative", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

describe("finding shape", () => {
  it("emits sequential SLOP-* ids", () => {
    const findings = detectSlopFindings(loadFixtureDir("redundant-boolean/positive"));
    expect(findings.length).toBeGreaterThan(0);
    findings.forEach((f, i) => expect(f.id).toBe(`SLOP-${String(i + 1).padStart(2, "0")}`));
  });

  it("ignores non-source files", () => {
    expect(detectSlopFindings([{ path: "README.md", text: "// TODO: implement everything 🚀" }])).toHaveLength(0);
  });
});
