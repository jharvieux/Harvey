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

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
  severity: string;
  confidence: string;
}

const CASES: Case[] = [
  // Ported from ATC slop-check.
  { name: "orphan TODO", dir: "orphan-todo", taxonomy: "M5 — Orphan TODO", posCount: 4, severity: "Low", confidence: "Likely" },
  { name: "narrating comment", dir: "narrating-comment", taxonomy: "M5 — Narrating comment", posCount: 2, severity: "Info", confidence: "Review" },
  { name: "rethrow catch", dir: "rethrow-catch", taxonomy: "M5 — Rethrow catch", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "single-call wrapper", dir: "single-call-wrapper", taxonomy: "M5 — Single-call wrapper", posCount: 1, severity: "Low", confidence: "Review" },
  // Additional researched classes.
  { name: "placeholder stub", dir: "placeholder", taxonomy: "M5 — Placeholder stub", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "elision placeholder", dir: "elision", taxonomy: "M5 — Elision placeholder", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "AI comment phrasing", dir: "ai-phrasing", taxonomy: "M5 — AI comment phrasing", posCount: 1, severity: "Info", confidence: "Review" },
  { name: "redundant boolean", dir: "redundant-boolean", taxonomy: "M5 — Redundant boolean", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "else after return", dir: "else-after-return", taxonomy: "M5 — Else after return", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "decorative emoji", dir: "emoji", taxonomy: "M5 — Decorative emoji", posCount: 2, severity: "Info", confidence: "Review" },
  { name: "redundant JSDoc", dir: "redundant-jsdoc", taxonomy: "M5 — Redundant JSDoc", posCount: 1, severity: "Low", confidence: "Review" },
  // Coverage fan-out (#362, #364, #370, #371).
  { name: "unused parameter", dir: "unused-parameter", taxonomy: "M5 — Unused parameter", posCount: 2, severity: "Low", confidence: "Review" },
  { name: "unused import", dir: "unused-import", taxonomy: "M5 — Unused import", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "single-use helper", dir: "single-use-helper", taxonomy: "M5 — Single-use helper", posCount: 1, severity: "Low", confidence: "Review" },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count, severity, confidence, and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Maintainability", status: "Open", severity: c.severity, confidence: c.confidence });
        expect(h.location).toMatch(/[^:]:\d+$/); // `path:line`, not a bare file — catches a detector that loses its line
      }
    });
    it("clears the benign negative (incl. the discrimination boundaries)", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

// The discrimination boundaries that keep these low-FP are the load-bearing logic — assert the
// exact line so a detector that fires on the wrong node (or a mutation that drops a guard) fails,
// not just one that stops firing entirely.
describe("discrimination boundaries (regression locks)", () => {
  it("rethrow keys on the SAME caught variable — a different-var rethrow is not flagged", () => {
    // negative/c.ts has `catch (caught) { throw fallbackErr }` — must stay silent, or the \1
    // backreference has been lost and every throw-in-catch would flag.
    const hits = byTaxonomy("rethrow-catch/negative", "M5 — Rethrow catch");
    expect(hits).toHaveLength(0);
  });

  it("wrapper flags a bare free-function forward but NOT a method-call predicate", () => {
    // negative/d.ts has `isAdminRole(role) { return ADMIN_ROLES.has(role) }` — the method-call
    // guard must keep it silent (this is the exact FP class tuned out during the dogfood).
    expect(byTaxonomy("single-call-wrapper/negative", "M5 — Single-call wrapper")).toHaveLength(0);
    const pos = byTaxonomy("single-call-wrapper/positive", "M5 — Single-call wrapper");
    expect(pos).toHaveLength(1);
    expect(pos[0]?.location).toBe("d.ts:2"); // anchors on the `export function getUser` declaration
    expect(pos[0]?.title).toContain("getUser");
  });

  it("orphan-todo covers all four markers and the paren form, but exempts any-paren refs", () => {
    const pos = byTaxonomy("orphan-todo/positive", "M5 — Orphan TODO");
    expect(pos.map((f) => f.location)).toEqual(["a.ts:2", "a.ts:3", "a.ts:4", "a.ts:5"]);
    expect(byTaxonomy("orphan-todo/negative", "M5 — Orphan TODO")).toHaveLength(0);
  });

  it("narrating-comment matches multiple verbs but not a verb-first long sentence", () => {
    expect(byTaxonomy("narrating-comment/positive", "M5 — Narrating comment")).toHaveLength(2);
    expect(byTaxonomy("narrating-comment/negative", "M5 — Narrating comment")).toHaveLength(0);
  });

  it("unused-parameter flags a trailing unused param but exempts a leading one before a used param, and never visits an anonymous inline callback", () => {
    // negative/handlers.ts has `errorHandler(err, req, res, next)` where only `next` (last) is
    // used — err/req/res come BEFORE the last used param, so the after-used convention must
    // keep them silent. It also has an anonymous `numbers.map((item, index, array) => ...)`
    // callback: never a named declaration, so this detector never even visits it — that's what
    // actually keeps the callback-contract shape silent (not ESLint's after-used rule, which a
    // live check showed DOES flag that shape).
    expect(byTaxonomy("unused-parameter/negative", "M5 — Unused parameter")).toHaveLength(0);
    const pos = byTaxonomy("unused-parameter/positive", "M5 — Unused parameter");
    expect(pos.map((f) => f.location)).toEqual(["keys.ts:3", "keys.ts:7"]);
    expect(pos[0]?.title).toContain("kid");
    expect(pos[1]?.title).toContain("includeEmail");
  });

  it("single-use-helper exempts an exported single-caller but still catches a non-exported one, and stays silent on a two-site helper", () => {
    const pos = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper");
    expect(pos).toHaveLength(1);
    expect(pos[0]?.title).toContain("computeDiscount");
    expect(byTaxonomy("single-use-helper/negative", "M5 — Single-use helper")).toHaveLength(0);
  });
});

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
