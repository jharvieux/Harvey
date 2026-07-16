// M6 indicator calibration gate: every hand-rolled-shape class ships only with a caught positive
// AND a cleared benign negative (the #61 fixture discipline), PLUS the free-tier language lock —
// the operator ruling on #267 makes the hedged wording load-bearing, so the vocabulary itself is
// gated here: no finding may ever name a replacement, and every finding must be non-grading Info.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectHandrolledFindings, hasClassMergeDep } from "./handrolled.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/handrolled/", import.meta.url));

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
  return detectHandrolledFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
}

// No "JSON round-trip clone" case: that shape is deliberately M7's (`M7 — JSON deep-clone` in
// perf-code.ts) — see handrolled.ts's header for the #278 double-count reasoning.
const CASES: Case[] = [
  { name: "JSON deep-equal", dir: "json-equal", taxonomy: "M6 — Indicator: JSON deep-equal", posCount: 1 },
  { name: "query-string parsing", dir: "querystring", taxonomy: "M6 — Indicator: query-string parsing", posCount: 1 },
  { name: "cookie parsing", dir: "cookie", taxonomy: "M6 — Indicator: cookie parsing", posCount: 2 },
  { name: "random-string id", dir: "random-id", taxonomy: "M6 — Indicator: random-string id", posCount: 2 },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Maintainability", status: "Open", severity: "Info", confidence: "Review" });
        expect(h.location).toMatch(/[^:]:\d+$/);
      }
    });
    it("clears the benign negative", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

describe("class-string merge (dep-gated)", () => {
  const TAX = "M6 — Indicator: class-string merge";

  it("catches the inline-JSX and cn-helper positives when a merge library is in the tree", () => {
    const hits = byTaxonomy("class-merge/positive", TAX);
    expect(hits).toHaveLength(2);
    expect(hits.map((h) => h.location.split(":")[0]).sort()).toEqual(["button.tsx", "cn.ts"]);
  });

  it("stays silent when no merge library is in the tree — the deliberate dep-drop shape", () => {
    const files = loadFixtureDir("class-merge/negative-no-dep");
    expect(hasClassMergeDep(files)).toBe(false);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });

  it("stays silent on a sentence-builder join even with the gate open — className context is required", () => {
    const files = loadFixtureDir("class-merge/negative-with-dep");
    expect(hasClassMergeDep(files)).toBe(true);
    expect(detectHandrolledFindings(files).filter((f) => f.taxonomy === TAX)).toHaveLength(0);
  });
});

describe("discrimination boundaries (regression locks)", () => {
  it("query-string: the flag anchors on the split(\"&\") site, and each lone split stays silent", () => {
    const pos = byTaxonomy("querystring/positive", "M6 — Indicator: query-string parsing");
    expect(pos[0]?.location).toBe("parse.ts:3");
    // negative has BOTH a lone split("&") and a lone split("=") in separate scopes.
    expect(byTaxonomy("querystring/negative", "M6 — Indicator: query-string parsing")).toHaveLength(0);
  });

  it("cookie: reads of document.cookie and cookie-named header strings flag; writes and non-cookie splits don't", () => {
    const pos = byTaxonomy("cookie/positive", "M6 — Indicator: cookie parsing");
    expect(pos.map((f) => f.location)).toEqual(["cookies.ts:2", "cookies.ts:12"]);
    expect(byTaxonomy("cookie/negative", "M6 — Indicator: cookie parsing")).toHaveLength(0);
  });

  it("random-id: only Math.random().toString(radix>10) flags — numeric formatting never does", () => {
    expect(byTaxonomy("random-id/positive", "M6 — Indicator: random-string id")).toHaveLength(2);
    expect(byTaxonomy("random-id/negative", "M6 — Indicator: random-string id")).toHaveLength(0);
  });
});

// The operator ruling's language discipline, as a gate: free-tier indicators must hedge and must
// never name the replacement — naming it IS the paid-tier judgment. If a future edit adds
// "replace with structuredClone()" to any field, this fails.
describe("free-tier language lock (#267 operator ruling)", () => {
  const allPositiveFindings = [
    ...detectHandrolledFindings(loadFixtureDir("json-equal/positive")),
    ...detectHandrolledFindings(loadFixtureDir("querystring/positive")),
    ...detectHandrolledFindings(loadFixtureDir("cookie/positive")),
    ...detectHandrolledFindings(loadFixtureDir("random-id/positive")),
    ...detectHandrolledFindings(loadFixtureDir("class-merge/positive")),
  ];
  const REPLACEMENT_NAMES =
    /structuredClone|isDeepStrictEqual|fast-deep-equal|deep-equal|URLSearchParams|useSearchParams|next\/headers|cookies\(\)|cookie-parse|randomUUID|getRandomValues|nanoid|\buuid\b|clsx|tailwind-merge|\bclassnames\b|lodash|should be replaced/i;

  it("produced findings to lock (the corpus is not empty)", () => {
    expect(allPositiveFindings.length).toBeGreaterThanOrEqual(8);
  });

  it("every finding is a hedged, non-grading Info indicator", () => {
    for (const f of allPositiveFindings) {
      expect(f.severity).toBe("Info");
      expect(f.confidence).toBe("Review");
      expect(f.taxonomy).toMatch(/^M6 — Indicator: /);
      expect(f.title).toContain("may be worth investigating");
      expect(f.title).toContain("Looks hand-rolled");
    }
  });

  it("no field ever names a replacement library or primitive", () => {
    for (const f of allPositiveFindings) {
      for (const field of [f.title, f.evidence, f.impact, f.fix]) {
        expect(field).not.toMatch(REPLACEMENT_NAMES);
      }
    }
  });
});
