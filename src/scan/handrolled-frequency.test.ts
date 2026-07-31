// Guards the frequency signatures (#406 item 1): every measured shape must count its own
// canonical example. A signature that cannot match its own example would report an
// honest-looking zero on the corpus — a junk count wearing the costume of a measurement.

import { describe, expect, it } from "vitest";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";
import { AI_FREQUENCY_CORPUS, buildFrequencyTargets, MEASURED_SHAPES, SHIPPED_SHAPES, UNMEASURED_SHAPES } from "./handrolled-frequency.js";

describe("measured shapes count their canonical example", () => {
  for (const shape of MEASURED_SHAPES) {
    it(`entry ${shape.entry} (${shape.name})`, () => {
      expect(shape.count({ path: shape.examplePath ?? "src/example.ts", text: shape.example })).toBeGreaterThanOrEqual(1);
    });
  }

  it("path-scoped shapes stay silent off their path", () => {
    for (const shape of MEASURED_SHAPES.filter((s) => s.examplePath !== undefined)) {
      expect(shape.count({ path: "src/elsewhere.ts", text: shape.example })).toBe(0);
    }
  });
});

describe("catalogue bookkeeping", () => {
  it("covers all 25 YES and 34 MAYBE entries exactly once, measured or unmeasured", () => {
    // The YES/MAYBE rows of docs/design/m6-handrolled-catalogue.md ("The tally" table).
    const yes = [3, 4, 11, 13, 16, 23, 24, 27, 28, 29, 30, 37, 41, 42, 44, 52, 53, 61, 68, 76, 81, 88, 89, 95, 98];
    const maybe = [5, 6, 12, 15, 18, 19, 22, 31, 32, 34, 35, 39, 40, 43, 47, 58, 59, 65, 66, 67, 69, 72, 73, 74, 75, 82, 83, 90, 92, 96, 99, 100, 101, 102];
    const covered = [...MEASURED_SHAPES, ...UNMEASURED_SHAPES].map((s) => s.entry).sort((a, b) => a - b);
    expect(covered).toEqual([...yes, ...maybe].sort((a, b) => a - b));
    for (const s of [...MEASURED_SHAPES, ...UNMEASURED_SHAPES]) {
      expect(yes.includes(s.entry) ? "YES" : "MAYBE").toBe(s.verdict);
    }
  });

  // #413: the provenance-tagged AI frequency tier.
  it("every corpus repo carries a provenance verdict with evidence", () => {
    const tiers = new Set(["professional", "ai-assisted", "ai-generated", "unclear"]);
    for (const t of [...EXTERNAL_CORPUS, ...AI_FREQUENCY_CORPUS]) {
      expect(tiers, t.slug).toContain(t.provenance);
      expect(t.provenanceNote.length, t.slug).toBeGreaterThan(0);
    }
  });

  it("AI frequency targets are pinned to a full 40-hex commit, and any slug shared with the drift corpus agrees on pin and provenance", () => {
    // #1524 gave cravab/flori-web/effective a full ExternalTarget entry too — shape frequency and
    // drift baseline are independent measurements over the SAME pinned tree, so overlap is now
    // intentional. What must never happen is the bookkeeping accident this check originally
    // guarded against: the same slug naming two DIFFERENT repos/commits in the two lists.
    // Provenance is checked too (restored/strengthened alongside #1524's dedup fix, not merely
    // left at "pin agrees"): buildFrequencyTargets() silently lets EXTERNAL_CORPUS's provenance
    // win a shared slug (it decides which provenance TIER the repo's indicators are summed into),
    // so a divergence there is a real data inconsistency, not a cosmetic one — it would previously
    // have been invisible because nothing read AI_FREQUENCY_CORPUS's provenance for a shared slug.
    const corpusBySlug = new Map(EXTERNAL_CORPUS.map((t) => [t.slug, t]));
    for (const t of AI_FREQUENCY_CORPUS) {
      expect(t.commit, t.slug).toMatch(/^[0-9a-f]{40}$/);
      const shared = corpusBySlug.get(t.slug);
      if (shared) {
        expect(shared.repo, t.slug).toBe(t.repo);
        expect(shared.commit, t.slug).toBe(t.commit);
        expect(shared.provenance, t.slug).toBe(t.provenance);
      }
    }
  });

  it("has at least one genuinely AI-generated repo to answer the #413 question", () => {
    expect(AI_FREQUENCY_CORPUS.some((t) => t.provenance === "ai-generated" && !t.curated)).toBe(true);
  });

  // #1524: src/cli/handrolled-frequency.ts sums per-repo indicator counts by iterating the built
  // targets list once per tier — a shared slug appearing twice would contribute to that sum twice,
  // while a same-tier repo present in only one list contributes once. This asserts the real overlap
  // (cravab/flori-web/effective are genuinely in both lists, per the assertion below) collapses to
  // one entry per slug, and that EXTERNAL_CORPUS's provenance wins the shared slug.
  describe("buildFrequencyTargets dedupes the corpus overlap (#1524)", () => {
    it("the overlap this test guards is real, not vacuous", () => {
      const externalSlugs = new Set(EXTERNAL_CORPUS.map((t) => t.slug));
      const overlap = AI_FREQUENCY_CORPUS.filter((t) => externalSlugs.has(t.slug));
      expect(overlap.length).toBeGreaterThan(0);
    });

    it("never lists a slug more than once", () => {
      const slugs = buildFrequencyTargets().map((t) => t.slug);
      expect(new Set(slugs).size).toBe(slugs.length);
    });

    it("length equals the union of both corpora's slugs, not their naive concatenation", () => {
      const unionSize = new Set([...EXTERNAL_CORPUS.map((t) => t.slug), ...AI_FREQUENCY_CORPUS.map((t) => t.slug)]).size;
      expect(buildFrequencyTargets().length).toBe(unionSize);
    });

    it("a slug present in EXTERNAL_CORPUS keeps that corpus's provenance, not AI_FREQUENCY_CORPUS's curated bucketing", () => {
      const bySlug = new Map(buildFrequencyTargets().map((t) => [t.slug, t]));
      for (const t of EXTERNAL_CORPUS) {
        expect(bySlug.get(t.slug)?.provenance, t.slug).toBe(t.provenance);
        expect(bySlug.get(t.slug)?.tier, t.slug).toBe(t.provenance);
      }
    });
  });

  it("shipped taxonomies exist in the real detector's output vocabulary", () => {
    // One synthetic file per shipped class — if a taxonomy string here drifts from
    // detectHandrolledFindings' output, the CLI would silently tally zeros for shipped classes.
    const files = [
      { path: "package.json", text: JSON.stringify({ dependencies: { clsx: "^2.0.0" } }) },
      {
        path: "src/all-shipped.tsx",
        text: [
          "const same = JSON.stringify(a) === JSON.stringify(b);",
          "const id = Math.random().toString(36);",
          'const pairs = qs.split("&").map((p) => p.split("="));',
          'const jar = document.cookie.split("; ");',
          'export const El = () => <div className={[a, b].filter(Boolean).join(" ")} />;',
        ].join("\n"),
      },
    ];
    const emitted = new Set(detectHandrolledFindings(files).map((f) => f.taxonomy));
    for (const s of SHIPPED_SHAPES) expect(emitted, s.taxonomy).toContain(s.taxonomy);
  });
});
