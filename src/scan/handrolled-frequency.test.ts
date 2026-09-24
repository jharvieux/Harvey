// Guards the frequency signatures (#406 item 1): every measured shape must count its own
// canonical example. A signature that cannot match its own example would report an
// honest-looking zero on the corpus — a junk count wearing the costume of a measurement.

import { describe, expect, it } from "vitest";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";
import { AI_FREQUENCY_CORPUS, buildFrequencyTargets, MEASURED_SHAPES, SHIPPED_SHAPES, UNMEASURED_SHAPES } from "./handrolled-frequency.js";

describe("measured shapes count their canonical example", () => {
  // Expected counts are derived from the planted snippets below, not from each shape's regex. Two
  // examples intentionally contain two independent literal occurrences (18 and 65), which makes a
  // constant counter and an accidental duplicate observable rather than merely checking presence.
  const plantedCounts: Record<number, number> = {
    3: 1, 4: 1, 5: 1, 6: 1, 11: 1, 12: 1, 13: 1, 15: 1, 16: 1, 18: 2, 22: 1, 23: 1,
    24: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1, 34: 1, 35: 1, 37: 1, 39: 1, 40: 1,
    41: 1, 42: 1, 43: 1, 44: 1, 47: 1, 52: 1, 53: 1, 58: 1, 59: 1, 61: 1, 65: 2,
    66: 1, 67: 1, 68: 1, 69: 1, 72: 1, 76: 1, 81: 1, 83: 1, 88: 1, 89: 1, 90: 1,
    95: 1, 98: 1, 99: 1, 100: 1, 101: 1,
  };

  for (const shape of MEASURED_SHAPES) {
    it(`entry ${shape.entry} (${shape.name})`, () => {
      expect(shape.count({ path: shape.examplePath ?? "src/example.ts", text: shape.example })).toBeGreaterThanOrEqual(1);
    });
  }

  it("pins zero, single, and repeated production counts for every measured shape (#2103)", () => {
    for (const shape of MEASURED_SHAPES) {
      const path = shape.examplePath ?? "src/example.ts";
      const expected = plantedCounts[shape.entry];
      expect(expected, `missing planted count for ${shape.entry}`).toBeDefined();
      const exactExpected = expected!;
      expect(shape.count({ path, text: "export const unrelated = true;" }), `negative ${shape.entry}`).toBe(0);
      expect(shape.count({ path, text: shape.example }), `single ${shape.entry}`).toBe(exactExpected);
      if (shape.unit === "matches") {
        expect(shape.count({ path, text: `${shape.example}\n${shape.example}` }), `repeated ${shape.entry}`).toBe(exactExpected * 2);
      } else {
        expect(
          [
            { path, text: shape.example },
            { path: path === "middleware.ts" ? "apps/web/middleware.js" : `other/${path}`, text: shape.example },
          ].reduce((total, file) => total + shape.count(file), 0),
          `repeated files ${shape.entry}`,
        ).toBe(2);
      }
    }
  });

  it("path-scoped shapes stay silent off their path", () => {
    for (const shape of MEASURED_SHAPES.filter((s) => s.examplePath !== undefined)) {
      expect(shape.count({ path: "src/elsewhere.ts", text: shape.example })).toBe(0);
    }
  });

  it("keeps nearby filter syntax out of the unique-via-indexOf counter", () => {
    const unique = MEASURED_SHAPES.find((shape) => shape.entry === 3)!;
    expect(unique.count({ path: "src/nearby.ts", text: "const kept = arr.filter((value) => Boolean(value));" })).toBe(0);
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

    it("carries any captured-history disclosure through the overlap dedupe and binds it to the active snapshot", () => {
      for (const t of buildFrequencyTargets()) {
        if (!t.capturedHistory) continue;
        expect(t.repo, t.slug).toBe(t.capturedHistory.snapshotRepo);
        expect(t.commit, t.slug).toBe(t.capturedHistory.snapshotCommit);
        expect(t.capturedHistory.originalRepo, t.slug).not.toBe(t.repo);
        expect(t.capturedHistory.sourceRun, t.slug).toBeGreaterThan(0);
        expect(t.capturedHistory.census.commits, t.slug).toBeGreaterThan(0);
      }
      expect(buildFrequencyTargets().filter((t) => t.capturedHistory).map((t) => t.slug)).toContain("flori-web");
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
