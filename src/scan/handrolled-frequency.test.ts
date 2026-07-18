// Guards the frequency signatures (#406 item 1): every measured shape must count its own
// canonical example. A signature that cannot match its own example would report an
// honest-looking zero on the corpus — a junk count wearing the costume of a measurement.

import { describe, expect, it } from "vitest";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";
import { AI_FREQUENCY_CORPUS, MEASURED_SHAPES, SHIPPED_SHAPES, UNMEASURED_SHAPES } from "./handrolled-frequency.js";

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

  it("AI frequency targets are pinned to a full 40-hex commit and never duplicate a corpus slug", () => {
    const corpusSlugs = new Set(EXTERNAL_CORPUS.map((t) => t.slug));
    for (const t of AI_FREQUENCY_CORPUS) {
      expect(t.commit, t.slug).toMatch(/^[0-9a-f]{40}$/);
      expect(corpusSlugs.has(t.slug), t.slug).toBe(false);
    }
  });

  it("has at least one genuinely AI-generated repo to answer the #413 question", () => {
    expect(AI_FREQUENCY_CORPUS.some((t) => t.provenance === "ai-generated" && !t.curated)).toBe(true);
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
