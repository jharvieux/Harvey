import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { SEMANTIC_CORPUS } from "./semantic-corpus.js";
import {
  FREE_RECALL_CORPUS,
  scoreFreeRecall,
  summarizeFreeRecall,
  unscoredFreeTarget,
  type FreeRecallTarget,
} from "./free-recall-corpus.js";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "X-1",
    title: "t",
    severity: "High",
    confidence: "Likely",
    category: "c",
    taxonomy: "tax",
    location: "app/api/thing/route.ts:1",
    status: "Open",
    evidence: "e",
    impact: "i",
    fix: "f",
    value: 3,
    ease: 3,
    safety: 3,
    ...over,
  } as Finding;
}

const target: FreeRecallTarget = {
  slug: "t",
  repo: "o/r",
  ref: "main",
  source: "docs/design/x.md",
  recordedMechanicalOn: "2026-01-01",
  recordedMechanical: 1,
  recordedMechanicalTotal: 2,
  entries: [
    { id: "P1", kind: "positive", cls: "ssrf", locations: ["lib/fetchUrl.ts"], match: ["ssrf"], note: "" },
    { id: "P2", kind: "positive", cls: "xss", locations: ["app/notes/page.tsx"], match: ["xss"], note: "" },
    { id: "N1", kind: "negative", cls: "anon key is public by design", locations: ["lib/client.ts"], match: ["exposed secret"], note: "" },
  ],
};

describe("scoreFreeRecall", () => {
  it("separates the free-count tier from the any-tier indicator count — the split the free tier is sold on", () => {
    const r = scoreFreeRecall(target, [
      finding({ location: "lib/fetchUrl.ts:4", evidence: "SSRF reachable", precisionTier: "high" }),
      finding({ location: "app/notes/page.tsx:9", evidence: "stored XSS", precisionTier: "review" }),
    ]);
    expect(r.caughtHigh).toBe(1);
    expect(r.caughtAnyTier).toBe(2);
    expect(r.rows.find((x) => x.id === "P2")?.tier).toBe("review");
  });

  it("scores an untiered finding as no catch rather than as a free-count hit", () => {
    // A detector that forgot precisionTier must not be silently promoted into the number the free
    // scan grades — the same rule calibration.ts enforces for the mechanical corpus.
    const r = scoreFreeRecall(target, [finding({ location: "lib/fetchUrl.ts:4", evidence: "SSRF reachable" })]);
    expect(r.caughtHigh).toBe(0);
    expect(r.caughtAnyTier).toBe(0);
  });

  it("fails the matrix when a free-count finding lands on a recorded non-vulnerability", () => {
    const r = scoreFreeRecall(target, [finding({ location: "lib/client.ts:2", evidence: "exposed secret in the browser client", precisionTier: "high" })]);
    expect(r.negativesFalsePositiveHigh).toEqual(["N1"]);
    expect(summarizeFreeRecall([r]).ok).toBe(false);
  });

  it("clears a negative that draws only a review-tier touch", () => {
    const r = scoreFreeRecall(target, [finding({ location: "lib/client.ts:2", evidence: "exposed secret in the browser client", precisionTier: "review" })]);
    expect(r.negativesCleared).toBe(1);
    expect(summarizeFreeRecall([r]).ok).toBe(true);
  });

  it("counts a finding that satisfies two entries, so a generous match cannot hide inside the recall number", () => {
    const t: FreeRecallTarget = { ...target, entries: [target.entries[0]!, { ...target.entries[0]!, id: "P1b" }] };
    const r = scoreFreeRecall(t, [finding({ location: "lib/fetchUrl.ts:4", evidence: "SSRF reachable", precisionTier: "high" })]);
    expect(r.caughtHigh).toBe(2);
    expect(r.sharedFindings).toBe(1);
  });

  it("uses the same all-token mechanism matcher as the semantic scorer", () => {
    const grouped: FreeRecallTarget = {
      ...target,
      recordedMechanical: 1,
      recordedMechanicalTotal: 1,
      entries: [{
        id: "P",
        kind: "positive",
        cls: "browser credential",
        locations: ["lib/openai.ts"],
        match: [],
        matchAll: [["openai", "browser", "key"]],
        note: "",
      }],
    };
    const right = finding({ location: "lib/openai.ts:9", evidence: "The OpenAI key is bundled for browser use", precisionTier: "high" });
    const partial = finding({ location: "lib/openai.ts:9", evidence: "The browser invokes OpenAI", precisionTier: "high" });
    expect(scoreFreeRecall(grouped, [right]).caughtHigh).toBe(1);
    expect(scoreFreeRecall(grouped, [partial]).caughtHigh).toBe(0);
  });
});

describe("the not-scored row", () => {
  it("carries its reason and keeps its positives out of the measured denominator", () => {
    const unscored = unscoredFreeTarget(target, "no clone");
    const scored = scoreFreeRecall(target, [finding({ location: "lib/fetchUrl.ts:4", evidence: "SSRF reachable", precisionTier: "high" })]);
    const m = summarizeFreeRecall([unscored, scored]);
    expect(unscored.reason).toBe("no clone");
    expect(m.unscoredTargets).toBe(1);
    // 2 positives from the scored target only — not 4. An unscanned target reports zero exactly
    // like a scanned one that missed everything, so it must not sit in the denominator.
    expect(m.positivesTotal).toBe(2);
  });

  it("refuses to exit clean when nothing at all could be scored", () => {
    expect(summarizeFreeRecall([unscoredFreeTarget(target, "no clone")]).ok).toBe(false);
  });
});

describe("the corpus itself", () => {
  it("covers every semantic-corpus target plus vandyand, so the free and paid columns score the same rows", () => {
    const slugs = FREE_RECALL_CORPUS.map((t) => t.slug).sort();
    expect(slugs).toEqual([...SEMANTIC_CORPUS.map((t) => t.slug), "vandyand"].sort());
  });

  it("carries a recorded mechanical baseline and a source doc for every target", () => {
    for (const t of FREE_RECALL_CORPUS) {
      expect(t.source, t.slug).toMatch(/^docs\/design\/.+\.md$/);
      expect(t.recordedMechanicalOn, t.slug).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(t.recordedMechanicalTotal, t.slug).toBeGreaterThan(0);
      expect(t.recordedMechanical, t.slug).toBeLessThanOrEqual(t.recordedMechanicalTotal);
    }
  });

  it("keeps a historical baseline's denominator separate from the reconciled live key", () => {
    const target = FREE_RECALL_CORPUS.find((t) => t.slug === "superredhat")!;
    expect(target.entries.filter((entry) => entry.kind === "positive")).toHaveLength(9);
    expect([target.recordedMechanical, target.recordedMechanicalTotal]).toEqual([11, 12]);
  });

  // #1355's vacuous-key rule USED to be checked here, and only here, for both this corpus and the
  // semantic one — coverage by coincidence, since FREE_RECALL_CORPUS happens to contain all four
  // semantic targets. #1560 moved it to src/scan/match-keyed-corpora.test.ts, over a registry that
  // is discovery-backed, so no corpus depends on being a member of this list to be swept. It is NOT
  // duplicated here: two copies of one rule drift, and the registry venue is the one that can say
  // what it did not read.
});
