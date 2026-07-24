import { describe, expect, it } from "vitest";
import { REAL_SOURCE_RECALL_TARGETS, mergeRealSourceRecall, scoreRealSourceRecallTarget } from "./real-source-recall.js";
import type { Finding } from "../findings.js";

// The live number (clone each pin, scan, score) is the CLI's job (validate-source-recall.ts --real,
// #960) — the same offline/binary/network split every other corpus in this repo uses. This suite
// proves the answer-key shape and the scoring/aggregation wiring, which CI can hold with no network.

function finding(over: Partial<Finding>): Finding {
  return {
    id: "F", title: "", severity: "High", confidence: "Confirmed", category: "", taxonomy: "",
    location: "", status: "Open", evidence: "", impact: "", fix: "", value: 3, ease: 3, safety: 3,
    mechanical: true, ...over,
  } as Finding;
}

describe("real-source-recall answer key (#960)", () => {
  it("names one already-disclosed vulnerability per pinned repo, each with a location and its disclosure issue", () => {
    expect(REAL_SOURCE_RECALL_TARGETS.length).toBeGreaterThanOrEqual(3);
    for (const target of REAL_SOURCE_RECALL_TARGETS) {
      expect(target.repo).toMatch(/^[\w.-]+\/[\w.-]+$/);
      expect(target.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(target.disclosureIssue).toBeGreaterThan(0);
      expect(target.entries.length).toBeGreaterThan(0);
      for (const e of target.entries) {
        expect(e.kind).toBe("positive");
        expect(e.location.length).toBeGreaterThan(0);
      }
    }
  });

  it("every entry id is unique across targets (no accidental collision when aggregated)", () => {
    const ids = REAL_SOURCE_RECALL_TARGETS.flatMap((t) => t.entries.map((e) => e.id));
    expect(new Set(ids).size).toBe(ids.length);
  });
});

function targetBySlug(slug: string) {
  const t = REAL_SOURCE_RECALL_TARGETS.find((t) => t.slug === slug);
  if (!t) throw new Error(`no real-source-recall target named ${slug}`);
  return t;
}

describe("real-source-recall scoring (#960)", () => {
  it("scores a target's own entries against its own scan output, independent of other targets", () => {
    const proposit = targetBySlug("proposit");
    const clean: Finding[] = []; // MEASURED 2026-07-24: currently uncaught on the real clone
    const matrix = scoreRealSourceRecallTarget(clean, proposit);
    expect(matrix.positivesTotal).toBe(proposit.entries.length);
    expect(matrix.positivesCaught).toBe(0);
  });

  it("registers a caught positive when a relevant finding lands on the entry's location", () => {
    const proposit = targetBySlug("proposit");
    const hit: Finding[] = [
      finding({ location: "lib/actions/invitation-actions.ts:42", taxonomy: "bola-owner", precisionTier: "review" }),
    ];
    const matrix = scoreRealSourceRecallTarget(hit, proposit);
    expect(matrix.positivesCaught).toBe(1);
  });

  it("aggregates per-target matrices by SUMMING confusion counts, not averaging percentages", () => {
    const proposit = targetBySlug("proposit");
    const saasLite = targetBySlug("saas-lite");
    const propositMatrix = scoreRealSourceRecallTarget(
      [finding({ location: "lib/actions/invitation-actions.ts:42", taxonomy: "bola-owner", precisionTier: "review" })],
      proposit,
    );
    const saasLiteMatrix = scoreRealSourceRecallTarget([], saasLite); // stays uncaught
    const merged = mergeRealSourceRecall([propositMatrix, saasLiteMatrix]);
    expect(merged.positivesTotal).toBe(propositMatrix.positivesTotal + saasLiteMatrix.positivesTotal);
    expect(merged.positivesCaught).toBe(1);
    expect(merged.metrics.tp).toBe(1);
    expect(merged.metrics.fn).toBe(merged.positivesTotal - 1);
  });
});
