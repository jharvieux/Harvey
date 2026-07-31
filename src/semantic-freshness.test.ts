import { describe, expect, it } from "vitest";
import { MAX_PASS_AGE_MS } from "./audit-pass-artifact.js";
import { SEMANTIC_CORPUS } from "./scan/semantic-corpus.js";
import { assessSemanticFreshness } from "./semantic-freshness.js";

// Anchored to the corpus's own oldest recorded date, so the tests move with the corpus instead of
// pinning a literal that a new target would silently invalidate.
const oldest = Math.min(...SEMANTIC_CORPUS.map((t) => Date.parse(t.recordedOn)));
const newest = Math.max(...SEMANTIC_CORPUS.map((t) => Date.parse(t.recordedOn)));
const DAY = 24 * 60 * 60 * 1000;

// An empty corpus would make every assertion in this file pass over zero rows. Throwing at load
// says so once, rather than leaving seven green tests that measured nothing.
const first = SEMANTIC_CORPUS[0];
if (!first) throw new Error("SEMANTIC_CORPUS is empty — every assertion in this file would be vacuous");

describe("assessSemanticFreshness", () => {
  it("has a population to measure — an empty corpus would make every assertion below vacuous", () => {
    expect(SEMANTIC_CORPUS.length).toBeGreaterThan(0);
  });

  it("reports every corpus target as fresh while the newest recorded date is inside the window", () => {
    const r = assessSemanticFreshness(oldest + 1 * DAY, {});
    expect(r.rows).toHaveLength(SEMANTIC_CORPUS.length);
    expect(r.stale).toEqual([]);
    expect(r.rows.every((row) => row.daysLeft > 0)).toBe(true);
  });

  // The failing direction. Without this the gate is one nobody has watched go red.
  it("reports every target STALE once the clock passes the window on the newest recorded date", () => {
    const r = assessSemanticFreshness(newest + MAX_PASS_AGE_MS + DAY, {});
    expect(r.stale).toHaveLength(SEMANTIC_CORPUS.length);
    expect(r.stale.every((row) => row.daysLeft < 0)).toBe(true);
  });

  it("goes stale exactly at the window boundary, not before it", () => {
        const at = Date.parse(first.recordedOn);
    const inside = assessSemanticFreshness(at + MAX_PASS_AGE_MS, {}).rows.find((r) => r.slug === first.slug);
    const outside = assessSemanticFreshness(at + MAX_PASS_AGE_MS + 1, {}).rows.find((r) => r.slug === first.slug);
    expect(inside?.stale).toBe(false);
    expect(outside?.stale).toBe(true);
  });

  it("prefers a recorded pass artifact over the corpus record, and counts the fallbacks", () => {
        const recent = new Date(newest + 10 * DAY).toISOString();
    const r = assessSemanticFreshness(newest + 11 * DAY, { [first.slug]: recent });
    const row = r.rows.find((x) => x.slug === first.slug);
    expect(row?.source).toBe("pass-artifact");
    expect(row?.ageDays).toBe(1);
    expect(r.withoutArtifact).toBe(SEMANTIC_CORPUS.length - 1);
  });

  // A fresh artifact must be able to RESCUE a target whose corpus record has aged out — otherwise
  // the alarm could never be cleared by doing the work it asks for, only by editing the corpus.
  it("a fresh pass artifact clears a target whose corpus record is already past the window", () => {
    const clock = newest + MAX_PASS_AGE_MS + 5 * DAY;
        const withoutArtifact = assessSemanticFreshness(clock, {}).rows.find((r) => r.slug === first.slug);
    const withArtifact = assessSemanticFreshness(clock, { [first.slug]: new Date(clock - DAY).toISOString() }).rows.find(
      (r) => r.slug === first.slug,
    );
    expect(withoutArtifact?.stale).toBe(true);
    expect(withArtifact?.stale).toBe(false);
  });

  it("treats an unparseable artifact date as absent rather than as never-stale NaN", () => {
        const r = assessSemanticFreshness(newest + MAX_PASS_AGE_MS + DAY, { [first.slug]: "not-a-date" });
    const row = r.rows.find((x) => x.slug === first.slug);
    expect(row?.source).toBe("corpus-record");
    expect(row?.stale).toBe(true);
  });
});
