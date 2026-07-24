import { describe, expect, it } from "vitest";
import { BREADTH_SWEEP } from "./breadth-sweep.js";
import { EXTERNAL_CORPUS } from "./external-corpus.js";

// The crux of #899/#900: the ungraded breadth tier must be structurally impossible to confuse with
// the graded corpus. These invariants hold that line at the manifest level — a BreadthTarget has
// nowhere to write a number a scorer could grade, and no target lives in both tiers.
describe("breadth-sweep manifest is ungraded by construction", () => {
  it("carries no baseline/scoring field on any target", () => {
    // If any of these ever appears, the target belongs in external-corpus.ts under corpus-drift —
    // the whole point of this tier is that it holds NO gradeable number.
    const forbidden = ["modules", "counted", "total", "mutationScore", "M8", "securityVerdict"];
    for (const t of BREADTH_SWEEP) {
      for (const key of forbidden) {
        expect(Object.keys(t), `${t.slug} must not carry "${key}" (that is a graded-corpus field)`).not.toContain(key);
      }
    }
  });

  it("shares no slug or repo with the graded corpus — a target is graded XOR ungraded, never both", () => {
    const gradedSlugs = new Set(EXTERNAL_CORPUS.map((t) => t.slug));
    const gradedRepos = new Set(EXTERNAL_CORPUS.map((t) => t.repo));
    for (const t of BREADTH_SWEEP) {
      expect(gradedSlugs, `${t.slug} is in both tiers`).not.toContain(t.slug);
      expect(gradedRepos, `${t.repo} is in both tiers`).not.toContain(t.repo);
    }
  });

  it("pins every target to a resolved 40-char commit with a bucket and licence", () => {
    const slugs = new Set<string>();
    for (const t of BREADTH_SWEEP) {
      expect(t.commit, `${t.slug} pin`).toMatch(/^[0-9a-f]{40}$/);
      expect(t.repo, `${t.slug} repo`).toMatch(/^[^/]+\/[^/]+$/);
      expect(["supabase", "prisma"]).toContain(t.bucket);
      expect(t.license.length, `${t.slug} licence`).toBeGreaterThan(0);
      expect(slugs.has(t.slug), `duplicate slug ${t.slug}`).toBe(false);
      slugs.add(t.slug);
    }
  });
});
