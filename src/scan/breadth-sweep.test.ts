import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
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

// The manifest invariants above hold the line at the INPUT. Until now nothing held it at the
// OUTPUT: the runner stamps every artifact `graded: false` and nothing would have caught that
// stamp being dropped, so a committed sweep artifact could have come to read exactly like a
// scored corpus result. These assert the envelope on the artifacts as committed.
const ungradedDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "breadth-sweep", "ungraded");

// Memoized: each artifact is asserted against several times and the raw findings arrays are large.
const envelopes = new Map<string, Record<string, unknown>>();
function readEnvelope(file: string): Record<string, unknown> {
  let env = envelopes.get(file);
  if (!env) {
    const raw = file.endsWith(".gz") ? gunzipSync(readFileSync(join(ungradedDir, file))).toString() : readFileSync(join(ungradedDir, file), "utf8");
    env = JSON.parse(raw) as Record<string, unknown>;
    delete env.findings; // the raw findings array is large and nothing here asserts against it
    envelopes.set(file, env);
  }
  return env;
}

describe("committed breadth-sweep artifacts are ungraded on their face", () => {
  const files = readdirSync(ungradedDir).filter((f) => f.endsWith(".json.gz") || f === "INDEX.json");

  // A zero-file glob passes every assertion below vacuously — the same shape as a fixture the
  // scanner never read reporting zero findings. Assert the population first.
  it("has an artifact for every manifest target, plus the index", () => {
    expect(files).toContain("INDEX.json");
    for (const t of BREADTH_SWEEP) expect(files, `no artifact for ${t.slug}`).toContain(`${t.slug}.json.gz`);
  });

  it.each(files)("%s is stamped graded:false and warns in its own body", (file) => {
    const env = readEnvelope(file);
    expect(env.graded, `${file} must carry graded:false — an artifact with no stamp reads as scored`).toBe(false);
    expect(String(env.warning), `${file} warning must name itself UNGRADED`).toContain("UNGRADED");
  });

  it.each(files)("%s carries no field a scorer could read as a baseline", (file) => {
    // The artifact mirror of the manifest's forbidden-key list. `total`/`counted` are the graded
    // corpus's scoring pair; `totalFindings` is a raw emission count and is deliberately allowed.
    const forbidden = ["counted", "total", "baseline", "expected", "score", "mutationScore", "recall", "precision"];
    for (const key of forbidden) {
      expect(Object.keys(readEnvelope(file)), `${file} must not carry "${key}"`).not.toContain(key);
    }
  });

  it.each(files.filter((f) => f !== "INDEX.json"))("%s lists the tiers it did not run", (file) => {
    const env = readEnvelope(file);
    if (env.status === "dropped") return; // a dropped target ran no tier at all; its reason is the disclosure
    expect(Array.isArray(env.notRunTiers) && (env.notRunTiers as unknown[]).length, `${file}: an absent module must read as "not run here", never as clean`).toBeGreaterThan(0);
  });
});
