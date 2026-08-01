// #1560 — #1355's vacuous-key rule, held over the SHAPE rather than over `CorpusEntry`.
//
// The check that used to live in free-recall-corpus.test.ts is here instead, and it is not a move
// for tidiness: that venue swept FREE_RECALL_CORPUS, which contains all four semantic targets by
// coincidence, so a semantic target that never joined the free-recall list would have been unswept
// with no venue able to say so. The registry is the population now, and the discovery check below
// is what keeps the registry honest.

import { describe, expect, it } from "vitest";
import { allSelfMatchingKeys, matchKeyedCorpora, undeclaredMatchKeyedShapes, type MatchKeyedCorpus } from "./match-keyed-corpora.js";
import { formatSelfMatchingKeys, selfMatchingKeys, type MatchKeyedRow } from "./calibration.js";

const vacuous = (over: Partial<MatchKeyedRow> = {}): MatchKeyedRow => ({ id: "PLANTED", kind: "positive", locations: ["lib/jwt.ts"], match: ["jwt"], ...over });

describe("#1560 every match-keyed corpus is swept for self-matching keys", () => {
  it("has none, across every registered corpus — and each corpus reports how many rows it scored", () => {
    const swept = allSelfMatchingKeys();
    // A corpus that quietly emptied would otherwise report the same clean zero as one that was read.
    for (const c of swept) expect(c.scanned, `${c.label} scored no rows at all`).toBeGreaterThan(0);
    expect(swept.flatMap((c) => c.rows.map((r) => `${c.label} ${formatSelfMatchingKeys([r])}`))).toEqual([]);
  });

  it("registers CORPUS, SEMANTIC_CORPUS and FREE_RECALL_CORPUS — the semantic one is the whole point of #1560", () => {
    expect(matchKeyedCorpora().map((c) => c.source)).toContain("src/scan/semantic-corpus.ts");
  });

  // The failing direction, exercised through the SHIPPING call site (allSelfMatchingKeys), not
  // through the primitive: a registry that stopped flattening a corpus's rows would leave the
  // primitive's own test green.
  it("NEGATIVE CONTROL — a vacuous key planted in ANY registered corpus is reported, in the multi-location form only SemanticEntry has", () => {
    for (const target of matchKeyedCorpora()) {
      const seeded: MatchKeyedCorpus[] = matchKeyedCorpora().map((c) => (c.label === target.label ? { ...c, rows: [...c.rows, vacuous()] } : c));
      const rows = allSelfMatchingKeys(seeded).find((c) => c.label === target.label)?.rows ?? [];
      expect(rows.map((r) => r.id), `${target.label} did not report a planted vacuous key`).toEqual(["PLANTED"]);
    }
    // A SemanticEntry pins a finding to ANY of several locations, so a key vacuous against just one
    // of them is vacuous for that whole entry. Checking only locations[0] would have missed
    // cipherx/CX-10, whose "bucket"/"storage" keys sit against its second location.
    const multi = selfMatchingKeys([vacuous({ locations: ["supabase/migrations", "lib/cors.ts"], match: ["cors"] })]);
    expect(multi[0]?.location).toBe("lib/cors.ts");
    expect(multi[0]?.keys).toEqual(["cors"]);
  });

  it("is silent on a key that names the MECHANISM rather than the path — the state every entry is supposed to be in", () => {
    expect(selfMatchingKeys([vacuous({ match: ["algorithm", "expiry"] })])).toEqual([]);
  });
});

describe("#1560 the registry is discovery-backed, so a third declaration of the shape cannot join the dark", () => {
  it("accounts for every source file declaring a `match: string[]` answer-key field", () => {
    // SemanticEntry was invisible for exactly this reason: nothing connected "a new interface with
    // location+keyword fields" to "the gate that sweeps them". This is that connection.
    expect(undeclaredMatchKeyedShapes()).toEqual([]);
  });
});
