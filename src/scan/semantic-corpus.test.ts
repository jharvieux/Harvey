// #870 — the semantic recall gate's scoring logic, held to the two things it exists to guarantee:
// a regression below a recorded baseline fails, and a pass that DIDN'T RUN never reads as a pass.

import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import {
  SEMANTIC_CORPUS,
  loadSemanticPass,
  scoreSemanticPass,
  summarizeSemantic,
  unscoredTarget,
  type SemanticTarget,
} from "./semantic-corpus.js";

const NOW = Date.parse("2026-07-23T12:00:00Z");
const FRESH = "2026-07-22T12:00:00Z";

function finding(location: string, title: string, evidence = ""): Finding {
  return {
    id: "SEM-01",
    title,
    severity: "High",
    confidence: "Likely",
    category: "Security",
    taxonomy: "M1 — Multi-tenant security",
    location,
    status: "Open",
    evidence,
    impact: "",
    fix: "",
    value: 4,
    ease: 3,
    safety: 4,
  };
}

const target = (over: Partial<SemanticTarget> = {}): SemanticTarget => ({
  slug: "t",
  repo: "o/t",
  ref: "main",
  source: "docs/design/x.md",
  recordedOn: "2026-07-18",
  recordedCaught: 2,
  entries: [
    { id: "A", kind: "positive", cls: "idor", locations: ["api/notes/route.ts"], match: ["idor", "ownership"], note: "" },
    { id: "B", kind: "positive", cls: "xss", locations: ["app/page.tsx"], match: ["xss"], note: "" },
    { id: "N", kind: "negative", cls: "mock cve list", locations: ["api/deps/route.ts"], match: ["dependency"], note: "" },
  ],
  ...over,
});

describe("scoreSemanticPass", () => {
  it("credits a planted finding only when the MECHANISM matches, not merely the file", () => {
    const t = target();
    const wrongMechanism = scoreSemanticPass(t, [finding("api/notes/route.ts", "Unbounded select on the notes list")]);
    expect(wrongMechanism.rows.find((r) => r.id === "A")?.pass).toBe(false);

    const rightMechanism = scoreSemanticPass(t, [finding("api/notes/route.ts", "IDOR — no ownership predicate")]);
    expect(rightMechanism.rows.find((r) => r.id === "A")?.pass).toBe(true);
  });

  it("fails the target when recall drops below the recorded baseline", () => {
    const t = target();
    const both = scoreSemanticPass(t, [
      finding("api/notes/route.ts", "IDOR — no ownership predicate"),
      finding("app/page.tsx", "Stored XSS"),
    ]);
    expect(both.positivesCaught).toBe(2);
    expect(both.regressed).toBe(false);
    expect(summarizeSemantic([both]).ok).toBe(true);

    const degraded = scoreSemanticPass(t, [finding("app/page.tsx", "Stored XSS")]);
    expect(degraded.positivesCaught).toBe(1);
    expect(degraded.regressed).toBe(true);
    expect(summarizeSemantic([degraded]).ok).toBe(false);
  });

  it("fails when the pass reports a recorded non-vulnerability", () => {
    const t = target();
    const fp = scoreSemanticPass(t, [
      finding("api/notes/route.ts", "IDOR — no ownership predicate"),
      finding("app/page.tsx", "Stored XSS"),
      finding("api/deps/route.ts", "Known-vulnerable dependency reported by this endpoint"),
    ]);
    expect(fp.negativesCleared).toBe(0);
    expect(summarizeSemantic([fp]).ok).toBe(false);
  });

  it("counts findings that satisfied more than one entry, so a generous match cannot inflate recall unremarked", () => {
    const t = target({
      entries: [
        { id: "A", kind: "positive", cls: "update tautology", locations: ["migrations"], match: ["update"], note: "" },
        { id: "B", kind: "positive", cls: "delete tautology", locations: ["migrations"], match: ["delete"], note: "" },
      ],
      recordedCaught: 2,
    });
    const one = scoreSemanticPass(t, [finding("supabase/migrations/0001.sql", "Tautological UPDATE and DELETE policies")]);
    expect(one.positivesCaught).toBe(2);
    expect(one.sharedFindings).toBe(1);
  });
});

describe("loadSemanticPass — a pass that did not run must never score as one", () => {
  const t = target();

  it("reports a missing artifact with the command that would produce it", () => {
    const load = loadSemanticPass(undefined, t, "/a/t/M1.pass.json", NOW);
    expect(load.ok).toBe(false);
    expect(load.ok === false && load.reason).toContain("record-pass");
  });

  it("rejects a non-semantic pass — a mechanical dump cannot score the semantic tier", () => {
    const load = loadSemanticPass({ module: "M1", pass: "live", generatedAt: FRESH, findings: [] }, t, "/p", NOW);
    expect(load.ok).toBe(false);
    expect(load.ok === false && load.reason).toContain("no \"semantic\" one");
  });

  // #1522: the M1 slot accumulates, so the semantic pass may sit under a tier recorded later. Before
  // that, recording another tier deleted it and this gate reported the target unscored — the recall
  // number dropping because an operator recorded MORE.
  it("scores the semantic pass when a later tier was recorded on top of it", () => {
    const load = loadSemanticPass(
      {
        module: "M1",
        pass: "connected",
        generatedAt: FRESH,
        findings: [{ id: "SB-DRIFT-01" }],
        priorPasses: [{ module: "M1", pass: "semantic", target: "/clone", generatedAt: FRESH, findings: [] }],
      },
      t,
      "/p",
      NOW,
    );
    expect(load.ok).toBe(true);
    expect(load.ok === true && load.artifact.pass).toBe("semantic");
  });

  it("rejects a stale artifact", () => {
    const load = loadSemanticPass({ module: "M1", pass: "semantic", generatedAt: "2026-01-01T00:00:00Z", findings: [] }, t, "/p", NOW);
    expect(load.ok).toBe(false);
    expect(load.ok === false && load.reason).toContain("stale");
  });

  it("rejects an artifact with no findings array rather than scoring it as zero recall", () => {
    const load = loadSemanticPass({ module: "M1", pass: "semantic", generatedAt: FRESH }, t, "/p", NOW);
    expect(load.ok).toBe(false);
    expect(load.ok === false && load.reason).toContain("no findings array");
  });

  it("accepts a fresh, well-formed semantic pass", () => {
    const load = loadSemanticPass({ module: "M1", pass: "semantic", target: "/clone", generatedAt: FRESH, findings: [] }, t, "/p", NOW);
    expect(load.ok).toBe(true);
  });
});

describe("summarizeSemantic — an unscored target is reported, not dropped", () => {
  it("keeps a row for every corpus target and never counts an unscored one as a regression", () => {
    const t = target();
    const rows = [unscoredTarget(t, "no artifact")];
    const m = summarizeSemantic(rows);
    expect(m.targets).toHaveLength(1);
    expect(m.unscoredTargets).toBe(1);
    expect(m.targets[0]?.regressed).toBe(false);
    // The denominator is scored targets only — an unrun pass must not dilute a measured ratio.
    expect(m.positivesTotal).toBe(0);
  });

  it("fails when NOTHING could be scored — a gate that measured nothing has not passed", () => {
    expect(summarizeSemantic([unscoredTarget(target(), "no artifact")]).ok).toBe(false);
  });
});

describe("the shipped corpus", () => {
  it("locks the audited 35-positive key and all four precision negatives", () => {
    const expected = {
      "nocode-rescue": ["NR-2", "NR-3", "NR-4", "NR-5", "NR-6"],
      superredhat: ["F-01", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-09", "F-12"],
      supatest: ["F1", "F2", "F3", "F5", "F9"],
      cipherx: ["CX-01", "CX-02", "CX-04", "CX-10", "CX-12", "CX-15", "CX-16", "CX-17", "CX-18", "CX-23", "CX-24", "CX-25", "CX-26", "CX-27", "CX-28", "CX-29"],
    } as const;
    const expectedNegatives = {
      "nocode-rescue": [],
      superredhat: ["F-N1"],
      supatest: ["F-N1"],
      cipherx: ["CX-21", "CX-22"],
    } as const;
    const positives = SEMANTIC_CORPUS.flatMap((candidate) =>
      candidate.entries.filter((entry) => entry.kind === "positive"),
    );
    const negatives = SEMANTIC_CORPUS.flatMap((candidate) =>
      candidate.entries.filter((entry) => entry.kind === "negative"),
    );
    expect(positives).toHaveLength(35);
    expect(negatives).toHaveLength(4);
    for (const candidate of SEMANTIC_CORPUS) {
      expect(candidate.entries.filter((entry) => entry.kind === "positive").map((entry) => entry.id))
        .toEqual([...expected[candidate.slug as keyof typeof expected]]);
      expect(candidate.entries.filter((entry) => entry.kind === "negative").map((entry) => entry.id))
        .toEqual([...expectedNegatives[candidate.slug as keyof typeof expectedNegatives]]);
      expect(candidate.recordedCaught).toBe(expected[candidate.slug as keyof typeof expected].length);
    }
  });

  it("rejects audited right-file wrong-mechanism findings", () => {
    const score = (slug: string, candidate: Finding, id: string) => {
      const corpusTarget = SEMANTIC_CORPUS.find((entry) => entry.slug === slug);
      if (!corpusTarget) throw new Error(`missing semantic target ${slug}`);
      expect(scoreSemanticPass(corpusTarget, [candidate]).rows.find((row) => row.id === id)?.pass).toBe(false);
    };
    score("nocode-rescue", finding("src/lib/ai.ts:8", "Prompt injection reaches the OpenAI request"), "NR-2");
    score("nocode-rescue", finding("src/pages/Dashboard.tsx:14", "Authentication is enforced only in localStorage"), "NR-5");
    score("superredhat", finding("lib/jwt.ts:6", "JWT lacks an explicit expiry but uses a deployment secret"), "F-09");
    score("supatest", finding("supabase/migrations/0001.sql:53", "Tautological profile UPDATE policy"), "F1");
    score("supatest", finding("supabase/migrations/0001.sql:76", "Tautological article UPDATE policy"), "F2");
    score("cipherx", finding("supabase/migrations/20260101000005_spec_buckets_and_rpc.sql:104", "plpgsql SQL injection through EXECUTE"), "CX-10");
    score("cipherx", finding("src/app/api/tickets/search/route.ts:10", "Reflected credentialed CORS"), "CX-17");
  });

  it("records a baseline no larger than the planted positives it is a baseline for", () => {
    for (const t of SEMANTIC_CORPUS) {
      const positives = t.entries.filter((e) => e.kind === "positive").length;
      expect(t.recordedCaught, `${t.slug} baseline exceeds its own answer key`).toBeLessThanOrEqual(positives);
    }
  });

  it("gives every entry both a location anchor and a mechanism keyword", () => {
    for (const t of SEMANTIC_CORPUS) {
      for (const e of t.entries) {
        expect(e.locations.length, `${t.slug}/${e.id} has no location anchor`).toBeGreaterThan(0);
        expect(e.match.length, `${t.slug}/${e.id} has no mechanism keyword`).toBeGreaterThan(0);
      }
    }
  });

  it("has unique target slugs and unique entry ids per target", () => {
    expect(new Set(SEMANTIC_CORPUS.map((t) => t.slug)).size).toBe(SEMANTIC_CORPUS.length);
    for (const t of SEMANTIC_CORPUS) {
      expect(new Set(t.entries.map((e) => e.id)).size, `${t.slug} has duplicate entry ids`).toBe(t.entries.length);
    }
  });
});
