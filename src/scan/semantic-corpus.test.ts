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

  it("matches an any-of list of all-of mechanism concepts without treating the location as evidence", () => {
    const t = target({
      entries: [{
        id: "A",
        kind: "positive",
        cls: "browser credential",
        locations: ["lib/openai.ts"],
        match: [],
        matchAll: [["openai", "browser", "key"], ["openai", "client", "credential"]],
        note: "",
      }],
      recordedCaught: 1,
    });
    expect(scoreSemanticPass(t, [finding("lib/openai.ts:9", "Browser bundles an OpenAI API key")]).positivesCaught).toBe(1);
    expect(scoreSemanticPass(t, [finding("lib/openai.ts:9", "Browser invokes OpenAI")]).positivesCaught).toBe(0);

    const locationOnly = target({
      entries: [{ id: "A", kind: "positive", cls: "jwt", locations: ["lib/jwt.ts"], match: ["jwt"], note: "" }],
      recordedCaught: 1,
    });
    expect(scoreSemanticPass(locationOnly, [finding("lib/jwt.ts:9", "Missing expiry")]).positivesCaught).toBe(0);
  });

  it("scores the fresh Nocode mechanisms without turning one shared finding into two findings", () => {
    const t = SEMANTIC_CORPUS.find((candidate) => candidate.slug === "nocode-rescue")!;
    const result = scoreSemanticPass(t, [
      finding("schema.sql:4", "Missing RLS leaves all multi-tenant tables exposed"),
      finding(
        "src/lib/ai.ts:9",
        "VITE OpenAI key is shipped to every browser",
        "VITE_OPENAI_API_KEY is supplied to a browser-enabled OpenAI client",
      ),
      finding(
        "src/pages/Dashboard.tsx:14",
        "Client-controlled localStorage values define identity, tenant, and admin authority",
        "localStorage controls user identity, workspace, role, and admin authority",
      ),
      finding("src/pages/Dashboard.tsx:61", "Ticket body is rendered through dangerouslySetInnerHTML"),
    ]);
    expect(result.positivesCaught).toBe(5);
    expect(result.sharedFindings).toBe(1);
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
    const cases: Array<[string, string, string, string]> = [
      ["nocode-rescue", "src/lib/ai.ts:8", "Prompt injection reaches the browser OpenAI request", "NR-2"],
      ["nocode-rescue", "src/pages/Dashboard.tsx:14", "Admin role is stored in localStorage", "NR-4"],
      ["nocode-rescue", "src/pages/Dashboard.tsx:14", "Authentication trusts localStorage identity", "NR-5"],
      ["superredhat", "lib/supabaseAdmin.ts:15", "A synthetic placeholder credential is committed", "F-01"],
      ["superredhat", "app/api/notes/[id]/route.ts:20", "Mass assignment changes note ownership", "F-03"],
      ["superredhat", "app/api/admin/users/route.ts:7", "Authorization header is parsed", "F-04"],
      ["superredhat", "lib/jwt.ts:6", "JWT lacks expiry but uses a deployment secret", "F-09"],
      ["supatest", "supabase/migrations/0001.sql:53", "Tautological profile UPDATE policy", "F1"],
      ["supatest", "supabase/migrations/0001.sql:76", "Tautological article UPDATE policy", "F2"],
      ["supatest", "supabase/migrations/0001.sql:90", "SECURITY DEFINER deletes audit rows", "F5"],
      ["supatest", "supabase/migrations/0001.sql:68", "Article policy exposes public content", "F9"],
      ["cipherx", ".env:2", "An anonymous JWT is committed for the public browser client", "CX-02"],
      ["cipherx", "src/app/api/internal/users/route.ts:8", "A cache response header leaks metadata", "CX-15"],
      ["cipherx", "supabase/migrations/20260101000005_spec_buckets_and_rpc.sql:104", "plpgsql SQL injection through EXECUTE", "CX-10"],
    ];
    expect(cases).toHaveLength(14);
    for (const [slug, location, title, id] of cases) score(slug, finding(location, title), id);
  });

  it("matches retained mechanisms when a fresh reviewer changes phrase order", () => {
    const cases: Array<[string, string, string, string]> = [
      ["superredhat", "lib/jwt.ts:6", "Application sessions can be forged because JWT verification uses a secret literal as a public fallback", "F-09"],
      ["supatest", "supabase/migrations/0001.sql:76", "The RLS policy on article rows permits UPDATE for every caller", "F1"],
      ["supatest", "supabase/migrations/0001.sql:81", "The RLS policy permits DELETE of any article", "F2"],
      ["supatest", "supabase/migrations/0001.sql:90", "A SECURITY DEFINER function returns profile email to any RPC caller", "F5"],
      ["supatest", "supabase/migrations/0001.sql:53", "The profile policy permits UPDATE and exposes email", "F9"],
      ["cipherx", "public/accounts.txt:1", "Public files disclose seeded account usernames and passwords", "CX-01"],
      ["cipherx", "public/backup.env:1", "A backup configuration file is served from the public web root", "CX-04"],
      ["cipherx", "storage_buckets.sql:8", "The storage backup bucket is readable by public clients", "CX-10"],
      ["cipherx", "spec_buckets_and_rpc.sql:104", "Caller input reaches dynamic SQL and creates SQL injection", "CX-12"],
      ["cipherx", "src/app/api/internal/users/route.ts:8", "A role header authorizes a service role client to dump secrets", "CX-15"],
      ["cipherx", "src/app/api/debug/route.ts:8", "The public debug response returns environment data and a live stack", "CX-18"],
    ];
    expect(cases).toHaveLength(11);
    for (const [slug, location, title, id] of cases) {
      const corpusTarget = SEMANTIC_CORPUS.find((entry) => entry.slug === slug)!;
      expect(scoreSemanticPass(corpusTarget, [finding(location, title)]).rows.find((row) => row.id === id)?.pass).toBe(true);
    }
  });

  it("scores the fresh CipherX anchors without accepting adjacent mechanisms", () => {
    const corpusTarget = SEMANTIC_CORPUS.find((entry) => entry.slug === "cipherx")!;
    const cases: Array<[string, string, string]> = [
      ["public/.htaccess:14", "Backup artifacts are served publicly with an admin account password", "CX-01"],
      ["src/app/api/search/route.ts:15", "Anonymous search invokes search_lab_data", "CX-24"],
      ["src/app/api/invoices/[id]/route.ts:21", "Triage duplicate: invoice RPC procedures bypass tenant ownership", "CX-26"],
      ["supabase/migrations/20260101000005_spec_buckets_and_rpc.sql:63", "Debug invoice RPC discloses another tenant's bill", "CX-27"],
      ["supabase/migrations/20260101000004_fix_auth_trigger.sql:10", "Signup trigger persists caller-controlled role metadata", "CX-28"],
    ];
    for (const [location, title, id] of cases) {
      expect(scoreSemanticPass(corpusTarget, [finding(location, title)]).rows.find((row) => row.id === id)?.pass).toBe(true);
    }

    const wrongMechanisms: Array<[string, string, string]> = [
      ["public/.htaccess:14", "Admin account password policy is documented for operators", "CX-01"],
      ["src/app/api/search/route.ts:15", "Search response has no pagination", "CX-24"],
      ["src/app/api/invoices/[id]/route.ts:21", "Invoice route omits a tenant predicate", "CX-26"],
      ["supabase/migrations/20260101000005_spec_buckets_and_rpc.sql:63", "Invoice table has an unbounded query", "CX-27"],
      ["supabase/migrations/20260101000004_fix_auth_trigger.sql:10", "Signup trigger omits an audit timestamp", "CX-28"],
    ];
    for (const [location, title, id] of wrongMechanisms) {
      expect(scoreSemanticPass(corpusTarget, [finding(location, title)]).rows.find((row) => row.id === id)?.pass).toBe(false);
    }
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
        expect(e.match.length + (e.matchAll?.flat().length ?? 0), `${t.slug}/${e.id} has no mechanism keyword`).toBeGreaterThan(0);
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
