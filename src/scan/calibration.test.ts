import { describe, expect, it } from "vitest";
import { buildCoverageMatrix, CORPUS, scoreEntry, type CorpusEntry } from "./calibration.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import { parseGitleaksFindings, type GitleaksResult } from "./secrets.js";
import type { Finding, PrecisionTier } from "../findings.js";

// Recorded-output helper: a minimal Finding mirroring what the scan modules emit, so these
// tests exercise the scorecard/mapping logic without invoking any external binary (the CI
// layer). Mirrors how src/scan/*.test.ts mock tool JSON.
function finding(partial: Partial<Finding> & { location: string; precisionTier: PrecisionTier }): Finding {
  return {
    id: "X", title: "", severity: "High", confidence: "Confirmed", category: "", taxonomy: "",
    status: "Open", evidence: "", impact: "", fix: "", value: 3, ease: 3, safety: 3,
    mechanical: true, ...partial,
  };
}

const entry = (o: Partial<CorpusEntry> & Pick<CorpusEntry, "id" | "kind" | "location" | "note" | "cls">): CorpusEntry => o;

describe("scoreEntry", () => {
  it("marks a positive caught when a relevant finding exists, recording its tier", () => {
    const e = entry({ id: "P-SQLI", kind: "positive", cls: "sqli", location: "search.js", match: ["sql"], expectedTier: "high", note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/api/search.js:11", taxonomy: "SQL injection", precisionTier: "high" })]);
    expect(row.pass).toBe(true);
    expect(row.caughtTier).toBe("high");
    expect(row.highFlagged).toBe(true);
  });

  it("marks a positive NOT caught when no relevant finding exists", () => {
    const e = entry({ id: "P-DEP", kind: "positive", cls: "dep", location: "lodash", match: ["lodash"], expectedTier: "review", note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/api/search.js:11", precisionTier: "high" })]);
    expect(row.pass).toBe(false);
    expect(row.caughtTier).toBeUndefined();
  });

  it("fails a negative that draws a HIGH-tier (free-count) finding", () => {
    const e = entry({ id: "N-PARAM", kind: "negative", cls: "param", location: "list.js", note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/api/list.js:8", taxonomy: "SQL injection", precisionTier: "high" })]);
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("FALSE POSITIVE");
  });

  it("clears a negative that only draws a review-tier finding (triaged out of the count)", () => {
    const e = entry({ id: "N-DSIH", kind: "negative", cls: "dsih", location: "about.js", note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/about.js:11", taxonomy: "audit dsih", precisionTier: "review" })]);
    expect(row.pass).toBe(true);
    expect(row.reviewFlagged).toBe(true);
  });

  it("keeps fixtures that share a file apart via match keywords (anon key vs. mis-prefixed secret)", () => {
    // Both live in .env.local; only the stripe secret is a finding. The anon-key negative must
    // stay clear, and the secret positive must be the one that matches.
    const stripe = finding({ location: "[source] .env.local:12", id: "SEC-GL-source-1", title: "NEXT_PUBLIC secret leak", taxonomy: "stripe", precisionTier: "review" });
    const anon = entry({ id: "N-ANON-KEY", kind: "negative", cls: "anon", location: ".env.local", match: ["anon"], note: "" });
    const secret = entry({ id: "P-NEXTPUBLIC", kind: "positive", cls: "secret", location: ".env.local", match: ["stripe", "secret"], expectedTier: "review", note: "" });
    expect(scoreEntry(anon, [stripe]).pass).toBe(true); // anon not mis-attributed the stripe hit
    expect(scoreEntry(anon, [stripe]).reviewFlagged).toBe(false);
    expect(scoreEntry(secret, [stripe]).pass).toBe(true);
  });

  it("reports a connected-tier entry as N/A, never a failure, even with no findings", () => {
    const e = entry({ id: "P-RLS", kind: "positive", cls: "rls", location: "audit_logs", expectedTier: "connected", note: "" });
    const row = scoreEntry(e, []);
    expect(row.pass).toBe(true);
    expect(row.detail).toContain("connected");
  });
});

describe("Batch B1 secrets corpus (recorded gitleaks output → tier mapping)", () => {
  // Recorded gitleaks findings mirroring the live `pnpm validate:calibration` run over
  // targets/calibration. Fed through the real secrets.ts tier mapping so this exercises which
  // rules are high-precision vs review, then scored against the B1 entries. No binary invoked.
  const gitleaks: GitleaksResult[] = [
    { RuleID: "supabase-service-role-jwt", File: "lib/admin.js", StartLine: 8, Match: '"role":"service_role"' },
    { RuleID: "supabase-secret-key", File: "lib/edge-config.js", StartLine: 4, Match: "sb_secret_Z9Qm2v" },
    { RuleID: "private-key", File: "certs/key.pem", StartLine: 1, Match: "-----BEGIN PRIVATE KEY-----" },
    { RuleID: "supabase-service-role-jwt", File: "prebuilt-bundle/chunk.4f2a.js", StartLine: 7, Match: '"role":"service_role"' },
    { RuleID: "harvey-db-uri-credentials", File: ".env.local", StartLine: 19, Match: "postgres://appuser:pw@db.calibrationref01.supabase.co" },
    // The 4 provider keys below are DEFANGED in the committed fixtures (real provider shapes trip
    // GitHub push protection), so the committed catch is generic-api-key with the provider word in
    // the var name; the match keyword resolves against that.
    { RuleID: "generic-api-key", File: "lib/llm.js", StartLine: 5, Match: 'OPENAI_API_KEY = "Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2"' },
    { RuleID: "generic-api-key", File: "lib/pay.js", StartLine: 4, Match: 'STRIPE_SECRET_KEY = "Rt7Yu1Ki5Op8Ld2Hj9Qw3Z9Qm2vXcW8rNpKdLhGfYsAe4"' },
    { RuleID: "generic-api-key", File: "lib/s3.js", StartLine: 5, Match: 'AWS_SECRET_ACCESS_KEY = "Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj4Gg1Fa9Sc0Rb5Tn3Uv8"' },
    { RuleID: "github-pat", File: "scripts/deploy.js", StartLine: 4, Match: "ghp_Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7N" },
    { RuleID: "generic-api-key", File: "lib/email.js", StartLine: 4, Match: 'SENDGRID_API_KEY = "Yl4ZpQaWsEdRfTgYhUjIkOlPzXcVbNmZ9Qm2vXcW8rNp"' },
    { RuleID: "generic-api-key", File: "lib/auth.js", StartLine: 7, Match: 'JWT_SIGNING_SECRET = "hs512_9QmZ2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj4Gg1Fa"' },
    // sk_test key trips stripe-access-token at review; the publishable line is gitleaks-allowlisted
    // (no finding); aws-setup.md and README.md are cleared, so they produce no rows here.
    { RuleID: "stripe-access-token", File: ".env.local", StartLine: 29, Match: "sk_test_51…" },
  ];
  const findings = parseGitleaksFindings(gitleaks, "source");

  it("catches every B1 positive at its declared tier and clears every B1 negative", () => {
    for (const e of secretsEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the ~100%-precision rules to the free count (5 high, 6 review)", () => {
    const m = buildCoverageMatrix(findings, secretsEntries);
    const positives = secretsEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(positives.filter((e) => e.expectedTier === "high").length);
    expect(m.positivesCaughtHigh).toBe(5);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});

describe("buildCoverageMatrix", () => {
  it("excludes connected-tier entries from the static positive/negative totals", () => {
    const m = buildCoverageMatrix([], CORPUS);
    const connected = CORPUS.filter((e) => e.expectedTier === "connected").length;
    expect(m.connectedNa).toBe(connected);
    expect(m.positivesTotal).toBe(CORPUS.filter((e) => e.kind === "positive" && e.expectedTier !== "connected").length);
    expect(m.negativesTotal).toBe(CORPUS.filter((e) => e.kind === "negative" && e.expectedTier !== "connected").length);
  });

  it("with zero findings: no positive is caught and every negative is cleared", () => {
    const m = buildCoverageMatrix([], CORPUS);
    expect(m.positivesCaught).toBe(0);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(false); // positives uncaught
  });

  it("ok is true only when every static positive is caught and every negative cleared", () => {
    // Synthesize one high-tier finding per static positive at its fixture location.
    const staticPositives = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier !== "connected");
    const synth: Finding[] = staticPositives.map((e) =>
      finding({ location: `${e.location}:1`, title: (e.match ?? [""])[0], taxonomy: (e.match ?? [""])[0], precisionTier: "high" }),
    );
    const m = buildCoverageMatrix(synth, CORPUS);
    expect(m.positivesCaught).toBe(m.positivesTotal);
    // Negatives whose location substring collides with a synthesized positive location would
    // fail here; assert none do (guards against ambiguous corpus locations).
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});
