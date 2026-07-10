import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildCoverageMatrix, CORPUS, scoreEntry, type CorpusEntry } from "./calibration.js";
import { b2DepsEntries } from "./calibration/b2-deps.entries.js";
import { b9SecretsEntries } from "./calibration/b9-secrets.entries.js";
import { b10DepsEntries } from "./calibration/b10-deps.entries.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs } from "./dependencies.js";
import { parseGitleaksFindings, type GitleaksResult } from "./secrets.js";
import { parseSemgrepFindings, type SemgrepResult } from "./semgrep.js";
import { checkKnownIoc, checkLockfilePresence } from "./supply-chain.js";
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

  it("does not let an environment-dependent checkout path leak a match keyword into the haystack (issue #86)", () => {
    // Mirrors the real B6 corpus entry: match keyword "decode" against jwt.decode()-for-authz.
    // The finding here is an UNRELATED header check on the same file, reported at an absolute
    // path under a fake checkout root ("/home/decodeproj/...") that happens to contain "decode"
    // as a substring. Scoring must not depend on where the repo was checked out — this must not
    // be scored as catching the jwt-decode-noverify positive.
    const e = entry({
      id: "P-JWT-DECODE-NOVERIFY", kind: "positive", cls: "jwt.decode() used for an authz decision",
      location: "middleware.ts", match: ["jwt-decode-noverify", "decode"], expectedTier: "review", note: "",
    });
    const unrelated = finding({
      location: "/home/decodeproj/checkout/targets/calibration/middleware.ts:5",
      title: "Missing X-Frame-Options", taxonomy: "missing security headers", precisionTier: "review",
    });
    const row = scoreEntry(e, [unrelated]);
    expect(row.pass).toBe(false);
    expect(row.caughtTier).toBeUndefined();
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

describe("Batch B2 deferred corpus (secondary manifest fixtures → real check output)", () => {
  // Reconstructs what validate-calibration.ts's scanManifestFixtures produces for the two fixture
  // app-roots by running the SAME detection functions offline (no binaries), then scores the seven
  // #71-deferred entries. Faithful to the live run: legacy-app (vulnerable, no lockfile) and
  // supported-app (clean, has a lockfile).
  const emptyDir = mkdtempSync(join(tmpdir(), "harvey-fixture-legacy-"));
  afterAll(() => rmSync(emptyDir, { recursive: true, force: true }));

  const legacyLabel = "fixtures/legacy-app/package.json";
  const legacyDeps = { next: "12.3.5", react: "16.4.0", "react-dom": "16.4.0", minimist: "1.2.5", "flatmap-stream": "0.1.1" };
  const supportedLabel = "fixtures/supported-app/package.json";
  const supportedDeps = { next: "15.5.16", react: "18.3.1", "react-dom": "18.3.1", esbuild: "0.21.5" };

  const findings: Finding[] = [
    // legacy-app: EOL next, vulnerable react-dom, critical minimist, IOC flatmap-stream, no lockfile.
    ...checkNextVersionCVEs("12.3.5", legacyLabel),
    ...checkKnownDependencyCVEs(legacyDeps, legacyLabel),
    ...checkKnownIoc(Object.keys(legacyDeps), legacyLabel),
    ...checkLockfilePresence(emptyDir, "fixtures/legacy-app"),
    // supported-app: everything clean; a real lockfile means checkLockfilePresence stays silent.
    ...checkNextVersionCVEs("15.5.16", supportedLabel),
    ...checkKnownDependencyCVEs(supportedDeps, supportedLabel),
    ...checkKnownIoc(Object.keys(supportedDeps), supportedLabel),
  ];

  const deferredIds = new Set([
    "P-NEXT-EOL", "N-NEXT-SUPPORTED", "P-REACT-DOM-CVE",
    "P-DEP-CVE-CRITICAL", "P-MISSING-LOCKFILE", "P-KNOWN-IOC-PKG", "N-POSTINSTALL-KNOWN",
  ]);
  const deferred = b2DepsEntries.filter((e) => deferredIds.has(e.id));

  it("covers all seven #71-deferred classes", () => {
    expect(deferred).toHaveLength(7);
  });

  it("catches every deferred positive at its declared tier and clears every deferred negative", () => {
    for (const e of deferred) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("lands minimist, the IOC package, and the missing lockfile in the free (high) count", () => {
    const high = new Set(findings.filter((f) => f.precisionTier === "high").map((f) => f.id));
    expect(high).toContain("DEP-CVE-2021-44906");
    expect(high).toContain("SUP-IOC-flatmap-stream");
    expect(high).toContain("SUP-NO-LOCKFILE");
  });

  it("draws nothing at all from the supported-app fixture", () => {
    expect(findings.filter((f) => f.location.includes("supported-app"))).toEqual([]);
  });
});

describe("Batch B9 secrets corpus (recorded gitleaks + semgrep output → tier mapping)", () => {
  // Recorded findings mirroring the live `pnpm validate:calibration` run over targets/calibration,
  // fed through the real secrets.ts / semgrep.ts tier mapping (no binary invoked). Exercises the
  // B9 additions: the gitleaks rules promoted to high (supabase-default-jwt-secret,
  // harvey-uri-credentials, harvey-http-authorization-bearer, npm-access-token, slack-webhook-url)
  // and the two ERROR+HIGH structural Semgrep rules, plus the review-tier detections.
  const gitleaks: GitleaksResult[] = [
    { RuleID: "supabase-default-jwt-secret", File: "supabase/docker.env", StartLine: 7, Match: "your-super-secret-jwt-token-with-at-least-32-characters-long" },
    { RuleID: "npm-access-token", File: ".npmrc", StartLine: 1, Match: "npm_FAKE0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u" },
    { RuleID: "private-key", File: "secrets/gcp-service-account.json", StartLine: 5, Match: "-----BEGIN PRIVATE KEY-----" },
    { RuleID: "slack-webhook-url", File: "lib/notify.js", StartLine: 6, Match: "https://hooks.slack.com/workflows/T0FAKE000/A0FAKE000/000000000000000000/FAKExXxXxXxXxXxX" },
    { RuleID: "harvey-uri-credentials", File: "lib/mailer.js", StartLine: 4, Match: "smtp://mailer:S3ndM4ilPwZ9Qm2v@smtp.mailprovider.example.com" },
    { RuleID: "harvey-http-authorization-bearer", File: "supabase/migrations/20260709000005_b9_db_webhook.sql", StartLine: 14, Match: "Bearer whsec_9f3Kd2mQ7pRs1TvWx8Yz0AbCd4Ef6GhJk" },
    { RuleID: "harvey-gcp-api-key", File: "lib/maps.js", StartLine: 5, Match: "AIzaSyD0FAKEkeyNotReal000000000000abcde" },
    { RuleID: "jwt", File: "lib/share.js", StartLine: 5, Match: "eyJhbGciOiJIUzI1NiJ9.eyJ1cmwiOiJyZXBvcnRzL3EzLnBkZiJ9.Kf3Zp7wV0nRtY8sLbUmEdHjGqAoIcPwZ1kY" },
    // N-SB-JWT-ROTATED: the rotated random secret draws only a generic-api-key review hit.
    { RuleID: "generic-api-key", File: "supabase/docker.env", StartLine: 12, Match: "ANON_JWT_SECRET=Rk7pQ2mZ9vXcW8sNdLhGfYtAe4Uo1Bx" },
  ];
  const semgrep: SemgrepResult[] = [
    { check_id: "secrets.harvey-nextconfig-env-secret", path: "next.config.js", start: { line: 11 }, extra: { severity: "ERROR", metadata: { confidence: "HIGH" }, message: "secret-named key inlined via env" } },
    { check_id: "secrets.harvey-edgefn-secret-fallback", path: "supabase/functions/send-email/index.ts", start: { line: 6 }, extra: { severity: "ERROR", metadata: { confidence: "HIGH" }, message: "hardcoded secret fallback" } },
    { check_id: "secrets.harvey-secret-in-url-param", path: "lib/weather.js", start: { line: 5 }, extra: { severity: "WARNING", metadata: { confidence: "MEDIUM" }, message: "secret in URL query parameter" } },
  ];
  const findings = [...parseGitleaksFindings(gitleaks, "source"), ...parseSemgrepFindings({ results: semgrep })];

  it("catches every B9 positive at its declared tier and clears every B9 negative", () => {
    for (const e of b9SecretsEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the ~100%-precision detections to the free count (8 high, 3 review)", () => {
    const m = buildCoverageMatrix(findings, b9SecretsEntries);
    const positives = b9SecretsEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(8);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(3);
    expect(m.ok).toBe(true);
  });
});

describe("Batch B10 dependency-CVE corpus (secondary manifest fixtures → real check output)", () => {
  // Reconstructs what validate-calibration.ts's scanManifestFixtures produces for the three B10
  // fixture app-roots by running the SAME offline check functions (no binaries), then scores every
  // B10 entry. Faithful to the live run: b10-vuln-deps (vulnerable), b10-nextauth-csrf (the isolated
  // OAuth-CSRF next-auth version), b10-patched-deps (clean).
  const vulnLabel = "fixtures/b10-vuln-deps/package.json";
  const vulnDeps = { next: "16.0.5", "next-auth": "4.24.5", jsonwebtoken: "8.5.1", "follow-redirects": "1.15.4", axios: "1.7.2", undici: "5.7.0", cookie: "0.5.0", ws: "7.4.5", sharp: "0.31.3" };
  const csrfLabel = "fixtures/b10-nextauth-csrf/package.json";
  const csrfDeps = { "next-auth": "4.19.0" };
  const patchedLabel = "fixtures/b10-patched-deps/package.json";
  const patchedDeps = { next: "16.2.5", "next-auth": "4.24.12", jsonwebtoken: "9.0.2", "follow-redirects": "1.15.6", axios: "1.8.2", undici: "5.28.3", cookie: "0.7.0", ws: "7.4.6", sharp: "0.32.6" };

  const findings: Finding[] = [
    ...checkNextVersionCVEs(vulnDeps.next, vulnLabel),
    ...checkKnownDependencyCVEs(vulnDeps, vulnLabel),
    ...checkKnownDependencyCVEs(csrfDeps, csrfLabel),
    ...checkNextVersionCVEs(patchedDeps.next, patchedLabel),
    ...checkKnownDependencyCVEs(patchedDeps, patchedLabel),
  ];

  it("covers all ten B10 classes (10 positives) plus the patched negatives", () => {
    expect(b10DepsEntries.filter((e) => e.kind === "positive")).toHaveLength(10);
  });

  it("catches every B10 positive at high and clears every B10 negative", () => {
    for (const e of b10DepsEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe("high");
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("draws nothing at all from the patched fixture", () => {
    expect(findings.filter((f) => f.location.includes("b10-patched-deps"))).toEqual([]);
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
