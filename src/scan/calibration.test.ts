import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { buildCoverageMatrix, CORPUS, mechanicalCorpus, moduleCensus, scoreEntry, type CorpusEntry } from "./calibration.js";
import { b2DepsEntries } from "./calibration/b2-deps.entries.js";
import { b9SecretsEntries } from "./calibration/b9-secrets.entries.js";
import { b10DepsEntries } from "./calibration/b10-deps.entries.js";
import { b11CryptoEntries } from "./calibration/b11-crypto.entries.js";
import { b12NextconfigEntries } from "./calibration/b12-nextconfig.entries.js";
import { b13SupaEntries } from "./calibration/b13-supa.entries.js";
import { b14AppLogicEntries } from "./calibration/b14-applogic.entries.js";
import { b15NextjsAuthzEntries } from "./calibration/b15-nextjs-authz.entries.js";
import { b17RaceUnscopedEntries } from "./calibration/b17-race-unscoped.entries.js";
import { knownPublicCredsEntries } from "./calibration/known-public-creds.entries.js";
import { m9AuthzEntries } from "./calibration/m9-authz.entries.js";
import { m9CheckEntries } from "./calibration/m9-checks.entries.js";
import { m9PortEntries } from "./calibration/m9-ports.entries.js";
import type { TargetFramework } from "./framework-detect.js";
import type { SourceInput } from "../detectors/app-router.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { scanBolaOwner } from "./bola-owner.js";
import { scanCounterRace } from "./counter-race.js";
import { classifyLeftoverAuth } from "./leftover-auth.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs } from "./dependencies.js";
import { parseGitleaksFindings, type GitleaksResult } from "./secrets.js";
import { checkPublicDirSensitive, parseSemgrepFindings, type SemgrepResult } from "./semgrep.js";
import { checkEdgeFunctionVerifyJwt, checkMigrationDefinerAnonGrant, checkMigrationDynamicSqlInjection, checkMigrationRlsInitplanStatic, checkMigrationRlsStatic, checkOpenSignupConfig } from "./supabase-static.js";
import { m7InitplanStaticEntries } from "./calibration/m7-initplan-static.entries.js";
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

  // #253: a bare package-name location substring-matches every manifest declaring it, so a
  // root-target entry could score off a fixture's finding while the root rule never fired —
  // how #212's fabricated P-NEXT-CVE-RSC row appeared to pass. `manifest` pins it to one.
  it("does not let a bare package-name location score a positive off another manifest's finding", () => {
    const e = entry({ id: "P-NEXT-CVE-29927", kind: "positive", cls: "framework cve", location: "next", manifest: "package.json", match: ["29927"], expectedTier: "high", note: "" });
    const fixtureOnly = [finding({ location: "fixtures/b10-vuln-deps/package.json (next)", title: "next@16.0.5 vulnerable to CVE-2025-29927", precisionTier: "high" })];
    expect(scoreEntry(e, fixtureOnly).pass).toBe(false);

    const rootManifest = [finding({ location: "package.json (next)", title: "next@14.2.5 vulnerable to CVE-2025-29927", precisionTier: "high" })];
    expect(scoreEntry(e, rootManifest).pass).toBe(true);
  });

  it("keeps a manifest-pinned negative from clearing on a different manifest's high finding", () => {
    const e = entry({ id: "N-NEXT-RSC-14X", kind: "negative", cls: "unaffected line", location: "next", manifest: "fixtures/b10-next14-rsc/package.json", match: ["55182"], note: "" });
    const wrongManifest = [finding({ location: "fixtures/b10-vuln-deps/package.json (next)", title: "CVE-2025-55182 RSC RCE", precisionTier: "high" })];
    expect(scoreEntry(e, wrongManifest).highFlagged).toBe(false);

    const ownManifest = [finding({ location: "fixtures/b10-next14-rsc/package.json (next)", title: "CVE-2025-55182 RSC RCE", precisionTier: "high" })];
    expect(scoreEntry(e, ownManifest).pass).toBe(false);
  });

  it("reports a connected-tier entry as N/A, never a failure, even with no findings", () => {
    const e = entry({ id: "P-RLS", kind: "positive", cls: "rls", location: "audit_logs", expectedTier: "connected", note: "" });
    const row = scoreEntry(e, []);
    expect(row.pass).toBe(true);
    expect(row.detail).toContain("connected");
  });

  it("fails loud when a relevant finding reaches the scorer with no precisionTier (#327)", () => {
    // The latent bug: a detector finding with no tier scored as "no tier at all" — a positive
    // registered as an outright miss and an untiered FP was invisible to precision, both silently.
    // An untiered finding relevant to an entry must now THROW, never score as a quiet miss/clear.
    const e = entry({ id: "P-UNTIERED", kind: "positive", cls: "x", location: "search.js", match: ["sql"], expectedTier: "review", note: "" });
    const untiered: Finding = { ...finding({ location: "pages/api/search.js:11", taxonomy: "SQL injection", precisionTier: "high" }), precisionTier: undefined };
    expect(() => scoreEntry(e, [untiered])).toThrow(/precisionTier/);
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
    // P-ENV-COMMITTED (#130): a committed bare .env carrying two live-shaped secrets at once —
    // distinct from .env.local above (P-ENV-COMMITTED's corpus entry location " .env:" only
    // matches a root file literally named ".env", not ".env.local"/".env.example"/"docker.env").
    { RuleID: "supabase-service-role-jwt", File: ".env", StartLine: 9, Match: '"role":"service_role"' },
    { RuleID: "harvey-db-uri-credentials", File: ".env", StartLine: 13, Match: "mongodb+srv://appuser:pw@cluster0.calibrationref01.mongodb.net" },
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

  it("promotes only the ~100%-precision rules to the free count (6 high, 6 review)", () => {
    const m = buildCoverageMatrix(findings, secretsEntries);
    const positives = secretsEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(positives.filter((e) => e.expectedTier === "high").length);
    expect(m.positivesCaughtHigh).toBe(6);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});

describe("Known-public/test-credential recognizer corpus (#225, recorded gitleaks output → tier mapping)", () => {
  // Recorded gitleaks findings mirroring the live `pnpm validate:calibration` run over
  // targets/calibration: each demo/test credential co-located with its internal correlation
  // marker (see gitleaks-supabase.toml), plus the genuine non-demo positives for regression.
  const gitleaks: GitleaksResult[] = [
    // #210 — the Supabase local-dev demo key, decoded and marked at the same file+line.
    { RuleID: "supabase-service-role-jwt", File: "supabase/seed.sql", StartLine: 89, Match: '"role":"service_role"' },
    { RuleID: "supabase-demo-key-marker", File: "supabase/seed.sql", StartLine: 89, Match: '"iss":"supabase-demo"' },
    { RuleID: "supabase-demo-key-marker", File: "supabase/seed.sql", StartLine: 91, Match: '"iss":"supabase-demo"' },
    { RuleID: "harvey-http-authorization-bearer", File: "scripts/checks.mjs", StartLine: 12, Match: "Bearer eyJhbGci…" },
    { RuleID: "supabase-service-role-jwt", File: "scripts/checks.mjs", StartLine: 12, Match: '"role":"service_role"' },
    { RuleID: "supabase-demo-key-marker", File: "scripts/checks.mjs", StartLine: 12, Match: '"iss":"supabase-demo"' },
    // Regression: the real, non-demo service-role key must still fire at high with no marker present.
    { RuleID: "supabase-service-role-jwt", File: "lib/admin.js", StartLine: 9, Match: '"role":"service_role"' },
    // #211 — a test/example SAML private key in a CI workflow, marked in the same file.
    { RuleID: "private-key", File: ".github/workflows/saml-integration-test.yml", StartLine: 17, Match: "-----BEGIN PRIVATE KEY-----" },
    { RuleID: "harvey-test-idp-marker", File: ".github/workflows/saml-integration-test.yml", StartLine: 3, Match: "ENTITY_ID" },
    // Regression: the real, non-demo private key must still fire at high with no marker present.
    { RuleID: "private-key", File: "certs/key.pem", StartLine: 1, Match: "-----BEGIN PRIVATE KEY-----" },
  ];
  const findings = parseGitleaksFindings(gitleaks, "source");

  it("clears the demo key (#210), down-ranks the SAML test key (#211), and leaves the real positives at high", () => {
    for (const e of [...knownPublicCredsEntries, ...secretsEntries.filter((e) => e.id === "P-SRV-ROLE-JWT-SRC")]) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("down-ranks the SAML test key to review rather than dropping it silently", () => {
    const saml = scoreEntry(knownPublicCredsEntries.find((e) => e.id === "N-SAML-TEST-PRIVATE-KEY")!, findings);
    expect(saml.reviewFlagged).toBe(true);
  });

  it("still flags the genuine private key at certs/key.pem at high (no marker present there)", () => {
    const real = findings.find((f) => f.location.includes("certs/key.pem"));
    expect(real?.precisionTier).toBe("high");
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
    // #595 — the Node process.env secret-fallback (review). Negatives (empty/fail-closed, non-secret name) draw nothing.
    { check_id: "secrets.harvey-node-secret-fallback", path: "lib/jwt-signing.ts", start: { line: 5 }, extra: { severity: "WARNING", metadata: { confidence: "MEDIUM" }, message: "process.env secret fallback to a hardcoded literal" } },
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

  it("promotes only the ~100%-precision detections to the free count (8 high, 4 review)", () => {
    const m = buildCoverageMatrix(findings, b9SecretsEntries);
    const positives = b9SecretsEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(8);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(4);
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

describe("Batch B11 crypto-API misuse corpus (recorded semgrep output → tier mapping)", () => {
  // Recorded semgrep findings mirroring the live `pnpm validate:calibration` run over
  // targets/calibration, fed through the real semgrep.ts tier mapping (no binary invoked). Exercises
  // the B11 crypto.yml additions: 5 ERROR+HIGH rules (no-IV createCipher, pseudoRandomBytes, 2-arg
  // jwt.verify, ignoreExpiration, ws:// URL) and 4 WARNING+MEDIUM heuristics (GCM no authTagLength,
  // AEAD no final(), client jwtDecode() render sink, hardcoded HMAC key). The seven negative
  // fixtures draw nothing, so they appear as no rows here.
  const error = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 8 },
    extra: { severity: "ERROR", metadata: { confidence: "HIGH" }, message: `${id} matched` },
  });
  const warning = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 9 },
    extra: { severity: "WARNING", metadata: { confidence: "MEDIUM" }, message: `${id} matched` },
  });
  const semgrep: SemgrepResult[] = [
    error("harvey-crypto-createcipher", "lib/cipher-noiv.js"),
    error("harvey-crypto-pseudorandombytes", "lib/pseudorandom.js"),
    error("harvey-jwt-verify-noalg", "lib/jwt-verify-noalg.js"),
    error("harvey-jwt-ignore-exp", "lib/jwt-ignore-exp.js"),
    error("harvey-insecure-ws-url", "lib/ws-client.js"),
    warning("harvey-gcm-no-authtaglength", "lib/gcm-notag.js"),
    warning("harvey-aead-decipher-no-final", "lib/aead-nofinal.js"),
    warning("harvey-jwt-decode-render", "components/RoleBadge.jsx"),
    warning("harvey-hmac-hardcoded-key", "lib/sign.js"),
    // #595 — jwt.sign with no expiresIn (review). The N-JWT-SIGN-EXPIRY negative draws nothing.
    warning("harvey-jwt-sign-noexpiry", "lib/jwt-signing.ts"),
  ];
  const findings = parseSemgrepFindings({ results: semgrep });

  it("catches every B11 positive at its declared tier and clears every B11 negative", () => {
    for (const e of b11CryptoEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the exact-API/literal rules to the free count (5 high, 5 review)", () => {
    const m = buildCoverageMatrix(findings, b11CryptoEntries);
    const positives = b11CryptoEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(5);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(5);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});

describe("Batch B12 next-config/client-surface corpus (recorded semgrep + public/ walk → tier mapping)", () => {
  // Recorded findings mirroring the live `pnpm validate:calibration` run over targets/calibration,
  // fed through the real semgrep.ts tier mapping (no binary invoked). Exercises the B12 additions:
  // 5 ERROR+HIGH Semgrep rules (wildcard remotePatterns, productionBrowserSourceMaps, '*' Server
  // Actions origin, excessive createSignedUrl TTL, '*' postMessage) + the checkPublicDirSensitive
  // filesystem check (the 6th high), and 5 WARNING+MEDIUM heuristics (auth token in Web Storage, CDN
  // script no SRI, ISR revalidate no secret, CRLF header injection ×2 incl. the multi-hop source,
  // 'message' listener no origin). The eleven negative fixtures draw nothing, so no rows here.
  const error = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 8 },
    extra: { severity: "ERROR", metadata: { confidence: "HIGH" }, message: `${id} matched` },
  });
  const warning = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 9 },
    extra: { severity: "WARNING", metadata: { confidence: "MEDIUM" }, message: `${id} matched` },
  });
  const semgrep: SemgrepResult[] = [
    error("harvey-img-remotepatterns-wild", "config-variants/insecure.config.js"),
    error("harvey-prod-sourcemaps", "config-variants/insecure.config.js"),
    error("harvey-serveractions-origin-wild", "config-variants/insecure.config.js"),
    error("harvey-signed-url-ttl", "lib/signed-url-ttl.js"),
    error("harvey-postmessage-wildcard", "components/PostMessageWild.jsx"),
    warning("harvey-token-in-webstorage", "lib/webstorage-token.js"),
    warning("harvey-missing-sri", "components/CdnScript.jsx"),
    warning("harvey-isr-revalidate-nosecret", "pages/api/isr-rebuild.js"),
    warning("harvey-crlf-header-injection", "pages/api/download.js"),
    warning("harvey-crlf-header-injection", "pages/api/crlf-multihop.js"),
    warning("harvey-postmessage-no-origin", "components/MessageListener.jsx"),
  ];

  // The 6th high class is a filesystem fact, so exercise the REAL checkPublicDirSensitive against a
  // temp public/ tree instead of a recorded semgrep row.
  const pubDir = mkdtempSync(join(tmpdir(), "harvey-b12-public-"));
  afterAll(() => rmSync(pubDir, { recursive: true, force: true }));
  mkdirSync(join(pubDir, "public", "fonts"), { recursive: true });
  writeFileSync(join(pubDir, "public", "backup.sql"), "-- inert");
  writeFileSync(join(pubDir, "public", ".env.production"), "X=1");
  writeFileSync(join(pubDir, "public", "favicon.ico"), "x");
  writeFileSync(join(pubDir, "public", "fonts", "inter.woff2"), "x");

  const findings = [...parseSemgrepFindings({ results: semgrep }), ...checkPublicDirSensitive(pubDir)];

  it("catches every B12 positive at its declared tier and clears every B12 negative", () => {
    for (const e of b12NextconfigEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the exact config-parse / literal / filesystem sinks to the free count (6 high, 6 review)", () => {
    const m = buildCoverageMatrix(findings, b12NextconfigEntries);
    const positives = b12NextconfigEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(6);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(6);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });

  it("the public/ walk flags only the sensitive files, not the benign assets", () => {
    const pub = checkPublicDirSensitive(pubDir);
    expect(pub.map((f) => f.location).sort()).toEqual(["public/.env.production", "public/backup.sql"]);
    expect(pub.every((f) => f.precisionTier === "high")).toBe(true);
  });
});

describe("Batch B13 supabase-static/injection corpus (recorded semgrep + real static checks → tier mapping)", () => {
  // Recorded findings mirroring the live `pnpm validate:calibration` run over targets/calibration,
  // fed through the real semgrep.ts tier mapping (no binary invoked). Exercises the B13 additions:
  // 3 ERROR+HIGH Semgrep rules (spawn shell:true, pg ssl:false to a pooler, auth.admin in a Client
  // Component) + 7 WARNING+MEDIUM injection-sink heuristics, plus the two new static checks
  // (checkMigrationRlsStatic — the honesty-flag HIGH class — and checkEdgeFunctionVerifyJwt) run
  // for real against a temp supabase/ tree. The negative fixtures draw nothing, so no rows for them.
  const error = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 8 },
    extra: { severity: "ERROR", metadata: { confidence: "HIGH" }, message: `${id} matched` },
  });
  const warning = (id: string, path: string): SemgrepResult => ({
    check_id: `src.scan.rules.semgrep.${id}`, path, start: { line: 9 },
    extra: { severity: "WARNING", metadata: { confidence: "MEDIUM" }, message: `${id} matched` },
  });
  const semgrep: SemgrepResult[] = [
    error("harvey-spawn-shell-true", "pages/api/thumbnail.js"),
    error("harvey-pg-ssl-disabled", "lib/pg-ssl-disabled.js"),
    error("harvey-auth-admin-in-client", "components/AdminUsersClient.jsx"),
    warning("harvey-select-star-pii", "pages/api/customers.js"),
    warning("harvey-cron-no-secret", "pages/api/cron/rollup.js"),
    warning("harvey-dynamic-require", "pages/api/plugin.js"),
    warning("harvey-dynamic-dispatch", "pages/api/dispatch.js"),
    warning("harvey-template-autoescape-off", "lib/render-template.js"),
    warning("harvey-html-template-literal", "pages/api/greet.js"),
    warning("harvey-incomplete-sanitize", "lib/sanitize-bad.js"),
    // #565 — Vite/no-code M1 secret shapes (ERROR+HIGH).
    error("harvey-vite-service-role-in-client", "src/lib/supabaseServiceClient.ts"),
    error("harvey-dangerously-allow-browser", "src/lib/openaiBrowser.ts"),
  ];

  // The two new static checks are filesystem facts, so run the REAL functions against a temp
  // supabase/ tree that mirrors the calibration target: audit_logs (RLS never enabled — positive),
  // documents (enabled in a later file) and service_state (RLS on, zero policies) as the two
  // negatives; a [functions.admin-refund] verify_jwt=false positive + a verify_jwt=true negative.
  const supaDir = mkdtempSync(join(tmpdir(), "harvey-b13-supa-"));
  afterAll(() => rmSync(supaDir, { recursive: true, force: true }));
  mkdirSync(join(supaDir, "supabase", "migrations"), { recursive: true });
  writeFileSync(
    join(supaDir, "supabase", "migrations", "20260708000001_schema.sql"),
    "create table public.audit_logs (id uuid primary key);\ncreate table public.documents (id uuid primary key);\ncreate table public.service_state (id uuid primary key);\n",
  );
  writeFileSync(
    join(supaDir, "supabase", "migrations", "20260708000002_rls.sql"),
    "alter table public.documents enable row level security;\nalter table public.service_state enable row level security;\n",
  );
  // #565 — a root schema.sql (no-code export shape) in a SEPARATE dir (keeps supaDir migrations-only
  // for the focused "flags only audit_logs" test below): nocode_tickets (RLS off → positive),
  // nocode_safe (RLS enabled in the same file → negative). checkMigrationRlsStatic reads a root
  // schema.sql, not just supabase/migrations.
  const rootSchemaDir = mkdtempSync(join(tmpdir(), "harvey-b13-rootschema-"));
  afterAll(() => rmSync(rootSchemaDir, { recursive: true, force: true }));
  writeFileSync(
    join(rootSchemaDir, "schema.sql"),
    "create table public.nocode_tickets (id uuid primary key);\ncreate table public.nocode_safe (id uuid primary key);\nalter table public.nocode_safe enable row level security;\n" +
      // #611 Gap B — bare (unqualified) create table (public implicit): workspaces RLS off (positive),
      // members RLS on via a bare alter (negative), private.internal_audit non-public schema (negative).
      "create table workspaces (id uuid primary key);\ncreate table members (id uuid primary key);\nalter table members enable row level security;\ncreate table private.internal_audit (id uuid primary key);\n",
  );
  // #602 — a migration with the plpgsql SQLi + DEFINER-anon-grant fixtures (and their safe siblings).
  writeFileSync(
    join(supaDir, "supabase", "migrations", "20260719000002_injection.sql"),
    "create function public.search_tickets_unsafe(p_query text) returns setof public.audit_logs language plpgsql security definer as $$\nbegin\n  return query execute 'select * from public.audit_logs where subject ilike ' || p_query;\nend;\n$$;\n" +
      "create function public.search_tickets_quoted(p_query text) returns setof public.audit_logs language plpgsql security definer as $$\nbegin\n  return query execute 'select * from public.audit_logs where subject = ' || quote_literal(p_query);\nend;\n$$;\n" +
      "create function public.get_user_by_email(p_email text) returns setof public.audit_logs language plpgsql security definer as $$\nbegin\n  return query select * from public.audit_logs where email = p_email;\nend;\n$$;\ngrant execute on function public.get_user_by_email(text) to anon;\n" +
      "create function public.get_my_tickets() returns setof public.audit_logs language plpgsql security definer as $$\nbegin\n  return query select * from public.audit_logs where auth.uid() is not null;\nend;\n$$;\ngrant execute on function public.get_my_tickets() to anon;\n",
  );
  writeFileSync(
    join(supaDir, "supabase", "config.toml"),
    "[functions.admin-refund]\nverify_jwt = false\n\n[functions.user-profile]\nverify_jwt = true\n\n[auth]\nenable_signup = true\n\n[auth.email]\nenable_confirmations = false\n",
  );

  const findings = [
    ...parseSemgrepFindings({ results: semgrep }),
    ...checkMigrationRlsStatic(supaDir),
    ...checkMigrationRlsStatic(rootSchemaDir),
    ...checkEdgeFunctionVerifyJwt(supaDir),
    ...checkOpenSignupConfig(supaDir),
    ...checkMigrationDynamicSqlInjection(supaDir), // #602 CX-12
    ...checkMigrationDefinerAnonGrant(supaDir), // #602 CX-11
  ];

  it("catches every B13 positive at its declared tier and clears every B13 negative", () => {
    for (const e of b13SupaEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the exact static/structural sinks to the free count (8 high, 12 review)", () => {
    const m = buildCoverageMatrix(findings, b13SupaEntries);
    const positives = b13SupaEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(8);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(12);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });

  it("the migration RLS check flags only audit_logs (clears the later-file-enabled and deny-all tables)", () => {
    const rls = checkMigrationRlsStatic(supaDir);
    expect(rls).toHaveLength(1);
    expect(rls[0]!.evidence).toContain("public.audit_logs");
    expect(rls[0]!.precisionTier).toBe("high");
  });
});

describe("Batch B14 app-logic heuristics corpus (real leftover-auth greps → tier mapping)", () => {
  // leftover-auth is a pure in-process grep (no binary), so run the REAL classifyLeftoverAuth over
  // the fixture contents that mirror targets/calibration — no recorded output needed. Each B14
  // check emits a review-tier finding; the negatives draw nothing at all (true silence, not just
  // "no free-count FP"). Mirrors the live `pnpm validate:calibration` run.
  const fixtures: { path: string; content: string }[] = [
    { path: "pages/api/promote.js", content: "if (req.headers[\"x-role\"] === \"admin\") { await admin.from(\"users\").update({ role: \"admin\" }).eq(\"id\", req.body.userId); }" },
    { path: "pages/api/promote-safe.js", content: "const { data: { user } } = await admin.auth.getUser(t); if (user?.app_metadata?.role === \"admin\") { await admin.from(\"users\").update({ role: \"admin\" }); }" },
    { path: "pages/api/checkout.js", content: "await stripe.paymentIntents.create({ amount: req.body.amount, currency: \"usd\" });" },
    { path: "pages/api/checkout-safe.js", content: "await stripe.paymentIntents.create({ amount: product.price_cents * req.body.quantity, currency: \"usd\" });" },
    { path: "pages/api/webhooks/inbound.js", content: "const event = req.body; await admin.from(\"subscriptions\").update({ status: event.status }).eq(\"customer_id\", event.customerId);" },
    { path: "pages/api/webhooks/inbound-signed.js", content: "const event = stripe.webhooks.constructEvent(req.body, req.headers[\"stripe-signature\"], process.env.STRIPE_WEBHOOK_SECRET); await admin.from(\"subscriptions\").update({ status: event.data.object.status });" },
    { path: "lib/audit-login.js", content: "export function auditLogin(email, password) { console.log(\"login attempt\", { email, password }); }" },
    { path: "lib/audit-login-safe.js", content: "export function auditLogin(email, success) { console.log(\"login attempt\", { email, success }); }" },
    { path: "pages/api/upload.js", content: "const buffer = Buffer.from(req.body); await admin.storage.from(\"uploads\").upload(req.query.name, buffer);" },
    { path: "pages/api/upload-safe.js", content: "const ALLOWED_MIME = [\"image/png\"]; const length = Number(req.headers[\"content-length\"]); if (!ALLOWED_MIME.includes(ct) || length > MAX) return; await admin.storage.from(\"uploads\").upload(req.query.name, buffer, { contentType: ct });" },
    // #576 — client-trust-boundary: a role decision made in client code (Web Storage / user-object role).
    { path: "src/components/AdminGateStorage.tsx", content: "const role = localStorage.getItem(\"role\"); if (role === \"admin\") { return <AdminControls />; } return <p>Members only</p>;" },
    { path: "src/components/AdminGateUser.tsx", content: "const navigate = useNavigate(); if (user.user_metadata.role !== \"admin\") { return null; } navigate(\"/admin\");" },
    { path: "src/lib/requireAdmin.ts", content: "const { data: profile } = await admin.from(\"profiles\").select(\"role\").eq(\"id\", user.id).single(); if (profile.role !== \"admin\") return new Response(\"Forbidden\", { status: 403 });" },
  ];
  const findings = fixtures.flatMap((f) => classifyLeftoverAuth(f));

  it("catches every B14 positive at review and leaves every B14 negative fully silent", () => {
    for (const e of b14AppLogicEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe("review");
      else expect(row.reviewFlagged, `${e.id} must draw no finding at all`).toBe(false);
    }
  });

  it("promotes none of the app-logic heuristics to the free count (0 high, 7 review)", () => {
    const m = buildCoverageMatrix(findings, b14AppLogicEntries);
    const positives = b14AppLogicEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(0);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(7);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});

describe("#353/#354/#433 mechanical graduations (real detectors over the committed fixtures)", () => {
  // Like the #221/#374 blocks: the REAL detectors against the REAL committed fixtures, so the answer
  // key can't drift from what the scanner emits. Covers the two #353 graduations (unscoped-write
  // grep + counter-race AST), the two #354 graduations lifted out of b15 (matcher + draftMode),
  // and the #433 graduation (bola-owner AST — P-BOLA-BODY-OWNER).
  const CAL = join(import.meta.dirname, "../../targets/calibration");
  const read = (p: string) => ({ path: p, content: readFileSync(join(CAL, p), "utf8") });
  const leftoverFixtures = [
    "pages/api/profile/update.js",
    "pages/api/profile/update-safe.js",
    "middleware.ts",
    "lib/middleware-matcher-safe.ts",
    "pages/api/preview/enable.js",
    "pages/api/preview/enable-safe.js",
  ].map(read);
  const findings = [...leftoverFixtures.flatMap((f) => classifyLeftoverAuth(f)), ...scanCounterRace(CAL), ...scanBolaOwner(CAL)];

  const graduated = [
    ...b17RaceUnscopedEntries,
    ...b15NextjsAuthzEntries.filter((e) =>
      ["P-MW-MATCHER-EXCLUDES-API", "N-MW-MATCHER-INCLUDES-API", "P-DRAFTMODE-NO-SECRET", "N-DRAFTMODE-SECRET-CHECKED", "P-BOLA-BODY-OWNER", "N-BOLA-SESSION-OWNER"].includes(e.id),
    ),
  ];

  it("catches each graduated positive at review and clears its benign sibling", () => {
    for (const e of graduated) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      // The "none"-tier sibling (WEBHOOK-REPLAY, #425) did NOT graduate: it passes as an intended
      // gap with no caught tier, and these leftover-auth/counter-race findings must not reach it.
      if (e.expectedTier === "none") expect(row.caughtTier, e.id).toBeUndefined();
      else if (e.kind === "positive") expect(row.caughtTier, e.id).toBe("review");
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("keeps every graduation at review tier — a heuristic rule never inflates the free count", () => {
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.precisionTier === "review")).toBe(true);
  });

  it("the counter-race AST fires once (the positive) and stays silent on the atomic RPC sibling", () => {
    const race = scanCounterRace(CAL).filter((f) => f.taxonomy === "Non-atomic read-modify-write race condition");
    expect(race).toHaveLength(1);
    expect(race[0]?.location).toContain("counter/increment.js");
  });

  it("the #433 bola-owner AST fires exactly once across the whole target — every other pages/api fixture stays silent", () => {
    // One hit total pins more than the corpus pair: the session-scoped sibling (invoice-safe),
    // the no-session handlers (order/get.js P-IDOR-PARAM, admin/dashboard.js P-MW-SOLE-AUTHZ —
    // whose by-design LLM-tier status this pass must not swallow), and the bare-id IDOR shape
    // (order/scoped.js) are all non-hits, measured, not assumed.
    const bola = scanBolaOwner(CAL);
    expect(bola).toHaveLength(1);
    expect(bola[0]?.location).toContain("pages/api/billing/invoice.js");
    expect(bola[0]?.precisionTier).toBe("review");
  });
});

describe("moduleCensus (#341 — per-module legibility so a blended count can't imply uniform coverage)", () => {
  it("tallies each module's fixtures and keeps thin modules visible, not averaged away", () => {
    const census = moduleCensus(CORPUS);
    const byModule = new Map(census.map((c) => [c.module, c]));

    // Every module the corpus tags must appear as its own row.
    const modulesInCorpus = new Set(CORPUS.map((e) => e.module ?? "M1"));
    expect(new Set(census.map((c) => c.module))).toEqual(modulesInCorpus);

    // The census must equal a direct recount — a thin module reads as thin, not blended into M1.
    for (const m of modulesInCorpus) {
      const entries = CORPUS.filter((e) => (e.module ?? "M1") === m);
      const row = byModule.get(m)!;
      expect(row.negatives).toBe(entries.filter((e) => e.kind === "negative").length);
      expect(row.positivesConnected).toBe(entries.filter((e) => e.kind === "positive" && e.expectedTier === "connected").length);
      expect(row.positivesStatic).toBe(entries.filter((e) => e.kind === "positive" && e.expectedTier !== "connected").length);
    }

    // M1 rows first, then ascending module number.
    expect(census[0]?.module).toBe("M1");
    const nums = census.map((c) => Number(c.module.replace(/^M/, "")));
    expect(nums).toEqual([...nums].sort((a, b) => a - b));
  });
});

describe("mechanicalCorpus (#398 — a module-tagged entry must never go silently unscored)", () => {
  // #398: validate-calibration.ts scores only entries with no `module` label (runMechanicalScan
  // is M1-only, #341's recorded decision). The defect this guards against isn't the exclusion
  // itself — it's an exclusion nobody can see: an entry dropped from the live gate AND absent
  // from the per-module census reads as "never existed" rather than "gated elsewhere."
  it("excludes exactly the module-tagged entries, keeps every M1 entry", () => {
    const scored = mechanicalCorpus(CORPUS);
    expect(scored.every((e) => e.module === undefined)).toBe(true);
    expect(scored).toHaveLength(CORPUS.filter((e) => e.module === undefined).length);
    // Canary: if a future edit stops tagging entries with `module`, this suite would pass
    // vacuously (an empty exclusion looks identical to a correct one). The corpus must actually
    // contain module-tagged entries for "excluded, not dropped" to mean anything.
    expect(CORPUS.some((e) => e.module !== undefined)).toBe(true);
    expect(scored.length).toBeLessThan(CORPUS.length);
  });

  it("every entry mechanicalCorpus excludes is still accounted for in the per-module census — excluded is not the same as gone", () => {
    const excluded = CORPUS.filter((e) => e.module !== undefined);
    const census = moduleCensus(CORPUS);
    const censusModules = new Set(census.map((c) => c.module));
    for (const e of excluded) {
      // The entry's module must appear as its own census row (not folded into M1, not missing).
      expect(censusModules.has(e.module as string), `${e.id} (module ${e.module}) missing from census`).toBe(true);
      const row = census.find((c) => c.module === e.module)!;
      expect(row.positivesStatic + row.positivesConnected + row.negatives, `${e.module} census row is empty`).toBeGreaterThan(0);
    }
  });
});

describe("buildCoverageMatrix", () => {
  it("excludes connected-tier AND no-rule-tier entries from the static positive total", () => {
    const m = buildCoverageMatrix([], CORPUS);
    const connected = CORPUS.filter((e) => e.expectedTier === "connected").length;
    expect(m.connectedNa).toBe(connected);
    // positivesTotal is the "must be caught" denominator: connected (live DB) and "none" (no
    // mechanical rule by design) are both out of it — neither is a recall miss when uncaught.
    expect(m.positivesTotal).toBe(CORPUS.filter((e) => e.kind === "positive" && e.expectedTier !== "connected" && e.expectedTier !== "none").length);
    expect(m.noRuleTotal).toBe(CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none").length);
    expect(m.negativesTotal).toBe(CORPUS.filter((e) => e.kind === "negative" && e.expectedTier !== "connected").length);
  });

  it("with zero findings: no positive is caught and every negative is cleared", () => {
    const m = buildCoverageMatrix([], CORPUS);
    expect(m.positivesCaught).toBe(0);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(false); // positives uncaught
  });

  it("ok is true only when every static positive is caught and every negative cleared", () => {
    // Synthesize one high-tier finding per static positive at its fixture location. A
    // manifest-pinned entry gets the real dependency-finding shape, "<manifest> (<pkg>)". A
    // "none"-tier positive is EXCLUDED: fabricating a finding for it would (correctly) fail its
    // by-design gap — that inverse behavior gets its own test below.
    const staticPositives = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier !== "connected" && e.expectedTier !== "none");
    const synth: Finding[] = staticPositives.map((e) =>
      finding({
        location: e.manifest ? `${e.manifest} (${e.location})` : `${e.location}:1`,
        title: (e.match ?? [""])[0],
        taxonomy: (e.match ?? [""])[0],
        precisionTier: "high",
      }),
    );
    const m = buildCoverageMatrix(synth, CORPUS);
    expect(m.positivesCaught).toBe(m.positivesTotal);
    // Negatives whose location substring collides with a synthesized positive location would
    // fail here; assert none do (guards against ambiguous corpus locations).
    expect(m.negativesCleared).toBe(m.negativesTotal);
    // No-rule gaps hold (nothing was fabricated at their class), so ok stays true.
    expect(m.noRuleHeld).toBe(m.noRuleTotal);
    expect(m.ok).toBe(true);
  });

  it("no-rule-tier positive: intended gap holds while silent, flips the gate loud once a rule fires", () => {
    // The "none" tier encodes an accepted no-mechanical-rule gap (#425). With no relevant finding
    // it passes as an intended gap and is kept OUT of the recall denominator — never a miss.
    const noRule = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none");
    expect(noRule.length, "expected at least one no-rule-tier corpus entry to exercise this path").toBeGreaterThan(0);
    const entry = noRule[0]!;

    const held = scoreEntry(entry, []);
    expect(held.pass, "an unfired by-design gap must pass").toBe(true);
    expect(held.detail).toContain("intended gap");

    // A finding of the entry's class at its location = a rule graduated. The gap must flip loud:
    // the entry fails, and buildCoverageMatrix.ok goes false so `pnpm verify` / the live gate catch
    // it. This is the whole point — a by-design gap can never silently become a claimed catch.
    const graduated = finding({
      location: `${entry.location}:1`,
      title: (entry.match ?? [""])[0],
      taxonomy: (entry.match ?? [""])[0],
      precisionTier: "review",
    });
    const flipped = scoreEntry(entry, [graduated]);
    expect(flipped.pass, "a rule firing on a by-design gap must fail the entry").toBe(false);
    expect(flipped.detail).toContain("REGRESSION");
    expect(buildCoverageMatrix([graduated], [entry]).ok).toBe(false);
  });
});

describe("#221 authz corpus (live detectAppRouterFindings output over the committed fixture)", () => {
  // Unlike the recorded-output batches above, this scores the REAL detector against the REAL
  // committed fixture — so the answer key can't drift away from what the scanner actually emits.
  const findings = detectAppRouterFindings(
    m9AuthzEntries.map((e) => ({
      path: e.location,
      text: readFileSync(join(import.meta.dirname, "../../targets/calibration", e.location), "utf8"),
    })),
  );

  it("catches the planted client-supplied-owner-id bug and clears both near-miss negatives", () => {
    for (const e of m9AuthzEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("emits every finding with an explicit precisionTier — none reach the scorer untiered (#327)", () => {
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.precisionTier !== undefined)).toBe(true);
  });

  it("draws one finding per planted positive and stays silent on the benign siblings (#427 update + delete; #465 bare-id + insert-value)", () => {
    const authed = findings.filter((f) => f.taxonomy === "M1 — Client-supplied owner id trusted by authenticated action");
    expect(authed).toHaveLength(2);
    const authedTitles = authed.map((h) => h.title).join(" | ");
    expect(authedTitles).toContain("updateProfileName");
    expect(authedTitles).toContain("deleteAccount");

    const noauth = findings.filter((f) => f.taxonomy === "M1 — Client-supplied owner id trusted by unauthenticated service-role action");
    expect(noauth).toHaveLength(2);
    const noauthTitles = noauth.map((h) => h.title).join(" | ");
    expect(noauthTitles).toContain("updateUserProfile");
    expect(noauthTitles).toContain("addMember");
  });

  it("subsumes the generic missing-auth finding on the #465 no-auth positives, but NOT on the RLS-client negative", () => {
    // One code defect, one finding: the widened owner-id finding carries the no-auth fact for
    // the service-role fixtures, while the RLS-client near-miss keeps the generic finding
    // (its defect really is just "no visible auth check").
    const missingAuth = findings.filter((f) => f.taxonomy === "M1 — Server Action missing authorization check");
    expect(missingAuth.map((f) => f.location).join(" | ")).toContain("actions-rls-bareid.ts");
    expect(missingAuth.filter((f) => f.location.includes("actions-svc-"))).toHaveLength(0);
  });

  it("keeps the class out of the free count — the AST cannot prove authorization is absent elsewhere", () => {
    const m = buildCoverageMatrix(findings, m9AuthzEntries);
    expect(m.positivesCaughtHigh).toBe(0);
    expect(m.negativesCleared).toBe(m.negativesTotal);
    expect(m.ok).toBe(true);
  });
});

describe("#848 M9 per-check corpus (live detectAppRouterFindings over the committed __fixtures__)", () => {
  // Each of the nine non-owner-id M9 checks bound to its detector's own committed fixtures. Fixtures
  // are loaded from src/detectors/__fixtures__/<dir>/<kind> and path-prefixed to the entry's
  // globally-unique `m9-corpus/<check>/<kind>` location, then scored with the SAME scoreEntry the
  // rest of the corpus uses — so the answer key can't drift from what the scanner emits, and no
  // file lands in the scanned calibration target.
  const FIXTURES_ROOT = fileURLToPath(new URL("../detectors/__fixtures__/", import.meta.url));
  function loadPrefixed(dir: string, prefix: string): SourceInput[] {
    const root = join(FIXTURES_ROOT, dir);
    const files: SourceInput[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d)) {
        const full = join(d, e);
        if (statSync(full).isDirectory()) walk(full);
        else if (e.endsWith(".txt")) files.push({ path: `${prefix}/${relative(root, full).replace(/\.txt$/, "").split(sep).join("/")}`, text: readFileSync(full, "utf8") });
      }
    };
    walk(root);
    return files;
  }

  const CHECKS: { check: string; dir: string; neg: string; framework?: TargetFramework }[] = [
    { check: "leak", dir: "server-client-leak", neg: "negative" },
    { check: "serveronly", dir: "missing-server-only", neg: "negative" },
    { check: "action-auth", dir: "server-action-auth", neg: "negative" },
    { check: "action-validation", dir: "server-action-validation", neg: "negative" },
    { check: "cache", dir: "cache-config", neg: "negative" },
    { check: "waterfall", dir: "waterfall", neg: "negative" },
    { check: "dynamic", dir: "dynamic-rendering", neg: "negative" },
    { check: "ssr", dir: "ssr-browser-api", neg: "negative-typeof" },
    { check: "spa", dir: "spa-error-boundary", neg: "negative-has-boundary", framework: "vite" },
  ];

  it("catches each check's planted positive at review tier and clears its boundary negative", () => {
    // Every M9 check the corpus names must have exactly one pos + one neg entry backing it.
    expect(m9CheckEntries.filter((e) => e.kind === "positive")).toHaveLength(CHECKS.length);
    expect(m9CheckEntries.filter((e) => e.kind === "negative")).toHaveLength(CHECKS.length);

    for (const { check, dir, neg, framework } of CHECKS) {
      const posEntry = m9CheckEntries.find((e) => e.location === `m9-corpus/${check}/positive`);
      const negEntry = m9CheckEntries.find((e) => e.location === `m9-corpus/${check}/negative`);
      expect(posEntry, `${check} positive entry`).toBeDefined();
      expect(negEntry, `${check} negative entry`).toBeDefined();

      const posFindings = detectAppRouterFindings(loadPrefixed(`${dir}/positive`, `m9-corpus/${check}/positive`), framework);
      const posRow = scoreEntry(posEntry!, posFindings);
      expect(posRow.pass, `${posEntry!.id}: ${posRow.detail}`).toBe(true);
      expect(posRow.caughtTier, posEntry!.id).toBe("review");

      const negFindings = detectAppRouterFindings(loadPrefixed(`${dir}/${neg}`, `m9-corpus/${check}/negative`), framework);
      const negRow = scoreEntry(negEntry!, negFindings);
      expect(negRow.pass, `${negEntry!.id}: ${negRow.detail}`).toBe(true);
      expect(negRow.highFlagged, `${negEntry!.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("keeps the whole M9-check class out of the free count (review tier only)", () => {
    // No M9 heuristic may inflate the security free count — every positive is review, not high.
    for (const { check, dir, framework } of CHECKS) {
      const findings = detectAppRouterFindings(loadPrefixed(`${dir}/positive`, `m9-corpus/${check}/positive`), framework);
      const m = buildCoverageMatrix(findings, m9CheckEntries.filter((e) => e.location === `m9-corpus/${check}/positive`));
      expect(m.positivesCaughtHigh, check).toBe(0);
    }
  });
});

describe("#917/#918 M9 port corpus (live detectAppRouterFindings over the Remix/TanStack fixtures)", () => {
  // The boundary-model ports (#916) graded: each ported check's fixture (src/detectors/__fixtures__/
  // {remix,tanstack}/<check>/{positive,negative}) is loaded, path-prefixed to the entry's
  // `m9-<fw>-corpus/<check>/<kind>` location, run through detectAppRouterFindings with the framework
  // flag, and scored with the SAME scoreEntry the rest of the corpus uses.
  const FIXTURES_ROOT = fileURLToPath(new URL("../detectors/__fixtures__/", import.meta.url));
  function loadPrefixed(dir: string, prefix: string): SourceInput[] {
    const root = join(FIXTURES_ROOT, dir);
    const files: SourceInput[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d)) {
        const full = join(d, e);
        if (statSync(full).isDirectory()) walk(full);
        else if (e.endsWith(".txt")) files.push({ path: `${prefix}/${relative(root, full).replace(/\.txt$/, "").split(sep).join("/")}`, text: readFileSync(full, "utf8") });
      }
    };
    walk(root);
    return files;
  }

  const PORTS: { fw: string; dir: string; framework: TargetFramework }[] = [
    { fw: "remix", dir: "remix", framework: "remix" },
    { fw: "tanstack", dir: "tanstack", framework: "tanstack-start" },
  ];
  const CHECKS = ["leak", "action-authz", "action-validation"];

  it("catches each ported check's planted positive at review tier and clears its negative", () => {
    // Every port × check must have exactly one pos + one neg entry backing it.
    expect(m9PortEntries.filter((e) => e.kind === "positive")).toHaveLength(PORTS.length * CHECKS.length);
    expect(m9PortEntries.filter((e) => e.kind === "negative")).toHaveLength(PORTS.length * CHECKS.length);

    for (const { fw, dir, framework } of PORTS) {
      for (const check of CHECKS) {
        const posLoc = `m9-${fw}-corpus/${check}/positive`;
        const negLoc = `m9-${fw}-corpus/${check}/negative`;
        const posEntry = m9PortEntries.find((e) => e.location === posLoc);
        const negEntry = m9PortEntries.find((e) => e.location === negLoc);
        expect(posEntry, `${fw}/${check} positive entry`).toBeDefined();
        expect(negEntry, `${fw}/${check} negative entry`).toBeDefined();

        const posFindings = detectAppRouterFindings(loadPrefixed(`${dir}/${check}/positive`, posLoc), framework);
        const posRow = scoreEntry(posEntry!, posFindings);
        expect(posRow.pass, `${posEntry!.id}: ${posRow.detail}`).toBe(true);
        expect(posRow.caughtTier, posEntry!.id).toBe("review");

        const negFindings = detectAppRouterFindings(loadPrefixed(`${dir}/${check}/negative`, negLoc), framework);
        const negRow = scoreEntry(negEntry!, negFindings);
        expect(negRow.pass, `${negEntry!.id}: ${negRow.detail}`).toBe(true);
        expect(negRow.highFlagged, `${negEntry!.id} must not be a free-count FP`).toBe(false);
      }
    }
  });

  it("discloses every non-ported check as a not-assessed row naming it (partial coverage stated)", () => {
    // A Remix target routes to the adapter; the checks it does NOT implement each draw a
    // not-assessed row, so partial coverage is never silently upgraded to full (#872 discipline).
    const findings = detectAppRouterFindings(loadPrefixed("remix/leak/positive", "m9-remix-corpus/leak/positive"), "remix");
    const notAssessed = findings.filter((f) => f.taxonomy.includes("not assessed") && f.confidence === "N/A");
    expect(notAssessed.length).toBeGreaterThan(0);
    // client-owner-id, server-only, route-segment/cache/dynamic-rendering config, Suspense, and the
    // route.ts handler convention have no Remix analogue and must each be named.
    expect(notAssessed.some((f) => f.taxonomy.includes("cache config"))).toBe(true);
    expect(notAssessed.some((f) => f.taxonomy.includes("Suspense"))).toBe(true);
    expect(notAssessed.every((f) => f.taxonomy.includes("Remix"))).toBe(true);
  });
});

describe("#374 static auth_rls_initplan corpus (live checkMigrationRlsInitplanStatic over the committed fixture)", () => {
  // Like the #221 block above: the REAL check against the REAL committed SQL fixtures, so the
  // answer key can't drift from what the scanner emits. The plants are the SAME migration the
  // connected-tier M7-P-RLS-INITPLAN / M7-N-WRAPPED-RLS pair scores against — no new SQL needed.
  const findings = checkMigrationRlsInitplanStatic(join(import.meta.dirname, "../../targets/calibration"));

  it("catches the bare-auth.uid() plant at review tier and clears the (select …)-wrapped sibling", () => {
    for (const e of m7InitplanStaticEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.reviewFlagged, `${e.id} must draw no finding at all`).toBe(false);
    }
  });

  it("keeps every finding of this class at review tier — a perf lint never inflates the security free count", () => {
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.precisionTier === "review")).toBe(true);
  });

  it("also surfaces the corpus's other bare auth.* policies without flagging any (select …)-wrapped one", () => {
    // The check runs over the whole migration set: the b15 storage own-folder policies and the
    // invoices auth.role() policy carry bare auth.* calls too (Splinter would lint them all).
    // Cross-class corpus negatives (e.g. N-STORAGE-OWNERSHIP-SCOPED-STATIC) keyword-match these
    // findings, which is exactly why the class stays at review tier: review hits are triaged out,
    // never free-count FPs.
    const flagged = findings.map((f) => f.location);
    expect(flagged.some((l) => l.includes("perf_orders_select_own"))).toBe(true);
    expect(flagged.every((l) => !l.includes("perf_events_select_own"))).toBe(true);
  });
});
