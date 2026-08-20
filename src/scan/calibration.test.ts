import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { readEntriesSafe, readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { AUDIT_MODULES, buildCoverageMatrix, CORPUS, darkenEntry, fatalRecallMisses, formatSelfMatchingKeys, isLiveTier, mechanicalCorpus, MIN_NEGATIVES_PER_MODULE, MIN_POSITIVES_PER_MODULE, moduleCensus, parityVerdict, scoreEntry, selfMatchingKeys, corpusMatchKeyedRows, unkeyedPositives, type CorpusEntry, type MatrixRow } from "./calibration.js";
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
import { owaspNodejsEntries } from "./calibration/owasp-nodejs.entries.js";
import { owaspReactEntries } from "./calibration/owasp-react.entries.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import type { TargetFramework } from "./framework-detect.js";
import type { SourceInput } from "../detectors/app-router.js";
import { secretsEntries } from "./calibration/secrets.entries.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { detectBolaOwnerFindings } from "./bola-owner.js";
import { detectCounterRaceFindings } from "./counter-race.js";
import { detectIdempotencyFindings } from "./idempotency.js";
import { walkSourceFiles } from "./common.js";
import { classifyLeftoverAuth } from "./leftover-auth.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs } from "./dependencies.js";
import { parseGitleaksFindings, type GitleaksResult } from "./secrets.js";
import { checkPublicDirSensitive, parseSemgrepFindings, type SemgrepResult } from "./semgrep.js";
import { checkEdgeFunctionVerifyJwt, checkMigrationDefinerAnonGrant, checkMigrationDefinerAuthz, checkMigrationDynamicSqlInjection, checkMigrationPolicySemantics, checkMigrationRlsInitplanStatic, checkMigrationRlsStatic, checkMigrationStorageBuckets, checkOpenSignupConfig } from "./supabase-static.js";
import { m7InitplanStaticEntries } from "./calibration/m7-initplan-static.entries.js";
import { checkKnownIoc, checkLockfilePresence } from "./supply-chain.js";
import { moduleMatches } from "./external-corpus.js";
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

  // #1344: the blind spot that let a precision regression reach main with every gate green. A
  // negative used to pass on "no high-tier hit" alone, so a widened rule that lit one up at REVIEW
  // tier scored "cleared (review-tier hit only)" — #1251's harvey-path-traversal on N-STORAGE-DB-PATH
  // surfaced only by hand-diffing dry-run/findings.json. A review-tier hit now has to be RECORDED.
  it("clears a negative whose review-tier hit is recorded in reviewTierHits (triaged out of the count)", () => {
    const e = entry({ id: "N-DSIH", kind: "negative", cls: "dsih", location: "about.js", reviewTierHits: ["audit dsih"], note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/about.js:11", taxonomy: "audit dsih", precisionTier: "review" })]);
    expect(row.pass).toBe(true);
    expect(row.reviewFlagged).toBe(true);
  });

  it("#1344: FAILS a negative that draws an UNRECORDED review-tier finding, naming the taxonomy", () => {
    const e = entry({ id: "N-DSIH", kind: "negative", cls: "dsih", location: "about.js", note: "" });
    const row = scoreEntry(e, [finding({ location: "pages/about.js:11", taxonomy: "audit dsih", precisionTier: "review" })]);
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("REVIEW-TIER REGRESSION");
    expect(row.detail).toContain("audit dsih");
  });

  it("#1344: a recorded taxonomy does not excuse a DIFFERENT review-tier rule arriving later", () => {
    const e = entry({ id: "N-DSIH", kind: "negative", cls: "dsih", location: "about.js", reviewTierHits: ["audit dsih"], note: "" });
    const row = scoreEntry(e, [
      finding({ location: "pages/about.js:11", taxonomy: "audit dsih", precisionTier: "review" }),
      finding({ location: "pages/about.js:12", taxonomy: "harvey-path-traversal", precisionTier: "review" }),
    ]);
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("harvey-path-traversal");
    expect(row.detail).not.toContain("audit dsih");
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

  // #1428 — the defect this replaced. A live-tier row used to be `pass: true` UNCONDITIONALLY with no
  // way for a caller to tell it apart from a scored pass, and no consumer anywhere scored one against
  // a live run: gutting all three B24 detector bodies left `validate-calibration` exiting 0 with
  // byte-identical output. These three cases are the offline half of the fix (the live half is
  // src/cli/validate-connected.ts, which needs a live stack and so runs outside `pnpm verify`):
  // NOT SCORED is flagged, a run that HAS the venue scores it for real, and — the negative control —
  // that scoring can FAIL. A gate nobody has watched fail is indistinguishable from a dead one.
  it("flags a live-tier entry NOT SCORED when the run has no such venue — a pass nobody can read as a result", () => {
    const e = entry({ id: "P-RLS", kind: "positive", cls: "rls", location: "audit_logs", expectedTier: "local", note: "" });
    const row = scoreEntry(e, []);
    expect(row.pass).toBe(true);
    expect(row.notScored).toBe(true);
    expect(row.detail).toContain("NOT SCORED");
  });

  it("scores a live-tier entry for real when the run declares its venue (#1428)", () => {
    const e = entry({ id: "P-RLS", kind: "positive", cls: "rls", location: "audit_logs", match: ["rls"], expectedTier: "local", note: "" });
    const row = scoreEntry(e, [finding({ location: "public.audit_logs", title: "RLS disabled", precisionTier: "high" })], new Set(["local"]));
    expect(row.notScored).toBe(false);
    expect(row.pass).toBe(true);
    expect(row.caughtTier).toBe("high");
  });

  it("FAILS a live-tier entry whose detector went silent, once its venue is declared (#1428)", () => {
    const e = entry({ id: "P-RLS", kind: "positive", cls: "rls", location: "audit_logs", match: ["rls"], expectedTier: "local", note: "" });
    const row = scoreEntry(e, [], new Set(["local"]));
    expect(row.notScored).toBe(false);
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("NOT caught");
    // ...and a run WITHOUT that venue must not turn the same silence into a pass anyone can quote.
    expect(scoreEntry(e, []).notScored).toBe(true);
  });

  it("scores only the venues the run declares — a `connected` row stays NOT SCORED on a local-only run (#1428)", () => {
    const e = entry({ id: "P-SCHEMA", kind: "positive", cls: "schema", location: "internal_ops", expectedTier: "connected", note: "" });
    expect(scoreEntry(e, [], new Set(["local"])).notScored).toBe(true);
    expect(scoreEntry(e, [], new Set(["local", "connected"])).notScored).toBe(false);
  });

  // #1157 — severity correctness. The gate must fail on a caught-but-MIS-RATED positive the way it
  // fails on a miss (#1063 shipped every CVE Medium; #1060 never escalated). These are the planted
  // wrong-severity negative controls proving the check FIRES, plus the it-passes-when-right control.
  it("passes severity when a caught positive delivers its answer-keyed severity (#1157)", () => {
    const e = entry({ id: "P-CVE", kind: "positive", cls: "cve", location: "package.json", match: ["minimist"], expectedTier: "high", expectedSeverity: "Critical", note: "" });
    const row = scoreEntry(e, [finding({ location: "package.json (minimist)", title: "minimist proto pollution", severity: "Critical", precisionTier: "high" })]);
    expect(row.pass).toBe(true);
    expect(row.severityMismatch).toBe(false);
    expect(row.deliveredSeverities).toEqual(["Critical"]);
  });

  it("FLAGS a caught positive delivered at the wrong severity (#1157 negative control)", () => {
    const e = entry({ id: "P-CVE", kind: "positive", cls: "cve", location: "package.json", match: ["minimist"], expectedTier: "high", expectedSeverity: "Critical", note: "" });
    // The exact #1063 shape: a real Critical CVE shipped as Medium. Detection passes (it was caught);
    // the severity assertion must fail.
    const row = scoreEntry(e, [finding({ location: "package.json (minimist)", title: "minimist proto pollution", severity: "Medium", precisionTier: "high" })]);
    expect(row.pass).toBe(true); // still caught — detection is fine
    expect(row.severityMismatch).toBe(true); // ...but the rating is wrong
    expect(row.detail).toContain("MISRATED");
  });

  it("does not score severity for an entry without an answer-keyed severity, or for a miss (#1157)", () => {
    const unannotated = entry({ id: "P-X", kind: "positive", cls: "x", location: "search.js", match: ["sql"], expectedTier: "high", note: "" });
    expect(scoreEntry(unannotated, [finding({ location: "search.js:1", taxonomy: "SQL injection", severity: "Low", precisionTier: "high" })]).severityMismatch).toBe(false);
    const missed = entry({ id: "P-Y", kind: "positive", cls: "y", location: "nowhere.js", match: ["nope"], expectedTier: "high", expectedSeverity: "Critical", note: "" });
    expect(scoreEntry(missed, []).severityMismatch).toBe(false); // a miss fails on detection, not severity
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

  // #1190/#1194's own answer key had the self-match hole: a finding's id derives from its FILE
  // PATH, so a match keyword that is a substring of the entry's own location makes ANY finding on
  // that fixture satisfy the entry. Scored against the REAL corpus row, not a synthetic one, so a
  // future edit that re-widens the phrase fails here rather than going quiet in the gate.
  const clientTenant = () => {
    const e = CORPUS.find((x) => x.id === "P-OWASP-MT-CLIENT-TENANT");
    if (!e) throw new Error("P-OWASP-MT-CLIENT-TENANT missing from the corpus");
    return e;
  };
  const onClientTenantFixture = (partial: Partial<Finding>) =>
    finding({ location: "targets/calibration/src/owasp-mt/client-supplied-tenant.ts:42", precisionTier: "high", ...partial });

  it("is not satisfied by an unrelated finding that merely lands on the client-supplied-tenant fixture", () => {
    const row = scoreEntry(clientTenant(), [
      onClientTenantFixture({ id: "SEC-XSS-src-owasp-mt-client-supplied-tenant-ts-42", title: "Reflected XSS", taxonomy: "Cross-site scripting", evidence: "res.send(`<p>${q}</p>`)" }),
    ]);
    expect(row.pass).toBe(false);
    expect(row.caughtTier).toBeUndefined();
  });

  it("is not satisfied by its Supabase sibling's finding, which shares the fixture and the taxonomy", () => {
    // P-OWASP-MT-CLIENT-TENANT-SUPABASE is a SEPARATE row for the .eq() builder sink. If this row
    // accepted that finding, the Prisma/Drizzle object-key detection could go silent with the gate
    // green — one probe's finding standing in for another's (#1062).
    const row = scoreEntry(clientTenant(), [
      onClientTenantFixture({
        id: "AUTH-client-supplied-tenant-tenant_id-src-owasp-mt-client-supplied-tenant-ts-1088",
        taxonomy: "Object-level authorization gap: tenant predicate populated from the request",
        evidence: 'Heuristic "client-supplied-tenant": `.eq("tenant_id", …)` scopes on `tenant_id`, and that value traces to `req.json()`.',
      }),
    ]);
    expect(row.pass).toBe(false);
  });

  it("still catches the Prisma object-key finding it exists to score", () => {
    const row = scoreEntry(clientTenant(), [
      onClientTenantFixture({
        id: "AUTH-client-supplied-tenant-tenantId-src-owasp-mt-client-supplied-tenant-ts-553",
        taxonomy: "Object-level authorization gap: tenant predicate populated from the request",
        evidence: 'Heuristic "client-supplied-tenant": `prisma.invoice.findMany` scopes on `tenantId`, and that value traces to `req.json()`.',
      }),
    ]);
    expect(row.pass).toBe(true);
    expect(row.caughtTier).toBe("high");
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
  // script no SRI, ISR revalidate no secret, CRLF header injection ×3 incl. the multi-hop source
  // and the #1224 App Router searchParams one,
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
    warning("harvey-crlf-header-injection", "app/api/ar-crlf-search/route.ts"),
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

  it("promotes only the exact config-parse / literal / filesystem sinks to the free count (6 high, 7 review)", () => {
    const m = buildCoverageMatrix(findings, b12NextconfigEntries);
    const positives = b12NextconfigEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(6);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(7);
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
    warning("harvey-dynamic-dispatch", "client-url-source/dynamic-dispatch-client.ts"),
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
      "create table workspaces (id uuid primary key);\ncreate table members (id uuid primary key);\nalter table members enable row level security;\ncreate table private.internal_audit (id uuid primary key);\n" +
      // #1323 — the SIX checks that read SQL through readMigrations, which was supabase/migrations-only
      // and therefore returned [] on this exact shape. Each planted defect is paired with the near-miss
      // that must stay silent, so a reverted reader fails here rather than in a review-tier-only gate
      // that exits 0 on a miss.
      "create table public.nocode_invoices (id uuid primary key, tenant_id uuid not null, owner_id uuid not null);\n" +
      "alter table public.nocode_invoices enable row level security;\n" +
      "create policy nocode_invoices_read on public.nocode_invoices for select to authenticated using (true);\n" +
      "create policy nocode_invoices_write on public.nocode_invoices for insert to authenticated with check (tenant_id = ((select auth.jwt()) ->> 'tenant_id')::uuid);\n" +
      "create policy nocode_invoices_own on public.nocode_invoices for update to authenticated using (tenant_id = ((select auth.jwt()) ->> 'tenant_id')::uuid and owner_id = auth.uid());\n" +
      "create or replace function public.nocode_set_role(target_user_id uuid, new_role text) returns void language plpgsql security definer as $$\nbegin\n  update public.profiles set role = new_role where id = target_user_id;\nend;\n$$;\n" +
      "create or replace function public.nocode_promote_guarded(target_user_id uuid, new_role text) returns void language plpgsql security definer as $$\nbegin\n  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then\n    raise exception 'not authorized';\n  end if;\n  update public.profiles set role = new_role where id = target_user_id;\nend;\n$$;\n" +
      "create or replace function public.nocode_search_invoices(p_filter text) returns setof public.nocode_invoices language plpgsql security definer as $$\nbegin\n  return query execute 'select * from public.nocode_invoices where amount::text like ''%' || p_filter || '%''';\nend;\n$$;\n" +
      "create or replace function public.nocode_bound_invoice_query(p_filter text) returns setof public.nocode_invoices language plpgsql security definer as $$\nbegin\n  return query execute 'select * from public.nocode_invoices where amount::text like $1' using p_filter;\nend;\n$$;\n" +
      "create or replace function public.nocode_all_invoices() returns setof public.nocode_invoices language plpgsql security definer as $$\nbegin\n  return query select * from public.nocode_invoices;\nend;\n$$;\ngrant execute on function public.nocode_all_invoices() to anon;\n" +
      "insert into storage.buckets (id, name, public) values ('nocode-attachments', 'nocode-attachments', true);\n" +
      "insert into storage.buckets (id, name, public) values ('nocode-private', 'nocode-private', false);\n" +
      "create policy nocode_attachments_anon_read on storage.objects for select to anon using (bucket_id = 'nocode-attachments');\n" +
      "create policy nocode_private_owner_read on storage.objects for select to anon using (bucket_id = 'nocode-private' and owner = (select auth.uid()));\n",
  );
  // #1425 — protect-then-unprotect, in its OWN dir so the "flags only audit_logs" test below keeps
  // supaDir focused. Three files, mirroring targets/calibration: billing_exports and import_staging
  // are created protected, a hotfix disables both, and only import_staging is reverted. export_audit
  // is the scope control — it proves the setup file was read, which neither #1425 entry can do.
  const rlsDisableDir = mkdtempSync(join(tmpdir(), "harvey-b13-rlsdisable-"));
  afterAll(() => rmSync(rlsDisableDir, { recursive: true, force: true }));
  mkdirSync(join(rlsDisableDir, "supabase", "migrations"), { recursive: true });
  writeFileSync(
    join(rlsDisableDir, "supabase", "migrations", "20260728000002_rls_disable_tables.sql"),
    "create table public.billing_exports (id uuid primary key);\nalter table public.billing_exports enable row level security;\n" +
      "create table public.import_staging (id uuid primary key);\nalter table public.import_staging enable row level security;\n" +
      "create table public.export_audit (id uuid primary key);\n",
  );
  writeFileSync(
    join(rlsDisableDir, "supabase", "migrations", "20260728000003_rls_disable_hotfix.sql"),
    "alter table public.billing_exports disable row level security;\nalter table public.import_staging disable row level security;\n",
  );
  writeFileSync(
    join(rlsDisableDir, "supabase", "migrations", "20260728000004_rls_disable_revert.sql"),
    "alter table public.import_staging enable row level security;\n",
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
    ...checkMigrationRlsStatic(rlsDisableDir), // #1425
    ...checkEdgeFunctionVerifyJwt(supaDir),
    ...checkOpenSignupConfig(supaDir),
    ...checkMigrationDynamicSqlInjection(supaDir), // #602 CX-12
    ...checkMigrationDefinerAnonGrant(supaDir), // #602 CX-11
    // #1323 — the six checks that fed off readMigrations, run over the ROOT-SCHEMA dir. Before the
    // fix every one of these returned [] here.
    ...checkMigrationPolicySemantics(rootSchemaDir),
    ...checkMigrationDefinerAuthz(rootSchemaDir),
    ...checkMigrationDynamicSqlInjection(rootSchemaDir),
    ...checkMigrationDefinerAnonGrant(rootSchemaDir),
    ...checkMigrationStorageBuckets(rootSchemaDir),
    ...checkMigrationRlsInitplanStatic(rootSchemaDir),
  ];

  it("catches every B13 positive at its declared tier and clears every B13 negative", () => {
    for (const e of b13SupaEntries) {
      const row = scoreEntry(e, findings);
      expect(row.pass, `${e.id}: ${row.detail}`).toBe(true);
      if (e.kind === "positive") expect(row.caughtTier, e.id).toBe(e.expectedTier);
      else expect(row.highFlagged, `${e.id} must not be a free-count FP`).toBe(false);
    }
  });

  it("promotes only the exact static/structural sinks to the free count (10 high, 12 review)", () => {
    const m = buildCoverageMatrix(findings, b13SupaEntries);
    const positives = b13SupaEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    // 8 before #1425; +2 for the protect-then-unprotect plant and its scope control.
    expect(m.positivesCaughtHigh).toBe(10);
    // 12 before #1323; +7 for the root-schema probes of the six checks readMigrations feeds
    // (checkMigrationStorageBuckets contributes two, one per half); +1 for #1708 client dispatch.
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(20);
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
    // #991 — allowlist-grant / multi-hop authz decision from untrusted input, and its session-gated twin.
    { path: "pages/api/authorize.js", content: "const userInput = req.body.action || \"\"; const data = String(userInput).split(\",\").join(\",\"); const allowedActions = [\"read\", \"write\", \"admin\"]; if (allowedActions.includes(String(data))) { res.json({ access: \"granted\", role: \"admin\" }); return; } res.json({ done: true });" },
    { path: "pages/api/authorize-safe.js", content: "function authzCheck(user, resource) { return Boolean(user) && Array.isArray(user.roles) && user.roles.includes(String(resource)); } const data = String(req.body.action || \"\"); const allowedActions = [\"read\", \"write\", \"admin\"]; if (!authzCheck(req.session.user, data)) { res.status(403).json({ error: \"forbidden\" }); return; } if (allowedActions.includes(data)) { res.json({ ok: true }); }" },
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

  it("promotes none of the app-logic heuristics to the free count (0 high, 8 review)", () => {
    const m = buildCoverageMatrix(findings, b14AppLogicEntries);
    const positives = b14AppLogicEntries.filter((e) => e.kind === "positive");
    expect(m.positivesCaught).toBe(positives.length);
    expect(m.positivesCaughtHigh).toBe(0);
    expect(positives.filter((e) => e.expectedTier === "review")).toHaveLength(8);
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
  const mechanicalFixtures = walkSourceFiles(CAL);
  const findings = [
    ...leftoverFixtures.flatMap((f) => classifyLeftoverAuth(f)),
    ...detectCounterRaceFindings(mechanicalFixtures),
    ...detectIdempotencyFindings(mechanicalFixtures),
    ...detectBolaOwnerFindings(mechanicalFixtures),
  ];

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
    const race = detectCounterRaceFindings(mechanicalFixtures).filter((f) => f.taxonomy === "Non-atomic read-modify-write race condition");
    expect(race).toHaveLength(1);
    expect(race[0]?.location).toContain("counter/increment.js");
  });

  it("the #433 bola-owner AST fires exactly once across the whole target — every other pages/api fixture stays silent", () => {
    // One hit total pins more than the corpus pair: the session-scoped sibling (invoice-safe),
    // the no-session handlers (order/get.js P-IDOR-PARAM, admin/dashboard.js P-MW-SOLE-AUTHZ —
    // whose by-design LLM-tier status this pass must not swallow), and the bare-id IDOR shape
    // (order/scoped.js) are all non-hits, measured, not assumed.
    const bola = detectBolaOwnerFindings(mechanicalFixtures);
    expect(bola).toHaveLength(1);
    expect(bola[0]?.location).toContain("pages/api/billing/invoice.js");
    expect(bola[0]?.precisionTier).toBe("review");
  });
});

describe("moduleCensus (#341 — per-module legibility so a blended count can't imply uniform coverage)", () => {
  it("tallies each module's fixtures and keeps thin modules visible, not averaged away", () => {
    const census = moduleCensus(CORPUS);
    const byModule = new Map(census.map((c) => [c.module, c]));

    // #1314: the census is exhaustive over the ten modules, not over what the corpus happens to
    // tag. A module with zero entries must still emit a row — an absent row cannot be flagged.
    expect(census.map((c) => c.module)).toEqual([...AUDIT_MODULES]);
    const modulesInCorpus = new Set(CORPUS.map((e) => e.module ?? "M1"));
    for (const m of modulesInCorpus) expect(AUDIT_MODULES).toContain(m);

    // The census must equal a direct recount — a thin module reads as thin, not blended into M1.
    for (const m of modulesInCorpus) {
      const entries = CORPUS.filter((e) => (e.module ?? "M1") === m);
      const row = byModule.get(m)!;
      expect(row.negatives).toBe(entries.filter((e) => e.kind === "negative").length);
      expect(row.positivesConnected).toBe(entries.filter((e) => e.kind === "positive" && isLiveTier(e.expectedTier)).length);
      expect(row.positivesStatic).toBe(entries.filter((e) => e.kind === "positive" && !isLiveTier(e.expectedTier)).length);
    }

    // M1 rows first, then ascending module number.
    expect(census[0]?.module).toBe("M1");
    const nums = census.map((c) => Number(c.module.replace(/^M/, "")));
    expect(nums).toEqual([...nums].sort((a, b) => a - b));
  });
});

describe("#1314 parity minimum over ALL ten modules (the two with zero fixtures were the two it could not flag)", () => {
  it("a module with zero entries renders as a row reading 0 and trips the minimum", () => {
    const census = moduleCensus([]);
    expect(census.map((c) => c.module)).toEqual([...AUDIT_MODULES]);
    expect(census.every((c) => c.positivesStatic === 0 && c.positivesConnected === 0 && c.negatives === 0)).toBe(true);
    const { thin, exempt } = parityVerdict([]);
    expect([...thin.map((t) => t.module), ...exempt.map((e) => e.module)].sort()).toEqual([...AUDIT_MODULES].sort());
  });

  it("NEGATIVE CONTROL — deleting a module's entries makes the gate fail on that module", () => {
    const victim = "M9";
    expect(parityVerdict(CORPUS).thin.map((t) => t.module)).not.toContain(victim);
    const without = CORPUS.filter((e) => (e.module ?? "M1") !== victim);
    const thin = parityVerdict(without).thin;
    expect(thin.map((t) => t.module)).toContain(victim);
    expect(thin.find((t) => t.module === victim)?.missing).toBe(`0/${MIN_POSITIVES_PER_MODULE} positives and 0/${MIN_NEGATIVES_PER_MODULE} negatives`);
  });

  it("enforces the boundary-negative half, not only positives (#427's comment claimed it; nothing checked it)", () => {
    const positivesOnly = CORPUS.filter((e) => (e.module ?? "M1") !== "M8" || e.kind === "positive");
    const row = parityVerdict(positivesOnly).thin.find((t) => t.module === "M8");
    expect(row?.missing).toBe(`0/${MIN_NEGATIVES_PER_MODULE} negatives`);
  });

  it("M2 stands on a NAMED substitute gate, and an exemption a module no longer needs fails loud", () => {
    // M6 was the second exempt module until #1371/#1453. Its exemption's original ground — that a
    // planted single-file fixture could not express a whole-repo shape count — was measured false
    // twice independently (#1454 over one planted file, 3 of 3; #1453 over the full set, 33 of 33).
    // #1454 could not delete the row, only re-express it as decisional, because the fixtures did not
    // exist yet; it wrote the hand-off into the row instead. #1453 landed them, so the row went. The
    // `stale` check is what would have fired had it stayed — proven positively in the last block
    // below, not merely by this list coming back short.
    const { thin, exempt, stale } = parityVerdict(CORPUS);
    expect(thin).toEqual([]);
    expect(stale).toEqual([]);
    expect(exempt.map((e) => e.module)).toEqual(["M2"]);
    for (const e of exempt) expect(e.exemption.substituteGates.length).toBeGreaterThan(0);
    // A module that grows real fixtures must lose its exemption rather than keep hiding behind it.
    const withM2Fixtures: CorpusEntry[] = [
      ...CORPUS,
      entry({ id: "P-M2-A", kind: "positive", cls: "c", module: "M2", location: "a", note: "" }),
      entry({ id: "P-M2-B", kind: "positive", cls: "c", module: "M2", location: "b", note: "" }),
      entry({ id: "N-M2-A", kind: "negative", cls: "c", module: "M2", location: "c", note: "" }),
    ];
    expect(parityVerdict(withM2Fixtures).stale).toEqual(["M2"]);
  });
});

describe("a corpus entry id cited in a source comment must exist (#1484's third correction)", () => {
  // The defect this gates, found by review and not by any check: the rationale comment above
  // `GATE_DEPTH` in app-router.ts named the row that protects it with an extra hyphen in the middle
  // of `M9C-GATEDEPTH-NEG`. So the one grep a future reader would run — "which row catches me if I
  // lower this?" — returned NOTHING, and the comment read as if the answer were recorded when it
  // was not. That is the silent-omission shape: an argument resting on a citation nobody can
  // follow. (This block cites the CORRECT id on purpose; a comment that spelled the broken one out
  // would trip its own gate, which is the rule working.)
  //
  // POPULATION, MEASURED 2026-07-31 before the gate was written rather than assumed: 100 `-POS`/
  // `-NEG`-shaped references across the git-tracked `src/**/*.ts`, of which exactly ONE dangled.
  // Deliberately keyed to that naming convention and nothing wider — the same sweep over every
  // `M<n>-…`-shaped token reads 40 "unknown" tokens, all of them finding ids and id PREFIXES rather
  // than corpus entries, so a wider rule would be noise a reader learns to ignore.
  const REFERENCE = /\bM\d+[A-Z]*-[A-Z0-9-]*-(?:POS|NEG)\b/g;
  const SRC = fileURLToPath(new URL("../", import.meta.url));

  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const { name, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) out.push(...sourceFiles(full));
      else if (name.endsWith(".ts") && !name.endsWith(".d.ts")) out.push(full);
    }
    return out;
  }

  it("every `-POS`/`-NEG` id named anywhere in src/ resolves to a real corpus entry", () => {
    const ids = new Set(CORPUS.map((e) => e.id));
    const dangling: string[] = [];
    let cited = 0;
    for (const file of sourceFiles(SRC)) {
      for (const [token] of readFileSync(file, "utf8").matchAll(REFERENCE)) {
        cited++;
        if (!ids.has(token)) dangling.push(`${relative(SRC, file)}: ${token}`);
      }
    }
    expect(dangling).toEqual([]);
    // Canary: a regex that stopped matching, or a tree that stopped citing ids, passes vacuously.
    expect(cited).toBeGreaterThan(50);
  });
});

describe("#1355 self-matching `match` keys (a keyword that is a substring of its own fixture path)", () => {
  it("no corpus entry carries a key that is a substring of its own location", () => {
    const rows = selfMatchingKeys(corpusMatchKeyedRows(CORPUS));
    expect(formatSelfMatchingKeys(rows)).toBe("");
    expect(rows).toEqual([]);
    // Canary: an empty corpus, or one that stopped using `match` at all, would pass vacuously.
    expect(CORPUS.filter((e) => e.match?.length).length).toBeGreaterThan(400);
  });

  it("NEGATIVE CONTROL — the check reports a planted self-matching key, in both the raw and the id-hyphenated shape", () => {
    const planted: CorpusEntry[] = [
      entry({ id: "P-CONTROL-RAW", kind: "positive", cls: "c", location: "src/owasp-mt/client-supplied-tenant.ts", match: ["tenant"], note: "" }),
      entry({ id: "P-CONTROL-HYPHEN", kind: "positive", cls: "c", location: "20260727000002_using_true_pii.sql", match: ["using-true-pii"], note: "" }),
      entry({ id: "N-CONTROL", kind: "negative", cls: "c", location: "sqli-parseint-safe.js", match: ["sql"], note: "" }),
      entry({ id: "P-CONTROL-CLEAN", kind: "positive", cls: "c", location: "sqli-denylist-guard.js", match: ["sql-injection"], note: "" }),
    ];
    const rows = selfMatchingKeys(corpusMatchKeyedRows(planted));
    expect(rows.map((r) => r.id)).toEqual(["P-CONTROL-RAW", "P-CONTROL-HYPHEN", "N-CONTROL"]);
    expect(formatSelfMatchingKeys(rows)).toContain("Re-scope the key");
    expect(formatSelfMatchingKeys(rows)).toContain("Delete the `match` list");
  });

  // The behavioural half, and the reason the string check matters: #1355's stated proof that a
  // positive's key really discriminates is that the row still FAILS when the finding it exists to
  // score is withheld. Planting a finding that carries NO corpus vocabulary at the entry's own
  // location is that test for every positive at once — only a key drawn from the location itself
  // can accept it.
  const unrelated = (location: string): Finding =>
    finding({
      location: `${location}:1`,
      id: "CONTROL-1355",
      title: "Unrelated control finding",
      taxonomy: "harvey-control-1355",
      evidence: "synthetic — #1355 masking control, never a real finding",
      precisionTier: "high",
    });

  // #1388: this used to read `e.match?.length &&`, which quietly excluded the 37 positives that
  // carried no key at all — the population it most needed to cover, since `relevantFindings`
  // short-circuits `if (!keys) return true` for exactly those. The filter is gone; the check now
  // runs over EVERY positive, and its coverage is asserted rather than implied so a future
  // narrowing shows up as a failing count instead of a quietly smaller denominator.
  it("EVERY positive rejects an unrelated finding planted at its own location", () => {
    const positives = CORPUS.filter((e) => e.kind === "positive");
    const masked = positives.filter((e) => scoreEntry(e, [unrelated(e.location)]).caughtTier !== undefined);
    expect(masked.map((e) => e.id)).toEqual([]);
    // Coverage, stated: every positive is in the denominator, none skipped for want of a key.
    expect(unkeyedPositives(CORPUS)).toEqual([]);
    expect(positives.length).toBeGreaterThan(400);
  });

  it("NEGATIVE CONTROL — a self-matching positive DOES accept that unrelated finding, which is the masking this check exists to stop", () => {
    const vacuous = entry({ id: "P-CONTROL", kind: "positive", cls: "c", location: "src/owasp-mt/client-supplied-tenant.ts", match: ["tenant"], expectedTier: "high", note: "" });
    expect(scoreEntry(vacuous, [unrelated(vacuous.location)]).pass).toBe(true);
    const scoped = { ...vacuous, match: ["scopes on `tenantId`"] };
    expect(scoreEntry(scoped, [unrelated(scoped.location)]).pass).toBe(false);
  });

  // #1388's own negative control, and the exact experiment the PR #1382 verifier ran and watched
  // PASS: strip a real positive's `match` list — which `formatSelfMatchingKeys` used to recommend —
  // and both halves of this gate must go red. Keyed off a REAL corpus row, not a planted one, so it
  // fails if the row is renamed rather than passing vacuously.
  it("NEGATIVE CONTROL — stripping a real positive's `match` list makes both halves of this gate fail", () => {
    const real = CORPUS.find((e) => e.id === "P-RLS-DISABLED") as CorpusEntry;
    expect(real.match?.length).toBeTruthy();
    const stripped: CorpusEntry[] = CORPUS.map((e) => (e.id === real.id ? { ...e, match: undefined } : e));
    expect(unkeyedPositives(stripped).map((e) => e.id)).toEqual([real.id]);
    const masked = stripped.filter((e) => e.kind === "positive" && scoreEntry(e, [unrelated(e.location)]).caughtTier !== undefined);
    expect(masked.map((e) => e.id)).toEqual([real.id]);
  });

  it("the remediation text does not tell a POSITIVE to delete its match list (#1388)", () => {
    const positive = selfMatchingKeys(corpusMatchKeyedRows([entry({ id: "P-C", kind: "positive", cls: "c", location: "src/owasp-mt/client-supplied-tenant.ts", match: ["tenant"], note: "" })]));
    expect(formatSelfMatchingKeys(positive)).not.toContain("Delete the `match` list");
    expect(formatSelfMatchingKeys(positive)).toContain("Do NOT delete the `match` list");
    // ...and still does for a negative, where a vacuous key was already equivalent to no key.
    const negative = selfMatchingKeys(corpusMatchKeyedRows([entry({ id: "N-C", kind: "negative", cls: "c", location: "sqli-parseint-safe.js", match: ["sql"], note: "" })]));
    expect(formatSelfMatchingKeys(negative)).toContain("Delete the `match` list");
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
  it("excludes live-tier AND no-rule-tier entries from the static positive total", () => {
    const m = buildCoverageMatrix([], CORPUS);
    expect(m.liveNotScored).toBe(CORPUS.filter((e) => isLiveTier(e.expectedTier)).length);
    // positivesTotal is the "must be caught" denominator: a live-tier row this run could not score
    // and a "none" row (no mechanical rule by design) are both out of it — neither is a recall miss.
    expect(m.positivesTotal).toBe(CORPUS.filter((e) => e.kind === "positive" && !isLiveTier(e.expectedTier) && e.expectedTier !== "none").length);
    expect(m.noRuleTotal).toBe(CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none").length);
    expect(m.negativesTotal).toBe(CORPUS.filter((e) => e.kind === "negative" && !isLiveTier(e.expectedTier)).length);
  });

  // The summary line used to call every `none` row "by design" while some are OUTSTANDING work.
  // Asserting the split is NON-TRIVIAL (both populations non-empty) is the part that can fail: a
  // count that silently collapsed to all-by-design would restore the misreport with the field intact.
  it("splits no-rule gaps into by-design boundaries and measured-gaps, so the roll-up cannot call both 'by design'", () => {
    const m = buildCoverageMatrix([], CORPUS);
    const measured = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none" && e.gapKind === "measured-gap");
    expect(m.noRuleMeasuredGap).toBe(measured.length);
    expect(measured.length, "a measured-gap row must exist or the split reports nothing").toBeGreaterThan(0);
    expect(m.noRuleTotal - m.noRuleMeasuredGap, "a by-design row must exist or the split reports nothing").toBeGreaterThan(0);
  });

  // #1428 — the denominator must MOVE when the run has the venue. Without this, a live row could be
  // "scored" and still sit outside every count, which is the old defect wearing a new field.
  it("counts a live-tier row into the totals once its venue is declared (#1428)", () => {
    const offline = buildCoverageMatrix([], CORPUS);
    const withLocal = buildCoverageMatrix([], CORPUS, new Set(["local"]));
    const localRows = CORPUS.filter((e) => e.expectedTier === "local");
    expect(localRows.length).toBeGreaterThan(0);
    expect(withLocal.liveNotScored).toBe(offline.liveNotScored - localRows.length);
    expect(withLocal.positivesTotal).toBe(offline.positivesTotal + localRows.filter((e) => e.kind === "positive").length);
    expect(withLocal.negativesTotal).toBe(offline.negativesTotal + localRows.filter((e) => e.kind === "negative").length);
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
    const staticPositives = CORPUS.filter((e) => e.kind === "positive" && !isLiveTier(e.expectedTier) && e.expectedTier !== "none");
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
    const noRule = CORPUS.filter((e) => e.kind === "positive" && e.expectedTier === "none" && (e.gapKind ?? "by-design") === "by-design");
    expect(noRule.length, "expected at least one by-design no-rule-tier corpus entry to exercise this path").toBeGreaterThan(0);
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
  // Each non-owner-id M9 check bound to its detector's own committed fixtures (nine at #848, the
  // remaining four #846/#843 checks plus the #1051 cache-bleed check added by #1047). Fixtures
  // are loaded from src/detectors/__fixtures__/<dir>/<kind> and path-prefixed to the entry's
  // globally-unique `m9-corpus/<check>/<kind>` location, then scored with the SAME scoreEntry the
  // rest of the corpus uses — so the answer key can't drift from what the scanner emits, and no
  // file lands in the scanned calibration target.
  const FIXTURES_ROOT = fileURLToPath(new URL("../detectors/__fixtures__/", import.meta.url));
  function loadPrefixed(dir: string, prefix: string): SourceInput[] {
    const root = join(FIXTURES_ROOT, dir);
    const files: SourceInput[] = [];
    const walk = (d: string) => {
      for (const { name: e, path: full, isDirectory } of readEntriesSafe(d).entries) {
        if (isDirectory) walk(full);
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
    { check: "segment", dir: "route-segment-config", neg: "negative" },
    { check: "segment-conflict", dir: "route-segment-conflict", neg: "negative" },
    { check: "suspense", dir: "missing-suspense", neg: "negative" },
    { check: "unbounded", dir: "unbounded-route", neg: "negative" },
    // #1484 split the bundled cache-bleed pair (three shapes, one match key) into one dir per shape.
    { check: "cache-bleed-unstable-cache", dir: "cache-bleed-unstable-cache", neg: "negative" },
    { check: "cache-bleed-use-cache", dir: "cache-bleed-use-cache", neg: "negative" },
    { check: "cache-bleed-cache-control", dir: "cache-bleed-cache-control", neg: "negative" },
    // #1263/#1292/#1262. The first three pairs are scored the opposite way round from their #848
    // siblings: the NEGATIVE carries the shape that used to false-fire, the POSITIVE the
    // near-identical shape that must still fire, so a fix that over-suppresses fails here.
    { check: "action-auth-helper", dir: "server-action-helper-gate", neg: "negative" },
    { check: "action-validation-helper", dir: "server-action-helper-validator", neg: "negative" },
    { check: "waterfall-guard", dir: "waterfall-guard", neg: "negative" },
    // #1484 split the bundled uncapped-retry pair (retry loop + fan-out, one match key) in two.
    { check: "uncapped-retry-loop", dir: "uncapped-retry-loop", neg: "negative" },
    { check: "uncapped-fanout", dir: "uncapped-fanout", neg: "negative" },
    // #1293, same inverted scoring: each negative is an FP shape MEASURED on carbon's pinned tree.
    { check: "ssr-client-route", dir: "ssr-client-route", neg: "negative" },
    { check: "ssr-shadowed-global", dir: "ssr-shadowed-global", neg: "negative" },
    { check: "ssr-early-return", dir: "ssr-early-return", neg: "negative" },
    { check: "leak-narrowed-select", dir: "leak-narrowed-select", neg: "negative" },
    // #1276, the family a real TanStack Start target produced and no authored fixture contained.
    { check: "tanstack-client-only", dir: "tanstack-client-only", neg: "negative", framework: "tanstack-start" },
    // #1438/#1441/#1439/#1440 — the four residuals of the PR that landed the three above. Scored
    // the same way round: each POSITIVE is a shape the fix must keep (or start) firing on, each
    // NEGATIVE the neighbouring shape it must not reach.
    // #1484 split the bundled waterfall-escape/action-gate-strength pairs into one dir per shape.
    { check: "waterfall-escape-switch", dir: "waterfall-escape-switch", neg: "negative" },
    { check: "waterfall-escape-loop", dir: "waterfall-escape-loop", neg: "negative" },
    { check: "waterfall-abort", dir: "waterfall-abort", neg: "negative" },
    { check: "action-gate-strength-logger", dir: "action-gate-strength-logger", neg: "negative" },
    { check: "action-gate-strength-discarded", dir: "action-gate-strength-discarded", neg: "negative" },
    { check: "uncapped-retry-while", dir: "uncapped-retry-while", neg: "negative" },
    // #1462/#1460/#1461, same inverted scoring — the three residual FP families #1293/#1276 left open.
    // #1484 criterion 3, second pass: the bundled action-dynamic-gate positive carried four
    // relevant findings and passed on any one of them — split into one dir per shape, each
    // regressing at its own code point (see the entries' notes).
    { check: "action-dynamic-gate-named", dir: "server-action-dynamic-gate-named", neg: "negative" },
    { check: "action-dynamic-gate-namespace", dir: "server-action-dynamic-gate-namespace", neg: "negative" },
    { check: "action-dynamic-gate-computed", dir: "server-action-dynamic-gate-computed", neg: "negative" },
    { check: "action-dynamic-gate-package", dir: "server-action-dynamic-gate-package", neg: "negative" },
    { check: "ssr-module-helper", dir: "ssr-module-helper", neg: "negative" },
    { check: "waterfall-helper-exit", dir: "waterfall-helper-exit", neg: "negative" },
    // #1434, the last raw-text AUTH_PATTERN test in the pass. Same inverted scoring.
    // #1484 split the bundled owner-id-helper-gate pair (logger + comment shapes) into one dir each.
    { check: "owner-id-helper-gate-logger", dir: "owner-id-helper-gate-logger", neg: "negative" },
    { check: "owner-id-helper-gate-comment", dir: "owner-id-helper-gate-comment", neg: "negative" },
    // #1500, #1462's own residual — same inverted scoring.
    { check: "action-gate-depth", dir: "server-action-gate-depth", neg: "negative" },
    // #1502, #1460's own residual — same inverted scoring.
    { check: "ssr-cross-file-helper", dir: "ssr-cross-file-helper", neg: "negative" },
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

  it("#1459: M1-boundary covers every M1 taxonomy the boundary pass emits", () => {
    // The #940 shape, made executable: a taxonomy landing without its corpus bucket being updated.
    // The boundary pass's noun is per-framework ("Server Action" / "route action" / "server
    // function") and a new adapter adds another, so this runs the REAL detector over every M9
    // fixture in this block and fails if any `M1 —` row it produces escapes the M1-boundary rule —
    // which would silently return that row to being scored by nothing, the exact defect #1459 fixed.
    const emitted = new Set<string>();
    for (const { check, dir, neg, framework } of CHECKS) {
      for (const kind of ["positive", neg]) {
        for (const f of detectAppRouterFindings(loadPrefixed(`${dir}/${kind}`, `m9-corpus/${check}/${kind}`), framework)) {
          if (f.taxonomy.startsWith("M1 ")) emitted.add(f.taxonomy);
        }
      }
    }
    expect(emitted.size, "the M9 fixtures must exercise the boundary pass's M1 output at all").toBeGreaterThan(0);
    for (const taxonomy of emitted) {
      expect(moduleMatches(taxonomy, "M1-boundary"), `${taxonomy} escapes the M1-boundary corpus key`).toBe(true);
    }
  });

  // #1718 — M9C-TANSTACK-CLIENTONLY-POS matches TWO findings under one `match` key. It is an
  // accepted exception to #1484's split rule (both come from ONE mechanism applied to two adjacent
  // reads, so neither can regress alone) ON CONDITION that the narrower risk is guarded instead:
  // BROWSER_GLOBALS is a shared Set of five names, and dropping ONE of them would leave the corpus
  // row green on the survivor. This is that guard — it names each global the fixture reads, so a
  // narrowing of the set for a single name fails here even though the entry itself still passes.
  it("both browser globals in the TanStack fixture are named individually (#1718)", () => {
    const findings = detectAppRouterFindings(
      loadPrefixed("tanstack-client-only/positive", "m9-corpus/tanstack-client-only/positive"),
      "tanstack-start",
    );
    const ssr = findings.filter((f) => f.taxonomy === "M9 — SSR-only API misuse");
    for (const global of ["localStorage", "document"]) {
      expect(
        ssr.some((f) => f.title.includes(`\`${global}\``)),
        `no SSR-only finding names \`${global}\` — if BROWSER_GLOBALS was narrowed, this class silently lost a member while M9C-TANSTACK-CLIENTONLY-POS stayed green on the other one`,
      ).toBe(true);
    }
    expect(ssr, "the fixture must keep reading at least two distinct browser globals for this guard to mean anything").toHaveLength(2);
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

describe("#1238 OWASP React RSC boundary (live detectAppRouterFindings over targets/calibration)", () => {
  // The one OWASP-React row whose detector is NOT runMechanicalScan's: the server→client leak check
  // is M9's, so validate-calibration excludes the pair and this is the gate that scores it instead.
  // Unlike the #848 block above these fixtures DO live in the scanned calibration target — the
  // OWASP corpus is measured by scanning that target, and moving them out would decouple this pair
  // from the run every other row in owasp-react.entries.ts is scored against.
  const CALIBRATION_REACT = fileURLToPath(new URL("../../targets/calibration/src/owasp-react/", import.meta.url));

  function loadReactFixtures(): SourceInput[] {
    return readNamesSafe(CALIBRATION_REACT)
      .filter((e) => e.endsWith(".tsx"))
      .map((e) => ({ path: `src/owasp-react/${e}`, text: readFileSync(join(CALIBRATION_REACT, e), "utf8") }));
  }

  const entries = owaspReactEntries.filter((e) => e.module === "M9");

  it("catches the whole-row prop crossing into a Client Component and clears the shaped projection", () => {
    expect(entries.map((e) => e.id).sort()).toEqual(["N-OWASP-REACT-SHAPED-BOUNDARY", "P-OWASP-REACT-RSC-BOUNDARY"]);
    const findings = detectAppRouterFindings(loadReactFixtures());
    for (const entry of entries) {
      const row = scoreEntry(entry, findings);
      expect(row.pass, `${entry.id}: ${row.detail}`).toBe(true);
    }
    const pos = scoreEntry(entries.find((e) => e.kind === "positive")!, findings);
    expect(pos.caughtTier, "the M9 boundary heuristic must never enter the free count").toBe("review");
  });

  it("fires on the ORM row read, not merely on a Supabase chain (#1238's actual widening)", () => {
    // The fixture binds `await db.getUser(userId)`. Before #1238 collectRawRowNames recognised only
    // `.from().select()`, so this test fails the moment that widening is reverted — which is the one
    // way this row could silently go back to reporting a gap.
    const findings = detectAppRouterFindings(loadReactFixtures());
    const leak = findings.find((f) => f.location.includes("rsc-boundary-full-object"));
    expect(leak?.evidence).toContain("user");
  });
});

// #1679 — the same arrangement as the block above, for the same reason: `P-CLIENT-RENDER-AUTHZ`
// graduated onto a detector that runs in the static-detect AST pass, not runMechanicalScan, so
// validate-calibration's M1 gate excludes the pair (`module: "M9"`) and this is what scores it.
// The fixtures stay in targets/calibration because the rest of B15 is measured by scanning it.
describe("#1679 client-render-only authz (live detectAppRouterFindings over targets/calibration)", () => {
  const CALIBRATION = fileURLToPath(new URL("../../targets/calibration/", import.meta.url));
  // The whole flow, both arms: two server components, the one client child they share. Loading the
  // child is not optional decoration — the rule's third condition is a fact about ITS body, so a
  // run without it would score the pair on two of the three conditions.
  const FLOW = ["app/admin/page.tsx", "app/admin/page-safe.tsx", "components/AdminDashboardClient.jsx"];
  const files: SourceInput[] = FLOW.map((rel) => ({ path: rel, text: readFileSync(join(CALIBRATION, rel), "utf8") }));
  const entries = b15NextjsAuthzEntries.filter((e) => e.id === "P-CLIENT-RENDER-AUTHZ" || e.id === "N-SERVER-ROLE-CHECK");

  it("flags the render-gated flow and clears the server-role-checked twin", () => {
    expect(entries.map((e) => e.id).sort()).toEqual(["N-SERVER-ROLE-CHECK", "P-CLIENT-RENDER-AUTHZ"]);
    const findings = detectAppRouterFindings(files);
    for (const entry of entries) {
      const row = scoreEntry(entry, findings);
      expect(row.pass, `${entry.id}: ${row.detail}`).toBe(true);
    }
    const pos = scoreEntry(entries.find((e) => e.kind === "positive")!, findings);
    expect(pos.caughtTier, "an M9 boundary heuristic must never enter the free count").toBe("review");
  });

  // The discriminating condition, isolated. page-safe.tsx differs from page.tsx by ONE thing: the
  // `getServerSession()` role check in front of the query. Delete the auth test from the detector
  // and this goes red while the assertion above stays green on the positive — which is the whole
  // reason the class needed a two-file rule rather than "a service-role read with no session hint",
  // an approximation whose candidate surface on this target is 40 files.
  it("the SERVER-side gate is what separates them, not the shape of the crossing", () => {
    const findings = detectAppRouterFindings(files);
    const rows = findings.filter((f) => f.taxonomy === "M1 — Authorization enforced only by a client-side conditional render");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.location).toContain("app/admin/page.tsx");
    // Scope control: both files WERE scanned. A pair the loader never read reports the same zero.
    const leaks = findings.filter((f) => f.taxonomy === "M9 — Server→client data leak").map((f) => f.location);
    expect(leaks.some((l) => l.includes("page-safe.tsx"))).toBe(true);
  });

  it("names the client child's actual gate, so the evidence is checkable against the source", () => {
    const row = detectAppRouterFindings(files).find((f) => f.taxonomy === "M1 — Authorization enforced only by a client-side conditional render");
    expect(row?.evidence).toContain("if (!isAdmin) return");
    expect(row?.evidence).toContain("components/AdminDashboardClient.jsx");
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
      for (const { name: e, path: full, isDirectory } of readEntriesSafe(d).entries) {
        if (isDirectory) walk(full);
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

describe("#1203 M7 blocking-loop (live detectPerfCodeFindings over the committed OWASP fixture)", () => {
  // P-OWASP-NODE-BLOCKING-LOOP is tagged module: "M7" in owasp-nodejs.entries.ts, which excludes
  // it from validate-calibration.ts's M1 mechanical scoring (mechanicalCorpus) — this block is
  // where it is actually proven caught, same shape as the #221/#374 blocks above: the REAL
  // detector against the REAL committed fixture, so the answer key can't drift from what the
  // scanner emits.
  const entry = owaspNodejsEntries.find((e) => e.id === "P-OWASP-NODE-BLOCKING-LOOP");
  if (!entry) throw new Error("P-OWASP-NODE-BLOCKING-LOOP missing from owasp-nodejs.entries.ts");
  const findings = detectPerfCodeFindings([
    { path: entry.location, text: readFileSync(join(import.meta.dirname, "../../targets/calibration", entry.location), "utf8") },
  ]);

  it("catches pbkdf2Sync and readFileSync in blocking-event-loop.ts at review tier", () => {
    const row = scoreEntry(entry, findings);
    expect(row.pass, row.detail).toBe(true);
    expect(row.caughtTier).toBe(entry.expectedTier);
  });

  it("fires both calls, each at Review confidence with the reachability caveat disclosed", () => {
    const hits = findings.filter((f) => f.taxonomy === "M7 — Blocking sync I/O in request handler");
    expect(hits).toHaveLength(2);
    expect(hits.every((f) => f.confidence === "Review")).toBe(true);
    expect(hits.every((f) => f.evidence.includes("reachability"))).toBe(true);
  });
});

// #1628 — which positives' misses FAIL the calibration gate. This is the rule the live gate's own
// in-run control replays; holding it here too means a change to it is caught under `pnpm verify`,
// with no binaries, rather than only in heavy-cli.
describe("fatalRecallMisses (#1628 — a review-tier miss is a regression, not a tracked gap)", () => {
  const row = (over: Partial<MatrixRow> & Pick<MatrixRow, "id">): MatrixRow => ({
    kind: "positive", cls: "c", pass: true, highFlagged: true, reviewFlagged: false,
    detail: "", severityMismatch: false, notScored: false, ...over,
  });

  it("fails a review-tier positive that nothing caught — the state #1628 found", () => {
    expect(fatalRecallMisses([row({ id: "P-R", expectedTier: "review", pass: false, highFlagged: false })]).map((r) => r.id)).toEqual(["P-R"]);
  });

  it("passes a review-tier positive caught at review tier, so the rule above is not always-on", () => {
    expect(fatalRecallMisses([row({ id: "P-R", expectedTier: "review", caughtTier: "review", highFlagged: false, reviewFlagged: true })])).toEqual([]);
  });

  it("still fails a high-tier positive caught only at review — the pre-existing rule is unchanged", () => {
    expect(fatalRecallMisses([row({ id: "P-H", expectedTier: "high", caughtTier: "review", highFlagged: false })]).map((r) => r.id)).toEqual(["P-H"]);
  });

  // The accepted-gap tier keeps its own inverted rule (a rule that GRADUATES onto it fails, in the
  // CLI's noRuleBroken). Folding it in here would make every by-design gap a recall failure.
  it("never claims a `none`-tier row, whichever way it scored", () => {
    expect(fatalRecallMisses([row({ id: "P-N", expectedTier: "none", pass: false, highFlagged: false })])).toEqual([]);
  });

  // A live row this run had no venue for is excluded from every count, never passed (#1428).
  it("never claims a NOT-SCORED live row", () => {
    expect(fatalRecallMisses([row({ id: "P-L", expectedTier: "local", notScored: true, highFlagged: false })])).toEqual([]);
  });

  it("never claims a negative — those are scored by the free-count and #1344 rules", () => {
    expect(fatalRecallMisses([row({ id: "N-X", kind: "negative", pass: false, highFlagged: true })])).toEqual([]);
  });
});

describe("darkenEntry (#1628's plant — the gate's negative control needs a real miss to score)", () => {
  const e = entry({ id: "P-SQLI", kind: "positive", cls: "sqli", location: "search.js", match: ["sql"], expectedTier: "review", note: "" });
  const hit = finding({ location: "pages/api/search.js:11", taxonomy: "SQL injection", precisionTier: "review" });
  const elsewhere = finding({ location: "pages/api/other.js:3", taxonomy: "SQL injection", precisionTier: "review" });

  it("drops exactly the findings that score the entry, and turns it into a fatal miss", () => {
    expect(scoreEntry(e, [hit, elsewhere]).pass).toBe(true);
    const darkened = darkenEntry(e, [hit, elsewhere]);
    expect(darkened).toEqual([elsewhere]);
    expect(fatalRecallMisses([scoreEntry(e, darkened)]).map((r) => r.id)).toEqual(["P-SQLI"]);
  });
});
