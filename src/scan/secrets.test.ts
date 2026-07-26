import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// #950: trufflehog/gitleaks absent from PATH must degrade to a disclosed coverage gap, not an
// uncaught ENOENT crash (mirrors the osv-scanner pattern, #512). Only those two binary names are
// faked here — every other execFileSync call (notably "git", used both by isGitRepoRoot and by
// this file's own test setup below) passes through to the real implementation untouched.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "trufflehog" || bin === "gitleaks") {
        const err = new Error(`spawnSync ${bin} ENOENT`) as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      }
      return actual.execFileSync(bin, args, opts as never);
    }),
  };
});

import {
  DOC_CONTEXT_CREDENTIAL_TAXONOMY,
  gitHistorySecretsUnavailableFinding,
  gitleaksAllowlistDisclosure,
  gitleaksSuppression,
  gitleaksUnavailableFinding,
  isDocExamplePath,
  isGitRepoRoot,
  parseGitleaksFindings,
  parseTruffleHogFindings,
  resolveBundleScan,
  scanSecrets,
  secretScanScopeFinding,
  truffleHogUnavailableFinding,
  type GitleaksResult,
  type TruffleHogResult,
} from "./secrets.js";

describe("parseTruffleHogFindings", () => {
  it("drops unverified hits — only a live-verified secret is ~100% precision", () => {
    const results: TruffleHogResult[] = [
      { DetectorName: "Stripe", Verified: true, SourceMetadata: { Data: { Filesystem: { file: "lib/pay.ts", line: 12 } } } },
      { DetectorName: "Generic", Verified: false, SourceMetadata: { Data: { Filesystem: { file: "lib/noise.ts", line: 3 } } } },
    ];
    const findings = parseTruffleHogFindings(results, "source");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("Stripe");
    expect(findings[0]?.precisionTier).toBe("high");
    expect(findings[0]?.severity).toBe("Critical");
    expect(findings[0]?.mechanical).toBe(true);
  });

  it("prefixes location with the scan scope so source/history/bundle hits aren't confused", () => {
    const results: TruffleHogResult[] = [
      { DetectorName: "Supabase", Verified: true, SourceMetadata: { Data: { Git: { file: "seed.ts", line: 5, commit: "abcdef0123456789" } } } },
    ];
    const findings = parseTruffleHogFindings(results, "git-history");
    expect(findings[0]?.location).toBe("[git-history] seed.ts:5 (commit abcdef012345)");
  });
});

describe("parseGitleaksFindings", () => {
  it("tags the decoded service-role rule as high precision / Critical", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-service-role-jwt", File: "lib/admin.ts", StartLine: 8, Match: '"role":"service_role"' },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings[0]?.precisionTier).toBe("high");
    expect(findings[0]?.severity).toBe("Critical");
    expect(findings[0]?.confidence).toBe("Confirmed");
  });

  it("tags generic gitleaks rules as review precision — regex/entropy alone isn't proof", () => {
    const results: GitleaksResult[] = [
      { RuleID: "generic-api-key", File: "lib/config.ts", StartLine: 2, Match: "apikey=abc123" },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.confidence).toBe("Review");
  });

  it("assigns stable, distinct ids per scope so source/bundle passes don't collide", () => {
    const results: GitleaksResult[] = [{ RuleID: "generic-api-key", File: "a.ts" }];
    const source = parseGitleaksFindings(results, "source");
    const bundle = parseGitleaksFindings(results, "bundle");
    expect(source[0]?.id).not.toBe(bundle[0]?.id);
  });

  it("gives private-key its own impact text, not the JWT-specific sentence (#211)", () => {
    const results: GitleaksResult[] = [{ RuleID: "private-key", File: "certs/key.pem", StartLine: 1 }];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings[0]?.impact).not.toContain("Decoded JWT role claim");
  });

  it("clears a high-precision hit co-located with the decoded supabase-demo iss claim (#210)", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-service-role-jwt", File: "supabase/seed.sql", StartLine: 2, Match: '"role":"service_role"' },
      { RuleID: "supabase-demo-key-marker", File: "supabase/seed.sql", StartLine: 2, Match: '"iss":"supabase-demo"' },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings).toHaveLength(0);
  });

  it("still flags a real (non-demo) service-role JWT with no demo marker present", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-service-role-jwt", File: "lib/admin.js", StartLine: 8, Match: '"role":"service_role"' },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("down-ranks a private-key hit sharing a CI workflow file with a test IdP marker, but doesn't drop it (#211)", () => {
    const results: GitleaksResult[] = [
      { RuleID: "private-key", File: ".github/workflows/main.yml", StartLine: 12 },
      { RuleID: "harvey-test-idp-marker", File: ".github/workflows/main.yml", StartLine: 3, Match: "ENTITY_ID" },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.severity).toBe("High");
    expect(findings[0]?.evidence).toContain("Down-ranked from Critical");
  });

  it("leaves a private-key hit outside a CI workflow at high, even with a test IdP marker elsewhere", () => {
    const results: GitleaksResult[] = [
      { RuleID: "private-key", File: "certs/key.pem", StartLine: 1 },
      { RuleID: "harvey-test-idp-marker", File: "certs/key.pem", StartLine: 1, Match: "ENTITY_ID" },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings[0]?.precisionTier).toBe("high");
  });

  it("assigns the same ids to the same findings regardless of input order (#302)", () => {
    const a: GitleaksResult = { RuleID: "generic-api-key", File: "lib/a.ts", StartLine: 1, Match: "apikey=aaa" };
    const b: GitleaksResult = { RuleID: "generic-api-key", File: "lib/b.ts", StartLine: 2, Match: "apikey=bbb" };
    const c: GitleaksResult = { RuleID: "private-key", File: "certs/key.pem", StartLine: 1 };

    const byId = (findings: ReturnType<typeof parseGitleaksFindings>) =>
      new Map(findings.map((f) => [f.location, f.id]));

    const run1 = byId(parseGitleaksFindings([a, b, c], "source"));
    const run2 = byId(parseGitleaksFindings([c, a, b], "source"));
    const run3 = byId(parseGitleaksFindings([b, c, a], "source"));

    expect(run2).toEqual(run1);
    expect(run3).toEqual(run1);
  });

  it("redacts a matched secret value so a real-shaped credential never reaches evidence (#308)", () => {
    const secret = "sk_test_51Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj";
    const results: GitleaksResult[] = [
      { RuleID: "stripe-access-token", File: "lib/pay.ts", StartLine: 4, Match: secret },
    ];
    const evidence = parseGitleaksFindings(results, "source")[0]?.evidence ?? "";
    expect(evidence).not.toContain(secret);
    expect(evidence).toContain(`[redacted, ${secret.length} chars]`);
    // A short prefix survives so triage can still distinguish two hits on the same rule+file.
    expect(evidence).toContain("sk_test_51Qm");
  });

  it("redacts the password inside a matched connection-string URI (#308)", () => {
    const uri = "postgres://appuser:S3cr3tP4ssZ9Qm2vXc@db.example.supabase.co";
    const results: GitleaksResult[] = [
      { RuleID: "harvey-db-uri-credentials", File: "supabase/migrations/001.sql", StartLine: 9, Match: uri },
    ];
    const evidence = parseGitleaksFindings(results, "source")[0]?.evidence ?? "";
    expect(evidence).not.toContain("S3cr3tP4ssZ9Qm2vXc");
    expect(evidence).not.toContain(uri);
  });

  it("keeps the structural service_role claim verbatim — it is not a secret (#308)", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-service-role-jwt", File: "lib/admin.ts", StartLine: 8, Match: '"role":"service_role"' },
    ];
    const evidence = parseGitleaksFindings(results, "source")[0]?.evidence ?? "";
    expect(evidence).toContain('"role":"service_role"');
    expect(evidence).not.toContain("[redacted");
  });

  it("never surfaces the internal correlation marker rules as findings themselves", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-demo-key-marker", File: "supabase/seed.sql", StartLine: 2 },
      { RuleID: "harvey-test-idp-marker", File: ".github/workflows/main.yml", StartLine: 3 },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings).toHaveLength(0);
  });
});

// #1078: the line-level allowlist deleted a real secret that merely shared a line with a public
// key. MEASURED 2026-07-26 (gitleaks 8.30.1) against Harvey's own config: `sk_live_…` alone was
// detected; the same secret with `pk_test_…` or `NEXT_PUBLIC_SUPABASE_ANON_KEY` on the line, or in
// a `config.template` file, was reported NOWHERE — 3 of 4 fixtures silently suppressed.
describe("allowlist suppressions are scoped to the value and counted (#1078)", () => {
  // Fake, structure-only Supabase JWTs (header.payload.sig). The two differ ONLY in the decoded
  // role claim — which is exactly why keying on line co-location could never separate them.
  const ANON_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJhbm9uIn0.sig";
  const SERVICE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.sig";
  // Defanged: the live-shaped key used against the real binary during the measurement above trips
  // GitHub push protection, and these tests exercise parseGitleaksFindings, not the gitleaks regex.
  const STRIPE_SECRET = "sk_live_FAKE_calibration_not_a_real_key_a9xZ3";

  it("keeps a real secret that shares a line with a publishable key or the anon key", () => {
    const results: GitleaksResult[] = [
      { RuleID: "stripe-access-token", File: "lib/pay.ts", StartLine: 4, Match: STRIPE_SECRET },
      { RuleID: "generic-api-key", File: "lib/pay.ts", StartLine: 4, Match: "pk_test_FAKEcalibrationPublishableKey01" },
      { RuleID: "jwt", File: ".env.local", StartLine: 8, Match: ANON_JWT },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings.map((f) => f.location)).toEqual(["[source] lib/pay.ts:4"]);
  });

  it("clears the anon key by its DECODED role claim and never the service_role sibling", () => {
    expect(gitleaksSuppression({ RuleID: "jwt", File: "a.ts", Match: ANON_JWT })?.reason).toBe("public-key");
    expect(gitleaksSuppression({ RuleID: "jwt", File: "a.ts", Match: SERVICE_JWT })).toBeUndefined();
  });

  it("does not grade a sample/template match, but counts it — a real value in a template is a leak class", () => {
    const results: GitleaksResult[] = [
      { RuleID: "stripe-access-token", File: "config.template", StartLine: 2, Match: STRIPE_SECRET },
      { RuleID: "stripe-access-token", File: ".env.example", StartLine: 1, Match: STRIPE_SECRET },
    ];
    expect(parseGitleaksFindings(results, "source")).toHaveLength(0);
    const row = gitleaksAllowlistDisclosure(results.map((r) => gitleaksSuppression(r)!));
    expect(row?.id).toBe("SEC-GL-ALLOW-00");
    expect(row?.evidence).toContain("2 credential-shaped match(es) in sample/template files");
    expect(row?.evidence).toContain("config.template:2");
  });

  it("emits no row when nothing was suppressed — the disclosure must not become background noise", () => {
    expect(gitleaksAllowlistDisclosure([])).toBeUndefined();
  });
});

// #1078: the sweep is a VERIFIED-credential sweep plus a working-tree pattern pass, and said so
// nowhere. MEASURED 2026-07-26 on a throwaway repo (trufflehog 3.96.0): a fake GitHub PAT added
// then removed is recovered by `--no-verification --results=unverified` (1 result) and by
// `--only-verified` (0 results) — production's flags cannot see it.
describe("secretScanScopeFinding (#1078)", () => {
  it("names both halves of the gap: verified-only, and history is not pattern-scanned", () => {
    const f = secretScanScopeFinding();
    expect(f.severity).toBe("Info");
    expect(f.evidence).toContain("--only-verified");
    expect(f.evidence).toContain("--no-git");
    expect(f.impact).toContain("only in git history");
    expect(f.fix).toContain("--results=unverified");
  });
});

// #1078: TruffleHog ships the provider's own rotation procedure and the commit provenance with
// every result, and Harvey discarded both on a Critical finding whose entire remediation IS
// rotation. Fixture CAPTURED VERBATIM from `trufflehog git --no-verification --results=unverified
// --json file://<fixture>` on trufflehog 3.96.0, 2026-07-26 (Verified flipped to true so it
// reaches the grading path; the real run's fake token could not verify).
describe("TruffleHog rotation guidance and commit provenance reach the finding (#1078)", () => {
  const captured: TruffleHogResult = {
    DetectorName: "Github",
    DecoderName: "PLAIN",
    Verified: true,
    Redacted: "",
    ExtraData: { rotation_guide: "https://howtorotate.com/docs/tutorials/github/", version: "2" },
    SourceMetadata: {
      Data: {
        Git: {
          commit: "1f475839d1a0156ec7afffc637ed841c070286a3",
          file: "lib/leaked-token.js",
          email: "C <c@h.test>",
          timestamp: "2026-07-26 04:39:34 +0000",
          line: 1,
        },
      },
    },
  };

  it("appends the provider rotation guide to the fix and the author/date to the evidence", () => {
    const f = parseTruffleHogFindings([captured], "git-history")[0];
    expect(f?.fix).toContain("https://howtorotate.com/docs/tutorials/github/");
    expect(f?.evidence).toContain("C <c@h.test>");
    expect(f?.evidence).toContain("2026-07-26 04:39:34 +0000");
  });

  it("reports a non-PLAIN decoder — a base64-buried secret is a different finding and a different search", () => {
    const f = parseTruffleHogFindings([{ ...captured, DecoderName: "BASE64" }], "source")[0];
    expect(f?.evidence).toContain("BASE64 decoder");
    const plain = parseTruffleHogFindings([captured], "source")[0];
    expect(plain?.evidence).not.toContain("decoder");
  });
});

// #934: the carbon shape — placeholder/default credentials in documentation and example-deployment
// paths reclassified to Low + the doc-context taxonomy (routed non-grading by quick-scan), never
// dropped and never a graded Critical. The four paths below are carbon's own four hit surfaces.
describe("doc/example-context credential reclassification (#934)", () => {
  const carbonStylePaths = [
    "packages/dev/docker/docker-compose.dev.yml", // *.dev.yml compose
    "contrib/deploying/simple-docker-caddy/docker-compose.prod.yml", // contrib/** (even a .prod.yml)
    "docs/content/docs/platform/self-hosting/docker-caddy.mdx", // docs/** + .mdx
    ".claude/skills/agent-browser/references/proxy-support.md", // vendored reference doc (.md)
  ];

  it("reclassifies a high-precision rule hit in every carbon-style doc/example path: Low, doc-context taxonomy, stated reason", () => {
    for (const file of carbonStylePaths) {
      const results: GitleaksResult[] = [
        { RuleID: "supabase-default-jwt-secret", File: file, StartLine: 5, Match: "your-super-secret-jwt-token-with-at-least-32-characters-long" },
      ];
      const f = parseGitleaksFindings(results, "source")[0];
      expect(f?.severity, file).toBe("Low");
      expect(f?.taxonomy, file).toBe(DOC_CONTEXT_CREDENTIAL_TAXONOMY);
      expect(f?.evidence, file).toContain("Reclassified from Critical");
      // Still a fact-precise match — it stays visible in the free report, not review-buried.
      expect(f?.precisionTier, file).toBe("high");
    }
  });

  it("leaves the same rule at Critical in application source — the rule keys on path context, not the rule id", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-default-jwt-secret", File: "supabase/docker-compose.yml", StartLine: 5, Match: "your-super-secret-jwt-token-with-at-least-32-characters-long" },
      { RuleID: "harvey-db-uri-credentials", File: "apps/erp/app/lib/db.server.ts", StartLine: 3, Match: "postgres://app:realpassword@db.internal" },
    ];
    const findings = parseGitleaksFindings(results, "source");
    for (const f of findings) {
      expect(f.severity).toBe("Critical");
      expect(f.taxonomy).toBe("Committed credential");
    }
  });

  it("does not touch review-tier rules — they are already outside the free grade", () => {
    const results: GitleaksResult[] = [
      { RuleID: "generic-api-key", File: "docs/setup.md", StartLine: 2, Match: "apikey=abc123" },
    ];
    const f = parseGitleaksFindings(results, "source")[0];
    expect(f?.precisionTier).toBe("review");
    expect(f?.taxonomy).toBe("Possible committed credential");
  });

  it("a TruffleHog live-VERIFIED secret in docs still grades Critical — verification outranks the path prior", () => {
    const results: TruffleHogResult[] = [
      { DetectorName: "Stripe", Verified: true, SourceMetadata: { Data: { Filesystem: { file: "docs/setup.md", line: 12 } } } },
    ];
    const f = parseTruffleHogFindings(results, "source")[0];
    expect(f?.severity).toBe("Critical");
    expect(f?.taxonomy).toBe("Committed credential");
  });
});

describe("isDocExamplePath (#934)", () => {
  it.each([
    ["docs/self-hosting/setup.md", true],
    ["README.mdx", true],
    ["contrib/deploying/bin/secrets-entrypoint.sh", true],
    ["examples/full-stack/compose.yml", true],
    ["packages/dev/docker/docker-compose.dev.yml", true],
    ["config/docker-compose.example.yml", true],
    ["apps/erp/app/lib/db.server.ts", false],
    ["docker-compose.yml", false], // a repo-root compose is the deployed shape, not an example
    ["supabase/config.toml", false],
    ["src/documents/render.ts", false], // "documents" is not the docs/ segment
  ])("%s -> %s", (path, expected) => {
    expect(isDocExamplePath(path)).toBe(expected);
  });
});

// #528: previously the isGitRepoRoot guard just made the git-history pass return [] with no
// disclosure — a cold engagement delivered as an archive/subdirectory had that tier silently
// unassessed. isGitRepoRoot is what scanSecrets branches on to decide whether to emit
// gitHistorySecretsUnavailableFinding, so exercising it directly proves the fail-loud contract
// without depending on the trufflehog binary itself.
describe("isGitRepoRoot (#528)", () => {
  const scratchDirs: string[] = [];
  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("is false for a non-git directory — the disclosure tier fires", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-secrets-nongit-"));
    scratchDirs.push(dir);
    expect(isGitRepoRoot(dir)).toBe(false);
  });

  it("is true for a real git repo root — no disclosure, behaves as today", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-secrets-gitroot-"));
    scratchDirs.push(dir);
    execFileSync("git", ["init", "-q"], { cwd: dir });
    expect(isGitRepoRoot(dir)).toBe(true);
  });

  it("is false for a SUBDIRECTORY of a git repo — the disclosure tier fires, matching #55's original guard", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-secrets-gitsub-"));
    scratchDirs.push(dir);
    execFileSync("git", ["init", "-q"], { cwd: dir });
    const sub = join(dir, "target");
    mkdirSync(sub);
    expect(isGitRepoRoot(sub)).toBe(false);
  });

  // #619: on a case-insensitive filesystem (macOS default) git reports the toplevel in the case
  // it recorded for the work tree, which can differ from the case the caller passes. The old
  // realpath-string-equality check false-negated a valid repo root and silently skipped the
  // git-history secret scan. Filesystem (dev+ino) identity is case-insensitive, so it stays true.
  it("is true when the passed dir differs only in CASE from git's recorded toplevel (#619)", () => {
    const parent = mkdtempSync(join(tmpdir(), "harvey-secrets-case-"));
    scratchDirs.push(parent);
    const real = join(parent, "RepoDir");
    mkdirSync(real);
    execFileSync("git", ["init", "-q"], { cwd: real });
    const variant = join(parent, "repodir");
    // Only manifests on a case-insensitive FS — on a case-sensitive FS `variant` doesn't exist
    // and the bug cannot occur, so there is nothing to assert.
    let caseInsensitive = false;
    try {
      caseInsensitive = statSync(variant).isDirectory();
    } catch {
      caseInsensitive = false;
    }
    if (!caseInsensitive) return;
    expect(isGitRepoRoot(variant)).toBe(true);
  });
});

describe("gitHistorySecretsUnavailableFinding (#528)", () => {
  it("discloses the coverage gap without claiming zero secrets, and never quotes a secret value (#308)", () => {
    const finding = gitHistorySecretsUnavailableFinding("/some/path is not a git repository root");
    expect(finding.id).toBe("SEC-TH-GH-00");
    expect(finding.severity).toBe("Info");
    expect(finding.evidence).not.toMatch(/ghp_|sk_|service_role/);
    expect(finding.impact).toContain("not a finding of zero secrets");
  });
});

describe("resolveBundleScan (#588)", () => {
  let root: string;
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function mkTarget(...bundleRels: string[]): string {
    root = mkdtempSync(join(tmpdir(), "harvey-bundle-"));
    for (const rel of bundleRels) mkdirSync(join(root, rel), { recursive: true });
    return root;
  }

  it("auto-detects a Vite dist/ build output when no explicit bundle is passed", () => {
    const dir = mkTarget("dist", "dist/assets");
    const r = resolveBundleScan(dir);
    expect(r.bundleDir).toBe(join(dir, "dist"));
    expect(r.disclosure).toBeUndefined();
  });

  it("prefers Next .next/static over dist/ when both exist", () => {
    const dir = mkTarget("dist", ".next/static");
    expect(resolveBundleScan(dir).bundleDir).toBe(join(dir, ".next", "static"));
  });

  it("discloses (never silently skips) when no recognized build output exists", () => {
    const dir = mkTarget("src");
    const r = resolveBundleScan(dir);
    expect(r.bundleDir).toBeUndefined();
    expect(r.disclosure?.id).toBe("SEC-BUNDLE-00");
    expect(r.disclosure?.severity).toBe("Info");
    expect(r.disclosure?.impact).toContain("not a finding of zero secrets");
  });

  it("honours an explicit bundle path, and discloses when the explicit path is missing", () => {
    const dir = mkTarget("build/out");
    expect(resolveBundleScan(dir, join(dir, "build", "out")).bundleDir).toBe(join(dir, "build", "out"));
    expect(resolveBundleScan(dir, join(dir, "nope")).disclosure?.id).toBe("SEC-BUNDLE-00");
  });
});

// #950: previously scanSecrets threw the raw ENOENT from runJson/runGitleaks, which propagated
// uncaught to quick-scan's main().catch() and hard-exited the CLI instead of degrading like
// osv-scanner already does (#512). Both binaries are faked absent (see the module mock above),
// so this exercises the real scanSecrets control flow end-to-end, not just the pure disclosure
// finding shape.
describe("scanSecrets degrades when trufflehog/gitleaks are absent from PATH (#950)", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("does not throw, and discloses one coverage-gap finding per missing tool", () => {
    dir = mkdtempSync(join(tmpdir(), "harvey-secrets-missing-bin-"));
    execFileSync("git", ["init", "-q"], { cwd: dir });

    const findings = scanSecrets(dir, dir);

    const th = findings.find((f) => f.id === "SEC-TH-00");
    expect(th).toBeDefined();
    expect(th?.evidence).toContain("trufflehog not found on PATH");

    const gl = findings.find((f) => f.id === "SEC-GL-00");
    expect(gl).toBeDefined();
    expect(gl?.evidence).toContain("gitleaks not found on PATH");

    // Exactly one disclosure per tool, not one per pass (filesystem + git-history for
    // TruffleHog) — the redundant second invocation is skipped once the first fails.
    expect(findings.filter((f) => f.id === "SEC-TH-00")).toHaveLength(1);
    expect(findings.filter((f) => f.id === "SEC-GL-00")).toHaveLength(1);
  });
});

describe("truffleHogUnavailableFinding / gitleaksUnavailableFinding (#950)", () => {
  it("truffleHogUnavailableFinding discloses the coverage gap without claiming zero secrets", () => {
    const finding = truffleHogUnavailableFinding("trufflehog not found on PATH");
    expect(finding.id).toBe("SEC-TH-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.impact).toContain("not a finding of zero secrets");
  });

  it("gitleaksUnavailableFinding discloses the coverage gap without claiming zero secrets", () => {
    const finding = gitleaksUnavailableFinding("gitleaks not found on PATH");
    expect(finding.id).toBe("SEC-GL-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.impact).toContain("not a finding of zero secrets");
  });
});
