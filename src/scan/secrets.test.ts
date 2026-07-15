import { describe, expect, it } from "vitest";
import { parseGitleaksFindings, parseTruffleHogFindings, type GitleaksResult, type TruffleHogResult } from "./secrets.js";

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

  it("never surfaces the internal correlation marker rules as findings themselves", () => {
    const results: GitleaksResult[] = [
      { RuleID: "supabase-demo-key-marker", File: "supabase/seed.sql", StartLine: 2 },
      { RuleID: "harvey-test-idp-marker", File: ".github/workflows/main.yml", StartLine: 3 },
    ];
    const findings = parseGitleaksFindings(results, "source");
    expect(findings).toHaveLength(0);
  });
});
