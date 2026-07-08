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
});
