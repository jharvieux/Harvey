import { describe, expect, it } from "vitest";
import { checkMissingSecurityHeaders, parseSemgrepFindings, type SemgrepOutput } from "./semgrep.js";

describe("parseSemgrepFindings", () => {
  it("tags ERROR+HIGH-confidence non-audit rules as high precision", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "harvey-service-role-in-client",
          path: "app/components/Foo.tsx",
          start: { line: 4 },
          extra: { message: "leak", severity: "ERROR", metadata: { confidence: "HIGH", harveySeverity: "Critical" } },
        },
      ],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.precisionTier).toBe("high");
    expect(findings[0]?.severity).toBe("Critical");
  });

  it("routes .audit. rules to review even at ERROR+HIGH — audit rules are excluded from the trusted count", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "p/owasp-top-ten.audit.some-rule",
          path: "app/x.ts",
          extra: { message: "m", severity: "ERROR", metadata: { confidence: "HIGH" } },
        },
      ],
    };
    expect(parseSemgrepFindings(output)[0]?.precisionTier).toBe("review");
  });

  it("routes WARNING/MEDIUM rules (e.g. open-redirect) to review", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "harvey-open-redirect",
          path: "app/api/go/route.ts",
          extra: { message: "redirect", severity: "WARNING", metadata: { confidence: "MEDIUM", harveySeverity: "Medium" } },
        },
      ],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.severity).toBe("Medium");
  });
});

describe("checkMissingSecurityHeaders", () => {
  it("flags a headers() function with no CSP header", () => {
    const source = `module.exports = { async headers() { return [{ source: "/(.*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] }]; } };`;
    const findings = checkMissingSecurityHeaders("next.config.js", source);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.precisionTier).toBe("review");
  });

  it("does not flag when CSP is present", () => {
    const source = `module.exports = { async headers() { return [{ headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }] }]; } };`;
    expect(checkMissingSecurityHeaders("next.config.js", source)).toEqual([]);
  });

  it("does not flag configs with no headers() function at all", () => {
    const source = `module.exports = { reactStrictMode: true };`;
    expect(checkMissingSecurityHeaders("next.config.js", source)).toEqual([]);
  });
});
