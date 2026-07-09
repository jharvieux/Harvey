import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkMissingCsp, parseSemgrepFindings, type SemgrepOutput } from "./semgrep.js";

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

describe("checkMissingCsp", () => {
  function withDir(files: Record<string, string>, fn: (dir: string) => void): void {
    const dir = mkdtempSync(join(tmpdir(), "harvey-csp-"));
    try {
      for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
      fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("flags a next.config with no CSP (P-NO-CSP) at review tier", () => {
    withDir({ "next.config.js": `module.exports = { reactStrictMode: true };` }, (dir) => {
      const findings = checkMissingCsp(dir);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.precisionTier).toBe("review");
    });
  });

  it("does not flag when a CSP is present in next.config", () => {
    withDir({ "next.config.js": `headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }]` }, (dir) => {
      expect(checkMissingCsp(dir)).toEqual([]);
    });
  });

  it("does not flag when CSP lives in middleware instead of next.config", () => {
    withDir({
      "next.config.js": `module.exports = {};`,
      "middleware.ts": `res.headers.set("Content-Security-Policy", "default-src 'self'");`,
    }, (dir) => {
      expect(checkMissingCsp(dir)).toEqual([]);
    });
  });

  it("does not flag a directory with no Next config to assert against", () => {
    withDir({ "readme.md": "hi" }, (dir) => {
      expect(checkMissingCsp(dir)).toEqual([]);
    });
  });
});
