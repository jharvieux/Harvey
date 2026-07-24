import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkMissingCsp, checkPublicDirSensitive, parseSemgrepFindings, type SemgrepOutput } from "./semgrep.js";

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

  it("#455: threads cwe/owasp from a rule's metadata onto the finding", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "python.django.security.injection.sql.sql-injection-using-db-cursor-execute",
          path: "app.py",
          extra: {
            message: "sqli",
            severity: "ERROR",
            metadata: {
              confidence: "HIGH",
              cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
              owasp: ["A03:2021 - Injection"],
            },
          },
        },
      ],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.cwe).toEqual(["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"]);
    expect(findings[0]?.owasp).toEqual(["A03:2021 - Injection"]);
  });

  it("#455: a finding whose rule carries no cwe/owasp metadata gets neither field — never invented", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "harvey-service-role-in-client",
          path: "app/components/Foo.tsx",
          extra: { message: "leak", severity: "ERROR", metadata: { confidence: "HIGH" } },
        },
      ],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.cwe).toBeUndefined();
    expect(findings[0]?.owasp).toBeUndefined();
  });

  it("#976: normalizes a registry rule's bare-STRING cwe/owasp to an array (a string reached .cwe.map and threw)", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "javascript.express.security.injection.tainted-sql-string",
          path: "app/api/route.ts",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- a registry rule can ship cwe/owasp as a bare string, which the JSON type does not force to a list
          extra: { message: "sqli", severity: "ERROR", metadata: { cwe: "CWE-89: SQL Injection", owasp: "A03:2021 - Injection" } as any },
        },
      ],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.cwe).toEqual(["CWE-89: SQL Injection"]);
    expect(findings[0]?.owasp).toEqual(["A03:2021 - Injection"]);
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

describe("checkPublicDirSensitive", () => {
  function withPublic(files: string[], fn: (dir: string) => void): void {
    const dir = mkdtempSync(join(tmpdir(), "harvey-public-"));
    try {
      for (const rel of files) {
        const full = join(dir, "public", rel);
        mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
        writeFileSync(full, "x");
      }
      fn(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("flags sensitive files (.env*, SQL dumps, keys) served from public/ at high tier", () => {
    withPublic([".env.production", "backup.sql", "certs/server.pem", "nested/id_rsa"], (dir) => {
      const findings = checkPublicDirSensitive(dir);
      expect(findings).toHaveLength(4);
      expect(findings.every((f) => f.precisionTier === "high")).toBe(true);
      expect(findings.map((f) => f.location).sort()).toEqual(
        ["public/.env.production", "public/backup.sql", "public/certs/server.pem", "public/nested/id_rsa"].sort(),
      );
    });
  });

  it("does not flag benign web assets (favicon, fonts, robots, images)", () => {
    withPublic(["favicon.ico", "fonts/inter.woff2", "robots.txt", "img/logo.png", "site.webmanifest"], (dir) => {
      expect(checkPublicDirSensitive(dir)).toEqual([]);
    });
  });

  it("returns nothing when there is no public/ directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-nopublic-"));
    try {
      expect(checkPublicDirSensitive(dir)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
