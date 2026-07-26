import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  checkMissingCsp,
  checkPublicDirSensitive,
  CI_PIPELINE_CATEGORY,
  CORS_BARE_WILDCARD_TAXONOMY,
  parseSemgrepFindings,
  partitionMarkerSuppressed,
  POSTMESSAGE_WILDCARD_TAXONOMY,
  runSemgrep,
  semgrepErrorFinding,
  semgrepScopeFinding,
  semgrepSuppressionFinding,
  semgrepUnavailableFinding,
  type SemgrepOutput,
} from "./semgrep.js";

// #950: semgrep absent from PATH must degrade to a disclosed coverage gap, not an uncaught
// ENOENT crash (mirrors the osv-scanner pattern, #512). Only "semgrep" is faked here — every
// other execFileSync call (there are none elsewhere in this file) would pass through untouched.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "semgrep") {
        const err = new Error("spawnSync semgrep ENOENT") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      }
      return actual.execFileSync(bin, args, opts as never);
    }),
  };
});

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

  it("#996: routes a workflow-file finding to the CI/CD pipeline category with the routing reason on the finding", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "yaml.github-actions.security.run-shell-injection.run-shell-injection",
          path: ".github/workflows/release.yml",
          start: { line: 38 },
          extra: { message: "shell injection", severity: "ERROR", metadata: { confidence: "HIGH" } },
        },
      ],
    };
    const f = parseSemgrepFindings(output)[0];
    expect(f?.category).toBe(CI_PIPELINE_CATEGORY);
    expect(f?.severity).toBe("High"); // severity kept — the section is non-grading, the finding is not softened
    expect(f?.precisionTier).toBe("high"); // still reaches the free report
    expect(f?.impact).toContain("outside the app-hygiene grade");
  });

  it("#996: a non-workflow finding keeps the app category untouched", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "harvey-permissive-cors",
          path: "app/api/route.ts",
          extra: { message: "cors", severity: "ERROR", metadata: { confidence: "HIGH", harveySeverity: "High" } },
        },
      ],
    };
    expect(parseSemgrepFindings(output)[0]?.category).toBe("Next.js/web footgun");
  });

  it("#996: metadata.harveyTaxonomy overrides the path-prefixed check_id as the finding's taxonomy", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "src.scan.rules.semgrep.harvey-permissive-cors-bare",
          path: "app/api/public/route.ts",
          extra: {
            message: "bare wildcard",
            severity: "ERROR",
            metadata: { confidence: "HIGH", harveySeverity: "Low", harveyTaxonomy: CORS_BARE_WILDCARD_TAXONOMY },
          },
        },
      ],
    };
    const f = parseSemgrepFindings(output)[0];
    expect(f?.taxonomy).toBe(CORS_BARE_WILDCARD_TAXONOMY);
    expect(f?.severity).toBe("Low");
    expect(f?.precisionTier).toBe("high");
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

  // #1077: MEASURED 2026-07-25 (semgrep 1.164.0) — all 915 rules across the six registry packs
  // Harvey loads carry metadata.references. Dropping it left 224/386 (58%) of a real deliverable's
  // findings carrying the identical generic placeholder one line after the rule's own guidance was
  // discarded (semgrep.ts:112 in the pre-fix code).
  it("#1077: composes the fix from the rule's own references + source, instead of the generic placeholder", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "package_managers.npm.npm-missing-minimum-release-age",
          path: "package.json",
          extra: {
            message: "missing minimumReleaseAge",
            severity: "ERROR",
            metadata: {
              confidence: "HIGH",
              references: ["https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing/", "https://github.com/npm/cli/pull/8965"],
              source: "https://semgrep.dev/r/package_managers.npm.npm-missing-minimum-release-age",
              likelihood: "LOW",
              impact: "HIGH",
            },
          },
        },
      ],
    };
    const [finding] = parseSemgrepFindings(output);
    expect(finding?.references).toEqual(["https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing/", "https://github.com/npm/cli/pull/8965"]);
    expect(finding?.fix).toContain("https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing/");
    expect(finding?.fix).toContain("https://semgrep.dev/r/package_managers.npm.npm-missing-minimum-release-age");
    expect(finding?.fix).not.toBe("Review the matched code path against the rule's remediation guidance.");
  });

  it("#1077: a rule with no references/source (every harvey-* custom rule today) keeps the generic placeholder fix, and no references field", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "harvey-dangerously-set-inner-html",
          path: "app/Bio.tsx",
          extra: { message: "xss", severity: "ERROR", metadata: { confidence: "HIGH" } },
        },
      ],
    };
    const [finding] = parseSemgrepFindings(output);
    expect(finding?.references).toBeUndefined();
    expect(finding?.fix).toBe("Review the matched code path against the rule's remediation guidance.");
  });

  it("#1077: a bare-STRING references value normalizes to an array, same as cwe/owasp (#976)", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "some.rule",
          path: "app/x.ts",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- proving the runtime shape a registry rule can ship, not the declared type
          extra: { message: "m", severity: "ERROR", metadata: { references: "https://example.com/one-link" } as any },
        },
      ],
    };
    const [finding] = parseSemgrepFindings(output);
    expect(finding?.references).toEqual(["https://example.com/one-link"]);
    expect(finding?.fix).toContain("https://example.com/one-link");
  });
});

// #996: the canonical non-grading taxonomies live twice — as exported constants (what
// NON_GRADING_TAXONOMIES keys on) and as metadata.harveyTaxonomy in the rule YAML (what the
// findings actually carry). A drift between them silently re-grades the class, so pin the sync.
describe("#996: rule YAML harveyTaxonomy stays in sync with the exported constants", () => {
  const ruleDir = fileURLToPath(new URL("./rules/semgrep/", import.meta.url));

  it("harvey-permissive-cors-bare declares CORS_BARE_WILDCARD_TAXONOMY", () => {
    expect(readFileSync(join(ruleDir, "base.yml"), "utf8")).toContain(`harveyTaxonomy: "${CORS_BARE_WILDCARD_TAXONOMY}"`);
  });

  it("harvey-postmessage-wildcard declares POSTMESSAGE_WILDCARD_TAXONOMY", () => {
    expect(readFileSync(join(ruleDir, "xss.yml"), "utf8")).toContain(`harveyTaxonomy: "${POSTMESSAGE_WILDCARD_TAXONOMY}"`);
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

// #950: previously runSemgrep threw the raw ENOENT, which propagated uncaught to quick-scan's
// main().catch() and hard-exited the CLI instead of degrading like every other mechanical tool.
describe("runSemgrep degrades on a missing binary (#950)", () => {
  it("returns a failure reason instead of throwing when semgrep is absent from PATH", () => {
    const { result, failure } = runSemgrep("/some/target");
    expect(failure).toBe("semgrep not found on PATH");
    expect(result).toEqual({});
  });
});

describe("semgrepUnavailableFinding (#950)", () => {
  it("discloses the coverage gap without claiming zero footguns found", () => {
    const finding = semgrepUnavailableFinding("semgrep not found on PATH");
    expect(finding.id).toBe("SEM-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.evidence).toContain("semgrep not found on PATH");
    expect(finding.impact).toContain("not a finding of zero footguns");
  });
});

// #1066: `--disable-nosem` makes semgrep report the matches a `nosem` marker would have hidden,
// but the OSS JSON does not say WHICH ones they were, so Harvey re-derives the marker. The point
// of the exercise is the count — a suppression the deliverable never mentions is one the audited
// party made on the auditor's behalf.
describe("partitionMarkerSuppressed (#1066)", () => {
  const withSource = (lines: string[]): { dir: string; file: string } => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-nosem-"));
    const file = join(dir, "Bio.tsx");
    writeFileSync(file, lines.join("\n"));
    return { dir, file };
  };

  it("routes a match to `suppressed` when the marker is on the matched line or the line above", () => {
    const { dir, file } = withSource([
      "export function A({ bio }) {",
      "  // nosemgrep",
      "  return <div dangerouslySetInnerHTML={{ __html: bio }} />;",
      "}",
      "export function B({ bio }) {",
      "  return <div dangerouslySetInnerHTML={{ __html: bio }} />; // nosem",
      "}",
      "export function C({ bio }) {",
      "  return <div dangerouslySetInnerHTML={{ __html: bio }} />;",
      "}",
    ]);
    try {
      const { reported, suppressed } = partitionMarkerSuppressed({
        results: [
          { check_id: "harvey-x", path: file, start: { line: 3 } },
          { check_id: "harvey-x", path: file, start: { line: 6 } },
          { check_id: "harvey-x", path: file, start: { line: 9 } },
        ],
      });
      expect(suppressed.map((r) => r.start?.line)).toEqual([3, 6]);
      expect(reported.map((r) => r.start?.line)).toEqual([9]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names every suppressed location and its rule in SEM-SUPPRESS-00, and stays silent when there are none", () => {
    expect(semgrepSuppressionFinding([], "/target")).toEqual([]);
    const [finding] = semgrepSuppressionFinding(
      [{ check_id: "harvey-dangerously-set-inner-html", path: "/target/app/Bio.tsx", start: { line: 12 } }],
      "/target",
    );
    expect(finding?.id).toBe("SEM-SUPPRESS-00");
    expect(finding?.confidence).toBe("N/A");
    expect(finding?.title).toContain("1 semgrep finding suppressed");
    expect(finding?.evidence).toContain("app/Bio.tsx:12 (harvey-dangerously-set-inner-html)");
  });
});

// #1066: derived from paths.scanned, not from the flags we passed — so a semgrep default ignore, a
// target-shipped .semgrepignore, or the [INTERNAL] override disappearing all read the same way.
describe("semgrepScopeFinding (#1066)", () => {
  it("counts and names JS/TS files semgrep never analysed, and stays silent when it analysed them all", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-scope-"));
    try {
      mkdirSync(join(dir, "vendor"), { recursive: true });
      mkdirSync(join(dir, "node_modules"), { recursive: true });
      writeFileSync(join(dir, "app.ts"), "export const a = 1;\n");
      writeFileSync(join(dir, "vendor", "lib.js"), "module.exports = 1;\n");
      writeFileSync(join(dir, "node_modules", "dep.js"), "module.exports = 1;\n");
      writeFileSync(join(dir, "README.md"), "not source\n");

      const [finding] = semgrepScopeFinding(dir, { paths: { scanned: [join(dir, "app.ts")] } });
      expect(finding?.id).toBe("SEM-SCOPE-00");
      expect(finding?.title).toContain("1 JS/TS source file");
      expect(finding?.evidence).toContain("vendor/lib.js");
      // node_modules is excluded by argv on purpose (osv-scanner owns dependencies), and a .md
      // file is not something the semgrep rules could have analysed — neither is a coverage gap.
      expect(finding?.evidence).not.toContain("node_modules");
      expect(finding?.evidence).not.toContain("README.md");

      expect(semgrepScopeFinding(dir, { paths: { scanned: [join(dir, "app.ts"), join(dir, "vendor", "lib.js")] } })).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// #1077: MEASURED 2026-07-25 (semgrep 1.164.0) — a file with a syntax error still appears in
// paths.scanned (so semgrepScopeFinding's diff above can't catch it) while contributing zero
// findings, indistinguishable from a clean file. The repo already states the principle this
// violates, verbatim, at runSemgrepOnFile's guard below — this closes the gap on the whole-tree
// engagement path, which never read `errors[]` at all.
describe("semgrepErrorFinding (#1077)", () => {
  it("names a per-file parse error, even though the file is also in paths.scanned", () => {
    const findings = semgrepErrorFinding("/target", {
      errors: [{ type: "Syntax error", message: "Syntax error at line /target/app/broken.tsx:1:\nsomething unexpected", path: "/target/app/broken.tsx" }],
      paths: { scanned: ["/target/app/broken.tsx"] },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ id: "SEM-ERR-00", confidence: "N/A", severity: "Info", category: "Coverage" });
    expect(findings[0]?.evidence).toContain("app/broken.tsx (Syntax error: Syntax error at line /target/app/broken.tsx:1:)");
  });

  // MEASURED 2026-07-25: semgrep emits errors[].type as a bare string for a whole-file syntax
  // error but as an array (e.g. ["PartialParsing", [...]]) for a partial-parse warning.
  it("handles errors[].type as an array without crashing or printing [object Object]", () => {
    const findings = semgrepErrorFinding("/target", {
      errors: [{ type: ["PartialParsing", ["some-detail"]], path: "/target/app/partial.ts" }],
    });
    expect(findings[0]?.evidence).toContain("PartialParsing");
    expect(findings[0]?.evidence).not.toContain("[object Object]");
  });

  it("names a file semgrep chose to skip (paths.skipped, only populated at --verbose) alongside any errors", () => {
    const findings = semgrepErrorFinding("/target", {
      paths: { scanned: [], skipped: [{ path: "/target/vendor/huge.js", reason: "too_big" }] },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("vendor/huge.js (skipped: too_big)");
  });

  it("stays silent when there are no errors and nothing was skipped", () => {
    expect(semgrepErrorFinding("/target", { paths: { scanned: ["/target/app/ok.ts"] } })).toEqual([]);
  });
});
