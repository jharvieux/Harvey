import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { readNamesSafe } from "../fs-walk.js";
import {
  checkMissingCsp,
  checkPublicDirSensitive,
  CI_PIPELINE_CATEGORY,
  CORS_BARE_WILDCARD_TAXONOMY,
  materializeRegistryPacks,
  parseSemgrepFindings,
  partitionGuardTokenSuppressed,
  partitionMarkerSuppressed,
  POSTMESSAGE_WILDCARD_TAXONOMY,
  runRegistryPacksOnFile,
  runSemgrep,
  runSemgrepPartitioned,
  scanDidNotRun,
  semgrepExecutionPlanReceipt,
  semgrepErrorFinding,
  semgrepScopeFinding,
  semgrepSuppressionFinding,
  semgrepUnavailableFinding,
  stripCommentsAndStrings,
  type SemgrepOutput,
  type SemgrepResult,
} from "./semgrep.js";
import { assertSuccessfulSemgrepExecutionReceipt } from "./semgrep-family-cache.js";

const CACHE_REGISTRY_PACKS = ["p/typescript", "p/react", "p/nextjs", "p/owasp-top-ten", "p/secrets", "p/security-audit"];

function seedRegistrySnapshot(cacheDir: string): { identity: string; files: string[] } {
  const bodies = CACHE_REGISTRY_PACKS.map((pack, index) => ({
    pack,
    body: `rules:\n  - id: fixture-registry-${index}-${pack.replaceAll("/", "-")}\n    message: fixture\n    severity: WARNING\n    languages: [typescript]\n    pattern: $X\n${index === 0 || index === 3 ? "  - id: fixture-overlapping-registry-rule\n    message: overlap\n    severity: WARNING\n    languages: [typescript]\n    pattern: $OVERLAP\n" : ""}`,
  }));
  const hash = createHash("sha256");
  for (const { pack, body } of bodies) hash.update(pack).update("\0").update(body);
  const identity = hash.digest("hex");
  const dir = join(cacheDir, "registry-packs", identity);
  mkdirSync(dir, { recursive: true });
  const files = bodies.map(({ pack, body }, index) => {
    const path = join(dir, `${index}-${pack.replaceAll("/", "-")}.yml`);
    writeFileSync(path, body);
    return path;
  });
  writeFileSync(join(cacheDir, "registry-packs", "current.json"), `${JSON.stringify({ schema: 1, identity })}\n`);
  return { identity, files };
}

function runSemgrepWithFixture(dir = "/some/target") {
  const root = mkdtempSync(join(tmpdir(), "harvey-semgrep-run-registry-"));
  try {
    return runSemgrep(dir, seedRegistrySnapshot(root).files);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("Semgrep registry snapshot reuse (#1864)", () => {
  it("reuses and revalidates the exact restored bytes without contacting the live registry", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-registry-reuse-"));
    try {
      const seeded = seedRegistrySnapshot(dir);
      expect(materializeRegistryPacks(dir, "reuse")).toEqual(seeded);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a retry snapshot whose bytes no longer match its manifest identity", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-registry-corrupt-"));
    try {
      const seeded = seedRegistrySnapshot(dir);
      writeFileSync(seeded.files[0]!, "rules: [changed]\n");
      const result = materializeRegistryPacks(dir, "reuse");
      expect(result.identity).toBeUndefined();
      expect(result.failure).toContain("restored Semgrep registry snapshot required on CI retry but is invalid");
      expect(result.failure).toContain("snapshot bytes hash to");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Real `semgrep 1.173.0` output, captured from a purpose-built corpus — NOT hand-written. See
// __fixtures__/semgrep/PROVENANCE.md for the exact command, builder, and tracked canonicalization.
// The old inline `SemgrepOutput` literals fed to parseSemgrepFindings were the #1063 fiction class in
// Harvey's core detector; two invented shapes (a no-cwe harvey rule, a fabricated bare-string-cwe
// rule) were corrected against this capture (#1156, closes #1150 row 7).
const CORPUS: SemgrepOutput = JSON.parse(
  readFileSync(new URL("./__fixtures__/semgrep/semgrep-1.173.0-corpus.json", import.meta.url), "utf8"),
) as SemgrepOutput;

// The captured record whose rule id ends with `suffix` — throws (never silently skips) if the
// re-capture ever drops the rule a test relies on.
function captured(suffix: string): SemgrepResult {
  const r = (CORPUS.results ?? []).find((x) => x.check_id.endsWith(suffix));
  if (!r) throw new Error(`no captured semgrep record for rule ending "${suffix}" — re-run build-corpus.mjs`);
  return r;
}

// #950: semgrep absent from PATH must degrade to a disclosed coverage gap, not an uncaught
// ENOENT crash (mirrors the osv-scanner pattern, #512). Only "semgrep" is faked here — every
// other execFileSync call (there are none elsewhere in this file) would pass through untouched.
// #1710: the thrown code is hoisted state so the invocation-pin tests below can exercise a
// non-ENOENT failure too; every test leaves it at "ENOENT".
const semgrepMock = vi.hoisted(() => ({ errCode: "ENOENT", outputs: [] as string[] }));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFile: vi.fn((bin: string, args: string[], opts: unknown, callback: (err: Error | null, stdout: string, stderr: string) => void) => {
      if (bin === "semgrep") {
        const err = new Error(`spawn semgrep ${semgrepMock.errCode}`) as NodeJS.ErrnoException;
        err.code = semgrepMock.errCode;
        queueMicrotask(() => callback(err, "", ""));
        return {} as never;
      }
      return actual.execFile(bin as never, args as never, opts as never, callback as never);
    }),
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "semgrep") {
        const output = semgrepMock.outputs.shift();
        if (output !== undefined) return output;
        const err = new Error(`spawnSync semgrep ${semgrepMock.errCode}`) as NodeJS.ErrnoException;
        err.code = semgrepMock.errCode;
        throw err;
      }
      return actual.execFileSync(bin, args, opts as never);
    }),
  };
});

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const CALIBRATION_ROOT = join(REPO_ROOT, "targets/calibration");
const SEMGREP_RULE_ROOT = join(REPO_ROOT, "src/scan/rules/semgrep");
const SQL_TEMPLATE_TAXONOMY = "src.scan.rules.semgrep.harvey-sql-injection-template";
const SQL_TEMPLATE_LITERAL = "$1 placeholders";
const SQL_TEMPLATE_MESSAGE =
  "Untrusted request input is interpolated into a raw SQL string reaching .query(). Use " +
  "parameterized queries ($1 placeholders with a params array), never string interpolation.";

// The base artifact had two result identities at each location because Semgrep 1.173 expanded
// the request-source regex's unnamed capture in the rule message. The stale member of each pair
// is removed; the survivor is the same raw match with the literal SQL placeholder intact.
const SQL_TEMPLATE_DUPLICATE_LINEAGE = {
  schema: 1,
  taxonomy: SQL_TEMPLATE_TAXONOMY,
  reason: "Semgrep 1.173 unnamed-capture message expansion; retain the literal-message identity",
  evidenceSha256: "a99574f1c232c46eb904310f6d03fac0bf28bee0adb1ecf59ab8d9d1c1c4c09b",
  rows: [
    ["lib/header-gateway-tenant.js:9", ["SEM-410", "SEM-411"], "SEM-389"],
    ["pages/api/cookie-report.js:10", ["SEM-370", "SEM-371"], "SEM-369"],
    ["pages/api/destructure-sql.js:9", ["SEM-406", "SEM-407"], "SEM-387"],
    ["pages/api/multihop-sql.js:11", ["SEM-376", "SEM-377"], "SEM-372"],
    ["pages/api/search.js:11", ["SEM-372", "SEM-373"], "SEM-370"],
    ["pages/api/sqli-const-denylist-guard.js:14", ["SEM-390", "SEM-391"], "SEM-379"],
    ["pages/api/sqli-const-guard-throw-swallowed.js:17", ["SEM-404", "SEM-405"], "SEM-386"],
    ["pages/api/sqli-const-unanchored-guard.js:14", ["SEM-394", "SEM-395"], "SEM-381"],
    ["pages/api/sqli-denylist-guard-braceless.js:12", ["SEM-384", "SEM-385"], "SEM-376"],
    ["pages/api/sqli-denylist-guard-throw.js:11", ["SEM-374", "SEM-375"], "SEM-371"],
    ["pages/api/sqli-denylist-guard.js:15", ["SEM-396", "SEM-397"], "SEM-382"],
    ["pages/api/sqli-enum-guard-throw-finally.js:15", ["SEM-408", "SEM-409"], "SEM-388"],
    ["pages/api/sqli-guard-braceless-no-return.js:14", ["SEM-392", "SEM-393"], "SEM-380"],
    ["pages/api/sqli-guard-no-return.js:13", ["SEM-386", "SEM-387"], "SEM-377"],
    ["pages/api/sqli-mflag-guard-braceless.js:11", ["SEM-382", "SEM-383"], "SEM-375"],
    ["pages/api/sqli-mflag-guard-throw.js:11", ["SEM-380", "SEM-381"], "SEM-374"],
    ["pages/api/sqli-mflag-guard.js:15", ["SEM-398", "SEM-399"], "SEM-383"],
    ["pages/api/sqli-reassigned-guard.js:17", ["SEM-402", "SEM-403"], "SEM-385"],
    ["pages/api/sqli-regex-guard-throw-swallowed.js:16", ["SEM-400", "SEM-401"], "SEM-384"],
    ["pages/api/sqli-unanchored-guard-braceless.js:10", ["SEM-368", "SEM-369"], "SEM-368"],
    ["pages/api/sqli-unanchored-guard-throw.js:11", ["SEM-378", "SEM-379"], "SEM-373"],
    ["pages/api/sqli-unanchored-guard.js:14", ["SEM-388", "SEM-389"], "SEM-378"],
  ],
} as const;
const SQL_TEMPLATE_DUPLICATE_LINEAGE_SHA256 = "d88ce40e6b5d2996f718b70d647b33bb1c849b91aaed4b67a701145f6bce1028";

function sqlTemplateLocation(result: SemgrepResult): string {
  const normalized = result.path.replaceAll("\\", "/");
  const marker = "targets/calibration/";
  const index = normalized.lastIndexOf(marker);
  const path = index >= 0 ? normalized.slice(index + marker.length) : normalized;
  return `${path}:${result.start?.line ?? 0}`;
}

function sqlTemplateResults(output: SemgrepOutput): SemgrepResult[] {
  return (output.results ?? []).filter((result) => result.check_id.endsWith("harvey-sql-injection-template"));
}

function assertSqlTemplateMessages(output: SemgrepOutput, raw: string, label: string): void {
  const results = sqlTemplateResults(output);
  const locations = results.map(sqlTemplateLocation).sort();
  const expectedLocations = [
    "app/api/ar-src-sql/route.ts:8",
    ...SQL_TEMPLATE_DUPLICATE_LINEAGE.rows.map(([location]) => location),
  ].sort();
  const substitutions = results.filter((result) => result.extra?.message !== `${SQL_TEMPLATE_MESSAGE}\n`);
  if (results.length !== 23 || new Set(locations).size !== 23 || JSON.stringify(locations) !== JSON.stringify(expectedLocations)) {
    throw new Error(`${label}: expected exactly 23 SQL-template findings at 23 frozen locations; received ${results.length}/${new Set(locations).size}`);
  }
  if (substitutions.length > 0) {
    throw new Error(`${label}: ${substitutions.length} SQL-template message substitutions`);
  }
  expect(raw.match(/\$1 placeholders/g)).toHaveLength(23);
  expect(raw).not.toContain("imp placeholders");
  expect(raw).not.toContain("// placeholders");

  const findings = parseSemgrepFindings({ ...output, results });
  for (const finding of findings) {
    expect(finding.title).toContain(SQL_TEMPLATE_LITERAL);
    expect(finding.evidence).toContain(SQL_TEMPLATE_LITERAL);
    expect(finding.impact).toContain(SQL_TEMPLATE_LITERAL);
    expect(JSON.stringify(finding)).not.toContain("imp placeholders");
    expect(JSON.stringify(finding)).not.toContain("// placeholders");
  }
}

function runSemgrep173(config: string): { raw: string; output: SemgrepOutput } {
  const binary = execFileSync("/usr/bin/env", ["sh", "-c", "command -v semgrep"], { encoding: "utf8" }).trim();
  expect(execFileSync(binary, ["--version"], { encoding: "utf8" }).trim()).toBe("1.173.0");
  const raw = execFileSync(binary, [
    "scan", "--json", "--metrics=off", "--disable-version-check", "--timeout", "0", "--jobs", "1",
    "--no-git-ignore", "--config", config, CALIBRATION_ROOT,
  ], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { raw, output: JSON.parse(raw) as SemgrepOutput };
}

describe("Semgrep 1.173 SQL-template message identity (#1954)", () => {
  it("freezes the exact 22-location stale-duplicate lineage receipt", () => {
    expect(SQL_TEMPLATE_DUPLICATE_LINEAGE.rows).toHaveLength(22);
    expect(new Set(SQL_TEMPLATE_DUPLICATE_LINEAGE.rows.map(([location]) => location)).size).toBe(22);
    expect(createHash("sha256").update(JSON.stringify(SQL_TEMPLATE_DUPLICATE_LINEAGE)).digest("hex"))
      .toBe(SQL_TEMPLATE_DUPLICATE_LINEAGE_SHA256);
  });

  it("keeps generated finding and report messages literal at all 23 locations", () => {
    const findings = JSON.parse(readFileSync(join(REPO_ROOT, "dry-run/findings.json"), "utf8")) as Array<Record<string, unknown>>;
    const report = JSON.parse(readFileSync(join(REPO_ROOT, "dry-run/findings-report.json"), "utf8")) as { findings: Array<Record<string, unknown>> };
    const assertArtifact = (rows: Array<Record<string, unknown>>, label: string): void => {
      const sqlRows = rows.filter((row) => row.taxonomy === SQL_TEMPLATE_TAXONOMY);
      expect(sqlRows, label).toHaveLength(23);
      expect(new Set(sqlRows.map((row) => row.location)), label).toEqual(new Set([
        "app/api/ar-src-sql/route.ts:8",
        ...SQL_TEMPLATE_DUPLICATE_LINEAGE.rows.map(([location]) => location),
      ]));
      for (const row of sqlRows) {
        expect(JSON.stringify(row), label).toContain(SQL_TEMPLATE_LITERAL);
        expect(JSON.stringify(row), label).not.toContain("imp placeholders");
        expect(JSON.stringify(row), label).not.toContain("// placeholders");
      }
    };
    assertArtifact(findings, "findings");
    assertArtifact(report.findings, "report");
    expect(report.findings).toEqual(findings);
  });

  describe.runIf(process.env.HARVEY_SEMGREP_LIVE_TESTS === "1")("live binary controls", () => {
    it("preserves the literal message in the base family and all-local monolith", () => {
      for (const [label, config] of [["base family", join(SEMGREP_RULE_ROOT, "base.yml")], ["all-local monolith", SEMGREP_RULE_ROOT]] as const) {
        const { raw, output } = runSemgrep173(config);
        assertSqlTemplateMessages(output, raw, label);
      }
    });

    it("fails exactly 22 rows when the request-source capture is physically restored", () => {
      const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-sql-message-red-"));
      try {
        const source = readFileSync(join(SEMGREP_RULE_ROOT, "base.yml"), "utf8");
        const reverted = source.replace(
          "regex: ^_?(?:req|request|nextReq|nextRequest|httpReq|incoming)$",
          "regex: ^_?(req|request|nextReq|nextRequest|httpReq|incoming)$",
        );
        expect(reverted).not.toBe(source);
        const config = join(dir, "base.yml");
        writeFileSync(config, reverted);
        const { raw, output } = runSemgrep173(config);
        expect(() => assertSqlTemplateMessages(output, raw, "physical unescaped reversion"))
          .toThrow("physical unescaped reversion: 22 SQL-template message substitutions");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("fails closed when one surviving SQL-template result is deleted", () => {
      const { raw, output } = runSemgrep173(join(SEMGREP_RULE_ROOT, "base.yml"));
      const deleted = { ...output, results: (output.results ?? []).filter((result) => result !== sqlTemplateResults(output)[0]) };
      expect(() => assertSqlTemplateMessages(deleted, raw, "physical survivor deletion"))
        .toThrow("physical survivor deletion: expected exactly 23 SQL-template findings at 23 frozen locations; received 22/22");
    });
  });
});

// Every case below feeds parseSemgrepFindings a REAL captured record (see CORPUS above), except the
// two labelled synthetic negative-controls whose shapes no real rule emits (PROVENANCE.md).
describe("parseSemgrepFindings", () => {
  it("tags a real ERROR+HIGH non-audit rule (harvey-service-role-in-client) as high precision", () => {
    const findings = parseSemgrepFindings({ results: [captured("harvey-service-role-in-client")] });
    expect(findings[0]?.precisionTier).toBe("high");
    expect(findings[0]?.severity).toBe("Critical"); // harveySeverity override, as the real rule ships it
  });

  it("routes a real .audit. rule to review even at ERROR+HIGH (code-string-concat) — audit rules are excluded from the trusted count", () => {
    const audit = captured("audit.code-string-concat.code-string-concat");
    expect(audit.extra?.severity).toBe("ERROR"); // guard: the routing is only meaningful because this really is ERROR+HIGH
    expect(audit.extra?.metadata?.confidence).toBe("HIGH");
    expect(parseSemgrepFindings({ results: [audit] })[0]?.precisionTier).toBe("review");
  });

  it("routes a real WARNING/MEDIUM rule (harvey-open-redirect) to review", () => {
    const findings = parseSemgrepFindings({ results: [captured("harvey-open-redirect")] });
    expect(findings[0]?.precisionTier).toBe("review");
    expect(findings[0]?.severity).toBe("Medium");
  });

  it("#455: threads a real registry rule's cwe/owasp arrays onto the finding (cors-misconfiguration)", () => {
    const findings = parseSemgrepFindings({ results: [captured("cors-misconfiguration.cors-misconfiguration")] });
    expect(findings[0]?.cwe).toEqual(["CWE-346: Origin Validation Error"]);
    expect(findings[0]?.owasp).toEqual(["A07:2021 - Identification and Authentication Failures", "A07:2025 - Authentication Failures"]);
  });

  // Synthetic negative-control: MEASURED 2026-07-26, every rule across the six packs Harvey loads
  // ships cwe, so a no-cwe match cannot be captured (PROVENANCE.md). The parser must still add
  // neither field when the metadata omits it — the shape a future cwe-less rule would produce.
  it("#455: a finding whose rule carries no cwe/owasp metadata gets neither field — never invented", () => {
    const output: SemgrepOutput = {
      results: [{ check_id: "harvey-no-cwe-synthetic", path: "app/x.ts", extra: { message: "m", severity: "ERROR", metadata: { confidence: "HIGH" } } }],
    };
    const findings = parseSemgrepFindings(output);
    expect(findings[0]?.cwe).toBeUndefined();
    expect(findings[0]?.owasp).toBeUndefined();
  });

  it("#996: routes a real workflow-file finding (run-shell-injection) to the CI/CD pipeline category with the routing reason", () => {
    const shell = captured("run-shell-injection.run-shell-injection");
    expect(shell.path).toContain(".github/workflows/"); // guard: the routing keys on this path
    const f = parseSemgrepFindings({ results: [shell] })[0];
    expect(f?.category).toBe(CI_PIPELINE_CATEGORY);
    expect(f?.severity).toBe("High"); // ERROR kept — the section is non-grading, the finding is not softened
    expect(f?.precisionTier).toBe("high"); // ERROR+HIGH still reaches the free report
    expect(f?.impact).toContain("outside the app-hygiene grade");
  });

  it("#996: a real non-workflow finding (harvey-permissive-cors) keeps the app category untouched", () => {
    expect(parseSemgrepFindings({ results: [captured("harvey-permissive-cors")] })[0]?.category).toBe("Next.js/web footgun");
  });

  it("#996: a real rule's metadata.harveyTaxonomy overrides the path-prefixed check_id (harvey-permissive-cors-bare)", () => {
    const bare = captured("harvey-permissive-cors-bare");
    expect(bare.extra?.metadata?.harveyTaxonomy).toBe(CORS_BARE_WILDCARD_TAXONOMY); // guard: the real rule still declares it
    const f = parseSemgrepFindings({ results: [bare] })[0];
    expect(f?.taxonomy).toBe(CORS_BARE_WILDCARD_TAXONOMY);
    expect(f?.severity).toBe("Low");
    expect(f?.precisionTier).toBe("high");
  });

  it("#976: normalizes a real registry rule's bare-STRING cwe/owasp to an array (bypass-tls-verification ships both as strings)", () => {
    const tls = captured("bypass-tls-verification.bypass-tls-verification");
    expect(typeof tls.extra?.metadata?.cwe).toBe("string"); // guard: this is the real bare-string carrier a string once reached .cwe.map() from (#976)
    const findings = parseSemgrepFindings({ results: [tls] });
    expect(findings[0]?.cwe).toEqual(["CWE-319: Cleartext Transmission of Sensitive Information"]);
    expect(findings[0]?.owasp).toEqual(["A03:2017 - Sensitive Data Exposure"]);
  });

  // #1077: dropping metadata.references left a real deliverable's findings carrying the identical
  // generic placeholder one line after the rule's own guidance was discarded. npm-missing-minimum-
  // release-age is a real registry rule that ships references + source.
  it("#1077: composes the fix from a real rule's own references + source, instead of the generic placeholder", () => {
    const [finding] = parseSemgrepFindings({ results: [captured("npm-missing-minimum-release-age.npm-missing-minimum-release-age")] });
    expect(finding?.references).toEqual([
      "https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/",
      "https://github.com/npm/cli/pull/8965",
    ]);
    expect(finding?.fix).toContain("https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/");
    expect(finding?.fix).toContain("https://semgrep.dev/r/package_managers.npm.npm-missing-minimum-release-age");
    expect(finding?.fix).not.toBe("Review the matched code path against the rule's remediation guidance.");
  });

  it("#1077: a real rule with no references/source (harvey-open-redirect, like every harvey-* rule today) keeps the generic placeholder fix", () => {
    const [finding] = parseSemgrepFindings({ results: [captured("harvey-open-redirect")] });
    expect(finding?.references).toBeUndefined();
    expect(finding?.fix).toBe("Review the matched code path against the rule's remediation guidance.");
  });

  // Synthetic negative-control: no rule across the six packs emits a bare-STRING references value
  // (bare-string cwe/owasp DO occur — see the #976 case above — bare-string references does not,
  // MEASURED 2026-07-26, PROVENANCE.md). The parser must still normalize it, same as cwe/owasp.
  it("#1077: a bare-STRING references value normalizes to an array, same as cwe/owasp (#976)", () => {
    const output: SemgrepOutput = {
      results: [
        {
          check_id: "some.rule.synthetic-bare-references",
          path: "app/x.ts",
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- proving the runtime shape the JSON type admits, which no captured rule exercises
          extra: { message: "m", severity: "ERROR", metadata: { references: "https://example.com/one-link" } as any },
        },
      ],
    };
    const [finding] = parseSemgrepFindings(output);
    expect(finding?.references).toEqual(["https://example.com/one-link"]);
    expect(finding?.fix).toContain("https://example.com/one-link");
  });
});

// #1166: semgrep 1.164 emits its new 4-level taxonomy (MEASURED live: MEDIUM appears in the JSON;
// CRITICAL/HIGH are the same taxonomy's upper bands). A registry rule with no harveySeverity override
// must deliver at the mapped band, not fall through to the old Medium default — a Critical shipping
// Medium was the bug. An unrecognised severity string fails loud instead of vanishing into a default.
describe("#1166: semgrep new-taxonomy severity strings map correctly, unknowns fail loud", () => {
  const registryResult = (severity: string): SemgrepOutput => ({
    results: [{ check_id: "registry.some-rule", path: "app/x.ts", extra: { message: "m", severity } }],
  });

  it("maps a CRITICAL registry rule (no override) to Critical, not Medium", () => {
    expect(parseSemgrepFindings(registryResult("CRITICAL"))[0]?.severity).toBe("Critical");
  });

  it("maps a HIGH registry rule (no override) to High, not Medium", () => {
    expect(parseSemgrepFindings(registryResult("HIGH"))[0]?.severity).toBe("High");
  });

  it("maps MEDIUM to Medium and LOW to Low", () => {
    expect(parseSemgrepFindings(registryResult("MEDIUM"))[0]?.severity).toBe("Medium");
    expect(parseSemgrepFindings(registryResult("LOW"))[0]?.severity).toBe("Low");
  });

  it("still maps the legacy ERROR/WARNING/INFO taxonomy", () => {
    expect(parseSemgrepFindings(registryResult("ERROR"))[0]?.severity).toBe("High");
    expect(parseSemgrepFindings(registryResult("WARNING"))[0]?.severity).toBe("Medium");
    expect(parseSemgrepFindings(registryResult("INFO"))[0]?.severity).toBe("Low");
  });

  it("negative control: an unmapped severity string throws rather than defaulting to Medium", () => {
    expect(() => parseSemgrepFindings(registryResult("SEVERE"))).toThrow(/Unmapped semgrep severity "SEVERE"/);
  });

  it("a harveySeverity override still wins over the semgrep severity", () => {
    const output: SemgrepOutput = {
      results: [{ check_id: "harvey-x", path: "app/x.ts", extra: { message: "m", severity: "MEDIUM", metadata: { harveySeverity: "Critical" } } }],
    };
    expect(parseSemgrepFindings(output)[0]?.severity).toBe("Critical");
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
    const { result, failure } = runSemgrepWithFixture();
    expect(failure).toBe("semgrep not found on PATH");
    expect(result).toEqual({});
  });
});

// #1710: both whole-tree execution paths share the measured parmap worker topology. The tests hold
// the contract and the failure direction; repeated real Carbon executions remain its falsifier.
describe("runSemgrep pins the deterministic invocation (#1710)", () => {
  const semgrepArgvs = (): string[][] =>
    vi
      .mocked(execFileSync)
      .mock.calls.filter((c) => c[0] === "semgrep")
      .map((c) => c[1] as string[]);

  const injectionRuleIds = [...readFileSync(new URL("./rules/semgrep/injection.yml", import.meta.url), "utf8").matchAll(/^\s*-\s*id:\s*([\w.-]+)\s*$/gm)].map((match) => match[1]!);
  const complementRuleIds = injectionRuleIds.filter((id) => id !== "harvey-log-injection");
  const injectionOutput = (ruleIds: readonly string[], results: SemgrepResult[] = []): SemgrepOutput => ({
    version: "1.173.0", results, errors: [], skipped_rules: [],
    paths: { scanned: ["/some/target/a.ts"], skipped: [] },
    time: { rules: [...ruleIds], fixpoint_timeouts: [] },
  });
  const queueMonolithicInjection = (options: {
    monolithic?: SemgrepOutput;
    firstLog?: SemgrepOutput;
    firstComplement?: SemgrepOutput;
    secondLog?: SemgrepOutput;
    secondComplement?: SemgrepOutput;
  } = {}): void => {
    const log = injectionOutput(["harvey-log-injection"]);
    const complement = injectionOutput(complementRuleIds);
    semgrepMock.outputs.push(...[
      options.monolithic ?? injectionOutput(["registry.other"], [{ check_id: "registry.other", path: "/some/target/a.ts", start: { line: 1 } }]),
      options.firstLog ?? log,
      options.firstComplement ?? complement,
      options.secondLog ?? log,
      options.secondComplement ?? complement,
    ].map((output) => JSON.stringify(output)));
  };

  it("pins the measured nine-worker parmap topology with the per-rule timeout disabled", () => {
    vi.mocked(execFileSync).mockClear();
    runSemgrepWithFixture();
    const argvs = semgrepArgvs();
    expect(argvs).toHaveLength(1); // ENOENT: binary absent, so no second attempt
    expect(argvs[0]?.slice(0, 4)).toEqual(["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"]);
    expect(argvs[0]?.join(" ")).toContain("--timeout 0");
  });

  it("fails closed without retrying through the unproved non-parmap topology", () => {
    semgrepMock.errCode = "EPERM";
    try {
      vi.mocked(execFileSync).mockClear();
      const result = runSemgrepWithFixture();
      const argvs = semgrepArgvs();
      expect(argvs).toHaveLength(1);
      expect(result.failure).toContain("semgrep run did not complete");
      expect(result.result).toEqual({});
    } finally {
      semgrepMock.errCode = "ENOENT";
    }
  });

  it("binds the unstable injection family to two ordered whole-root j1 partitions", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-plan-"));
    try {
      const receipt = semgrepExecutionPlanReceipt(seedRegistrySnapshot(dir).files);
      expect(receipt.schema).toBe(5);
      const injection = receipt.families.find((family) => family.id === "local-injection");
      expect(injection?.topology).toBe("whole-root-rule-partition-v1");
      expect(injection?.mergeAlgorithm).toBe("canonical-semgrep-family-output-v1");
      expect(injection?.verification).toBe("paired-topology-exact");
      expect(injection?.partitions.map((partition) => ({ id: partition.id, ordinal: partition.ordinal, count: partition.ownedRuleIds.length }))).toEqual([
        { id: "log", ordinal: 0, count: 1 },
        { id: "complement", ordinal: 1, count: 29 },
      ]);
      expect(injection?.partitions[0]?.ownedRuleIds).toEqual(["harvey-log-injection"]);
      expect(injection?.partitions.flatMap((partition) => partition.ownedRuleIds).sort()).toEqual(injection?.ownedRuleIds);
      expect(injection?.partitions.every((partition) => partition.argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 1" && partition.argv.join(" ").includes("--timeout 0"))).toBe(true);
      expect(injection).toMatchObject({ familyId: "local-injection", sourceKind: "local-config", sourceId: "injection.yml" });
      expect(injection?.ruleIds).toContain("harvey-log-injection");
      const owner = receipt.families.find((family) => family.id === "registry-0-p-typescript");
      const excluded = receipt.families.find((family) => family.id === "registry-3-p-owasp-top-ten");
      expect(owner?.ownedRuleIds).toContain("fixture-overlapping-registry-rule");
      expect(excluded?.ownedRuleIds).not.toContain("fixture-overlapping-registry-rule");
      expect(excluded?.excludedRuleIds).toContain("fixture-overlapping-registry-rule");
      expect(receipt.families.flatMap((family) => family.ownedRuleIds).filter((id) => id === "fixture-overlapping-registry-rule")).toHaveLength(1);
      const implementation = readFileSync(new URL("./semgrep.ts", import.meta.url), "utf8");
      expect(implementation).toContain("2720a80865498f7a782b59d616a91789fee17aaa852102bc1430316a25c9f49f");
      expect(implementation).toContain('const LOCAL_INJECTION_FAMILY = "local-injection"');
      expect(receipt.families.filter((family) => family.id !== "local-injection").every((family) =>
        (family.id === "registry-singleton-direct-response-write" && family.verification === "paired-cold-exact")
        || (family.verification === "single" && family.argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 9")
      )).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("replaces monolithic injection output only after two exact cold one-worker executions", () => {
    const row = (line: number): SemgrepResult => ({
      check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line },
      extra: { message: `line ${line}`, severity: "WARNING", metadata: { confidence: "MEDIUM" } },
    });
    const other: SemgrepResult = { check_id: "registry.other", path: "/some/target/a.ts", start: { line: 1 } };
    queueMonolithicInjection({
      monolithic: injectionOutput(["registry.other"], [other, row(10)]),
      firstLog: injectionOutput(["harvey-log-injection"], [row(10), row(20)]),
      secondLog: injectionOutput(["harvey-log-injection"], [row(20), row(10)]),
    });
    vi.mocked(execFileSync).mockClear();
    try {
      const run = runSemgrepWithFixture();
      expect(run.failure).toBeUndefined();
      expect(() => assertSuccessfulSemgrepExecutionReceipt(run.executionPlan)).not.toThrow();
      expect(run.result.results?.map((result) => `${result.check_id}:${result.start?.line}`)).toEqual([
        "registry.other:1",
        "src.scan.rules.semgrep.harvey-log-injection:10",
        "src.scan.rules.semgrep.harvey-log-injection:20",
      ]);
      const argvs = semgrepArgvs();
      expect(argvs).toHaveLength(5);
      expect(argvs[0]?.slice(0, 4)).toEqual(["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"]);
      expect(argvs.slice(1).every((argv) => argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 1")).toBe(true);
      expect(argvs.slice(1).map((argv) => argv.find((arg) => arg.includes("local-injection-"))?.match(/local-injection-(log|complement)-/)?.[1])).toEqual(["log", "complement", "log", "complement"]);
      const monolithicReceipt = run.executionPlan?.families.find((family) => family.verification === "single");
      expect(monolithicReceipt?.argv.filter((arg) => arg === "--config")).toHaveLength(argvs[0]!.filter((arg) => arg === "--config").length);
      expect(monolithicReceipt?.argv).toEqual(monolithicReceipt?.attempts[0]?.argv);
      expect(monolithicReceipt?.argv.every((arg) => !arg.includes("/private/tmp/"))).toBe(true);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it("fails monolithic delivery when a paired injection component differs", () => {
    const row = (line: number): SemgrepResult => ({ check_id: "harvey-log-injection", path: "/some/target/a.ts", start: { line } });
    queueMonolithicInjection({
      firstLog: injectionOutput(["harvey-log-injection"], [row(10)]),
      secondLog: injectionOutput(["harvey-log-injection"], [row(10), row(20)]),
    });
    try {
      const run = runSemgrepWithFixture();
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired partitioned.*local-injection.*log\.(?:resultsSha256|semanticSha256)/i);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it.each([
    ["finding", (output: SemgrepOutput) => { output.results!.push({ check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line: 20 } }); }],
    ["scanned path", (output: SemgrepOutput) => { output.paths!.scanned!.push("/some/target/b.ts"); }],
    ["skipped path", (output: SemgrepOutput) => { output.paths!.skipped!.push({ path: "/some/target/b.ts", reason: "analysis_failed_parser_or_internal_error" }); }],
    ["skipped rule", (output: SemgrepOutput) => { (output.skipped_rules ??= []).push({ rule_id: "src.scan.rules.semgrep.harvey-log-injection", reason: "analysis_failed_parser_or_internal_error" }); }],
    ["error", (output: SemgrepOutput) => { output.errors!.push({ type: "Syntax error", path: "/some/target/b.ts", message: "unexpected token" }); }],
    ["executed rule", (output: SemgrepOutput) => { (output.time!.rules ??= []).push("src.scan.rules.semgrep.harvey-log-injection-second"); }],
    ["fixpoint timeout", (output: SemgrepOutput) => { (output.time!.fixpoint_timeouts ??= []).push({ error_type: "Fixpoint timeout", location: { path: "/some/target/b.ts", start: { line: 1 }, end: { line: 1 } } }); }],
  ] as const)("fails paired-cold delivery when only the second run changes its semantic %s population", (_name, mutate) => {
    const base: SemgrepOutput = {
      version: "1.173.0",
      results: [{ check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line: 10 } }],
      errors: [],
      paths: { scanned: ["/some/target/a.ts"], skipped: [] },
      time: { rules: ["src.scan.rules.semgrep.harvey-log-injection"], fixpoint_timeouts: [] },
    };
    const changed = structuredClone(base);
    mutate(changed);
    queueMonolithicInjection({ firstLog: base, secondLog: changed });
    try {
      const run = runSemgrepWithFixture();
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired partitioned.*local-injection.*differ|executed rule.*absent/i);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it("fails paired-cold delivery when the second run substitutes the old line-74 parser diagnostic", () => {
    const path = "/some/target/apps/erp/app/modules/inventory/ui/Traceability/TraceabilityGraph.tsx";
    const diagnostic = (line: 74 | 79): SemgrepOutput => {
      const old = line === 74;
      const start = { line, col: old ? 18 : 1, offset: 0 };
      const end = { line, col: old ? 53 : 2, offset: old ? 35 : 1 };
      const token = old ? 'import("./utils").IssueContainment' : "}";
      return {
        version: "1.173.0",
        results: [],
        errors: [{
          code: 3,
          level: "warn",
          type: ["PartialParsing", [{ path, start, end }]],
          message: `Syntax error at line ${path}:${line}:\n \`${token}\` was unexpected`,
          path,
          spans: [{ file: path, start, end }],
        }],
        paths: { scanned: [path], skipped: [{ path, reason: "analysis_failed_parser_or_internal_error" }] },
        time: { rules: ["src.scan.rules.semgrep.harvey-log-injection"], fixpoint_timeouts: [] },
      };
    };
    const line79 = diagnostic(79);
    queueMonolithicInjection({ firstLog: line79, secondLog: diagnostic(74) });
    try {
      const run = runSemgrepWithFixture();
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired partitioned.*local-injection.*differ/i);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it("executes the production partitioned injection seam twice at j1 and every other family once at j9", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-partitioned-policy-"));
    try {
      const target = join(dir, "target");
      mkdirSync(target);
      writeFileSync(join(target, "a.ts"), "export {};\n");
      const registry = seedRegistrySnapshot(dir).files;
      const plan = semgrepExecutionPlanReceipt(registry);
      const output = (ruleIds: string[]): string => JSON.stringify({
        version: "1.173.0", results: [], errors: [], paths: { scanned: [join(target, "a.ts")], skipped: [] }, time: { rules: ruleIds, fixpoint_timeouts: [] },
      });
      for (const family of plan.families) {
        if (family.topology === "whole-root-rule-partition-v1") {
          for (let attempt = 0; attempt < 2; attempt += 1) for (const partition of family.partitions) semgrepMock.outputs.push(output(partition.ownedRuleIds));
        } else {
          const envelope = output(family.ruleIds);
          semgrepMock.outputs.push(envelope, ...(family.verification === "paired-cold-exact" ? [envelope] : []));
        }
      }
      vi.mocked(execFileSync).mockClear();
      const run = await runSemgrepPartitioned(target, registry, {
        dir: join(dir, "cache"), mode: "off", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(run.failure).toBeUndefined();
      expect(run.executionPlan).toMatchObject({ schema: 5, status: "succeeded", strategy: plan.strategy, ownershipSha256: plan.ownershipSha256 });
      expect(run.executionPlan?.families.map((family) => Object.fromEntries(Object.entries(family).filter(([key]) => !["loadedRuleIds", "status", "attempts"].includes(key))))).toEqual(plan.families);
      expect(plan.families.find((family) => family.id === "local-injection")?.partitions.map((partition) => partition.ownedRuleIds.length)).toEqual([1, 29]);
      const calls = semgrepArgvs();
      const injection = calls.filter((argv) => argv.some((arg) => arg.includes("local-injection-")));
      expect(injection).toHaveLength(4);
      expect(injection.every((argv) => argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 1")).toBe(true);
      expect(injection.map((argv) => argv.find((arg) => arg.includes("local-injection-"))?.match(/local-injection-(log|complement)-/)?.[1])).toEqual(["log", "complement", "log", "complement"]);
      expect(calls.filter((argv) => !argv.some((arg) => arg.includes("local-injection-"))).every((argv) =>
        argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 9"
      )).toBe(true);
    } finally {
      semgrepMock.outputs.length = 0;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an executed rule that is absent from the bound family config receipt", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-partitioned-unknown-rule-"));
    try {
      const target = join(dir, "target");
      mkdirSync(target);
      writeFileSync(join(target, "a.ts"), "export {};\n");
      const registry = seedRegistrySnapshot(dir).files;
      const plan = semgrepExecutionPlanReceipt(registry);
      const output = (ruleIds: string[]): string => JSON.stringify({
        version: "1.173.0", results: [], errors: [], paths: { scanned: [join(target, "a.ts")], skipped: [] }, time: { rules: ruleIds, fixpoint_timeouts: [] },
      });
      for (const [ordinal, family] of plan.families.entries()) {
        const rules = ordinal === 0 ? [...family.ruleIds, "unregistered-runtime-rule"] : family.ruleIds;
        const envelope = output(rules);
        semgrepMock.outputs.push(envelope, ...(family.verification === "paired-cold-exact" ? [envelope] : []));
      }
      const run = await runSemgrepPartitioned(target, registry, {
        dir: join(dir, "cache"), mode: "off", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(plan.families).not.toHaveLength(0);
      expect(run.executionPlan).toBeUndefined();
      expect(run.failure).toMatch(/executed rule.*absent from the bound config receipt.*unregistered-runtime-rule/i);
    } finally {
      semgrepMock.outputs.length = 0;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a metadata-planned family whose runtime command never completes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-partitioned-missing-family-"));
    try {
      const target = join(dir, "target");
      mkdirSync(target);
      writeFileSync(join(target, "a.ts"), "export {};\n");
      const registry = seedRegistrySnapshot(dir).files;
      const plan = semgrepExecutionPlanReceipt(registry);
      const run = await runSemgrepPartitioned(target, registry, {
        dir: join(dir, "cache"), mode: "off", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(plan.families[0]!.ruleIds).not.toHaveLength(0);
      expect(run.executionPlan).toBeUndefined();
      expect(run.failure).toMatch(/partitioned Semgrep did not complete.*registry-0.*(?:unavailable|not found)/i);
    } finally {
      semgrepMock.outputs.length = 0;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails partitioned delivery before a divergent injection pair can enter the family cache", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-partitioned-mismatch-"));
    try {
      const target = join(dir, "target");
      const cache = join(dir, "cache");
      mkdirSync(target);
      writeFileSync(join(target, "a.ts"), "export {};\n");
      const registry = seedRegistrySnapshot(dir).files;
      const plan = semgrepExecutionPlanReceipt(registry);
      const output = (rule: string, lines: number[], ruleIds: readonly string[] = [rule]): string => JSON.stringify({
        version: "1.173.0",
        results: lines.map((line) => ({ check_id: rule, path: join(target, "a.ts"), start: { line } })),
        errors: [], paths: { scanned: [join(target, "a.ts")], skipped: [] }, time: { rules: ruleIds, fixpoint_timeouts: [] },
      });
      const injectionIndex = plan.families.findIndex((family) => family.id === "local-injection");
      for (const family of plan.families) {
        if (family.id === "local-injection") {
          semgrepMock.outputs.push(
            output("src.scan.rules.semgrep.harvey-log-injection", [10]),
            output(family.partitions[1]!.ownedRuleIds[0]!, [], family.partitions[1]!.ownedRuleIds),
            output("src.scan.rules.semgrep.harvey-log-injection", [10, 20]),
            output(family.partitions[1]!.ownedRuleIds[0]!, [], family.partitions[1]!.ownedRuleIds),
          );
        } else {
          semgrepMock.outputs.push(output(family.ruleIds[0]!, [], family.ruleIds));
        }
      }
      const run = await runSemgrepPartitioned(target, registry, {
        dir: cache, mode: "read-write", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired partitioned.*local-injection.*differ/i);
      expect(existsSync(join(cache, "semgrep-families", "local-injection"))).toBe(false);
      const failureKeyDirs = readNamesSafe(join(cache, "semgrep-family-failures", "local-injection"));
      expect(failureKeyDirs).toHaveLength(1);
      const failureFiles = readNamesSafe(join(cache, "semgrep-family-failures", "local-injection", failureKeyDirs[0]!));
      expect(failureFiles).toHaveLength(1);
      const failedArtifact = JSON.parse(readFileSync(join(cache, "semgrep-family-failures", "local-injection", failureKeyDirs[0]!, failureFiles[0]!), "utf8")) as { reusable: boolean; failure: { attempts: unknown[] } };
      expect(failedArtifact).toMatchObject({ reusable: false, failure: { attempts: [{ attempt: 1 }, { attempt: 2 }] } });

      semgrepMock.outputs.length = 0;
      const injection = plan.families[injectionIndex]!;
      for (let attempt = 0; attempt < 2; attempt += 1) for (const partition of injection.partitions) {
        semgrepMock.outputs.push(output(partition.ownedRuleIds[0]!, partition.id === "log" ? [10] : [], partition.ownedRuleIds));
      }
      for (const family of plan.families.slice(injectionIndex + 1)) semgrepMock.outputs.push(output(family.ruleIds[0]!, [], family.ruleIds));
      const callsBeforeRerun = semgrepArgvs().length;
      const rerun = await runSemgrepPartitioned(target, registry, {
        dir: cache, mode: "read-write", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(rerun.failure).toBeUndefined();
      expect(rerun.records.find((record) => record.family === "local-injection")?.cache).toBe("miss");
      expect(semgrepArgvs().length - callsBeforeRerun).toBeGreaterThanOrEqual(4);
    } finally {
      semgrepMock.outputs.length = 0;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// #1368: the fix-verification gate's registry-pack replay (src/fix/detector-rerun.ts) must degrade
// to a disclosed notRun the same way runSemgrep does — never a false clean because the network fetch
// the registry packs need failed. Same ENOENT-mocked "binary absent" fake this file already uses for
// runSemgrep, since the failure branch inside runRegistryPacksOnFile is the identical catch(execFileSync
// throws) => { failure } path regardless of WHETHER the throw came from a missing binary or an
// unreachable registry — this proves that shared path degrades, not the network specifically (the
// live success path, which needs a real network fetch, is proven in src/fix/detector-rerun.test.ts).
describe("runRegistryPacksOnFile degrades on failure, never a false clean (#1368)", () => {
  it("returns a failure reason and an empty rule-id set instead of throwing when semgrep is unavailable", async () => {
    const { result, ruleIds, failure } = await runRegistryPacksOnFile("/some/target/file.js", "/some/target");
    expect(failure).toBe("semgrep not found on PATH");
    expect(result).toEqual({});
    expect(ruleIds.size).toBe(0);
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

// #1664: the predicate validate-calibration halts on — a scoring gate that sees SEM-00 must say THE
// SCAN DID NOT RUN instead of rendering a recall table over zero results. Both directions: reverting
// the predicate to always-empty makes the first test fail.
describe("scanDidNotRun (#1664)", () => {
  it("returns the SEM-00 row so a scoring gate can halt on it", () => {
    const sem = semgrepUnavailableFinding("semgrep run did not complete (killed by signal SIGBUS)");
    const rows = scanDidNotRun([sem]);
    expect(rows.map((f) => f.id)).toEqual(["SEM-00"]);
    expect(rows[0]?.evidence).toContain("SIGBUS");
  });

  it("returns nothing on a scan that ran — real findings and other disclosure rows do not halt the gate", () => {
    const real = { ...semgrepUnavailableFinding("unused"), id: "SEM-ERR-00" };
    expect(scanDidNotRun([real])).toEqual([]);
    expect(scanDidNotRun([])).toEqual([]);
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

  // #1093 (part 2): semgrep's own `// nosemgrep: rule-id` form scopes a marker to ONLY the named
  // rule(s) — the re-derivation above used to ignore that scoping and withhold ANY finding on the
  // marked line, moving an unrelated rule's match into `suppressed` instead of `reported`.
  it("scopes a `nosemgrep: rule-id` marker to only the named rule, leaving an unrelated rule's match on the same line reported", () => {
    const { dir, file } = withSource(["export function A() {", "  doDangerousThing(); // nosemgrep: harvey-a", "}"]);
    try {
      const { reported, suppressed } = partitionMarkerSuppressed({
        results: [
          { check_id: "harvey-a", path: file, start: { line: 2 } },
          { check_id: "harvey-b", path: file, start: { line: 2 } },
        ],
      });
      expect(suppressed.map((r) => r.check_id)).toEqual(["harvey-a"]);
      expect(reported.map((r) => r.check_id)).toEqual(["harvey-b"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a bare `nosemgrep` marker (no rule-id scope) still suppresses every rule on the line", () => {
    const { dir, file } = withSource(["export function A() {", "  doDangerousThing(); // nosemgrep", "}"]);
    try {
      const { reported, suppressed } = partitionMarkerSuppressed({
        results: [
          { check_id: "harvey-a", path: file, start: { line: 2 } },
          { check_id: "harvey-b", path: file, start: { line: 2 } },
        ],
      });
      expect(suppressed.map((r) => r.check_id).sort()).toEqual(["harvey-a", "harvey-b"]);
      expect(reported).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a scoped marker naming a DIFFERENT rule does not suppress the rule that actually matched", () => {
    const { dir, file } = withSource(["export function A() {", "  doDangerousThing(); // nosemgrep: harvey-unrelated", "}"]);
    try {
      const { reported, suppressed } = partitionMarkerSuppressed({
        results: [{ check_id: "harvey-a", path: file, start: { line: 2 } }],
      });
      expect(suppressed).toEqual([]);
      expect(reported.map((r) => r.check_id)).toEqual(["harvey-a"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// #1093 (part 1): both rules used to end in a `pattern-not-regex` LINE_PREFIX text search
// (#1066) with no cross-line "am I inside a block comment" state — a multi-line block comment
// whose interior lines didn't start with `*` still reached a guard-shaped token and cleared a
// genuinely unguarded route. Both rules now match unconditionally in auth.yml and this
// re-derives the check on the WHOLE matched span via a real comment/string state machine.
describe("stripCommentsAndStrings (#1093)", () => {
  it("blanks out //, /* multi-line */, and string/template literal contents while preserving line count", () => {
    const src = [
      "function f() {",
      "  // requireAdmin() in a line comment",
      "  /*",
      "  requireAdmin()",
      "  */",
      '  const s = "requireAdmin()";',
      "  doTheThing();",
      "}",
    ].join("\n");
    const stripped = stripCommentsAndStrings(src);
    expect(stripped.split("\n")).toHaveLength(src.split("\n").length);
    expect(stripped).not.toMatch(/requireAdmin/);
    expect(stripped).toMatch(/doTheThing\(\)/);
  });
});

describe("partitionGuardTokenSuppressed (#1093)", () => {
  const withSource = (lines: string[]): { dir: string; file: string } => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-guard-token-"));
    const file = join(dir, "route.ts");
    writeFileSync(file, lines.join("\n"));
    return { dir, file };
  };

  it("a fake guard call wrapped in a MULTI-LINE block comment does not clear harvey-route-noauth (the block-comment hole)", () => {
    const { dir, file } = withSource([
      "export default async function handler(req, res) {",
      "  /*",
      "  requireAdmin()",
      "  */",
      '  await admin.from("settings").delete().eq("key", req.body.key);',
      "}",
    ]);
    try {
      const { reported, guarded } = partitionGuardTokenSuppressed({
        results: [{ check_id: "harvey-route-noauth", path: file, start: { line: 1 }, end: { line: 6 } }],
      });
      expect(guarded).toEqual([]);
      expect(reported).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a real guard call in actual code still clears harvey-route-noauth", () => {
    const { dir, file } = withSource([
      "export default async function handler(req, res) {",
      "  requireAdmin(req);",
      '  await admin.from("settings").delete().eq("key", req.body.key);',
      "}",
    ]);
    try {
      const { reported, guarded } = partitionGuardTokenSuppressed({
        results: [{ check_id: "harvey-route-noauth", path: file, start: { line: 1 }, end: { line: 4 } }],
      });
      expect(reported).toEqual([]);
      expect(guarded).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("a rule this mechanism does not own passes through untouched", () => {
    const { dir, file } = withSource(["export function f() { doTheThing(); }"]);
    try {
      const { reported, guarded } = partitionGuardTokenSuppressed({
        results: [{ check_id: "harvey-something-else", path: file, start: { line: 1 }, end: { line: 1 } }],
      });
      expect(guarded).toEqual([]);
      expect(reported).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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

  // #1954, measured with the current paired-cold production topology over carbon@92e19c0. Each
  // Semgrep 1.173.0 run keeps 87 findings / 4,152 scanned paths / 30 top-level rules, 32 skips,
  // 26 raw→26 canonical errors, and six timeout-only records on six paths. The client-visible
  // PartialParsing span is 79:1–79:2. The client disclosure names that line while the separate raw
  // diagnostic receipt remains intact for strict producer↔replay comparison.
  it("preserves the current paired-cold Semgrep 1.173.0 line-79 PartialParsing evidence in SEM-ERR-00", () => {
    const path = "/target/apps/erp/app/modules/inventory/ui/Traceability/TraceabilityGraph.tsx";
    const point = { line: 79, col: 1, offset: 0 };
    const [finding] = semgrepErrorFinding("/target", {
      version: "1.173.0",
      errors: [
        {
          code: 3,
          level: "warn",
          type: ["PartialParsing", [{ path, start: point, end: { line: 79, col: 2, offset: 1 } }]],
          message: `Syntax error at line ${path}:79:\n \`}\` was unexpected`,
          path,
          spans: [{ file: path, start: point, end: { line: 79, col: 2, offset: 1 } }],
        },
      ],
      paths: { scanned: [path], skipped: [{ path, reason: "analysis_failed_parser_or_internal_error" }] },
    });
    expect(finding).toMatchObject({ id: "SEM-ERR-00", title: "2 analysis records semgrep could not fully evaluate" });
    expect(finding?.evidence).toContain("TraceabilityGraph.tsx:79");
    expect(finding?.evidence).toContain('"line":79');
    expect(finding?.evidence).not.toContain("IssueContainment");
    expect(finding?.evidence).not.toContain(":74");
  });

  it("names a file semgrep chose to skip (paths.skipped, only populated at --verbose) alongside any errors", () => {
    const findings = semgrepErrorFinding("/target", {
      paths: { scanned: [], skipped: [{ path: "/target/vendor/huge.js", reason: "too_big" }] },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("vendor/huge.js (skipped: too_big)");
  });

  it("discloses timeout-only paths through SEM-ERR-00", () => {
    const path = "/target/app/timeout-only.ts";
    const findings = semgrepErrorFinding("/target", {
      errors: [], paths: { scanned: [path], skipped: [] },
      time: { rules: ["harvey-taint"], fixpoint_timeouts: [{
        error_type: "Fixpoint timeout", severity: "warn",
        message: `Fixpoint timeout while performing taint analysis at ${path}:1:0`,
        location: { path, start: { line: 1 }, end: { line: 1 } },
      }] },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.evidence).toContain("1 fixpoint timeout(s)");
    expect(findings[0]?.evidence).toContain("app/timeout-only.ts");
  });

  it("stays silent when there are no errors and nothing was skipped", () => {
    expect(semgrepErrorFinding("/target", { paths: { scanned: ["/target/app/ok.ts"] } })).toEqual([]);
  });
});
