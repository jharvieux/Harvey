import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
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

const CACHE_REGISTRY_PACKS = ["p/typescript", "p/react", "p/nextjs", "p/owasp-top-ten", "p/secrets", "p/security-audit"];

function seedRegistrySnapshot(cacheDir: string): { identity: string; files: string[] } {
  const bodies = CACHE_REGISTRY_PACKS.map((pack, index) => ({
    pack,
    body: `rules:\n  - id: fixture-registry-${index}-${pack.replaceAll("/", "-")}\n    message: fixture\n    severity: WARNING\n    languages: [typescript]\n    pattern: $X\n`,
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
    const { result, failure } = runSemgrep("/some/target");
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

  it("pins the measured nine-worker parmap topology with the per-rule timeout disabled", () => {
    vi.mocked(execFileSync).mockClear();
    runSemgrep("/some/target");
    const argvs = semgrepArgvs();
    expect(argvs).toHaveLength(1); // ENOENT: binary absent, so no second attempt
    expect(argvs[0]?.slice(0, 4)).toEqual(["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"]);
    expect(argvs[0]?.join(" ")).toContain("--timeout 0");
  });

  it("fails closed without retrying through the unproved non-parmap topology", () => {
    semgrepMock.errCode = "EPERM";
    try {
      vi.mocked(execFileSync).mockClear();
      const result = runSemgrep("/some/target");
      const argvs = semgrepArgvs();
      expect(argvs).toHaveLength(1);
      expect(result.failure).toContain("semgrep run did not complete");
      expect(result.result).toEqual({});
    } finally {
      semgrepMock.errCode = "ENOENT";
    }
  });

  it("receipts paired one-worker verification only for the unstable injection family", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-semgrep-plan-"));
    try {
      const receipt = semgrepExecutionPlanReceipt(seedRegistrySnapshot(dir).files);
      expect(receipt.schema).toBe(3);
      const injection = receipt.families.find((family) => family.id === "local-injection");
      expect(injection?.argv.slice(0, 4)).toEqual(["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "1"]);
      expect(injection?.argv.join(" ")).toContain("--timeout 0");
      expect(injection?.verification).toBe("paired-cold-exact");
      expect(injection).toMatchObject({ familyId: "local-injection", sourceKind: "local-config", sourceId: "injection.yml" });
      expect(injection?.ruleIds).toContain("harvey-log-injection");
      expect(receipt.families.filter((family) => family.id !== "local-injection").every((family) =>
        family.verification === "single" && family.argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 9"
      )).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("replaces monolithic injection output only after two exact cold one-worker executions", () => {
    const output = (results: SemgrepResult[]): string => JSON.stringify({
      version: "1.173.0", results, errors: [],
      paths: { scanned: ["/some/target/a.ts"], skipped: [] },
      time: { rules: ["src.scan.rules.semgrep.harvey-log-injection"], fixpoint_timeouts: [] },
    });
    const row = (line: number): SemgrepResult => ({
      check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line },
      extra: { message: `line ${line}`, severity: "WARNING", metadata: { confidence: "MEDIUM" } },
    });
    const other: SemgrepResult = { check_id: "registry.other", path: "/some/target/a.ts", start: { line: 1 } };
    semgrepMock.outputs.push(output([other, row(10)]), output([row(10), row(20)]), output([row(20), row(10)]));
    vi.mocked(execFileSync).mockClear();
    try {
      const run = runSemgrep("/some/target");
      expect(run.failure).toBeUndefined();
      expect(run.result.results?.map((result) => `${result.check_id}:${result.start?.line}`)).toEqual([
        "registry.other:1",
        "src.scan.rules.semgrep.harvey-log-injection:10",
        "src.scan.rules.semgrep.harvey-log-injection:20",
      ]);
      const argvs = semgrepArgvs();
      expect(argvs).toHaveLength(3);
      expect(argvs[0]?.slice(0, 4)).toEqual(["--x-ignore-semgrepignore-files", "--x-parmap", "-j", "9"]);
      expect(argvs.slice(1).every((argv) => argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 1")).toBe(true);
      expect(argvs.slice(1).every((argv) => argv.some((arg) => arg.endsWith("/injection.yml")))).toBe(true);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it("fails monolithic delivery when the paired cold injection outputs differ", () => {
    const output = (lines: number[]): string => JSON.stringify({
      version: "1.173.0",
      results: lines.map((line) => ({ check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line } })),
      errors: [], paths: { scanned: ["/some/target/a.ts"], skipped: [] },
      time: { rules: ["src.scan.rules.semgrep.harvey-log-injection"], fixpoint_timeouts: [] },
    });
    semgrepMock.outputs.push(output([10]), output([10]), output([10, 20]));
    try {
      const run = runSemgrep("/some/target");
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired cold.*local-injection.*differ/i);
    } finally {
      semgrepMock.outputs.length = 0;
    }
  });

  it.each([
    ["finding", (output: SemgrepOutput) => { output.results!.push({ check_id: "src.scan.rules.semgrep.harvey-log-injection", path: "/some/target/a.ts", start: { line: 20 } }); }],
    ["scanned path", (output: SemgrepOutput) => { output.paths!.scanned!.push("/some/target/b.ts"); }],
    ["skipped path", (output: SemgrepOutput) => { output.paths!.skipped!.push({ path: "/some/target/b.ts", reason: "analysis_failed_parser_or_internal_error" }); }],
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
    semgrepMock.outputs.push(JSON.stringify(base), JSON.stringify(base), JSON.stringify(changed));
    try {
      const run = runSemgrep("/some/target");
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired cold.*local-injection.*differ/i);
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
    semgrepMock.outputs.push(JSON.stringify(line79), JSON.stringify(line79), JSON.stringify(diagnostic(74)));
    try {
      const run = runSemgrep("/some/target");
      expect(run.result).toEqual({});
      expect(run.failure).toMatch(/paired cold.*local-injection.*differ/i);
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
        const envelope = output(family.ruleIds);
        semgrepMock.outputs.push(envelope, ...(family.verification === "paired-cold-exact" ? [envelope] : []));
      }
      vi.mocked(execFileSync).mockClear();
      const run = await runSemgrepPartitioned(target, registry, {
        dir: join(dir, "cache"), mode: "off", targetRevision: "revision", targetTree: "tree",
        implementation: "implementation", externalInputs: { semgrep: "1.173.0" },
      });
      expect(run.failure).toBeUndefined();
      expect(run.executionPlan).toEqual(plan);
      expect(run.executionPlan?.schema).toBe(3);
      expect(plan.families.some((family) => "subpartitions" in family)).toBe(false);
      const calls = semgrepArgvs();
      const injection = calls.filter((argv) => argv.some((arg) => arg.endsWith("/injection.yml")));
      expect(injection).toHaveLength(2);
      expect(injection.every((argv) => argv.slice(0, 4).join(" ") === "--x-ignore-semgrepignore-files --x-parmap -j 1")).toBe(true);
      expect(calls.filter((argv) => !argv.some((arg) => arg.endsWith("/injection.yml"))).every((argv) =>
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
      for (const family of plan.families) {
        if (family.id === "local-injection") {
          semgrepMock.outputs.push(
            output("src.scan.rules.semgrep.harvey-log-injection", [10]),
            output("src.scan.rules.semgrep.harvey-log-injection", [10, 20]),
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
      expect(run.failure).toMatch(/paired cold.*local-injection.*differ/i);
      expect(existsSync(join(cache, "semgrep-families", "local-injection"))).toBe(false);
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
