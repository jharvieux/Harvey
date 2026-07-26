import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { divergedCloneFindings, wholeRepoDivergedCloneFindings } from "./diverged-clones.js";
import {
  duplicationSummary,
  JSCPD_DISCLOSED_GLOBS,
  JSCPD_IGNORE_GLOBS,
  jscpdAnalysedNothingReason,
  jscpdIgnoreScopeFinding,
  jscpdToFindings,
  jscpdUnavailableFinding,
  knipEntryUncertainFinding,
  knipEntryUncertainReason,
  knipReducedTierFinding,
  knipToFindings,
  knipUnavailableFinding,
  matchesGlob,
  matchesJscpdIgnoreGlob,
  mergeJscpdReports,
  mergeKnipReports,
  touchesSecurityPath,
  touchesTenantSupabasePath,
  type JscpdGlobMatch,
  type JscpdReport,
  type KnipReport,
} from "./quality-scan.js";
import { buildCoverageMatrix } from "./scan/calibration.js";
import { m4m5Entries } from "./scan/calibration/m4-m5.entries.js";

// Base two entries shaped from real `jscpd --reporters json` output (captured against a
// throwaway two-file clone) — jscpd's json reporter emits duplicates out of size order. The
// self-clone and tiny-header entries below are hand-built negative fixtures standing in for the
// #232 FP shapes (icon-table self-repetition, shared import headers), not captured tool output.
const jscpdReport: JscpdReport = {
  statistics: { total: { percentage: 12.5, duplicatedLines: 40, lines: 320 } },
  duplicates: [
    {
      format: "typescript",
      lines: 11,
      tokens: 113,
      fragment: "function calculateTotal(items) {\n  let total = 0;\n  return total;\n}",
      firstFile: { name: "src/a.ts", start: 1, end: 11 },
      secondFile: { name: "src/b.ts", start: 1, end: 11 },
    },
    {
      format: "typescript",
      lines: 60,
      tokens: 900,
      fragment: "x".repeat(300),
      firstFile: { name: "src/big1.ts", start: 5, end: 65 },
      secondFile: { name: "src/big2.ts", start: 10, end: 70 },
    },
    // Same file both sides. #232 assumed this shape was inert repeated DATA and excluded the whole
    // band; #1080 measured that false and #1095 restored it to the scored findings — at 40 lines it
    // clears MIN_SIGNIFICANT_LINES and is scored exactly like a cross-file clone.
    {
      format: "typescript",
      lines: 40,
      tokens: 500,
      fragment: "<path d=\"M10 10L20 20\" />".repeat(10),
      firstFile: { name: "src/icons.tsx", start: 1, end: 40 },
      secondFile: { name: "src/icons.tsx", start: 50, end: 90 },
    },
    // #232: a 6-line shared import header — real cross-file overlap, but under
    // MIN_SIGNIFICANT_LINES, not worth a maintainability finding on its own.
    {
      format: "typescript",
      lines: 6,
      tokens: 80,
      fragment: "import { a } from \"./a\";\nimport { b } from \"./b\";",
      firstFile: { name: "src/c.ts", start: 1, end: 6 },
      secondFile: { name: "src/d.ts", start: 1, end: 6 },
    },
  ],
};

describe("jscpdToFindings", () => {
  it("sorts worst clone clusters first regardless of report order", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings[0]?.location).toContain("big1.ts");
    expect(findings[1]?.location).toContain("icons.tsx"); // 40 lines, self-file — ranked on size like any other clone (#1095)
    expect(findings[2]?.location).toContain("a.ts");
  });

  it("scales severity with duplicated line count", () => {
    const [big, self, small] = jscpdToFindings(jscpdReport);
    expect(big?.severity).toBe("Medium"); // 60 lines >= 50
    expect(self?.severity).toBe("Low"); // 40 lines: >= 15, < 50 — the SAME ladder cross-file clones use (#1095)
    expect(small?.severity).toBe("Info"); // 11 lines < 15
  });

  it("truncates long fragments and reports exact line/token counts in impact", () => {
    const [big] = jscpdToFindings(jscpdReport);
    expect(big?.evidence.length).toBeLessThanOrEqual(241);
    expect(big?.impact).toBe("60 duplicated lines (900 tokens) — a fix in one copy is a fix missed in the other.");
  });

  it("assigns unique sequential M4 ids, with the #365/#1080 meta rows trailing and never colliding with the sequential ids", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.map((f) => f.id)).toEqual(["M4-01", "M4-02", "M4-03", "M4-00"]);
  });

  it("tags every clone at the high precision tier (issue #72 calibration)", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.every((f) => f.precisionTier === "high")).toBe(true);
  });

  // #1095 (operator ruling 2026-07-26): #232's exclusion of this band was measured false by #1080.
  // A second copy inside the SAME file is the #1081 failure mode with weaker discovery cues than
  // the cross-file case, so it earns a scored finding on identical terms.
  it("scores a same-file clone above the floor, with in-file fix text and a collapsed location (#1095)", () => {
    const self = jscpdToFindings(jscpdReport).find((f) => f.location.includes("icons.tsx"));
    expect(self).toBeDefined();
    expect(self!.location).toBe("src/icons.tsx:1-40 ↔ :50-90"); // path stated once, not repeated
    expect(self!.title).toBe("Duplicated code within one file: src/icons.tsx");
    expect(self!.fix).toContain("call it at both sites");
    expect(self!.fix).not.toContain("shared logic into one function/module");
    expect(self!.impact).toContain("no filename to jog the memory");
  });

  it("emits no INDIVIDUAL finding for clusters under the significant-lines gate — e.g. a shared import header (#232)", () => {
    const findings = jscpdToFindings(jscpdReport);
    expect(findings.some((f) => f.location.includes("src/c.ts"))).toBe(false);
  });
});

// #365: the 5-9-line band the significance floor drops is where AI-assisted duplication
// concentrates (measured 2026-07-16 on the external corpus: 30% of proposit's cross-file clones).
// The floor stays, but the band must be DISCLOSED as an aggregate, never silently absorbed.
describe("jscpdToFindings — sub-threshold small-clone disclosure (#365)", () => {
  it("discloses the dropped band in one M4-00 aggregate naming the pairs and their sizes", () => {
    const findings = jscpdToFindings(jscpdReport);
    const disclosure = findings.find((f) => f.id === "M4-00");
    expect(disclosure?.severity).toBe("Info");
    expect(disclosure?.location).toBe("(repo-wide)");
    expect(disclosure?.title).toContain("1 small cross-file clone(s)");
    expect(disclosure?.evidence).toContain("src/c.ts:1-6 ↔ src/d.ts:1-6 (6 lines)");
  });

  it("does not count self-file repetition in the M4-00 sub-threshold disclosure — it gets its own M4-SELF-00 row instead (#1080)", () => {
    const selfOnly: JscpdReport = {
      statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 100 } },
      duplicates: [
        {
          format: "typescript",
          lines: 7,
          tokens: 80,
          fragment: "<path />",
          firstFile: { name: "src/icons.tsx", start: 1, end: 7 },
          secondFile: { name: "src/icons.tsx", start: 20, end: 27 },
        },
      ],
    };
    const findings = jscpdToFindings(selfOnly);
    expect(findings.find((f) => f.id === "M4-00")).toBeUndefined();
    expect(findings.map((f) => f.id)).toEqual(["M4-SELF-00"]);
  });

  it("emits no disclosure row at all when nothing was dropped — an empty band is not a finding", () => {
    const bigOnly: JscpdReport = {
      statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 100 } },
      duplicates: [jscpdReport.duplicates[1]!],
    };
    expect(jscpdToFindings(bigOnly).find((f) => f.id === "M4-00")).toBeUndefined();
  });
});

// #361: a clone in an auth/guard/security path is the code most likely to become an M1 finding
// when one copy is patched and its sibling isn't — mirror M5's #226 elevation for M4.
const securityJscpdReport: JscpdReport = {
  statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 500 } },
  duplicates: [
    // 25 lines -> base Low, elevated to Medium (one side in an auth path is enough).
    {
      format: "typescript",
      lines: 25,
      tokens: 246,
      fragment: "if (session === null) { return problems; }",
      firstFile: { name: "dup/auth/session-check-api.ts", start: 10, end: 35 },
      secondFile: { name: "app/actions/session-check.ts", start: 12, end: 37 },
    },
    // 11 lines -> base Info, elevated to Low (middleware path).
    {
      format: "typescript",
      lines: 11,
      tokens: 120,
      fragment: "const token = header.slice(7);",
      firstFile: { name: "src/middleware/rate-limit.ts", start: 1, end: 11 },
      secondFile: { name: "src/middleware/rate-limit-edge.ts", start: 1, end: 11 },
    },
    // 60 lines -> already Medium; stays Medium but still gets the cross-check note.
    {
      format: "typescript",
      lines: 60,
      tokens: 700,
      fragment: "export function requireRole(role) {}",
      firstFile: { name: "lib/guards/role-a.ts", start: 1, end: 60 },
      secondFile: { name: "lib/guards/role-b.ts", start: 1, end: 60 },
    },
    // 'auth' as a mere substring (authors.ts) must NOT elevate — same tokenizer as M5 (#226).
    {
      format: "typescript",
      lines: 25,
      tokens: 250,
      fragment: "const byline = formatAuthor(post.author);",
      firstFile: { name: "src/blog/authors.ts", start: 1, end: 25 },
      secondFile: { name: "src/blog/contributors.ts", start: 1, end: 25 },
    },
    // #400: a test naming an auth path (tests/e2e/auth/*.spec.ts) is not a per-handler
    // authorization drift risk — must NOT elevate, even though touchesSecurityPath matches "auth".
    {
      format: "typescript",
      lines: 11,
      tokens: 120,
      fragment: "await page.goto('/auth/idp-initiated');",
      firstFile: { name: "tests/e2e/auth/idp-initiated.spec.ts", start: 1, end: 11 },
      secondFile: { name: "tests/e2e/auth/idp-initiated-2.spec.ts", start: 1, end: 11 },
    },
  ],
};

describe("jscpdToFindings — security-path elevation (#361)", () => {
  const findings = jscpdToFindings(securityJscpdReport);
  const byFile = (s: string) => findings.find((f) => f.location.includes(s));

  it("elevates a Low clone touching an auth path to Medium, even when only one side is security-relevant", () => {
    const f = byFile("dup/auth/session-check-api.ts");
    expect(f?.severity).toBe("Medium");
    expect(f?.title).toContain("security-relevant path");
  });

  it("elevates an Info clone in a middleware path to Low", () => {
    expect(byFile("rate-limit.ts")?.severity).toBe("Low");
  });

  it("keeps an already-Medium guard-path clone at Medium but adds the cross-check note", () => {
    const f = byFile("lib/guards/role-a.ts");
    expect(f?.severity).toBe("Medium");
    expect(f?.impact).toContain("M1 authorization review");
  });

  it("appends the patched-one-copy cross-check note to every security-path clone", () => {
    for (const loc of ["dup/auth/session-check-api.ts", "rate-limit.ts", "lib/guards/role-a.ts"]) {
      expect(byFile(loc)?.impact).toContain("confirm the other copy(ies) were too");
    }
  });

  it("does not elevate a clone whose path merely contains 'auth' as a substring (authors.ts)", () => {
    const f = byFile("src/blog/authors.ts");
    expect(f?.severity).toBe("Low"); // plain 25-line severity, no elevation
    expect(f?.impact).not.toContain("M1 authorization review");
  });

  it("does not elevate a clone confined to test/e2e files even though the path contains 'auth' (#400)", () => {
    const f = byFile("tests/e2e/auth/idp-initiated.spec.ts");
    expect(f?.severity).toBe("Info"); // plain 11-line severity, no elevation
    expect(f?.title).not.toContain("security-relevant path");
    expect(f?.impact).not.toContain("M1 authorization review");
  });

  it("raises the BFTB value alongside the elevated severity", () => {
    expect(byFile("dup/auth/session-check-api.ts")?.value).toBe(4);
  });
});

// #399: the v2 widening of the #360 diverged-clone pass's file selection — content-based, not
// path-based, so it needs both signals present (not either alone) to stay defensible.
describe("touchesTenantSupabasePath (#399)", () => {
  it("admits a file that both scopes by a tenant key AND queries supabase", () => {
    const source = `
      const { data } = await supabase.from("customers").select("*").eq("organisation_id", orgId);
    `;
    expect(touchesTenantSupabasePath(source)).toBe(true);
  });

  it("does not admit a tenant-key literal with no supabase query", () => {
    const source = `const filters = { organisation_id: orgId, status: "active" };`;
    expect(touchesTenantSupabasePath(source)).toBe(false);
  });

  it("does not admit a supabase query with no tenant-key literal", () => {
    const source = `const { data } = await supabase.from("public_settings").select("*");`;
    expect(touchesTenantSupabasePath(source)).toBe(false);
  });

  it("does not admit plain source with neither signal", () => {
    expect(touchesTenantSupabasePath("export function add(a: number, b: number) { return a + b; }")).toBe(false);
  });
});

// LIVE corpus measurement for the M4 slice of m4-m5.entries.ts. validate-calibration.ts scores
// only mechanical-scan modules (module === undefined), so without this test the M4 entries would
// be an answer key nothing ever checks. Runs the REAL full M4 layer over targets/calibration/dup
// exactly as src/cli/quality-scan.ts wires it — jscpd (a local node dependency, not an external
// binary) plus the #360 diverged-clone pass over the security-path files — then scores the merged
// findings through the shared calibration harness (the M3 pattern from hotspot-scan.test.ts,
// with live tool output instead of a recorded report).
describe("M4 calibration corpus — measured against a live jscpd + diverged-clone run (#361/#360)", () => {
  const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const dupDir = join(repoRoot, "targets", "calibration", "dup");

  function runJscpdLive(): JscpdReport {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-jscpd-test-"));
    try {
      execFileSync(
        join(repoRoot, "node_modules", ".bin", "jscpd"),
        [
          dupDir,
          "--reporters",
          "json",
          "--output",
          outDir,
          "--threshold",
          "100",
          "--absolute",
          "--silent",
          "--noTips",
          // #838: gitignore-aware repo-root detection walks up from dupDir into this repo's real
          // .git — in a worktree checkout that's a FILE pointing at the primary checkout's gitdir,
          // and reading it from a sandboxed subprocess throws ENOENT deep inside jscpd's own
          // error-swallowing pipeline, so it silently writes no report at all. `dupDir` is a fixed
          // fixture dir already covered by the explicit --ignore globs below, so gitignore
          // awareness adds nothing here — disabling it sidesteps the repo walk entirely.
          "--no-gitignore",
          "--ignore",
          JSCPD_IGNORE_GLOBS.join(","),
        ],
        { stdio: ["ignore", "ignore", "pipe"] },
      );
      const reportPath = join(outDir, "jscpd-report.json");
      if (!existsSync(reportPath)) {
        throw new Error(`jscpd exited without writing a report to ${reportPath} — expected real M4 findings from ${dupDir}`);
      }
      const report = JSON.parse(readFileSync(reportPath, "utf8")) as JscpdReport;
      for (const dup of report.duplicates) {
        dup.firstFile.name = relative(dupDir, resolve(dup.firstFile.name));
        dup.secondFile.name = relative(dupDir, resolve(dup.secondFile.name));
      }
      return report;
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  }

  // Mirrors src/cli/quality-scan.ts's securityPathFiles exactly: admit on EITHER
  // touchesSecurityPath (path, #360) OR touchesTenantSupabasePath (content, #399).
  function widenedSecurityFiles(dir: string, rel = ""): { path: string; source: string }[] {
    const files: { path: string; source: string }[] = [];
    for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (entry.name !== "generated") files.push(...widenedSecurityFiles(dir, relPath));
      } else if (entry.name.endsWith(".ts")) {
        const source = readFileSync(join(dir, relPath), "utf8");
        if (touchesSecurityPath(relPath) || touchesTenantSupabasePath(source)) files.push({ path: relPath, source });
      }
    }
    return files;
  }

  // #809: the opt-in whole-repo pass's own fixture subdirectory — kept separate from the rest of
  // dup/ so this measurement stays deterministic (it doesn't have to reason about whether some
  // unrelated M4 fixture elsewhere in the corpus incidentally near-misses another one under the
  // whole-repo pass's wider admission).
  function wideRepoFiles(dir: string, rel = ""): { path: string; source: string }[] {
    const files: { path: string; source: string }[] = [];
    for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) files.push(...wideRepoFiles(dir, relPath));
      else if (entry.name.endsWith(".ts")) files.push({ path: relPath, source: readFileSync(join(dir, relPath), "utf8") });
    }
    return files;
  }

  it("catches every planted M4 positive and stays silent on every M4 negative", { timeout: 30_000 }, () => {
    const securityFiles = widenedSecurityFiles(dupDir);
    const wideFiles = wideRepoFiles(join(dupDir, "wide"));
    const findings = [
      ...jscpdToFindings(runJscpdLive()),
      ...divergedCloneFindings(securityFiles),
      ...wholeRepoDivergedCloneFindings(wideFiles),
    ];
    const m4Entries = m4m5Entries.filter((e) => e.module === "M4");
    expect(m4Entries.length).toBeGreaterThanOrEqual(14); // guards against the corpus silently shrinking
    const matrix = buildCoverageMatrix(findings, m4Entries);
    const failed = matrix.rows.filter((r) => !r.pass).map((r) => `${r.id}: ${r.detail}`);
    expect(failed).toEqual([]);

    // The matrix scores caught-at-tier only; the #361 elevation contract (severity + note) is
    // asserted here against the same live findings so the fixture can't silently degrade.
    const sec = findings.find((f) => f.location.includes("auth/session-check-api.ts"));
    expect(sec?.severity).toBe("Medium");
    expect(sec?.impact).toContain("M1 authorization review");

    // Same for #360/#399/#1095: exactly THREE diverged families exist in the security-path fixture
    // set — the require-tenant guards (v1, path-scoped), the customer/order stores (v2, content-
    // scoped) and the two workspace-guard copies inside ONE file (#1095) — and nothing else may
    // pair (the session-check clones are a consistent Type-2 rename; api-key-check.ts is
    // structurally distinct). Trailing hyphen distinguishes this narrow-pass id family
    // ("M4-DIV-NN") from the wide-pass one ("M4-DIVW-NN") below — both start with "M4-DIV".
    const diverged = findings.filter((f) => f.id.startsWith("M4-DIV-"));
    expect(diverged).toHaveLength(3);
    const tenantGuard = diverged.find((f) => f.location.includes("require-tenant-api.ts"));
    expect(tenantGuard?.location).toContain("require-tenant-admin.ts");
    const tenantStore = diverged.find((f) => f.location.includes("customer.store.ts"));
    expect(tenantStore?.location).toContain("order.store.ts");
    // #1095: the same-file family. Both copies are in workspace-guard.ts, so the location names
    // that path twice — the pair the pass could not see at all before this change.
    const sameFile = diverged.find((f) => f.location.includes("workspace-guard.ts"));
    expect(sameFile?.severity).toBe("High");
    expect(sameFile?.location.match(/workspace-guard\.ts/g)).toHaveLength(2);

    // #809: exactly ONE whole-repo family — the export-config pair — and notification-format.ts
    // (structurally distinct, similar size) stays unpaired.
    const wideDiverged = findings.filter((f) => f.id.startsWith("M4-DIVW-"));
    expect(wideDiverged).toHaveLength(1);
    expect(wideDiverged[0]!.severity).toBe("Medium"); // not High — no security-path guarantee here
    expect(wideDiverged[0]!.location).toContain("export-config-a.ts");
    expect(wideDiverged[0]!.location).toContain("export-config-b.ts");
    expect(wideDiverged[0]!.location).not.toContain("notification-format.ts");
  });
});

describe("duplicationSummary", () => {
  it("recomputes the percentage from every significant cluster, cross-file or self-file, excluding only the sub-threshold band (#232/#1095)", () => {
    // The 60-, 40- and 11-line clusters count — the self-file 40-liner among them, since #1095
    // scores it; only the 6-line header is excluded. round(10000 * 111/320) / 100 = 34.69.
    const summary = duplicationSummary(jscpdReport);
    expect(summary.duplicatedLines).toBe(111);
    expect(summary.percentage).toBe(34.69);
  });

  it("counts the dropped small-clone band separately without polluting the headline percentage (#365)", () => {
    const summary = duplicationSummary(jscpdReport);
    expect(summary.subThresholdCloneCount).toBe(1); // the c.ts/d.ts import header
    expect(summary.selfFileCloneCount).toBe(0); // the self-file 40-liner is scored now, not disclosed as a dropped band
  });
});

describe("JSCPD_IGNORE_GLOBS", () => {
  it("excludes the #232-evidenced generated/vendored/demo FP shapes on top of the standard build dirs", () => {
    expect(JSCPD_IGNORE_GLOBS).toEqual(expect.arrayContaining(["**/node_modules/**", "**/dist/**", "**/.next/**", "**/generated/**"]));
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("database.types.ts"))).toBe(true);
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("vendor"))).toBe(true);
    expect(JSCPD_IGNORE_GLOBS.some((g) => g.includes("demo"))).toBe(true);
  });
});

// #1080: the ignore globs are never disclosed to the reader — this exercises the glob matcher and
// the M4-SCOPE-00 disclosure row built from it.
describe("matchesJscpdIgnoreGlob / matchesGlob (#1080)", () => {
  it("matches a build-artifact path via a leading **/ + trailing /** glob", () => {
    expect(matchesJscpdIgnoreGlob("apps/main/node_modules/foo/bar.ts")).toBe(true);
    expect(matchesJscpdIgnoreGlob("src/normal/file.ts")).toBe(false);
  });

  it("requires an exact basename match for a literal glob, not a substring", () => {
    expect(matchesGlob("**/database.types.ts", "src/database.types.ts")).toBe(true);
    expect(matchesGlob("**/database.types.ts", "src/foodatabase.types.ts")).toBe(false);
  });

  it("the demo glob is a SUBSTRING match — a shipped demos/ directory is excluded by it too", () => {
    expect(matchesGlob("**/*demo*/**", "apps/demos/product-tour.tsx")).toBe(true);
  });
});

describe("jscpdIgnoreScopeFinding (#1080)", () => {
  it("returns undefined when nothing matched any disclosed glob", () => {
    const matches = JSCPD_DISCLOSED_GLOBS.map((glob) => ({ glob, count: 0 }));
    expect(jscpdIgnoreScopeFinding(matches)).toBeUndefined();
  });

  it("names the matched globs, their counts, and an example, naming the demos/ substring risk", () => {
    const matches: JscpdGlobMatch[] = JSCPD_DISCLOSED_GLOBS.map((glob) => ({ glob, count: 0 }));
    const demoGlob = matches.find((m) => m.glob === "**/*demo*/**")!;
    demoGlob.count = 3;
    demoGlob.example = "apps/demos/tour.tsx";
    const finding = jscpdIgnoreScopeFinding(matches);
    expect(finding?.id).toBe("M4-SCOPE-00");
    expect(finding?.evidence).toContain("apps/demos/tour.tsx");
    expect(finding?.evidence).toContain("3 files");
    expect(finding?.evidence).toContain("SUBSTRING match");
  });
});

// Shaped from a real knip fixture: one fully-dead file + one file with two
// unreferenced exports (a function and a const).
const knipReport: KnipReport = {
  files: ["src/dead.ts"],
  issues: [
    {
      file: "src/mixed.ts",
      exports: [{ name: "neverImported", line: 4 }],
      types: [{ name: "UnusedType", line: 9 }],
    },
    {
      file: "src/clean.ts",
      exports: [],
      types: [],
    },
  ],
};

describe("knipToFindings", () => {
  it("reports a fully-unused file with a measured line count when supplied", () => {
    const findings = knipToFindings(knipReport, { "src/dead.ts": 12 });
    const fileFinding = findings.find((f) => f.location === "src/dead.ts");
    expect(fileFinding?.impact).toBe("Entire file (12 lines) is unreferenced.");
  });

  it("never fabricates a line count when none was measured", () => {
    const findings = knipToFindings(knipReport);
    const fileFinding = findings.find((f) => f.location === "src/dead.ts");
    expect(fileFinding?.impact).toBe("Entire file is unreferenced.");
  });

  it("splits value exports (confirmed dead code) from exported types (review-tier), skipping clean files (#693)", () => {
    const findings = knipToFindings(knipReport);
    const valueExport = findings.find((f) => f.location === "src/mixed.ts" && f.confidence === "Confirmed");
    const typeExport = findings.find((f) => f.location === "src/mixed.ts" && f.confidence === "Review");
    // The unused VALUE export is confirmed dead code, grade-counted.
    expect(valueExport?.evidence).toContain("neverImported");
    expect(valueExport?.evidence).not.toContain("UnusedType");
    // The exported TYPE is a separate review-tier triage item, not "delete this dead code".
    expect(typeExport?.evidence).toContain("UnusedType");
    expect(typeExport?.title).toContain("Exported-but-unreferenced type");
    expect(findings.find((f) => f.location === "src/clean.ts")).toBeUndefined();
  });

  it("does not claim a precise line reduction for partial dead value exports", () => {
    const findings = knipToFindings(knipReport);
    const valueExport = findings.find((f) => f.location === "src/mixed.ts" && f.confidence === "Confirmed");
    expect(valueExport?.impact).toContain("manual look");
  });

  it("tags files and value exports at high precision, but exported types at review tier — not grade-counted (#693)", () => {
    const findings = knipToFindings(knipReport);
    const highTier = findings.filter((f) => f.precisionTier === "high");
    const reviewTier = findings.filter((f) => f.precisionTier === "review");
    // The unused file and the value export stay high/confirmed.
    expect(highTier.every((f) => f.confidence === "Confirmed")).toBe(true);
    expect(highTier.some((f) => f.location === "src/dead.ts")).toBe(true);
    // The exported type is review-tier and does NOT tell the reader to delete it.
    expect(reviewTier).toHaveLength(1);
    expect(reviewTier[0]?.confidence).toBe("Review");
    expect(reviewTier[0]?.fix).not.toContain("Delete");
    expect(reviewTier[0]?.fix).toContain("export");
  });

  // #1101: M5 ids are positional, so before the sort they named a POSITION in knip's output rather
  // than a finding — and knip's order is not stable run-to-run (MEASURED 2026-07-26: 8 identical
  // `pnpm quality-scan targets/calibration` runs produced 3 distinct orderings). M4 and M5 each
  // invoke quality-scan separately, so the two invocations minted the same id for two different
  // findings and the assembled deliverable was rejected for duplicate ids. Deliberately exercises
  // only the pure transform, so it cannot depend on which deps happen to be installed.
  it("assigns each id from the finding, not from knip's emission order (#1101)", () => {
    // The real shape: sibling routes whose rows are identical apart from their location, which knip
    // emits in either order, plus two unreferenced files in either order.
    const report = (order: string[]): KnipReport => ({
      files: [...order],
      issues: order.map((file) => ({ file, exports: [], types: [], unlisted: [{ name: "jsonwebtoken", line: 1 }] })),
    });
    const rows = (r: KnipReport): string[][] => knipToFindings(r).map((f) => [f.id, f.location, f.title]);
    expect(rows(report(["app/api/b/route.ts", "app/api/a/route.ts"]))).toEqual(rows(report(["app/api/a/route.ts", "app/api/b/route.ts"])));
    // And each id names the same finding whichever order arrived — not merely a matching pair of lists.
    expect(rows(report(["app/api/b/route.ts", "app/api/a/route.ts"])).map((r) => `${r[0]}=${r[1]}`)).toEqual([
      "M5-01=app/api/a/route.ts",
      "M5-02=app/api/b/route.ts",
      "M5-03=app/api/a/route.ts",
      "M5-04=app/api/b/route.ts",
    ]);
  });
});

// #1050: knip's unused-dependency verdicts come from the resolved import graph, so a scope whose
// own config and plugins could not be loaded (#696/#810) never saw the config files that reference
// build-time deps. Those rows must be review candidates, not a confident "delete this".
describe("knipToFindings — unused dependencies (#1050)", () => {
  const depReport: KnipReport = {
    files: [],
    issues: [{ file: "package.json", exports: [], types: [], dependencies: [{ name: "left-pad", line: 6 }], devDependencies: [{ name: "rimraf", line: 10 }] }],
  };

  it("reports prod and dev unused deps as separate findings, confirmed when the scope resolved", () => {
    const findings = knipToFindings(depReport);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.confidence === "Confirmed" && f.precisionTier === "high")).toBe(true);
    expect(findings.find((f) => f.title.includes("Unused dependencies"))?.evidence).toContain("left-pad");
    expect(findings.find((f) => f.title.includes("Unused devDependencies"))?.evidence).toContain("rimraf");
  });

  it("drops to review tier for a scope whose config/plugins could not be resolved", () => {
    const findings = knipToFindings(depReport, {}, new Set(), new Set(["package.json"]));
    expect(findings.every((f) => f.confidence === "Review" && f.precisionTier === "review")).toBe(true);
    expect(findings[0]?.fix).toContain("Install the target's dependencies");
  });
});

// #1080: the six IssueRecords keys #1050 left dropped at the KnipIssue type boundary — MEASURED
// against knip 5.88.1's json reporter (node_modules/knip/dist/reporters/json.js). Not captured tool
// output; hand-built to cover each new category's own emission path.
describe("knipToFindings — #1080 (unlisted/unresolved/duplicates/enumMembers/optionalPeerDependencies/catalog/binaries/owners)", () => {
  const report: KnipReport = {
    files: [],
    issues: [
      {
        file: "src/lib/report.ts",
        owners: [{ name: "@team-platform" }],
        exports: [],
        types: [],
        unlisted: [{ name: "chalk", line: 2 }],
        unresolved: [{ name: "./missing-module", line: 4 }],
        duplicates: [[{ name: "helper", line: 5 }, { name: "default", line: 5 }]],
        enumMembers: { Status: [{ name: "ARCHIVED", line: 9 }] },
        optionalPeerDependencies: [{ name: "react-dom", line: 1 }],
        catalog: [{ name: "typescript", line: 1 }],
        binaries: [{ name: "some-cli" }],
      },
    ],
  };

  it("reports an unlisted import as a supply-chain-flagged Medium finding", () => {
    const findings = knipToFindings(report);
    const f = findings.find((r) => r.title.includes("Unlisted import"));
    expect(f?.severity).toBe("Medium");
    expect(f?.evidence).toContain("chalk");
    expect(f?.impact).toContain("supply-chain");
    expect(f?.impact).toContain("@team-platform"); // owners enrichment threaded through
  });

  it("reports an unresolved import as a broken-import finding", () => {
    const findings = knipToFindings(report);
    const f = findings.find((r) => r.title.includes("Unresolved import"));
    expect(f?.severity).toBe("Medium");
    expect(f?.evidence).toContain("./missing-module");
  });

  it("reports duplicate exports of the same symbol", () => {
    const findings = knipToFindings(report);
    const f = findings.find((r) => r.title.includes("Duplicate export"));
    expect(f?.evidence).toContain("helper / default");
  });

  it("reports unused enum members", () => {
    const findings = knipToFindings(report);
    const f = findings.find((r) => r.title.includes("Unused enum member"));
    expect(f?.evidence).toContain("Status.ARCHIVED");
  });

  it("reports unused optional peer dependencies and catalog entries as separate findings", () => {
    const findings = knipToFindings(report);
    expect(findings.find((r) => r.title.includes("optional peer dependency"))?.evidence).toContain("react-dom");
    expect(findings.find((r) => r.title.includes("catalog"))?.evidence).toContain("typescript");
  });

  it("reports an unused declared binary at review tier", () => {
    const findings = knipToFindings(report);
    const f = findings.find((r) => r.title.includes("binary"));
    expect(f?.evidence).toContain("some-cli");
    expect(f?.precisionTier).toBe("review");
  });

  it("emits nothing for any of the six categories when absent (back-compat with a merged/legacy report)", () => {
    const bare: KnipReport = { files: [], issues: [{ file: "src/clean.ts", exports: [], types: [] }] };
    expect(knipToFindings(bare)).toEqual([]);
  });
});

// #226: dead code in auth/guard/security paths is a stronger signal than routine slop — the
// atc cross-tenant Critical was preceded by exactly this shape (a guard helper written and never
// wired in). Not shaped from a captured knip run; hand-built to cover the elevation paths.
const securityKnipReport: KnipReport = {
  files: ["src/middleware/AuthGuard.tsx", "src/blog/authors.ts"],
  issues: [
    {
      file: "lib/security/guards.ts",
      exports: [{ name: "requireTenantMatch", line: 3 }],
      types: [],
    },
  ],
};

describe("knipToFindings — security-path elevation (#226)", () => {
  it("elevates unused exports in a security-relevant file above routine Low and cross-links the authz review", () => {
    const findings = knipToFindings(securityKnipReport);
    const guard = findings.find((f) => f.location === "lib/security/guards.ts");
    expect(guard?.severity).toBe("Medium");
    expect(guard?.impact).toContain("authz");
    expect(guard?.impact).toContain("M1 authorization review");
  });

  it("elevates a fully-unused file in an auth/guard path, including camelCase/PascalCase names", () => {
    const findings = knipToFindings(securityKnipReport, { "src/middleware/AuthGuard.tsx": 40 });
    const authGuard = findings.find((f) => f.location === "src/middleware/AuthGuard.tsx");
    expect(authGuard?.severity).toBe("Medium");
    expect(authGuard?.impact).toContain("authorization is actually enforced");
  });

  it("does not false-positive elevate a file that merely contains 'auth' as a substring (authors.ts)", () => {
    const findings = knipToFindings(securityKnipReport);
    const authors = findings.find((f) => f.location === "src/blog/authors.ts");
    expect(authors?.severity).toBe("Low");
  });

  it("leaves routine (non-security-path) unused exports at Low, unchanged", () => {
    const findings = knipToFindings(knipReport);
    const mixed = findings.find((f) => f.location === "src/mixed.ts");
    expect(mixed?.severity).toBe("Low");
  });
});

// #223: a knip failure (e.g. target's node_modules isn't installed) must not crash the whole
// quality-scan and drop M4's jscpd findings — the CLI substitutes this disclosure finding instead.
describe("knipUnavailableFinding", () => {
  it("discloses the M5 coverage gap without claiming zero dead code", () => {
    const finding = knipUnavailableFinding("Cannot find module 'vitest/config'");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.taxonomy).toContain("M5");
    expect(finding.evidence).toContain("Cannot find module 'vitest/config'");
    expect(finding.impact).toContain("incomplete");
  });
});

// #505: the M4 mirror — a jscpd timeout/crash on one workspace of a monorepo target must not drop
// the other workspaces' duplication findings, so the CLI substitutes this disclosure instead of
// crashing the whole run.
describe("jscpdUnavailableFinding", () => {
  it("discloses the M4 coverage gap, distinct from the M4-00 sub-threshold meta row, without claiming zero duplication", () => {
    const finding = jscpdUnavailableFinding("apps/rag: did not complete within 120s (timed out)");
    expect(finding.id).toBe("M4-99");
    expect(finding.id).not.toBe("M4-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.taxonomy).toContain("M4");
    expect(finding.evidence).toContain("apps/rag: did not complete within 120s (timed out)");
    expect(finding.impact).toContain("incomplete");
  });
});

// #580: knip completing without error is not proof its entry resolution was correct — on a Vite
// target whose plugin didn't auto-activate, knip falls back to default index.*-only resolution and
// can report most of src/ as unused. Ratios below are the numbers MEASURED (2026-07-18) against a
// real synthetic Vite fixture: a mis-resolved run (no `vite` install) reported 5/7 = 71% of scanned
// files unused; the same fixture with `vite` genuinely installed dropped to 4/7 with vite.config.ts
// correctly excluded from the unused list.
describe("knipEntryUncertainReason (#580)", () => {
  it("discloses on an implausibly high unused-file ratio, even with vite resolvable", () => {
    const report: KnipReport = { files: ["vite.config.ts", "src/utils/b.ts", "src/utils/c.ts", "src/utils/d.ts", "src/utils/e.ts"], issues: [] };
    const reason = knipEntryUncertainReason(report, 7, true, true);
    expect(reason).toContain("5/7 source files");
    expect(reason).toContain("71%");
    expect(reason).toContain("mis-resolved entry points");
  });

  it("discloses when vite entry markers are present but vite isn't resolvable from the scope, even at a low ratio", () => {
    const report: KnipReport = { files: ["src/one-stale-file.ts"], issues: [] };
    const reason = knipEntryUncertainReason(report, 20, true, false);
    expect(reason).toContain("vite.config.*/index.html");
    expect(reason).toContain("isn't resolvable");
  });

  it("does not fire on a normal, well-resolved Vite target (low ratio, vite resolvable)", () => {
    const report: KnipReport = { files: ["src/utils/orphan.ts"], issues: [] };
    const reason = knipEntryUncertainReason(report, 8, true, true);
    expect(reason).toBeUndefined();
  });

  it("does not fire on a non-Vite target with no entry markers, even at a high ratio, below the minimum-file floor", () => {
    // Too few scanned files for the ratio to mean anything (MIN_FILES_FOR_RATIO_SIGNAL guard) and
    // no Vite markers at all — nothing here should read as "Vite entry resolution uncertain".
    const report: KnipReport = { files: ["a.ts", "b.ts", "c.ts"], issues: [] };
    const reason = knipEntryUncertainReason(report, 3, false, true);
    expect(reason).toBeUndefined();
  });
});

// #931: jscpd writing no report is ambiguous between #505's genuine "<2 comparable files" clean
// zero and jscpd analysing nothing on a real target (measured on documenso/documenso: the same
// commit/flags scored 0 findings at one absolute clone path and 1,256 at another). This is the
// pre-fix regression: a bare `< 2 ? clean zero : clean zero` would report the same silent zero for
// both, exactly the "an unstated limitation reads as a clean bill of health" failure CLAUDE.md
// forbids.
describe("jscpdAnalysedNothingReason (#931)", () => {
  it("does not fire when the scope genuinely has fewer than 2 comparable source files", () => {
    expect(jscpdAnalysedNothingReason(0)).toBeUndefined();
    expect(jscpdAnalysedNothingReason(1)).toBeUndefined();
  });

  it("discloses a coverage gap when jscpd wrote no report despite >=2 comparable source files", () => {
    const reason = jscpdAnalysedNothingReason(3395);
    expect(reason).toBeDefined();
    expect(reason).toContain("3395");
    expect(reason).toContain("analysed nothing");
  });
});

// #810: the reduced-mode disclosure — knip couldn't load the target's config (no node_modules), so
// M5 re-ran with plugins disabled. A distinct row from both M5-00 (didn't complete) and M5-99
// (completed but untrustworthy), because the cause and remediation differ.
describe("knipReducedTierFinding (#810)", () => {
  it("discloses the reduced no-deps run as M5-98, distinct from the M5-00 gap and M5-99 uncertain rows", () => {
    const finding = knipReducedTierFinding("apps/web: Cannot find module '@vitejs/plugin-react'");
    expect(finding.id).toBe("M5-98");
    expect(finding.id).not.toBe("M5-00");
    expect(finding.id).not.toBe("M5-99");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.taxonomy).toContain("M5");
    expect(finding.evidence).toContain("@vitejs/plugin-react");
    expect(finding.evidence).toContain("plugins disabled");
    // tells the operator how to get confirmed (non-review) findings back
    expect(finding.fix).toContain("dependencies");
  });
});

describe("knipEntryUncertainFinding (#580)", () => {
  it("discloses the uncertainty as a distinct row from M5-00 (did-not-complete)", () => {
    const finding = knipEntryUncertainFinding("apps/web: 5/7 source files (71%) reported unused — implausibly high, a signal of mis-resolved entry points rather than genuine dead code");
    expect(finding.id).toBe("M5-99");
    expect(finding.id).not.toBe("M5-00");
    expect(finding.severity).toBe("Info");
    expect(finding.confidence).toBe("N/A");
    expect(finding.taxonomy).toContain("M5");
    expect(finding.evidence).toContain("apps/web: 5/7 source files");
    expect(finding.impact).toContain("may be significantly over- or under-stated");
  });
});

// #505: quality-scan runs jscpd/knip per workspace on a monorepo target, then merges their reports
// back into one before the existing (already-tested) jscpdToFindings/knipToFindings transforms run.
describe("mergeJscpdReports (#505)", () => {
  it("concatenates duplicates and sums the line totals from every workspace's report", () => {
    const a: JscpdReport = { statistics: { total: { percentage: 10, duplicatedLines: 20, lines: 200 } }, duplicates: [jscpdReport.duplicates[0]!] };
    const b: JscpdReport = { statistics: { total: { percentage: 5, duplicatedLines: 5, lines: 100 } }, duplicates: [jscpdReport.duplicates[1]!] };
    const merged = mergeJscpdReports([a, b]);
    expect(merged.duplicates).toEqual([a.duplicates[0], b.duplicates[0]]);
    expect(merged.statistics.total.lines).toBe(300);
    expect(merged.statistics.total.duplicatedLines).toBe(25);
  });

  it("merging zero reports (every workspace gapped out) yields an empty, valid report", () => {
    const merged = mergeJscpdReports([]);
    expect(merged.duplicates).toEqual([]);
    expect(merged.statistics.total.lines).toBe(0);
    expect(jscpdToFindings(merged)).toEqual([]);
  });
});

describe("mergeKnipReports (#505)", () => {
  it("concatenates files and issues from every workspace's report", () => {
    const a: KnipReport = { files: ["apps/main/src/dead.ts"], issues: [] };
    const b: KnipReport = { files: [], issues: [{ file: "apps/rag/src/mixed.ts", exports: [{ name: "x", line: 1 }], types: [] }] };
    const merged = mergeKnipReports([a, b]);
    expect(merged.files).toEqual(["apps/main/src/dead.ts"]);
    expect(merged.issues).toEqual(b.issues);
  });
});
