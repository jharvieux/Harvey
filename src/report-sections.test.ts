// The two client-facing report sections that were specified but never reached the page
// (report-template/sections.mjs):
//
//   #1045 — §3b Test quality: render.mjs gated the section on a `testQuality` key NO producer ever
//           set, and the shape it drew (one overall score) was not the per-module table the
//           skeleton specifies. So a full mutation run's numbers were computed and dropped.
//   #1048 — §0 Limitations & liability: `grep -n liabilit report-template/*.mjs` returned nothing,
//           so every delivered report carried no scope caveat and no liability cap.
//
// These pin what a paying client SEES, plus the honesty rules the numbers must never lose: a scoped
// score is never a whole-repo claim, an ungenerated Line-cov cell is never drawn as 0%, and an
// absent measurement is a stated gap rather than an omitted section.

import { describe, expect, it } from "vitest";
import {
  DRAFT_NOTICE,
  DRAFT_TERMS,
  derivedScopeLimits,
  draftTermsBadge,
  legalTermsSection,
  testQualityAction,
  testQualityBlock,
  testQualitySection,
} from "../report-template/sections.mjs";
import { assembleEngagementDocument } from "./audit-report.js";
import { runAudit } from "./audit-runner.js";
import type { RunContext } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import type { CoverageRow, FindingsDocument, ReportMeta, TestQuality } from "./findings.js";
import { validateFindings } from "./findings.js";

const tq = (over: Partial<TestQuality> = {}): TestQuality => ({
  mutationScore: 62.5,
  coveredScope: ["src/auth.ts", "src/billing.ts"],
  wholeRepo: true,
  scopeNote: "run covered all 2 file(s) matched by the configured mutate globs",
  rows: [
    { module: "src/auth", lineCoverage: 94, mutationScore: 41, survivingCount: 12, hotspotSurvivingCount: 3 },
    { module: "src/billing", lineCoverage: 70, mutationScore: 68, survivingCount: 4, hotspotSurvivingCount: 0 },
  ],
  lineCoverage: { status: "ran" },
  survivors: [{ file: "src/auth.ts", line: 42, mutator: "ConditionalExpression", hotspot: true }],
  survivorTotal: 16,
  ...over,
});

const meta = (over: Partial<ReportMeta> = {}): ReportMeta => ({
  client: "Acme", subtitle: "Q3 audit", date: "2026-07-25", commit: "abc1234", auditor: "Harvey",
  confidential: true, overallHealth: 7, tenantIsolation: "Verified", authModel: "Supabase",
  headline: "Partial audit", scope: "the app repo at abc1234", methodology: "ten modules",
  outOfScope: "infrastructure", ...over,
});

const doc = (over: Partial<FindingsDocument> = {}): FindingsDocument => ({ meta: meta(), findings: [], ...over });

describe("§3b Test quality — the documented per-module table (#1045)", () => {
  it("renders every column the skeleton specifies, with each module's real numbers", () => {
    const html = testQualitySection(tq());
    for (const header of ["Module / file", "Line cov", "Mutation score", "Surviving mutants (critical)", "Action"]) {
      expect(html).toContain(header);
    }
    expect(html).toContain("src/auth");
    expect(html).toContain("94%"); // line coverage — the column the old single-score shape had nowhere to put
    expect(html).toContain("41%"); // that module's mutation score, not just the overall one
    expect(html).toContain("3</b> of 12"); // hotspot survivors of total, per docs/m8-test-quality.md §5
  });

  // #1076: the covered-code score is Stryker's OTHER published headline metric — shown alongside
  // the primary score so "your tests are bad" and "your tests are decent but reach half the code"
  // don't collapse into one number. Absent from an older artifact ⇒ simply not rendered, never
  // fabricated as 0 or a copy of the primary score.
  it("shows the covered-code score alongside the primary score when the run computed it (#1076)", () => {
    const html = testQualitySection(tq({ mutationScoreBasedOnCoveredCode: 58.1 }));
    expect(html).toContain("58.1");
    expect(html).toContain("% of COVERED code");
  });

  it("omits the covered-code score entirely when the run's artifact predates it", () => {
    expect(testQualitySection(tq())).not.toContain("% of COVERED code");
  });

  it("flags the false-confidence gap — high line coverage over a low mutation score", () => {
    const html = testQualitySection(tq());
    // The auth row (94 line cov vs 41 mutation) is flagged; billing (70 vs 68) is within the gap.
    expect(html.match(/cov-badge[^>]*>False confidence/g)).toHaveLength(1);
    expect(html).toContain("False confidence: 94% of lines run but only 41% of injected faults are caught.");
  });

  it("says WHY a Line-cov cell is missing instead of drawing it as 0% (#819)", () => {
    const html = testQualitySection(tq({
      rows: [{ module: "src/auth", mutationScore: 41, survivingCount: 2, hotspotSurvivingCount: 0 }],
      lineCoverage: { status: "partial", reason: "no coverage script in the target's package.json" },
    }));
    expect(html).toContain("not generated");
    expect(html).toContain("no coverage script in the target's package.json");
    expect(html).not.toMatch(/<td>0%<\/td>/);
  });

  it("never presents a scoped or unverified score as a whole-repo claim (#319/#504)", () => {
    const scoped = testQualitySection(tq({ wholeRepo: false, scopeNote: "549 file(s) were never mutated" }));
    expect(scoped).toContain("NOT a whole-repo coverage claim");
    expect(scoped).toContain("549 file(s) were never mutated");
    expect(testQualitySection(tq())).not.toContain("NOT a whole-repo coverage claim");
  });

  it("discloses the surviving mutants it did not list individually, by count", () => {
    const html = testQualitySection(tq());
    expect(html).toContain("src/auth.ts</code>:42");
    expect(html).toContain("+ 15 more surviving mutant(s)"); // 16 total − 1 listed
  });

  it("derives an Action per row, and an operator-written one wins", () => {
    expect(testQualityAction({ module: "a", lineCoverage: 94, mutationScore: 41, survivingCount: 12, hotspotSurvivingCount: 3 }))
      .toMatch(/False confidence.*3 surviving mutant\(s\) on flagged M1\/M3 hotspot/s);
    expect(testQualityAction({ module: "a", mutationScore: 100, survivingCount: 0, hotspotSurvivingCount: 0 }))
      .toMatch(/No surviving mutants/);
    expect(testQualityAction({ module: "a", mutationScore: 41, survivingCount: 2, hotspotSurvivingCount: 0, action: "write a denial test for the RLS policy at line 42" }))
      .toBe("write a denial test for the RLS policy at line 42");
  });

  it("states the absence when no mutation measurement was produced — never an omitted section", () => {
    const coverage: CoverageRow[] = [{ module: "M8", name: "Test quality", status: "partial", reason: "Stryker's initial dry run FAILED" }];
    const html = testQualityBlock(doc({ coverage }));
    expect(html).toContain("No mutation measurement on this engagement");
    expect(html).toContain("Stryker's initial dry run FAILED");
    expect(html).toContain("not a clean result");
  });
});

// The acceptance criterion #1045 names: a --findings-out document produced from a target whose
// mutation tier really ran must render a non-empty test-quality section. This drives the WHOLE
// path — probe → runAudit → assembleEngagementDocument → renderer — against a fake Stryker
// artifact, which is exactly the seam that was missing (the producer never set the key).
describe("a real mutation run reaches the rendered report (#1045)", () => {
  const artifact = {
    summary: {
      overall: { mutationScore: 62.5 },
      coveredScope: ["src/auth.ts"],
      survivingMutants: [{ file: "src/auth.ts", line: 42, mutatorName: "ConditionalExpression", hotspot: true }],
    },
    reportRows: [{ module: "src/auth", lineCoverage: 94, mutationScore: 41, survivingCount: 12, hotspotSurvivingCount: 3 }],
    scope: { verified: true, scoped: false, note: "run covered all 1 file(s) matched by the configured mutate globs" },
    lineCoverage: { status: "ran" },
  };
  const ctx: RunContext = {
    targetDir: "/target",
    env: { connected: false, dynamic: false, llm: false },
    exec: (_c, argv) => ({
      ok: true,
      output: argv.includes("mutation-scan")
        ? JSON.stringify(artifact)
        : argv.includes("quality-scan")
          ? "[]"
          : argv.includes("detect-static")
            ? "loaded 42 source files (30 product-code) from /target"
            : "",
    }),
    exists: () => true,
    isGitRepoRoot: () => true,
    captureDir: "/capture",
    readFindings: () => [],
    readArtifact: (p) => (p.endsWith("M8.json") ? artifact : undefined),
  };

  it("carries M8's per-module rows into the assembled document and out to the page", () => {
    const { recorded, testQuality } = runAudit(AUDIT_RUNNERS, ctx);
    expect(testQuality?.rows).toHaveLength(1);
    const assembled = assembleEngagementDocument(recorded, ctx.env, [], meta(), undefined, undefined, testQuality);
    expect(validateFindings(assembled).ok).toBe(true);
    const html = testQualityBlock(assembled);
    expect(html).toContain("62.5<span");
    expect(html).toContain("src/auth");
    expect(html).toContain("41%");
    expect(html).not.toContain("No mutation measurement");
  });
});

describe("§0 Limitations & liability (#1048)", () => {
  it("always renders — the section is never gated on the wording being present", () => {
    const html = legalTermsSection(doc());
    expect(html).toContain("Limitations &amp; liability");
  });

  it("marks tooling-drafted wording as unapproved, on the section AND the cover", () => {
    const html = legalTermsSection(doc());
    expect(html).toContain(DRAFT_NOTICE);
    expect(html).toContain("DO NOT DELIVER THIS REPORT AS-IS");
    expect(html).toContain("#11"); // the entity + engagement-terms work
    expect(html).toContain("#743"); // trust pages / legal review
    expect(draftTermsBadge(doc())).toContain(DRAFT_NOTICE);
  });

  it("covers every element the skeleton requires", () => {
    const text = DRAFT_TERMS.map(([h, p]) => `${h} ${p}`).join(" ").toLowerCase();
    expect(text).toContain("point-in-time");
    expect(text).toContain("not a complete inventory");
    expect(text).toContain("not a substitute for a full penetration test");
    expect(text).toContain("limited to the fees actually paid");
    expect(text).toContain("without warranty");
  });

  it("takes operator/counsel-approved wording verbatim and drops the draft banner", () => {
    const html = legalTermsSection(doc({ legalTerms: { text: "Liability is capped at the fees paid.", approvedBy: "Counsel" } }));
    expect(html).toContain("Liability is capped at the fees paid.");
    expect(html).toContain("approved by Counsel");
    expect(html).not.toContain(DRAFT_NOTICE);
    expect(html).not.toContain("Limitation of liability"); // the draft's own headings are gone
    expect(draftTermsBadge(doc({ legalTerms: { text: "x" } }))).toBe("");
  });

  it("derives what was NOT assessed from the coverage ledger, with each reason", () => {
    const coverage: CoverageRow[] = [
      { module: "M1", name: "Multi-tenant security", status: "ran", detail: "pnpm scan" },
      { module: "M2", name: "Local pen-test", status: "requires-live-run", reason: "no local stack was stood up" },
    ];
    const derived = derivedScopeLimits(coverage);
    expect(derived).toContain("1 of 2 module row(s) were NOT fully assessed");
    expect(derived).toContain("M2 — requires-live-run: no local stack was stood up");
    expect(legalTermsSection(doc({ coverage }))).toContain("no local stack was stood up");
  });

  it("does not claim completeness when the ledger is absent", () => {
    expect(derivedScopeLimits(undefined)).toContain("treat the scope as unstated rather than complete");
  });
});
