// Layer 1 for the external-repo corpus (#222): runs in `pnpm verify` with no clone and no
// network. Three jobs:
//   - prove the drift scorer actually fails on movement (the point of the corpus);
//   - pin the M10 classifier against the REAL column names from the swept repos (#233's over/
//     under-match verdicts);
//   - prove the m10FindingsFromSchema adapter (#279) shapes a schema classification pass into
//     Finding[] correctly, since Layer 2 is the only place it runs against real migrations.
// Layer 2 (clone each pinned commit, re-run detect-static/quality-scan/mutation-scan and classify
// each target's own migrations, score against the baselines) needs network + binaries, so it is
// NOT here: it is `pnpm corpus-drift`, scheduled in .github/workflows/corpus-drift.yml (#263).
// These two layers are complementary — Layer 1 proves the scorers fail on movement without
// cloning anything, Layer 2 supplies the real movement.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseRecordedReasons, validateRecordedReason } from "../recorded-reasons.js";
import { classifyColumn } from "../../tools/pii-classify.mjs";
import {
  EXTERNAL_CORPUS,
  explainDrift,
  FREE_TIER_EXPECTATIONS,
  isMutationBaseline,
  isNotRun,
  m10FindingsFromSchema,
  moduleMatches,
  revalidateNotRunReasons,
  scoreExternalBaseline,
  scoreFreeTierExpectation,
  scoreMutationBaseline,
  type ExternalTarget,
  type FreeTierExpectation,
  type MutationBaseline,
} from "./external-corpus.js";
import { buildQuickScanReport } from "../quick-scan.js";
import { DOC_CONTEXT_CREDENTIAL_TAXONOMY } from "./secrets.js";
import type { Finding, Severity } from "../findings.js";

function finding(taxonomy: string, severity: Severity = "Perf", location = "app/page.tsx:1"): Finding {
  return {
    id: "X", title: "", severity, confidence: "Confirmed", category: "", taxonomy,
    location, status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, mechanical: true,
  };
}

const target = (slug: string): ExternalTarget => {
  const t = EXTERNAL_CORPUS.find((x) => x.slug === slug);
  if (!t) throw new Error(`no corpus target ${slug}`);
  return t;
};

describe("external corpus manifest", () => {
  it("pins every target to a full 40-char commit — a baseline against a moving ref is meaningless", () => {
    for (const t of EXTERNAL_CORPUS) {
      expect(t.commit, t.slug).toMatch(/^[0-9a-f]{40}$/);
    }
  });

  it("records a reason for every module that did not run, never a bare zero", () => {
    // The coverage guard (CLAUDE.md): a module that cannot run is `partial`/`requires-live-run`
    // WITH THE REASON. A not-run module scored 0 would read as "clean" — the exact silent-skip
    // this repo treats as a defect.
    for (const t of EXTERNAL_CORPUS) {
      for (const [module, baseline] of Object.entries(t.modules)) {
        if (isNotRun(baseline)) expect(baseline.reason.length, `${t.slug}/${module}`).toBeGreaterThan(20);
        else expect(baseline.note.length, `${t.slug}/${module}`).toBeGreaterThan(20);
      }
    }
  });

  it("scores M5-knip on every target — none remains unrun after #519's per-workspace knip", () => {
    // knip without the target's `npm install` yields a knip-FAILED artifact, not a dead-code
    // measurement (#223). Which targets are scored is MEASURED, not assumed. #251 added the install
    // step the CLAUDE.md M5 row calls for (2 scored -> 4); #322's per-module scan root gave
    // mvp-boilerplate a scoped measurement over nextjs/ (4 -> 5); and #544 gave saas-lite — the last
    // holdout — a measured baseline once #519 made knip run PER WORKSPACE (the whole-repo run used
    // to die loading apps/web's eslint config). All 6 carried a real M5-knip baseline from then on,
    // and #894/#897's five new targets each got one measured the same way — including the three
    // pnpm-workspace targets, where knip falls back to #810's reduced no-dependencies tier and
    // discloses it as M5-98 rather than failing. Enumerated, not counted: a target silently
    // dropping to not-run is exactly what this asserts against.
    const scored = EXTERNAL_CORPUS.filter((t) => !isNotRun(t.modules["M5-knip"]!)).map((t) => t.slug);
    expect(scored.sort()).toEqual([
      "boxyhq", "carbon", "cravab", "documenso", "effective", "flori-web", "ghostfolio",
      "inbox-zero", "launch-mvp", "multi-tenant-starter", "mvp-boilerplate", "proposit",
      "rallly", "saas-lite", "subscription-payments", "supabase-security-labs", "tanstack-com",
    ]);
  });

  it("#251: neither remaining M5-knip gap blames a missing `npm install` — the install step exists now", () => {
    // The point of the install step is that "needs the target's npm install" stops being an
    // acceptable reason. If a future change reintroduces that reason, the install step has silently
    // stopped working (or stopped being wired into the job) and the honest fix is to repair it, not
    // to re-record the old excuse.
    for (const t of EXTERNAL_CORPUS) {
      const m5 = t.modules["M5-knip"]!;
      if (isNotRun(m5)) expect(m5.reason, t.slug).not.toMatch(/needs the target's own `npm install`/);
    }
  });

  it("#278: M5-slop is scored on every target (detect-static needs no npm install)", () => {
    // Unlike M5-knip, the slop detector is a source-only AST pass — it has no npm-install
    // prereq, so every target should carry a measured M5-slop baseline, never not-run.
    for (const t of EXTERNAL_CORPUS) {
      expect(isNotRun(t.modules["M5-slop"]!), t.slug).toBe(false);
    }
  });

  it("#483: M6-indicator is scored on every target (detect-static needs no npm install, same as M5-slop)", () => {
    for (const t of EXTERNAL_CORPUS) {
      expect(isNotRun(t.modules["M6-indicator"]!), t.slug).toBe(false);
    }
  });

  it("#1459: M1-boundary is scored on every target — same detect-static pass, same no-install prereq", () => {
    // The class this key exists for is High/Likely, so an unmeasured target is the worst case:
    // a widening could light it up and nothing would move. A measured ZERO is the FP floor.
    for (const t of EXTERNAL_CORPUS) {
      expect(isNotRun(t.modules["M1-boundary"]), t.slug).toBe(false);
    }
  });

  it("#1459: every M1-boundary baseline has counted === total — the class is High-only, never Info", () => {
    for (const t of EXTERNAL_CORPUS) {
      const m1 = t.modules["M1-boundary"];
      if (!isNotRun(m1)) expect(m1.counted, t.slug).toBe(m1.total);
    }
  });

  it("#483: every M6-indicator baseline has counted === total — the findings are Info-only by design (#267), so the two can never diverge", () => {
    for (const t of EXTERNAL_CORPUS) {
      const m6 = t.modules["M6-indicator"]!;
      if (!isNotRun(m6)) expect(m6.counted, t.slug).toBe(m6.total);
    }
  });
});

describe("scoreExternalBaseline", () => {
  it("passes when a scan reproduces the recorded counted total", () => {
    // The waterfall row this used to include was #1292's false positive (`if (existing) return`
    // before an INSERT); the baseline is 2 since it was removed.
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [
      finding("M9 — Accidental dynamic rendering"),
      finding("M9 — Accidental dynamic rendering"),
    ]);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: true, actual: 2, drift: 0 });
  });

  it("FAILS on a new over-match — the regression this corpus exists to catch", () => {
    // multi-tenant-starter's M7 is a MEASURED zero on a 3.1k-line repo with no perf surface —
    // its baseline note calls any M7 finding here "almost certainly a new over-match".
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [finding("M7 — Unbounded select")]);
    const m7 = rows.find((r) => r.module === "M7")!;
    expect(m7.pass).toBe(false);
    expect(m7.drift).toBe(1);
    expect(m7.detail).toContain("DRIFT +1");
  });

  it("FAILS when a real detection stops firing", () => {
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), []);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: false, drift: -2 });
  });

  it("#1459: FAILS when the boundary pass's authorization half stops firing — the hole this key closes", () => {
    // The negative control the issue asked for, as a unit: gutting the mutation collector removes
    // every `M1 — … missing authorization check` row and leaves the M9 count untouched. Before this
    // key, that produced NO failing row anywhere in the manifest.
    // #1500 zeroed tanstack-com's own M1-boundary baseline (6 -> 0, its whole family was cleared),
    // so this control moved to inbox-zero, whose 5 counted rows are ALL this same taxonomy (see
    // that baseline's note) rather than a mix with the owner-id class.
    const rows = scoreExternalBaseline(target("inbox-zero"), []);
    expect(rows.find((r) => r.module === "M1-boundary")).toMatchObject({ pass: false, drift: -5 });
    expect(rows.find((r) => r.module === "M1-boundary")!.detail).toContain("DRIFT -5");
  });

  it("#1459: keeps the SQL/RLS tier's `M1 — Multi-tenant security` out of the boundary key", () => {
    // Two different tiers share the `M1 —` prefix; only the boundary pass's own output is measured
    // here, and sweeping the migration tier in would silently merge two measurements (the #278 M5
    // and #360 M4 lesson).
    expect(moduleMatches("M1 — Multi-tenant security", "M1-boundary")).toBe(false);
    expect(moduleMatches("M1 — route action missing authorization check", "M1-boundary")).toBe(true);
    expect(moduleMatches("M1 — Client-supplied owner id trusted by authenticated action", "M1-boundary")).toBe(true);
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [finding("M1 — Multi-tenant security")]);
    expect(rows.find((r) => r.module === "M1-boundary")).toMatchObject({ pass: true, drift: 0 });
  });

  it("ignores Info findings, so the demoted exhaustive-deps class can't re-enter the count", () => {
    // #230 demoted exhaustive-deps to Info rather than deleting it. If a future change promotes
    // it back to a graded severity, proposit's M7 jumps 36 -> 71 and this scorer must catch it.
    // #1475 gave the class a second Info member on the same principle: state sprawl still emits
    // and still ships, but its render-count claim was false on React >= 18, so it is Info here too.
    const rows = scoreExternalBaseline(target("mvp-boilerplate"), [
      finding("M7 — Unbounded select"),
      finding("M7 — State sprawl", "Info"),
      finding("M7 — Client fetch in useEffect"),
      finding("M7 — Client fetch in useEffect"),
      finding("M7 — Nested-loop join"),
      finding("M7 — Missing hook dependencies", "Info"),
    ]);
    expect(rows.find((r) => r.module === "M7")).toMatchObject({ pass: true, actual: 4 });
  });

  it("keeps the #360 diverged-clone pass out of M4's jscpd baseline — shared 'M4 —' prefix, separate modules", () => {
    // Same split rationale as M5-knip/M5-slop: one taxonomy family, two detectors with
    // independent drift profiles. A diverged-clone finding must move ONLY the M4-diverged row.
    const rows = scoreExternalBaseline(target("saas-lite"), [
      finding("M4 — Diverged security-path clone", "High"),
      finding("M4 — Duplication", "Medium"),
    ]);
    expect(rows.find((r) => r.module === "M4")).toMatchObject({ actual: 1 });
    expect(rows.find((r) => r.module === "M4-diverged")).toMatchObject({ actual: 1 });
  });

  it("skips not-run modules instead of scoring them 0 against a baseline", () => {
    // multi-tenant-starter's M8: its only suite spawns a Docker Postgres per mutant, recorded
    // not-run. Scoring the absent findings as 0 would read as "no test-quality problems" — the
    // silent-skip inversion the coverage guard exists to prevent. (Was saas-lite's M5-knip until
    // #544 gave it a measured per-workspace baseline.)
    expect(scoreExternalBaseline(target("multi-tenant-starter"), []).map((r) => r.module)).not.toContain("M8");
  });

  it("scores M5-knip where knip ran, and catches the dead tenant-authz guard going missing", () => {
    // multi-tenant-starter's two knip findings, one of which is #226's security cross-link on real
    // code: `lib/security/guards.ts` exports tenant-authz guards nothing calls, on the repo whose
    // #217 Critical IS a missing-authz bug. If that detection stops firing, a quality module lost
    // the finding that corroborates a Critical — so the baseline must fail, not shrug.
    const dead = (): Finding => finding("M5 — Slop / dead code", "Low");
    expect(scoreExternalBaseline(target("multi-tenant-starter"), [dead(), dead()]).find((r) => r.module === "M5-knip"))
      .toMatchObject({ pass: true, actual: 2 });
    expect(scoreExternalBaseline(target("multi-tenant-starter"), [dead()]).find((r) => r.module === "M5-knip"))
      .toMatchObject({ pass: false, drift: -1 });
  });

  it("#483: M6-indicator counts Info findings — excluding them the way every other module does would score every target's baseline as a permanent 0", () => {
    // handrolled.ts's indicators are severity "Info" by construction (#267's non-grading ruling).
    // The generic countedFor path (severity !== "Info") would read 0 regardless of what the
    // detector actually produced, so the drift check could never fail — the opposite of the point.
    const rows = scoreExternalBaseline(target("boxyhq"), [
      finding("M6 — Indicator: email-shape regex", "Info"),
      finding("M6 — Indicator: cookie serialization", "Info"),
    ]);
    expect(rows.find((r) => r.module === "M6-indicator")).toMatchObject({ pass: true, actual: 2 });
  });

  it("#483: M6-indicator FAILS when the detector stops firing, same as every other counted module", () => {
    const rows = scoreExternalBaseline(target("boxyhq"), []);
    expect(rows.find((r) => r.module === "M6-indicator")).toMatchObject({ pass: false, drift: -2 });
  });

  it("#483: M6-indicator doesn't pick up a lookalike M6 taxonomy that isn't the indicator pass", () => {
    // Namespaced explicitly ("M6 — Indicator: …") rather than by the generic "M6 " prefix so a
    // future non-indicator M6 class (the paid triage tier) can't silently fall into this module.
    const rows = scoreExternalBaseline(target("boxyhq"), [finding("M6 — Some future paid-tier class", "Medium")]);
    expect(rows.find((r) => r.module === "M6-indicator")).toMatchObject({ actual: 0 });
  });

  it("#278: M5-knip and M5-slop don't double-count each other, the bug that started the split", () => {
    // subscription-payments read 18 pre-#278 because both scanners' `M5 —` findings were summed
    // under one key. knip's dead-code finding and detect-static's style findings must land in
    // separate buckets even though they share the "M5 " taxonomy prefix.
    const findings = [
      finding("M5 — Slop / dead code", "Low"), // knip: 1 of subscription-payments' measured 10 (#1128)
      finding("M5 — Else after return", "Low"), // detect-static slop
      finding("M5 — Single-call wrapper", "Low"), // detect-static slop
    ];
    const rows = scoreExternalBaseline(target("subscription-payments"), findings);
    expect(rows.find((r) => r.module === "M5-knip")).toMatchObject({ expected: 10, actual: 1, pass: false });
    expect(rows.find((r) => r.module === "M5-slop")).toMatchObject({ expected: 14, actual: 2, pass: false });
  });
});

// Issue #1564: `scoreExternalBaseline` sizes a drift; `explainDrift` names the rows that
// moved. Reproduces the shape of both 2026-07-30 incidents this exists for — carbon's genuine M7
// regression silenced by an unrelated change, and a mixed M5-slop movement — without either one
// needing a real clone: the "prior run" here is just a second synthetic Finding[] standing in for a
// previous --json output, which is exactly what --baseline-findings supplies in production.
describe("explainDrift (#1564)", () => {
  it("names the exact row REMOVED when a real finding is silenced — the carbon M7 shape", () => {
    // A genuine `M7 — Nested-loop join` at MultiSelect.tsx:153 was present in the prior run and is
    // gone from the current one: a regression, not a precision fix, and the row itself must say so.
    const prior = [finding("M7 — Nested-loop join", "Medium", "packages/react/src/MultiSelect.tsx:153")];
    const current: typeof prior = [];
    const explanation = explainDrift("M7", current, prior);
    expect(explanation.hasBaseline).toBe(true);
    expect(explanation.removed).toEqual([{ location: "packages/react/src/MultiSelect.tsx:153", taxonomy: "M7 — Nested-loop join", severity: "Medium" }]);
    expect(explanation.added).toEqual([]);
  });

  it("names the exact row ADDED on an increase, not just the count", () => {
    const prior = [finding("M9 — Accidental dynamic rendering", "Medium", "app/a.tsx:1")];
    const current = [
      finding("M9 — Accidental dynamic rendering", "Medium", "app/a.tsx:1"),
      finding("M9 — Accidental dynamic rendering", "Medium", "app/b.tsx:9"),
    ];
    const explanation = explainDrift("M9", current, prior);
    expect(explanation.added).toEqual([{ location: "app/b.tsx:9", taxonomy: "M9 — Accidental dynamic rendering", severity: "Medium" }]);
    expect(explanation.removed).toEqual([]);
  });

  it("splits a MIXED movement into its added and removed halves, not one blended count — the M5-slop shape", () => {
    // -653 read as a mass regression; it was actually ~10% wrongly spared (removed, real) plus a
    // majority genuine reclassification (added elsewhere) — a split only the row lists make visible,
    // not the bare count.
    const prior = [
      finding("M5 — Else after return", "Low", "a.ts:1"),
      finding("M5 — Else after return", "Low", "b.ts:2"),
      finding("M5 — Single-call wrapper", "Low", "c.ts:3"),
    ];
    const current = [
      finding("M5 — Else after return", "Low", "a.ts:1"), // unchanged, present both times
      finding("M5 — Single-call wrapper", "Low", "d.ts:4"), // added: a new location
      // b.ts:2 and c.ts:3 are gone: removed
    ];
    const explanation = explainDrift("M5-slop", current, prior);
    expect(explanation.added).toEqual([{ location: "d.ts:4", taxonomy: "M5 — Single-call wrapper", severity: "Low" }]);
    expect(explanation.removed).toEqual([
      { location: "b.ts:2", taxonomy: "M5 — Else after return", severity: "Low" },
      { location: "c.ts:3", taxonomy: "M5 — Single-call wrapper", severity: "Low" },
    ]);
  });

  it("discloses the fallback, rather than a silent empty diff, when no prior snapshot is available", () => {
    // The honest cheapest option (CLAUDE.md's disclosure discipline): with nothing to diff against
    // (no --baseline-findings passed), explainDrift says so via hasBaseline: false and hands back
    // the module's CURRENT findings — never an empty added/removed pair that would read as "nothing
    // moved" when in fact nothing was checked.
    const current = [finding("M7 — Nested-loop join", "Medium", "x.ts:9")];
    const explanation = explainDrift("M7", current, undefined);
    expect(explanation.hasBaseline).toBe(false);
    expect(explanation.added).toEqual([]);
    expect(explanation.removed).toEqual([]);
    expect(explanation.current).toEqual([{ location: "x.ts:9", taxonomy: "M7 — Nested-loop join", severity: "Medium" }]);
  });

  it("respects Info exclusion the same way countedFor does, so an Info-only movement doesn't appear as a real row", () => {
    const prior = [finding("M7 — Missing hook dependencies", "Info", "e.ts:1")];
    const current: typeof prior = [];
    const explanation = explainDrift("M7", current, prior);
    // Info findings are excluded from what M7 counts (#230) — explainDrift must agree with
    // scoreExternalBaseline's own filter or it would "explain" a drift that never scored as one.
    expect(explanation.removed).toEqual([]);
  });

  it("counts M6-indicator's Info findings, same carve-out as countedFor (#483)", () => {
    const prior = [finding("M6 — Indicator: email-shape regex", "Info", "f.ts:1")];
    const current: typeof prior = [];
    const explanation = explainDrift("M6-indicator", current, prior);
    expect(explanation.removed).toEqual([{ location: "f.ts:1", taxonomy: "M6 — Indicator: email-shape regex", severity: "Info" }]);
  });
});

// #300 — M8 is scored as a mutation percentage, not a finding count. These prove the scorer fails
// on real test-quality movement; whether the two scoreable targets still hit their numbers needs
// their cloned trees + Stryker, which is `pnpm corpus-drift --m8` (.github/workflows/corpus-m8.yml).
describe("scoreMutationBaseline (#300)", () => {
  const baseline = (): MutationBaseline => ({ mutationScore: 20, killed: 7, valid: 35, coveredScope: ["lib/server-common.ts"], note: "boxyhq's measured baseline" });

  it("passes when a Stryker run reproduces the recorded kill count", () => {
    expect(scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 20, killed: 7, valid: 35 }))
      .toMatchObject({ pass: true, drift: 0 });
  });

  it("states the covered scope on every drift line so the score never reads as repo-level (#319)", () => {
    // The misrepresentation #319 guards against: "20%" (or "100%") quoted as a whole-repo test-
    // quality claim. Whether it passes or drifts, the scored line must carry the file the score is
    // measured over and the "NOT a whole-repo coverage claim" caveat.
    const pass = scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 20, killed: 7, valid: 35 });
    expect(pass.detail).toContain("lib/server-common.ts");
    expect(pass.detail).toContain("NOT a whole-repo coverage claim");
    const drift = scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 17.1, killed: 6, valid: 35 });
    expect(drift.detail).toContain("lib/server-common.ts");
    expect(drift.detail).toContain("NOT a whole-repo coverage claim");
  });

  it("FAILS when the suite gets worse — a mutant that used to die now survives", () => {
    // The regression M8 exists to catch: someone weakens an assertion and the suite stops
    // detecting a mutation it previously killed.
    const row = scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 17.1, killed: 6, valid: 35 });
    expect(row.pass).toBe(false);
    expect(row.drift).toBe(-1);
    expect(row.detail).toContain("DRIFT");
  });

  it("FAILS on a kill-for-survivor swap that leaves the percentage identical", () => {
    // Why the scorer compares killed/valid and not just the rounded score: 7/35 and 7/35 at a
    // different mutant population is still 20%, but the suite is measuring different code. A
    // percentage-only check would call this green.
    expect(scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 20, killed: 4, valid: 20 }))
      .toMatchObject({ pass: false });
  });

  it("FAILS when the mutant population grows but nothing new is killed", () => {
    // The target's source grew (or Stryker's mutators changed) and the suite didn't follow —
    // real drift in what fraction of the code is actually tested.
    expect(scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 15.6, killed: 7, valid: 45 }))
      .toMatchObject({ pass: false });
  });

  // #432: boxyhq's own spec calls Math.random() (unseeded) to pick generateToken's length, and
  // that random length being even vs odd changes whether one specific mutant survives — measured
  // 2026-07-16/17 as a genuine 7-vs-8-of-35 split across repeated clone+install+Stryker runs, not
  // a one-off. A baseline earns `tolerance` only after being measured flaky like this.
  it("passes within a target's measured tolerance without weakening the default (tolerance 0)", () => {
    const flaky = (): MutationBaseline => ({ ...baseline(), tolerance: 1 });
    expect(scoreMutationBaseline("boxyhq", flaky(), { mutationScore: 22.9, killed: 8, valid: 35 }))
      .toMatchObject({ pass: true, drift: 1 });
    expect(scoreMutationBaseline("boxyhq", flaky(), { mutationScore: 20, killed: 7, valid: 35 }))
      .toMatchObject({ pass: true, drift: 0 });
    // Still fails outside the measured band — tolerance absorbs the observed wobble, not any drift.
    expect(scoreMutationBaseline("boxyhq", flaky(), { mutationScore: 25.7, killed: 9, valid: 35 }))
      .toMatchObject({ pass: false });
    expect(scoreMutationBaseline("boxyhq", flaky(), { mutationScore: 14.3, killed: 5, valid: 35 }))
      .toMatchObject({ pass: false });
    // The default (no tolerance field) is untouched: exact equality still applies to every other
    // baseline, so this fix doesn't quietly loosen drift detection repo-wide.
    expect(scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 22.9, killed: 8, valid: 35 }))
      .toMatchObject({ pass: false });
  });

  // #1419: the inbox-zero case, verbatim. It MEASURED 75.2% (94 detected of 125) in CI while its
  // baseline stores 76% (80/125 killed) — the two move independently because Stryker counts a
  // TIMEOUT as detected but not as killed, which is exactly what `tolerance` is there to absorb.
  // The row printed the BASELINE's 76%, a number that run did not produce.
  it("prints the MEASURED score on a pass, not the baseline's, when the two differ (#1419)", () => {
    const inboxZero = (): MutationBaseline => ({ mutationScore: 76, killed: 80, valid: 125, tolerance: 2, coveredScope: ["apps/web/utils"], note: "inbox-zero's measured baseline" });
    const row = scoreMutationBaseline("inbox-zero", inboxZero(), { mutationScore: 75.2, killed: 80, valid: 125 });
    expect(row.pass).toBe(true);
    expect(row.detail).toContain("MEASURED 75.2%");
    // Both, labelled — the baseline is the thing the run was scored against and must stay legible.
    expect(row.detail).toContain("RECORDED baseline is 76%");
    // The old string is the regression marker: a passing row asserting a percentage as the
    // measurement when it is the baseline's.
    expect(row.detail).not.toContain("matches baseline: 76%");
  });

  it("says `exactly` only when the run reproduced every number, so the two cases are distinguishable", () => {
    const row = scoreMutationBaseline("boxyhq", baseline(), { mutationScore: 20, killed: 7, valid: 35 });
    expect(row.detail).toContain("matches baseline exactly: 20% (7/35 killed)");
    expect(row.detail).not.toContain("RECORDED baseline");
  });

  it("names the measured tolerance in the printed claim so a reader doesn't read the number as exact", () => {
    const flaky = (): MutationBaseline => ({ ...baseline(), tolerance: 1 });
    const row = scoreMutationBaseline("boxyhq", flaky(), { mutationScore: 20, killed: 7, valid: 35 });
    expect(row.detail).toContain("±1 killed");
  });
});

describe("M8 manifest shape (#300)", () => {
  it("gives an m8 Stryker config to exactly the targets carrying a mutation baseline", () => {
    // The two must agree: a config with no baseline means the job scores against nothing, and a
    // baseline with no config means nothing ever measures it. corpus-drift throws on the mismatch;
    // this catches it in `pnpm verify`, before the monthly job would.
    for (const t of EXTERNAL_CORPUS) {
      expect(t.m8 !== undefined, `${t.slug}: m8 config vs baseline`).toBe(isMutationBaseline(t.modules.M8));
    }
    // #1268: inbox-zero and rallly joined — a pnpm-aware install (and, for inbox-zero, disabling
    // the target's own enableGlobalVirtualStore) resolved the pnpm-workspace blocker that used to
    // leave both not-run. #1496: multi-tenant-starter joined through a DIFFERENT mechanism — its
    // own suite still isn't scored (Docker per mutant); m8-corpus.ts's `extraFiles` vendors a
    // separate DB-free suite instead (see its M8 baseline note).
    expect(EXTERNAL_CORPUS.filter((t) => t.m8).map((t) => t.slug).sort()).toEqual(["boxyhq", "inbox-zero", "multi-tenant-starter", "proposit", "rallly"]);
  });

  it("carries a covered scope matching the Stryker mutate config on every mutation baseline (#319)", () => {
    // The denominator that keeps the score honest must be present AND must be the exact files the
    // job mutates — a coveredScope that drifted from the m8 config would describe a scope the
    // score isn't actually over.
    for (const t of EXTERNAL_CORPUS.filter((x) => x.m8)) {
      const m8 = t.modules.M8;
      expect(isMutationBaseline(m8), t.slug).toBe(true);
      if (!isMutationBaseline(m8)) continue;
      expect(m8.coveredScope.length, t.slug).toBeGreaterThan(0);
      expect([...m8.coveredScope].sort(), t.slug).toEqual([...(t.m8!.config.mutate as string[])].sort());
    }
  });

  // #432: boxyhq's baseline earned its tolerance by being measured flaky across repeated runs
  // (see its note); proposit's suite has shown no such instability and keeps the default exact
  // match — a tolerance appearing without a measured reason would be exactly the "defensive slack"
  // CLAUDE.md's doctrine forbids.
  it("only grants a mutation tolerance to a target measured flaky, with the reason in its note", () => {
    const boxyhq = EXTERNAL_CORPUS.find((t) => t.slug === "boxyhq")!.modules.M8;
    expect(isMutationBaseline(boxyhq)).toBe(true);
    if (isMutationBaseline(boxyhq)) {
      expect(boxyhq.tolerance).toBe(1);
      expect(boxyhq.note).toMatch(/Math\.random/);
    }
    const proposit = EXTERNAL_CORPUS.find((t) => t.slug === "proposit")!.modules.M8;
    expect(isMutationBaseline(proposit)).toBe(true);
    if (isMutationBaseline(proposit)) expect(proposit.tolerance).toBeUndefined();
  });

  it("keeps a measured reason on every M8 that mutation testing does not score", () => {
    // The coverage guard on the module #300 is specifically about: the two blocked targets and the
    // two zero-test ones must each say WHY they aren't a mutation score — never omitted, never a 0.
    for (const t of EXTERNAL_CORPUS.filter((x) => !x.m8)) {
      const m8 = t.modules.M8;
      if (isNotRun(m8)) expect(m8.reason.length, t.slug).toBeGreaterThan(20);
      else expect(m8.note, t.slug).toMatch(/zero-coverage finding/);
    }
  });

  it("does not let a mutation baseline be counted as findings by the source-tier scorer", () => {
    // A MutationBaseline's numbers are percentages/mutant counts. If scoreExternalBaseline ever
    // starts counting M8 findings against one, it would score proposit's 100 as "100 findings
    // expected, 0 found" — a fabricated drift on a module that measured perfectly.
    expect(scoreExternalBaseline(target("proposit"), []).map((r) => r.module)).not.toContain("M8");
  });

  it("still scores the zero-test targets by finding count — #224's finding IS the measurement", () => {
    // The other half of the split: where a target has no suite at all, M8 is a plain ModuleBaseline
    // and must keep being scored from findings, not skipped along with the mutation ones.
    const zeroCoverage = finding("M8 — No automated test suite", "High");
    expect(scoreExternalBaseline(target("subscription-payments"), [zeroCoverage]).find((r) => r.module === "M8"))
      .toMatchObject({ pass: true, actual: 1 });
  });

  it("keeps detect-static's test-intent findings out of the mutation-tier M8 count — shared 'M8 —' prefix, separate modules", () => {
    // The #372 test-intent detectors and the mutation tier (M8-00 suite-absent, M8-01 stub-check,
    // M8-02 surviving mutants) are different measurements. Before the split, a test-intent finding
    // moved the M8 finding-count baseline (and falsely flagged mutation not-run reasons as stale —
    // the 2026-07-17 saas-lite drift failure).
    const rows = scoreExternalBaseline(target("subscription-payments"), [
      finding("M8 — No automated test suite", "High"),
      finding("M8 — Happy-path-only tests on security-critical code", "Medium"),
    ]);
    expect(rows.find((r) => r.module === "M8")).toMatchObject({ actual: 1 });
    expect(rows.find((r) => r.module === "M8-intent")).toMatchObject({ actual: 1 });
  });

  it("scores the mutation tier's measurement-gap findings as M8, not M8-intent (#940)", () => {
    // #932's "Root-workspace test suite not reachable per-app" and #503's env-fragile-suite finding
    // are mutation-tier (mutation-scan/stub-check) findings. Because M8-intent is defined by
    // exclusion from M8_MUTATION_TAXONOMIES, a mutation-tier taxonomy missing from that set leaks
    // into M8-intent — which is exactly the documenso drift #940 fixed: its M8 measurement-gap scored
    // 0 as M8 (baseline 1) and inflated M8-intent to 2 (baseline 1). documenso's M8/M8-intent are
    // both counted:1, so with the mutation finding correctly attributed the two rows reproduce.
    const rows = scoreExternalBaseline(target("documenso"), [
      finding("M8 — Root-workspace test suite not reachable per-app", "Medium"),
      finding("M8 — Call-count-only test", "Low"),
    ]);
    expect(rows.find((r) => r.module === "M8")).toMatchObject({ actual: 1, pass: true });
    expect(rows.find((r) => r.module === "M8-intent")).toMatchObject({ actual: 1, pass: true });
  });
});

// #322 — per-module scan roots. The mechanism must never let two modules' numbers describe
// different trees silently: a target that declares any scan root gets the scanned scope stamped
// on every scored row.
describe("per-module scan roots (#322)", () => {
  it("records mvp-boilerplate's M5-knip root in the manifest — the only per-module root today", () => {
    expect(target("mvp-boilerplate").scanRoots).toEqual({ "M5-knip": "nextjs" });
    for (const t of EXTERNAL_CORPUS.filter((x) => x.slug !== "mvp-boilerplate")) {
      expect(t.scanRoots, t.slug).toBeUndefined();
    }
  });

  it("stamps the scanned scope on every row of a target whose modules disagree on scope", () => {
    const rows = scoreExternalBaseline(target("mvp-boilerplate"), []);
    const knip = rows.find((r) => r.module === "M5-knip")!;
    expect(knip.scope).toBe("nextjs");
    expect(knip.detail).toContain("scanned scope: nextjs");
    const m4 = rows.find((r) => r.module === "M4")!;
    expect(m4.scope).toBe("whole-repo");
    expect(m4.detail).toContain("scanned scope: whole-repo");
  });

  it("leaves scope out of the detail on targets whose modules all scan the same tree", () => {
    const rows = scoreExternalBaseline(target("proposit"), []);
    expect(rows.every((r) => r.scope === "whole-repo")).toBe(true);
    expect(rows.every((r) => !r.detail.includes("scanned scope"))).toBe(true);
  });
});

// #321 — the standard drift pass re-attempts every source-tier module each run; these prove the
// re-validation notices when a not-run reason has stopped being true (the module now produces real
// findings), and stays quiet while the reason still holds. The signature defect this closes: a
// stale excuse silently costing coverage that only someone stumbling into it would catch.
describe("revalidateNotRunReasons (#321)", () => {
  // saas-lite records M8 not-run — every test file it ships is a Playwright E2E spec, so there is
  // no unit suite for Stryker to mutate at all (#1436's M8_E2E_ONLY_SUITE). (multi-tenant-starter,
  // this block's prior example, gained a real mutation baseline under #1496 — a vendored, DB-free
  // suite, not its own Docker-dependent one — so it no longer records M8 not-run.)
  const notRunTarget = (): ExternalTarget => {
    const t = EXTERNAL_CORPUS.find((x) => x.slug === "saas-lite");
    if (!t || !isNotRun(t.modules.M8!)) throw new Error("saas-lite/M8 is expected to be recorded not-run");
    return t;
  };
  const m8Finding = (id: string): Finding => ({ ...finding("M8 — Survives implementation deletion", "Medium"), id });

  it("stays quiet while the reason holds — mutation-scan still emits only its #224 M8-00 did-not-run finding", () => {
    // The sentinel is the tool saying it STILL couldn't run; it must not read as the module working.
    const rows = revalidateNotRunReasons(notRunTarget(), [{ ...finding("M8 — No automated test suite", "High"), id: "M8-00" }]);
    expect(rows).toEqual([]);
  });

  it("stays quiet when nothing at all was produced for the not-run module", () => {
    expect(revalidateNotRunReasons(notRunTarget(), [])).toEqual([]);
  });

  it("fails loud when the not-run module produces real findings — the reason has decayed", () => {
    const rows = revalidateNotRunReasons(notRunTarget(), [m8Finding("M8-42"), m8Finding("M8-43")]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ module: "M8", pass: false, actual: 2 });
    expect(rows[0]?.detail).toContain("STALE");
  });

  it("does not fire on a target whose modules all ran — nothing to re-validate", () => {
    expect(revalidateNotRunReasons(target("subscription-payments"), [m8Finding("M8-07")])).toEqual([]);
  });

  it("stays quiet when M4 emits only its #505/#931 M4-99 did-not-complete disclosure", () => {
    // #948 fixed the cwd/path-relativity bug that made documenso — this test's original real-world
    // example — record M4 not-run (it now has a real 835/1256 baseline instead, see external-corpus.ts).
    // The mechanism this test guards is general, not specific to that one target: an M4-99-only
    // production is the tool saying it STILL couldn't complete, and must not read as M4 having run
    // and decay the not-run reason. A synthetic not-run target keeps that guard alive independent of
    // any one corpus baseline's measured state.
    const notRunM4: ExternalTarget = {
      slug: "synthetic-m4-not-run",
      repo: "example/example",
      commit: "0000000000000000000000000000000000000",
      license: "MIT",
      provenance: "professional",
      provenanceNote: "synthetic fixture for this test only",
      securityVerdict: "n/a",
      modules: {
        M4: { reason: "jscpd could not complete on this scope (synthetic fixture)", falsifier: "false" },
        M8: { reason: "not exercised by this fixture", falsifier: "false" },
        "M1-boundary": { reason: "not exercised by this fixture", falsifier: "false" },
      },
    };
    expect(isNotRun(notRunM4.modules.M4!)).toBe(true);
    const m499: Finding = { ...finding("M4 — Duplication", "Info"), id: "M4-99" };
    expect(revalidateNotRunReasons(notRunM4, [m499]).filter((r) => r.module === "M4")).toEqual([]);
  });

  it("does not read a test-intent finding as evidence against an M8 MUTATION not-run reason", () => {
    // The 2026-07-17 false alarm: saas-lite's M8 mutation tier is not-run (E2E-only suite), and
    // detect-static's #372 test-intent pass produced a real "M8 —" finding — a different
    // measurement that says nothing about whether Stryker can run. The M8/M8-intent split keeps
    // it from decaying the mutation reason.
    const t = EXTERNAL_CORPUS.find((x) => x.slug === "saas-lite")!;
    expect(isNotRun(t.modules.M8)).toBe(true);
    const intent = finding("M8 — Happy-path-only tests on security-critical code", "Medium");
    expect(revalidateNotRunReasons(t, [intent]).filter((r) => r.module === "M8")).toEqual([]);
  });
});

// #261/#227 — the free-tier calibration invariant. These prove the SCORER: that it fails when the
// free tier cries wolf or stays quiet. Whether the four real repos actually land on the right side
// of it is not knowable here (it needs their cloned trees) — that's `pnpm corpus-drift`, which ran
// green on all four at these baselines on 2026-07-15.
const expectation = (slug: string): FreeTierExpectation => {
  const e = FREE_TIER_EXPECTATIONS.find((x) => x.slug === slug);
  if (!e) throw new Error(`no free-tier expectation for ${slug}`);
  return e;
};

// An indicator is a review-tier "Multi-tenant security" finding (selectIndicators, #220).
const rlsIndicator = (severity: Severity): Finding => ({
  ...finding("M1 — RLS policy semantic tenancy review", severity),
  category: "Multi-tenant security",
  precisionTier: "review",
});

describe("free-tier calibration invariant (#261)", () => {
  it("covers exactly #227's four named repos, #934's scale case and #1473's graded-channel case, each pinned in the corpus", () => {
    // The invariant is defined against these targets by name; a target quietly dropped from the
    // list is the check silently shrinking. launch-mvp joined on 2026-07-31 (#1473) — it is the
    // corpus's clearest known-vulnerable member and sat outside this gate until `mustBeLoud` could
    // express a promise the indicator channel does not carry.
    expect(FREE_TIER_EXPECTATIONS.map((e) => e.slug).sort()).toEqual(["carbon", "launch-mvp", "multi-tenant-starter", "mvp-boilerplate", "proposit", "saas-lite"]);
    for (const e of FREE_TIER_EXPECTATIONS) {
      expect(EXTERNAL_CORPUS.some((t) => t.slug === e.slug), e.slug).toBe(true);
    }
  });

  it("FAILS when the free tier cries wolf — an F on a repo #227 calls sound", () => {
    const graded: Finding = { ...finding("M1 — Leaked service-role key", "Critical"), precisionTier: "high" };
    const report = buildQuickScanReport([graded]);
    expect(report.grade).toBe("F");
    const rows = scoreFreeTierExpectation(expectation("mvp-boilerplate"), report);
    const f = rows.find((r) => r.check === "must not score F")!;
    expect(f.pass).toBe(false);
    expect(f.detail).toContain("CRIED WOLF");
  });

  it("FAILS when the free tier accuses a sound repo of a tenancy hole", () => {
    const rows = scoreFreeTierExpectation(expectation("saas-lite"), buildQuickScanReport([rlsIndicator("High")]));
    const f = rows.find((r) => r.check.startsWith("must not accuse"))!;
    expect(f.pass).toBe(false);
    expect(f.detail).toContain("CRIED WOLF");
  });

  it("FAILS when the free tier stays quiet on a known-vulnerable repo", () => {
    // multi-tenant-starter's #217 Critical (any authed user self-joins any tenant as owner) must
    // have SOME free-tier signal. Silence here is the promise broken.
    const rows = scoreFreeTierExpectation(expectation("multi-tenant-starter"), buildQuickScanReport([]));
    const f = rows.find((r) => r.check.startsWith("must raise"))!;
    expect(f.pass).toBe(false);
    expect(f.detail).toContain("STAYED QUIET");
  });

  it("does not accept the Info-severity tenancy disclosure as the loud signal", () => {
    // Every target with migrations draws the Info "Tenancy model assumed" note (#220). If that
    // counted as raising the alarm, the two known-vulnerable repos would pass on a note that says
    // nothing about them — the invariant would be self-satisfying.
    const rows = scoreFreeTierExpectation(expectation("proposit"), buildQuickScanReport([rlsIndicator("Info")]));
    expect(rows.find((r) => r.check.startsWith("must raise"))).toMatchObject({ pass: false });
    expect(scoreFreeTierExpectation(expectation("proposit"), buildQuickScanReport([rlsIndicator("High")]))
      .find((r) => r.check.startsWith("must raise"))).toMatchObject({ pass: true });
  });

  it("does not grade the known-vulnerable repos — their Critical is an indicator, never a hygiene verdict", () => {
    // #213/#220: a review-tier indicator must not move the grade. So the invariant deliberately
    // makes no grade claim for these two, and asserting one would re-create the #213 inversion.
    for (const slug of ["multi-tenant-starter", "proposit"]) {
      expect(expectation(slug).mustNotScoreF, slug).toBe(false);
    }
    const report = buildQuickScanReport([rlsIndicator("Critical")]);
    expect(report.grade).toBe("A");
  });
});

// #934 — the scale additions to the scorer: the doc-context credential invariant (two-sided) and
// the explicit not-asserted indicator-posture row.
describe("free-tier doc-context credential invariant (#934)", () => {
  const docCred = (id: string): Finding => ({
    ...finding(id, "Low"),
    category: "Secret exposure",
    taxonomy: DOC_CONTEXT_CREDENTIAL_TAXONOMY,
    precisionTier: "high",
  });

  it("passes when doc-context creds are reported informational and none is graded", () => {
    const rows = scoreFreeTierExpectation(expectation("carbon"), buildQuickScanReport([docCred("GL-1"), docCred("GL-2")]));
    const r = rows.find((x) => x.check.startsWith("doc/example"))!;
    expect(r.pass).toBe(true);
    expect(r.detail).toContain("2 doc-context credential(s)");
  });

  it("FAILS when a doc-context cred reaches the graded set — the reclassification regressed", () => {
    // Simulate a regression: same taxonomy but marked exploitability-verified, which grades it.
    const regressed = { ...docCred("GL-1"), exploitabilityVerified: true };
    const rows = scoreFreeTierExpectation(expectation("carbon"), buildQuickScanReport([regressed]));
    expect(rows.find((x) => x.check.startsWith("doc/example"))).toMatchObject({ pass: false });
  });

  it("FAILS when zero doc-context creds are reported on a pinned tree known to contain them", () => {
    // A lost finding is a recall regression, not a cleaner repo — the tree is frozen at the pin.
    const rows = scoreFreeTierExpectation(expectation("carbon"), buildQuickScanReport([]));
    const r = rows.find((x) => x.check.startsWith("doc/example"))!;
    expect(r.pass).toBe(false);
    expect(r.detail).toContain("GONE DARK");
  });

  it("emits an explicit not-asserted indicator-posture row instead of silently scoring one fewer check", () => {
    const rows = scoreFreeTierExpectation(expectation("carbon"), buildQuickScanReport([docCred("GL-1")]));
    const r = rows.find((x) => x.check === "indicator posture")!;
    expect(r.pass).toBe(true);
    expect(r.detail).toContain("not asserted");
  });
});

// M10's answer key on REAL swept columns. The sweep's #233 triage found the module both over- and
// under-matching; these lock in each verdict against the columns that produced it.
describe("M10 classifier on real external-corpus columns (#233)", () => {
  it("flags proposit's plaintext per-tenant secrets — the must-not-miss headline finding", () => {
    // organisations.ai_api_key / smtp_pass are stored plaintext and readable by ANY org member
    // via normal RLS `SELECT *`. Per #233 this must outrank the contact PII in the report.
    expect(classifyColumn("ai_api_key", "text", "organisations")).toMatchObject({ category: "SECRET", confidence: "high" });
    expect(classifyColumn("smtp_pass", "text", "organisations")).toMatchObject({ category: "SECRET", confidence: "high" });
  });

  it("catches boxyhq's opaquely-named encrypted secret store", () => {
    // jackson_store.value holds BoxyHQ SAML/SSO config including IdP secrets — a name-only
    // matcher skips a column called `value`, which is exactly what #233 fixed.
    expect(classifyColumn("value", "text", "jackson_store")).toMatchObject({ category: "SECRET" });
  });

  it("does not call an org's own name personal PII (the #233 over-match)", () => {
    expect(classifyColumn("name", "text", "organisations")).toBeNull();
  });

  it("does not call a capability token a stored credential (the #233 over-match)", () => {
    // Invite / share-link / reset tokens are capabilities, not secrets at rest.
    expect(classifyColumn("token", "text", "organisation_invitations")).toBeNull();
  });

  it("still classifies genuine contact PII on the same repos", () => {
    expect(classifyColumn("email", "text", "profiles")).toMatchObject({ infotype: "EMAIL", category: "PII" });
  });
});

// #279: m10FindingsFromSchema is the adapter corpus-drift.ts feeds real cloned migrations
// through — no network needed here, a minimal inline schema proves the shaping is right.
describe("m10FindingsFromSchema (#279)", () => {
  const SCHEMA = `
    create table organisations (
      id uuid,
      ai_api_key text,
      name text
    );
    create table widgets (
      id uuid,
      color text
    );
  `;

  it("emits one Finding per table with a classified column, at that table's severity", () => {
    // organisations.name is excluded (the #233 org-entity-table suppression), leaving only
    // ai_api_key: SECRET/high scores 6 -> "High" (scoreToSeverity's >=4 band).
    const findings = m10FindingsFromSchema(SCHEMA);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      taxonomy: "M10 — Data classification",
      location: "organisations",
      severity: "High",
    });
  });

  it("never emits a table with zero classified columns", () => {
    // widgets has no PII/PHI/PCI/SECRET column — must not appear at all, not as a 0/Info finding.
    const findings = m10FindingsFromSchema(SCHEMA);
    expect(findings.some((f) => f.location === "widgets")).toBe(false);
  });

  it("is scoreExternalBaseline-countable: severity is never Info", () => {
    // buildDataMap's lowest possible score (one low-confidence match) is 0.3 -> "Low", never
    // "Info" — so counted === total for every M10 baseline in the manifest, by construction.
    const ambiguous = `
      create table proposals (
        id uuid,
        name text
      );
    `;
    const findings = m10FindingsFromSchema(ambiguous);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).not.toBe("Info");
  });
});

// #1473 — the "don't stay quiet" promise, split from the one CHANNEL it used to be scored on.
//
// launch-mvp is the target that separated them. MEASURED 2026-07-28 against
// ShenSeanChen/launch-mvp-stripe-nextjs-supabase @ 513a8f0 via
// `buildQuickScanReport(await runMechanicalScan({ dir }))`: grade F (51/100), 0 indicators, graded
// set 4 High + 1 Low — three of the Highs being #774's unauthenticated service-role account-deletion
// route, which is Confirmed and category "Broken access control", so it is graded and never reaches
// the review-tier indicator channel. Under the old field ALL THREE possible values produced a false
// statement about that repo, which is why it sits outside this gate today.
//
// These prove the SCORER, not the repos — whether the real trees land on the right side of it is
// `pnpm corpus-drift`'s job. The planted target below is a REPORT shaped exactly like launch-mvp's
// measurement, so a regression that re-conflates the channels fails here.
describe("free-tier loudness invariant is channel-agnostic and can fail (#1473)", () => {
  const gradedHigh: Finding = { ...finding("M1 — Object-level authorization", "High"), category: "Broken access control", precisionTier: "high" };
  const loudLike = (over: Partial<FreeTierExpectation> = {}): FreeTierExpectation => ({ slug: "planted", mustNotScoreF: false, why: "planted for the #1473 scorer proof", ...over });

  // launch-mvp's shape: loud in the graded set, silent in the indicator channel.
  const gradedOnly = buildQuickScanReport([gradedHigh, gradedHigh, gradedHigh]);
  // multi-tenant-starter's shape: the reverse.
  const indicatorOnly = buildQuickScanReport([rlsIndicator("High")]);

  it("the planted target reproduces launch-mvp's measurement: loud graded, zero indicators", () => {
    expect(gradedOnly.findings.filter((f) => f.severity === "High")).toHaveLength(3);
    expect(gradedOnly.indicators).toHaveLength(0);
    // Not asserting the letter: the point is that the graded channel carries real Highs while the
    // indicator channel is empty — the split the old single field could not express.
    expect(gradedOnly.grade).not.toBe("A");
  });

  it("PASSES on the graded channel where mustRaiseLoudIndicator could only produce a false statement", () => {
    const row = scoreFreeTierExpectation(loudLike({ mustBeLoud: "graded" }), gradedOnly).find((r) => r.check.startsWith("must be loud"))!;
    expect(row.pass).toBe(true);
    expect(row.detail).toContain("graded channel LOUD");
    expect(row.detail).toContain("indicator channel quiet");
    // The sentence the old field would have printed about this exact report.
    expect(row.detail).not.toContain("STAYED QUIET");
  });

  it("FAILS — planted: a known-vulnerable target whose asserted channel carries nothing", () => {
    // The proof the invariant can be false. The same target, asserted on the channel that is silent.
    const row = scoreFreeTierExpectation(loudLike({ mustBeLoud: "indicator" }), gradedOnly).find((r) => r.check.startsWith("must be loud"))!;
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("STAYED QUIET");
    expect(row.detail).toContain('the "indicator" channel carried nothing');
  });

  it("FAILS when the free tier goes silent on BOTH channels — the promise itself broken", () => {
    const row = scoreFreeTierExpectation(loudLike({ mustBeLoud: "either" }), buildQuickScanReport([])).find((r) => r.check.startsWith("must be loud"))!;
    expect(row.pass).toBe(false);
    expect(row.detail).toContain("graded channel quiet");
    expect(row.detail).toContain("indicator channel quiet");
  });

  it('"either" accepts whichever channel actually carried it, and names it', () => {
    for (const report of [gradedOnly, indicatorOnly]) {
      expect(scoreFreeTierExpectation(loudLike({ mustBeLoud: "either" }), report).find((r) => r.check.startsWith("must be loud"))!.pass).toBe(true);
    }
    expect(scoreFreeTierExpectation(loudLike({ mustBeLoud: "either" }), indicatorOnly).find((r) => r.check.startsWith("must be loud"))!.detail).toContain("indicator channel LOUD");
  });

  it("does not accept an informational-only report as loud — that IS staying quiet", () => {
    // #213: the informational section is seen-and-reported-but-not-graded BY DESIGN. If it counted,
    // any target with a placeholder credential in its docs would satisfy the promise (carbon's shape).
    const informationalOnly = buildQuickScanReport([{ ...finding("M1 — Doc-context credential", "Low"), taxonomy: DOC_CONTEXT_CREDENTIAL_TAXONOMY, category: "Secret exposure", precisionTier: "high" }]);
    expect(informationalOnly.findings).toHaveLength(0);
    expect(scoreFreeTierExpectation(loudLike({ mustBeLoud: "either" }), informationalOnly).find((r) => r.check.startsWith("must be loud"))!.pass).toBe(false);
  });

  it("stops calling a target's posture NOT ASSESSED once mustBeLoud asserts it (#934's row, corrected)", () => {
    const row = scoreFreeTierExpectation(loudLike({ mustBeLoud: "graded" }), gradedOnly).find((r) => r.check === "indicator posture")!;
    expect(row.pass).toBe(true);
    expect(row.detail).not.toContain("NOT ASSESSED");
    expect(row.detail).toContain('asserted on the "graded" channel');
    // carbon's genuinely-unasserted posture keeps the original wording.
    expect(scoreFreeTierExpectation(expectation("carbon"), gradedOnly).find((r) => r.check === "indicator posture")!.detail).toContain("NOT ASSESSED");
  });

  it("leaves every PRE-EXISTING corpus row scored exactly as before — the new field is opt-in", () => {
    // launch-mvp is the one row that opted IN (#1473's whole point); every other row predates the
    // field and must not have quietly gained an assertion nobody measured.
    for (const e of FREE_TIER_EXPECTATIONS.filter((x) => x.slug !== "launch-mvp")) {
      expect(e.mustBeLoud, `${e.slug} predates #1473 and must not have gained an unmeasured assertion`).toBeUndefined();
      expect(scoreFreeTierExpectation(e, gradedOnly).some((r) => r.check.startsWith("must be loud")), e.slug).toBe(false);
    }
  });

  // #1473's mechanism was shipped with a PLANTED control and no corpus row, so nothing tied it to a
  // real repo. These three do — and the third is the one that makes the row mean something: it is
  // the exact regression launch-mvp was pinned to catch.
  describe("launch-mvp is the row the mechanism exists for", () => {
    const launchMvp = (): FreeTierExpectation => expectation("launch-mvp");

    it('asserts the GRADED channel, and makes no "must not score F" claim about a repo that should grade badly', () => {
      expect(launchMvp().mustBeLoud).toBe("graded");
      expect(launchMvp().mustNotScoreF).toBe(false);
      expect(launchMvp().mustRaiseLoudIndicator).toBeUndefined();
      expect(launchMvp().why).toContain("F (51/100)");
    });

    it("PASSES on its measured shape: graded loud, indicator channel empty", () => {
      // The report below reproduces the 2026-07-31 measurement of the pinned tree — 4 graded Highs,
      // 0 indicators — not a convenient synthetic one.
      const measured = buildQuickScanReport([gradedHigh, gradedHigh, gradedHigh, { ...gradedHigh, id: "cors", severity: "High" }]);
      expect(measured.indicators).toHaveLength(0);
      const row = scoreFreeTierExpectation(launchMvp(), measured).find((r) => r.check.startsWith("must be loud"))!;
      expect(row.pass).toBe(true);
      expect(row.detail).toContain("graded channel LOUD");
      const posture = scoreFreeTierExpectation(launchMvp(), measured).find((r) => r.check === "indicator posture")!;
      expect(posture.detail).not.toContain("NOT ASSESSED");
    });

    it("FAILS if the object-level-authz Highs stop firing — the regression this target was pinned for", () => {
      // The same scan on the 2026-07-26 scanner emitted ZERO of these rows (#1174). If they go dark
      // again, the free tier is silent on two unauthenticated service-role Criticals and this row is
      // what says so.
      const withoutAuthzHighs = buildQuickScanReport([{ ...gradedHigh, severity: "Low" }]);
      const row = scoreFreeTierExpectation(launchMvp(), withoutAuthzHighs).find((r) => r.check.startsWith("must be loud"))!;
      expect(row.pass).toBe(false);
      expect(row.detail).toContain("STAYED QUIET");
    });
  });
});

// #1436 — a not-run reason is a claim, and the two M8 reasons this issue names were dated MEASURED,
// well-written, invisible to `pnpm validate-reasons --revalidate`, and described conditions (a suite
// gaining container reuse, a repo gaining a unit suite) that resolve UPSTREAM with nothing here
// noticing. `ModuleNotRun.falsifier` is what the type now demands; this block is what keeps the
// registry BLOCK — the half `--revalidate` actually reads — attached to it. A comment can be deleted
// while the object survives, and then the module is silently unwatched again.
describe("#1436 — every recorded not-run carries a falsifier the reason registry can see", () => {
  const source = readFileSync(new URL("./external-corpus.ts", import.meta.url), "utf8");
  const blocks = parseRecordedReasons(source, "src/scan/external-corpus.ts");
  const notRuns = EXTERNAL_CORPUS.flatMap((t) =>
    Object.entries(t.modules)
      .filter(([, m]) => m !== undefined && isNotRun(m))
      .map(([module, m]) => ({ slug: t.slug, module, notRun: m as { reason: string; falsifier: string } })),
  );

  it("finds the not-runs this test exists to watch, so it cannot pass by scoring an empty set", () => {
    // #1496: multi-tenant-starter/M8 left this list — it now carries a real MutationBaseline (a
    // vendored, DB-free suite), not a not-run reason. saas-lite and carbon still have no scoreable
    // suite at all and remain the population this test watches.
    //
    // #1693: this floor tracks the LIVE population — MEASURED 2026-07-31 at 6 (saas-lite,
    // ghostfolio, carbon, tanstack-com, cravab, flori-web), and #1499 set it at exactly the
    // population of the day (5 of 5) rather than leaving slack. It was briefly dropped to 4, which
    // would have let two not-runs silently stop being watched. When a reason is retired, drop this
    // by one in the same commit; when one is added, raise it.
    expect(notRuns.length).toBeGreaterThanOrEqual(6);
    expect(notRuns.map((n) => `${n.slug}/${n.module}`)).toContain("saas-lite/M8");
    expect(notRuns.map((n) => `${n.slug}/${n.module}`)).toContain("carbon/M8");
  });

  it("every not-run's falsifier appears verbatim as a FALSIFIER: in a well-formed block in the same file", () => {
    const falsifiersInBlocks = new Set(blocks.map((b) => b.fields.FALSIFIER).filter((f) => f !== undefined));
    for (const { slug, module, notRun } of notRuns) {
      expect(notRun.falsifier, `${slug}/${module} has an empty falsifier`).not.toBe("");
      expect(falsifiersInBlocks, `${slug}/${module}'s falsifier is on the object but in no REASON block — --revalidate would never run it`).toContain(notRun.falsifier);
    }
    for (const b of blocks) expect(validateRecordedReason(b, () => true), `block at line ${b.line}`).toEqual([]);
  });

  // The contract is one-way and easy to get backwards: NON-ZERO means the blocker holds, 0 means it
  // is GONE, 127 means the re-test could not run at all. #1426 found seven falsifiers where a bare
  // `grep` (exit 2) or a broken pipe (exit 1) read as "still blocked" by accident. Every command here
  // therefore ends in an explicit `exit 0` / `exit 1` and opens with a `command -v` / `test -f` guard
  // that exits 127. Asserted structurally rather than by running them — three need the network.
  it("every falsifier ends in explicit exits and guards its own prerequisites with 127", () => {
    for (const { slug, module, notRun } of notRuns) {
      expect(notRun.falsifier, `${slug}/${module}`).toContain("exit 127");
      expect(notRun.falsifier, `${slug}/${module}`).toContain("exit 0");
      expect(notRun.falsifier, `${slug}/${module}`).toContain("exit 1");
    }
  });

  // The negative control: the tie between object and block must be able to FAIL. Delete the block a
  // not-run's falsifier lives in and the check must notice — otherwise this whole describe is
  // decorative, which is the shape #1436 exists to end.
  it("FAILS when the block a not-run's falsifier lives in is deleted", () => {
    const victim = notRuns.find((n) => n.slug === "saas-lite" && n.module === "M8")!;
    const gutted = source.split("\n").filter((l) => !l.includes(`FALSIFIER: ${victim.notRun.falsifier.slice(0, 40)}`)).join("\n");
    const stillThere = new Set(parseRecordedReasons(gutted, "x").map((b) => b.fields.FALSIFIER));
    expect(stillThere.has(victim.notRun.falsifier), "removing the FALSIFIER: line must break the tie").toBe(false);
  });
});
