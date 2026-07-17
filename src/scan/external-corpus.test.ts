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

import { describe, expect, it } from "vitest";
import { classifyColumn } from "../../tools/pii-classify.mjs";
import {
  EXTERNAL_CORPUS,
  FREE_TIER_EXPECTATIONS,
  isMutationBaseline,
  isNotRun,
  m10FindingsFromSchema,
  revalidateNotRunReasons,
  scoreExternalBaseline,
  scoreFreeTierExpectation,
  scoreMutationBaseline,
  type ExternalTarget,
  type FreeTierExpectation,
  type MutationBaseline,
} from "./external-corpus.js";
import { buildQuickScanReport } from "../quick-scan.js";
import type { Finding, Severity } from "../findings.js";

function finding(taxonomy: string, severity: Severity = "Perf"): Finding {
  return {
    id: "X", title: "", severity, confidence: "Confirmed", category: "", taxonomy,
    location: "app/page.tsx:1", status: "Open", evidence: "", impact: "", fix: "",
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

  it("records M5-knip as unrun on every target where knip could not resolve the config", () => {
    // knip without the target's `npm install` yields a knip-FAILED artifact, not a dead-code
    // measurement (#223) — recorded not-run, never a zero that would read as "no dead code".
    // Which targets those are is MEASURED, not assumed. #251 added the install step the CLAUDE.md
    // M5 row calls for, which took this from 2 scored to 4: the two that remain unrun now fail for
    // reasons no install can fix (saas-lite's eslint-config-next patch error, mvp-boilerplate's
    // missing root package.json), each measured 2026-07-15.
    const scored = EXTERNAL_CORPUS.filter((t) => !isNotRun(t.modules["M5-knip"]!)).map((t) => t.slug);
    expect(scored.sort()).toEqual(["boxyhq", "multi-tenant-starter", "proposit", "subscription-payments"]);
    for (const t of EXTERNAL_CORPUS.filter((x) => !scored.includes(x.slug))) {
      expect(isNotRun(t.modules["M5-knip"]!), t.slug).toBe(true);
    }
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
});

describe("scoreExternalBaseline", () => {
  it("passes when a scan reproduces the recorded counted total", () => {
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), [
      finding("M9 — Accidental dynamic rendering"),
      finding("M9 — Accidental dynamic rendering"),
      finding("M9 — Data-fetching waterfall"),
    ]);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: true, actual: 3, drift: 0 });
  });

  it("FAILS on a new over-match — the regression this corpus exists to catch", () => {
    // boxyhq is a Pages Router app: #231 requires the App-Router checks to stay silent. A single
    // M9 finding here is the pre-#231 misfire coming back.
    const rows = scoreExternalBaseline(target("boxyhq"), [finding("M9 — Accidental dynamic rendering")]);
    const m9 = rows.find((r) => r.module === "M9")!;
    expect(m9.pass).toBe(false);
    expect(m9.drift).toBe(1);
    expect(m9.detail).toContain("DRIFT +1");
  });

  it("FAILS when a real detection stops firing", () => {
    const rows = scoreExternalBaseline(target("multi-tenant-starter"), []);
    expect(rows.find((r) => r.module === "M9")).toMatchObject({ pass: false, drift: -3 });
  });

  it("ignores Info findings, so the demoted exhaustive-deps class can't re-enter the count", () => {
    // #230 demoted exhaustive-deps to Info rather than deleting it. If a future change promotes
    // it back to a graded severity, proposit's M7 jumps 49 -> 79 and this scorer must catch it.
    const rows = scoreExternalBaseline(target("mvp-boilerplate"), [
      finding("M7 — Unbounded select"),
      finding("M7 — Index used as list key"),
      finding("M7 — State sprawl"),
      finding("M7 — Missing hook dependencies", "Info"),
    ]);
    expect(rows.find((r) => r.module === "M7")).toMatchObject({ pass: true, actual: 3 });
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
    // saas-lite's M5-knip: knip dies loading the target's eslint config, so there is no dead-code
    // measurement to compare. Scoring the absent findings as 0 would read as "no dead code" —
    // the silent-skip inversion the coverage guard exists to prevent. (Was proposit until #251's
    // install step gave proposit a real baseline.)
    expect(scoreExternalBaseline(target("saas-lite"), []).map((r) => r.module)).not.toContain("M5-knip");
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

  it("#278: M5-knip and M5-slop don't double-count each other, the bug that started the split", () => {
    // subscription-payments read 18 pre-#278 because both scanners' `M5 —` findings were summed
    // under one key. knip's dead-code finding and detect-static's style findings must land in
    // separate buckets even though they share the "M5 " taxonomy prefix.
    const findings = [
      finding("M5 — Slop / dead code", "Low"), // knip: 1 of subscription-payments' measured 8
      finding("M5 — Else after return", "Low"), // detect-static slop
      finding("M5 — Single-call wrapper", "Low"), // detect-static slop
    ];
    const rows = scoreExternalBaseline(target("subscription-payments"), findings);
    expect(rows.find((r) => r.module === "M5-knip")).toMatchObject({ expected: 8, actual: 1, pass: false });
    expect(rows.find((r) => r.module === "M5-slop")).toMatchObject({ expected: 10, actual: 2, pass: false });
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
});

describe("M8 manifest shape (#300)", () => {
  it("gives an m8 Stryker config to exactly the targets carrying a mutation baseline", () => {
    // The two must agree: a config with no baseline means the job scores against nothing, and a
    // baseline with no config means nothing ever measures it. corpus-drift throws on the mismatch;
    // this catches it in `pnpm verify`, before the monthly job would.
    for (const t of EXTERNAL_CORPUS) {
      expect(t.m8 !== undefined, `${t.slug}: m8 config vs baseline`).toBe(isMutationBaseline(t.modules.M8));
    }
    expect(EXTERNAL_CORPUS.filter((t) => t.m8).map((t) => t.slug).sort()).toEqual(["boxyhq", "proposit"]);
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
    const zeroCoverage = finding("M8 — Test quality", "High");
    expect(scoreExternalBaseline(target("subscription-payments"), [zeroCoverage]).find((r) => r.module === "M8"))
      .toMatchObject({ pass: true, actual: 1 });
  });
});

// #321 — the standard drift pass re-attempts every source-tier module each run; these prove the
// re-validation notices when a not-run reason has stopped being true (the module now produces real
// findings), and stays quiet while the reason still holds. The signature defect this closes: a
// stale excuse silently costing coverage that only someone stumbling into it would catch.
describe("revalidateNotRunReasons (#321)", () => {
  // saas-lite records M5-knip not-run for an upstream eslint-patch bug that may resolve on a dep bump.
  const notRunTarget = (): ExternalTarget => {
    const t = EXTERNAL_CORPUS.find((x) => x.slug === "saas-lite");
    if (!t || !isNotRun(t.modules["M5-knip"]!)) throw new Error("saas-lite/M5-knip is expected to be recorded not-run");
    return t;
  };
  const knipFinding = (id: string): Finding => ({ ...finding("M5 — Slop / dead code", "Low"), id });

  it("stays quiet while the reason holds — knip still emits only its #223 M5-00 did-not-run finding", () => {
    // The sentinel is the tool saying it STILL couldn't run; it must not read as the module working.
    const rows = revalidateNotRunReasons(notRunTarget(), [knipFinding("M5-00")]);
    expect(rows).toEqual([]);
  });

  it("stays quiet when nothing at all was produced for the not-run module", () => {
    expect(revalidateNotRunReasons(notRunTarget(), [])).toEqual([]);
  });

  it("fails loud when the not-run module produces real findings — the reason has decayed", () => {
    const rows = revalidateNotRunReasons(notRunTarget(), [knipFinding("M5-42"), knipFinding("M5-43")]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ module: "M5-knip", pass: false, actual: 2 });
    expect(rows[0]?.detail).toContain("STALE");
  });

  it("does not fire on a target whose modules all ran — nothing to re-validate", () => {
    expect(revalidateNotRunReasons(target("subscription-payments"), [knipFinding("M5-07")])).toEqual([]);
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
  it("covers exactly #227's four named repos, each pinned in the corpus", () => {
    // The invariant is defined against these four by name; a target quietly dropped from the list
    // is the check silently shrinking.
    expect(FREE_TIER_EXPECTATIONS.map((e) => e.slug).sort()).toEqual(["multi-tenant-starter", "mvp-boilerplate", "proposit", "saas-lite"]);
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
