// External-repo regression corpus (issue #222) — the answer key for the six PUBLIC targets swept
// on 2026-07-12, recorded as a manifest + per-module baselines so a precision regression on real
// code fails a check instead of waiting for the next live sweep (the #210 demo-key FP shipped
// exactly that way).
//
// WHY A MANIFEST AND NOT VENDORED FIXTURES (form (a), not form (b) of the issue's proposal):
// #222 recommended distilling the offending files into targets/calibration. That is NOT safe for
// the security-critical three it named:
//   - Wallens11/supabase-multi-tenant-starter (the self-join migration) ships **no LICENSE file**
//     — all-rights-reserved by default, so its source cannot be copied into this repo at all.
//   - The other five are MIT/Apache-2.0: copyable only WITH their notices, and a distilled copy
//     silently goes stale against the upstream it claims to represent.
// Distilling would also change what is being measured: the FP shapes that drove #230/#232 (dup%
// denominators, generated-file ratios, whole-repo render trees) are properties of the repo AS A
// WHOLE — a minimal extract cannot reproduce a 5.27%-of-52,165-lines duplication figure. The
// planted-bug fixtures in targets/calibration remain the right tool for the mechanical rules; this
// corpus is the complementary real-world tier, pinned by commit and cloned on demand.
//
// The baselines below were MEASURED on 2026-07-14 by cloning each pinned commit and running
// `pnpm detect-static` / `pnpm quality-scan` — not transcribed from the sweep's pre-fix notes.
// They therefore reflect the state AFTER the #230/#231/#232/#233 precision fixes landed, which is
// what a drift check must compare against. Numbers that moved materially since the sweep are
// called out per target (e.g. mvp-boilerplate's headline dup% 13.3% -> 1.35% once #232 excluded
// its `monero/patches/**` fork-mirror).
//
// LAYER 2 NOW EXISTS (#263): `pnpm corpus-drift` (src/cli/corpus-drift.ts, scheduled in
// .github/workflows/corpus-drift.yml) clones each pin and scores these baselines for real. Its
// first run corrected several numbers that had never been through the scorer: the M4 baselines
// were jscpd's raw CLUSTER counts (203/13/90/11/28) where the scorer counts FINDINGS (68/6/39/4/
// 14), the M8 baselines were test-FILE counts, and two M5 modules recorded as needs-install turned
// out to run fine. Per-target notes say which. The lesson is the corpus's own: a baseline no job
// ever scores is a number nobody has checked.

import type { Finding } from "../findings.js";
import type { QuickScanReport } from "../quick-scan.js";

export interface ModuleBaseline {
  // Findings that count as work: everything the detectors emit at a severity other than "Info".
  // #230 demoted the exhaustive-deps class to Info rather than dropping it, so a raw total would
  // still count 31 style notes as perf work — `counted` is the number the report stands behind.
  counted: number;
  // Every finding the module emits at this commit, Info included. Pinned too: a change in the
  // Info tail is a real behavior change worth seeing, just not a graded one.
  total: number;
  note: string;
}

// A module that did not execute is recorded with the REASON, never omitted and never zero —
// zero would read as "clean" (CLAUDE.md's coverage guard; the same discipline as moduleRan in
// coverage-scorecard.ts).
export interface ModuleNotRun {
  reason: string;
}

export interface ExternalTarget {
  slug: string; // local clone dir name used by the sweep + this file's baselines
  repo: string; // owner/name on GitHub
  commit: string; // pinned — baselines are only meaningful against this tree
  license: string;
  // The security verdict from the 2026-07-12 sweep, as filed for responsible disclosure.
  // Kept alongside the quality baselines because #222's operator correction is explicit: this
  // corpus gates the WHOLE audit, not just security.
  securityVerdict: string;
  disclosureIssue?: number;
  // #278: quality-scan's knip pass (dead code) and detect-static's slop pass (style) both emitted
  // `M5 —` findings that used to be merged into one scored module, double-counting M5 (subscription-
  // payments read 18 against a measured 8). They measure different things and drift independently,
  // so each gets its own key and its own baseline — scoreExternalBaseline's moduleMatches below is
  // the real match rule that keeps them apart (a shared "M5 " prefix can't distinguish them).
  modules: Partial<Record<"M4" | "M5-knip" | "M5-slop" | "M7" | "M8" | "M9" | "M10", ModuleBaseline | ModuleNotRun>>;
}

export function isNotRun(m: ModuleBaseline | ModuleNotRun): m is ModuleNotRun {
  return "reason" in m;
}

// knip usually needs the TARGET's own node_modules to resolve its config imports (CLAUDE.md's M5
// row), and none of the six are vendored with deps — so M5-knip is not-run on the targets where it
// actually failed, rather than falsely 0. NOT uniformly: #263's first real Layer 2 run found knip
// resolves multi-tenant-starter's and subscription-payments' configs without any install, so those
// two carry measured baselines. Which targets those are is a measurement, not an assumption.
const M5_KNIP_NEEDS_INSTALL: ModuleNotRun = {
  reason: "knip needs the target's own `npm install` to resolve config imports — not run in the source-only sweep (CLAUDE.md M5 prereq). Confirmed live: quality-scan emits its M5-00 'did not run' finding (#223) rather than a silent zero.",
};

// mutation-scan shells out to a `stryker` binary that is NOT a dependency of this repo (it must be
// installed in/alongside the target) AND needs a target-specific stryker.conf — no corpus target
// ships one. So on every target with a real test suite, M8 throws rather than measuring: recorded
// not-run with the reason, per the coverage guard. The targets WITHOUT a suite are different — they
// don't need Stryker at all, because #224's zero-coverage finding IS the measurement.
//
// #277 investigated actually closing this 2026-07-15 rather than just re-stating the gap. Result:
// vendoring a config per target (Option 1 in the issue) DOES work on the easiest case — proposit,
// `npm install --legacy-peer-deps` (react 19 vs @ai-sdk/react's peer range conflicts without it)
// + a stryker.conf scoped to lib/pdf/launch.ts (its one file with real coverage) killed 21/21
// mutants in ~1s wall clock, and confirmed reports/mutation/mutation.json as Stryker 9.6.1's
// default JSON path. But the other three each carry a target-specific blocker a generic wrapper
// can't paper over (see each target's note below), and even wiring the ONE working case into the
// scheduled Layer 2 job needs a target `npm install` step plus a much longer timeout than the
// current job's ~2m10s — i.e. a new workflow, which is out of this sweep's granted paths
// (.github/workflows/ is supervised). Recorded as a follow-up rather than attempted here.
const M8_NEEDS_STRYKER: ModuleNotRun = {
  reason: "mutation-scan needs a `stryker` binary on PATH plus a target-specific stryker.conf.* (CLAUDE.md's M8 prereq); this target has a real test suite but ships no Stryker config, so the scan throws instead of scoring. Recorded not-run rather than 0 — a 0 here would read as 'no surviving mutants', the exact inversion of an unmeasured suite. Was recorded as a test-FILE count (#263 found the number never matched what the scorer counts: scanner findings).",
};

// tools/pii-classify.mjs now has a static-schema CLI path (`pnpm pii-classify --schema
// supabase/migrations`, #250), but running it against these targets means cloning each pinned
// commit — the deferred Layer 2 supervisor pass this file's header describes, same as the
// detect-static/quality-scan drift scoring for every other module here. Recorded as not-run for
// drift purposes until that clone-and-run pass lands; the must-not-miss columns are asserted
// directly against real column names in external-corpus.test.ts in the meantime.
const M10_NEEDS_SCHEMA_INPUT: ModuleNotRun = {
  reason: "M10's static-schema CLI path now exists (tools/pii-classify.mjs --schema, #250) but hasn't been re-run against this target's cloned migrations yet — that's the deferred Layer 2 clone-and-score pass. Classifier behavior on this target's real columns is asserted in external-corpus.test.ts instead.",
};

export const EXTERNAL_CORPUS: ExternalTarget[] = [
  {
    slug: "proposit",
    repo: "JakeLeoDev/proposit",
    commit: "82838cef3606a176c4bca0af0587c5ea6b08d3a0",
    license: "MIT",
    securityVerdict: "1 Critical (world-readable invitation tokens), 2 High (invite acceptance trusts client userId; member self-escalation to admin)",
    disclosureIssue: 214,
    modules: {
      M4: { counted: 68, total: 104, note: "5.27% (2749/52165 lines), 203 raw clone clusters — of which 104 are the cross-file clones jscpdToFindings emits and 68 are counted (36 are sub-15-line Info). The 203 originally recorded here was jscpd's cluster count, not the counted findings this scorer compares (fixed #263 when the Layer 2 job first scored it). Was 9.75%/199 clones pre-#232; the drop is that fix excluding generated/demo paths, NOT the repo changing. Per #232 ~75% of what remains is genuine per-entity copy-paste (CRUD forms, per-entity tool/store/service files) — the corpus's strongest real M4 signal and a factory-refactor case." },
      "M5-knip": M5_KNIP_NEEDS_INSTALL,
      "M5-slop": { counted: 6, total: 16, note: "#278: measured 2026-07-15 via detect-static (previously excluded from scoring entirely to avoid double-counting M5-knip). 3 'Single-call wrapper' + 3 'Else after return' counted; 10 Info-tail (narrating comments, AI phrasing, decorative emoji, redundant JSDoc)." },
      M7: { counted: 49, total: 79, note: "30 of the 79 are the exhaustive-deps class #230 demoted to Info (~0 real), leaving 49 counted. The real vein is 26 'Unbounded select' on growable request-path lists (low-sev latent scalability). Residual FP tail still counted: 5 inline-literal, 4 context-value-recreated, 2 index-key — the micro-render shapes #230 judged ~0% real (see follow-up)." },
      M8: M8_NEEDS_STRYKER, // `vitest run` script + a single *.test.* file: a real (if thin) suite, so mutation-scan needs the Stryker config this target doesn't have. #277: verified 2026-07-15 a scoped config (mutate: lib/pdf/launch.ts) runs clean (21/21 killed, ~1s) after `npm install --legacy-peer-deps` — but that's a hand-tuned config, not something the wrapper generates.
      M9: { counted: 8, total: 8, note: "4 'Server Action missing input validation' + 4 'Accidental dynamic rendering'. Distinct from the 4 M1 'Server Action missing authorization check' the same run emits — #231 routed the authz vein to M1/#221 rather than scoring it as M9 rendering, and this split is what that fix looks like on real code." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
  {
    slug: "subscription-payments",
    repo: "vercel/nextjs-subscription-payments",
    commit: "bdd0813206e47e6b218d42f15a7976c8a0d3c3eb",
    license: "MIT",
    securityVerdict: "1 Medium (client-controlled trial length -> arbitrarily long free subscription); otherwise sound — webhook sig verified, RLS scoped, service-role server-only",
    disclosureIssue: 215,
    modules: {
      M4: { counted: 6, total: 8, note: "5.2% (309/5947 lines), 13 raw clusters -> 8 cross-file findings, 6 counted (fixed #263: the 13 was jscpd's cluster count, not counted findings). Down from the sweep's 6.13%/22 clones now #232 excludes `types_db.ts` (Supabase codegen was ~50% of this repo's clones)." },
      "M5-knip": { counted: 8, total: 8, note: "Ran WITHOUT the target's `npm install` — knip resolved its config anyway (fixed #263: recorded as not-run on the assumption it couldn't, measured as 8). 3 unused files + 5 unused-export files; the Medium is utils/supabase/middleware. If a future knip/config change makes this fail, it degrades to the M5-00 'did not run' finding (#223) and this baseline fails loudly rather than silently reading 0." },
      "M5-slop": { counted: 10, total: 12, note: "#278: the double-counting case that started this split — this target's detect-static findings (9 'Else after return' + 1 'Single-call wrapper') were being summed with M5-knip's 8, reading 18 against a measured 8. Measured 2026-07-15: 10 counted, 2 Info." },
      M7: { counted: 2, total: 3, note: "One of the smallest surfaces in the corpus: 2 raw <img> + 1 Info exhaustive-deps. A good FALSE-POSITIVE regression guard — a well-maintained Vercel example should stay near-silent; a jump here means a new over-match." },
      M8: { counted: 1, total: 1, note: "No test script and zero *.test.*/*.spec.* files at this commit, so mutation-scan needs no Stryker: it emits exactly #224's M8-00 zero-coverage finding (High), which IS the measurement. Recorded as 1 counted finding — the 0 previously here was a test-FILE count and would have read as 'no M8 problems' on a repo with no tests at all, inverting the finding's meaning (fixed #263)." },
      M9: { counted: 2, total: 2, note: "2 'Accidental dynamic rendering'. Low and stable — the second FP guard alongside M7." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
  {
    slug: "boxyhq",
    repo: "boxyhq/saas-starter-kit",
    commit: "abc9b686823cbfb4973c79bc36fea37a3244be6c",
    license: "Apache-2.0",
    securityVerdict: "1 Medium (team billing authz enforced only in UI), 1 Low (invite path bypasses the admins-cant-create-owners guard)",
    disclosureIssue: 216,
    modules: {
      M4: { counted: 39, total: 66, note: "4.93% (1148/23283 lines), 90 raw clusters -> 66 cross-file findings, 39 counted (fixed #263: the 90 was jscpd's cluster count). Per #232 the real signal is the API-handler envelope (a `createHandler` extraction candidate), lower severity than proposit's." },
      "M5-knip": M5_KNIP_NEEDS_INSTALL,
      "M5-slop": { counted: 12, total: 13, note: "#278: measured 2026-07-15. 9 'Else after return' + 2 'Orphan TODO' + 1 'Single-call wrapper' counted; 1 Info. The corpus's highest slop count on a target with real test coverage — a real regression guard, not just the zero-test targets." },
      M7: { counted: 17, total: 17, note: "Includes the corpus's one genuine middleware stall ('Fetch in middleware hot path') — one of the two real request-path finds #230 kept. The 9 inline-literal + 3 index-key are the residual micro-render tail." },
      M8: M8_NEEDS_STRYKER, // Best-tested target in the corpus (real `jest` script + 8 test files, plus playwright) — and precisely why it can't be scored without a Stryker config. #277: the playwright specs need a built app + a real browser, a heavier prerequisite than a unit-test mutation run; not attempted.
      M9: { counted: 0, total: 0, note: "MEASURED zero, and it is the #231 fix working: this is a PAGES Router app, where the App-Router-only checks must not fire at all. Pre-#231 it drew a bogus server-only hit. Any non-zero M9 here is a straight regression of that fix." },
      M10: {
        reason: "Prisma schema, no SQL migrations — the sweep did not scan it. Its `jackson_store.value` (SAML/SSO config incl. IdP secrets) is the #233 opaque-encrypted-store case and IS asserted in external-corpus.test.ts against the classifier.",
      },
    },
  },
  {
    slug: "multi-tenant-starter",
    repo: "Wallens11/supabase-multi-tenant-starter",
    commit: "dcc147c0f945737f69df79e8aa544dc09e84ccbb",
    // No LICENSE file at this commit -> all rights reserved. This is why the corpus clones on
    // demand instead of vendoring: distilling this repo's migration into targets/calibration, as
    // #222 proposed, would be copying unlicensed source.
    license: "none (no LICENSE file — all rights reserved)",
    securityVerdict: "1 Critical (any authed user self-joins any tenant as owner), 1 High (cross-tenant invitation tampering) — both confirmed dynamically against a local self-hosted clone",
    disclosureIssue: 217,
    modules: {
      M4: { counted: 0, total: 1, note: "0.35% (11/3167 lines), 6 raw clusters -> 1 cross-file finding, and it is Info (sub-15-line), so 0 counted (fixed #263: the 6 was jscpd's cluster count). A MEASURED near-zero on the smallest target; the sweep's 2.95% was the pre-#232 denominator." },
      // The one target small enough (13 deps) to `npm install` cheaply, so M5-knip DID run here.
      "M5-knip": { counted: 2, total: 2, note: "Ran WITHOUT the target's node_modules — knip still resolves this 13-dep repo's config, so M5-knip is the one target scored here (fixed #263: recorded as 1 finding, measured as 2 — knip reports the two files separately, it does not roll them into one). Both REAL, and the first is security-weighted: `lib/security/guards.ts` exports requireTenantAccess/requireTenantAdmin and NOTHING calls them, on the same repo whose self-join Critical (#217) is a missing-authz bug. #226's security cross-link firing on real code: the dead guard IS the vulnerability's fingerprint. The second is unused exports in lib/supabase/server.ts." },
      "M5-slop": { counted: 0, total: 0, note: "#278: measured 2026-07-15 — MEASURED zero, consistent with M4/M7's floor readings on this 3.1k-line repo. Any non-zero here is almost certainly a new over-match." },
      M7: { counted: 0, total: 0, note: "MEASURED zero — a 3.1k-line repo with no perf surface. A useful floor: any M7 finding appearing here is almost certainly a new over-match." },
      M8: M8_NEEDS_STRYKER, // One hand-rolled `test/rls.test.mjs` run via `node --test` — detectNoTestSuite counts the `--test` script as a real suite, so this needs Stryker too. #277: verified 2026-07-15 this test spins up a Docker Postgres container per run — mutation testing would pay that cost per mutant, well beyond any CI budget without a dedicated long-running job.
      M9: { counted: 3, total: 3, note: "2 'Accidental dynamic rendering' + 1 'Data-fetching waterfall'." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
  {
    slug: "mvp-boilerplate",
    repo: "devtodollars/mvp-boilerplate",
    commit: "2aac5c2fcb45c35aa4a5f5eb9eb66645f0f84e70",
    license: "MIT",
    securityVerdict: "1 Low / latent (over-broad anon+authenticated grants on xmr_invoices, not exploitable today — RLS default-deny blocks it); base boilerplate otherwise sound, and the mechanical demo-key Criticals were the #210 FP",
    disclosureIssue: 218,
    modules: {
      M4: { counted: 4, total: 7, note: "1.35% (211/15684 lines), 11 raw clusters -> 7 cross-file findings, 4 counted (fixed #263: the 11 was jscpd's cluster count). The sweep's headline '13.3%, highest in the corpus' was almost entirely `monero/patches/**` whole-file fork-mirrors. #232's vendored-path exclusion is what closed that ~12-point gap; this target is the regression guard for it." },
      "M5-knip": M5_KNIP_NEEDS_INSTALL,
      "M5-slop": { counted: 6, total: 11, note: "#278: measured 2026-07-15. 5 'Else after return' + 1 'Orphan TODO' counted; 5 Info." },
      M7: { counted: 3, total: 4, note: "1 unbounded select + 1 index-key + 1 state-sprawl counted, 1 exhaustive-deps demoted to Info." },
      M8: { counted: 1, total: 1, note: "No package.json at the repo root (it's a monorepo whose apps carry their own) and zero test files — mutation-scan emits #224's M8-00 zero-coverage finding (High), which IS the measurement. 1 counted, not the 0 test-FILE count previously recorded (fixed #263)." },
      M9: { counted: 1, total: 1, note: "1 'Data-fetching waterfall'." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
  {
    slug: "saas-lite",
    repo: "makerkit/nextjs-saas-starter-kit-lite",
    commit: "37def9c20b01a3514cf69b5b3383bef3e5ffbcb9",
    license: "MIT",
    securityVerdict: "1 Low (unauthenticated open redirect via the auth-callback `next` param); otherwise sound — RLS scoped on read AND write, service-role server-only",
    disclosureIssue: 219,
    modules: {
      M4: { counted: 14, total: 16, note: "1.15% (318/27617 lines), 28 raw clusters -> 16 cross-file findings, 14 counted (fixed #263: the 28 was jscpd's cluster count). The sweep's 499-line identical `database.types.ts` copy is now excluded by #232." },
      "M5-knip": M5_KNIP_NEEDS_INSTALL,
      "M5-slop": { counted: 23, total: 26, note: "#278: measured 2026-07-15. 22 'Redundant JSDoc' + 1 'Orphan TODO' counted; 3 Info. The corpus's highest slop count — a well-maintained starter kit whose JSDoc habit trips the detector, worth watching for FP drift." },
      M7: { counted: 23, total: 24, note: "Includes the corpus's other genuine request-path stall ('Blocking sync I/O in request handler' — the execSync-on-a-/version-route case #230 kept) plus an 'Await in loop (N+1)' and a raw <img>. The 11 inline-literal + 6 index-key + 2 context-value are the residual micro-render tail. 22 -> 23 when #269 added the 'React Compiler flag unresolvable' class: this repo sets `reactCompiler: ENABLE_REACT_COMPILER` (env-derived), the exact unresolvable-flag case #249 filed. Baseline rebased by #263's first real Layer 2 run — an intended new detection, not a regression, and the drift check catching it on day one is the corpus working." },
      M8: M8_NEEDS_STRYKER, // `turbo test` script + 3 test files — a partial suite, between boxyhq and the zero-test targets, and still unscoreable without a Stryker config. #277: same class of per-repo tuning cost as the others (turbo monorepo test orchestration); not attempted.
      M9: { counted: 2, total: 2, note: "2 'Accidental dynamic rendering'." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
];

// #227's free-tier calibration invariant, as data. The product promise in one line: the free tier
// must not cry wolf on a decent repo, and must not stay quiet on a bad one. #244 encoded this over
// SYNTHETIC findings — which can only prove the grading arithmetic, never that the DETECTORS put
// real repos on the right side of it. Scored against a real quick-scan by the Layer 2 job (#261).
//
// "Loud" is deliberately `indicators at a real severity`, not `indicators.length > 0`: every target
// with migrations draws the Info-severity "Tenancy model assumed" disclosure (#220), so counting it
// would let the bad repos pass on a note that says nothing about them. Measured 2026-07-15.
export interface FreeTierExpectation {
  slug: string;
  mustNotScoreF: boolean;
  // true  -> at least one non-Info tenant-isolation indicator (the app IS known-vulnerable)
  // false -> no such indicator (a decent repo must not be accused)
  mustRaiseLoudIndicator: boolean;
  why: string;
}

export const FREE_TIER_EXPECTATIONS: FreeTierExpectation[] = [
  {
    slug: "mvp-boilerplate",
    mustNotScoreF: true,
    mustRaiseLoudIndicator: false,
    why: "#227's don't-cry-wolf case: a sound boilerplate whose only mechanical hits were the #210 demo-key FP. An F here, or a tenant-isolation accusation, is the free tier lying about a decent repo. Measured: A (92), 1 Info-only indicator (the tenancy-model disclosure).",
  },
  {
    slug: "saas-lite",
    mustNotScoreF: true,
    mustRaiseLoudIndicator: false,
    why: "The other don't-cry-wolf case: RLS scoped on read AND write, service-role server-only. Its one real issue (open redirect) is not a tenancy hole and must not surface as one. Measured: A (97), 0 indicators.",
  },
  {
    slug: "multi-tenant-starter",
    mustNotScoreF: false,
    mustRaiseLoudIndicator: true,
    why: "The don't-stay-quiet case: any authed user self-joins any tenant as owner (#217 Critical, confirmed dynamically). If the free tier is silent here it has failed the promise. Measured: 4 High RLS indicators. Its grade is deliberately unconstrained — the Critical is an indicator, never a graded hygiene verdict (#213/#220).",
  },
  {
    slug: "proposit",
    mustNotScoreF: false,
    mustRaiseLoudIndicator: true,
    why: "The other don't-stay-quiet case: world-readable invitation tokens (#214 Critical). Measured: 1 High RLS indicator on organisation_invitations — the very table the Critical is about.",
  },
];

interface FreeTierRow {
  slug: string;
  check: string;
  pass: boolean;
  detail: string;
}

// Scores a REAL free-tier quick-scan of `slug`'s pinned commit against #227's invariant.
export function scoreFreeTierExpectation(expectation: FreeTierExpectation, report: QuickScanReport): FreeTierRow[] {
  const loud = report.indicators.filter((i) => i.severity !== "Info");
  const rows: FreeTierRow[] = [];

  if (expectation.mustNotScoreF) {
    rows.push({
      slug: expectation.slug,
      check: "must not score F",
      pass: report.grade !== "F",
      detail: report.grade !== "F"
        ? `grade ${report.grade} (${report.score}/100)`
        : `CRIED WOLF: graded F (${report.score}/100) on a repo #227 calls sound — the free tier is failing decent repos`,
    });
  }

  const raised = loud.length > 0;
  rows.push({
    slug: expectation.slug,
    check: expectation.mustRaiseLoudIndicator ? "must raise a loud tenant-isolation indicator" : "must not accuse a sound repo of a tenancy hole",
    pass: raised === expectation.mustRaiseLoudIndicator,
    detail: raised === expectation.mustRaiseLoudIndicator
      ? `${loud.length} non-Info indicator(s)`
      : expectation.mustRaiseLoudIndicator
        ? `STAYED QUIET: 0 non-Info indicators on a known-vulnerable repo (${report.indicators.length} Info-only) — the deep-scan Critical has no free-tier signal`
        : `CRIED WOLF: ${loud.length} non-Info indicator(s) (${loud.map((i) => i.title).join("; ")}) on a repo #227 calls sound`,
  });

  return rows;
}

interface DriftRow {
  slug: string;
  module: string;
  expected: number;
  actual: number;
  drift: number;
  pass: boolean;
  detail: string;
}

// quality-scan's knip pass emits every M5 finding under this one literal taxonomy string; nothing
// else in the codebase uses it. #278: M5-slop is everything ELSE prefixed "M5 " (detect-static's
// 11 style classes — else-after-return, single-call wrapper, etc, src/detectors/slop.ts) — matched
// by exclusion rather than an enumerated list, so a new slop class detect-static adds later is
// still scored under M5-slop without this file needing an update to notice it.
const M5_KNIP_TAXONOMY = "M5 — Slop / dead code";

function moduleMatches(taxonomy: string, module: string): boolean {
  if (module === "M5-knip") return taxonomy === M5_KNIP_TAXONOMY;
  if (module === "M5-slop") return taxonomy.startsWith("M5 ") && taxonomy !== M5_KNIP_TAXONOMY;
  return taxonomy.startsWith(`${module} `);
}

function countedFor(findings: Finding[], module: string): number {
  return findings.filter((f) => moduleMatches(f.taxonomy, module) && f.severity !== "Info").length;
}

// Scores a real scan of `target`'s pinned commit against its recorded baseline. Exact equality:
// these are deterministic AST/text passes over a frozen tree, so any movement is a real change in
// scanner behavior and should be looked at — either a precision fix (update the baseline in the
// same PR) or a regression (fix the scanner). A tolerance band would just hide small drifts.
// Modules recorded as not-run are skipped, never scored 0 — a 0 would read as "clean".
export function scoreExternalBaseline(target: ExternalTarget, findings: Finding[]): DriftRow[] {
  return Object.entries(target.modules).flatMap(([module, baseline]) => {
    if (isNotRun(baseline)) return [];
    const actual = countedFor(findings, module);
    const drift = actual - baseline.counted;
    return [{
      slug: target.slug,
      module,
      expected: baseline.counted,
      actual,
      drift,
      pass: drift === 0,
      detail: drift === 0
        ? `matches baseline (${baseline.counted} counted)`
        : `DRIFT ${drift > 0 ? "+" : ""}${drift}: expected ${baseline.counted} counted, got ${actual} — a precision fix (update the baseline) or a regression (fix the scanner)`,
    }];
  });
}
