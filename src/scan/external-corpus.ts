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

import { M4_DIVERGED_TAXONOMY } from "../diverged-clones.js";
import type { Finding } from "../findings.js";
import type { QuickScanReport } from "../quick-scan.js";
import { classifyMigrationSql, classifyPrismaSchema } from "../../tools/pii-classify.mjs";
import { M8_CORPUS_CONFIGS, type M8CorpusConfig } from "./m8-corpus.js";

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

// #300: M8 on a target with a REAL suite is measured as a mutation score, not a finding count —
// a distinct shape rather than a reused ModuleBaseline, because `counted: 100` would be read by
// every other scorer here as "100 findings" when it means "100% of mutants killed". The two
// zero-test targets keep their ModuleBaseline: there the #224 finding IS the measurement, and a
// finding count is exactly the right unit for it.
//
// #319: `coveredScope` is REQUIRED, not optional, and that is the whole point. A mutation score is
// only ever measured over the files Stryker's `mutate` glob names (m8-corpus.ts scopes it to the
// files the suite actually covers). proposit's 100% is 100% of ONE file in an otherwise-untested
// repo; boxyhq's 20% is over one file out of a 23k-line tree. A bare percentage reads as a
// repo-level test-quality claim and is a misrepresentation — the corpus's own trust-budget lesson
// (#263) one level up. Making the covered files a required field means no MutationBaseline can be
// constructed, and formatMutationClaim means no score can be printed, without the denominator that
// makes "100% over one file" legible.
export interface MutationBaseline {
  mutationScore: number; // percent, as summarizeMutationReport computes it
  killed: number;
  valid: number; // mutants Stryker could actually judge (excludes Ignored/CompileError)
  // #319: the files the score is measured over — Stryker's `mutate` scope, a subset of the repo,
  // NEVER the whole tree. Always non-empty; this is the denominator that keeps the score honest.
  coveredScope: string[];
  // #432: the ± band on `killed` a Stryker re-run is allowed to land in and still count as a match.
  // Defaults to 0 (exact match) — a target only earns a nonzero tolerance after being MEASURED
  // flaky across multiple runs, never added defensively. See scoreMutationBaseline's header for why
  // exact equality is the right default and what earns an exception.
  tolerance?: number;
  note: string;
}

export function isMutationBaseline(m: ModuleBaseline | ModuleNotRun | MutationBaseline): m is MutationBaseline {
  return "mutationScore" in m;
}

// #319: the ONE way a mutation score is written into the manifest's drift output — score always
// carried with the covered scope that makes it honest, never a bare percentage. scoreMutationBaseline
// routes every pass/fail line through this so "20%" can't appear without "over lib/server-common.ts".
function formatMutationClaim(b: MutationBaseline): string {
  const scope = b.coveredScope.length === 1
    ? b.coveredScope[0]
    : `${b.coveredScope.length} files (${b.coveredScope.join(", ")})`;
  // #432: a nonzero tolerance means this baseline is a measured band, not a point value — say so
  // wherever the claim is printed, so a reader doesn't read "20% (7/35 killed)" as more precise
  // than it is.
  const band = b.tolerance ? ` (±${b.tolerance} killed, measured flaky — see note)` : "";
  return `${b.mutationScore}% (${b.killed}/${b.valid} killed)${band} over ${scope} — a scoped subset, NOT a whole-repo coverage claim`;
}

// #413: authorship provenance of a corpus repo, classified by evidence (commit trailers, AI-tool
// files like CLAUDE.md/.cursor/rules, comment style, contributor/release history) — NOT by naming
// prior. This is metadata for the M6 hand-rolled-frequency measurement, which asks whether the
// catalogue's "common in AI code" shapes actually appear more in AI-authored code than in
// professional code. It does not touch the measured per-module drift baselines.
//   - professional : org/maintained product, human contributors, no AI fingerprints
//   - ai-assisted  : AI trailers/CLAUDE.md but a capable-dev population (real team, CI, no slop)
//   - ai-generated : AI-authored MVP (Claude co-author / cursor rules driving the build), the
//                    non-engineer vibe-coding population M6's wedge actually targets
//   - unclear      : ambiguous evidence (recorded honestly, never forced into a tier)
export type Provenance = "professional" | "ai-assisted" | "ai-generated" | "unclear";

export interface ExternalTarget {
  slug: string; // local clone dir name used by the sweep + this file's baselines
  repo: string; // owner/name on GitHub
  commit: string; // pinned — baselines are only meaningful against this tree
  license: string;
  // #413: authorship provenance (see Provenance above). Metadata only — the drift baselines below
  // are unaffected. `provenanceNote` records the evidence the verdict rests on.
  provenance: Provenance;
  provenanceNote: string;
  // The security verdict from the 2026-07-12 sweep, as filed for responsible disclosure.
  // Kept alongside the quality baselines because #222's operator correction is explicit: this
  // corpus gates the WHOLE audit, not just security.
  securityVerdict: string;
  disclosureIssue?: number;
  // #279: clone-relative path to the target's SQL migrations, for corpus-drift.ts to feed
  // classifyMigrationSql. Undefined means "no schema input this classifier can read". #299 closed
  // the one target this used to name (boxyhq's double-quoted Prisma migration.sql) by extending
  // parseColumns/parseTableNames to read quoted identifiers — every corpus target now has one.
  schemaPath?: string;
  // #278: quality-scan's knip pass (dead code) and detect-static's slop pass (style) both emitted
  // `M5 —` findings that used to be merged into one scored module, double-counting M5 (subscription-
  // payments read 18 against a measured 8). They measure different things and drift independently,
  // so each gets its own key and its own baseline — scoreExternalBaseline's moduleMatches below is
  // the real match rule that keeps them apart (a shared "M5 " prefix can't distinguish them).
  // M8 alone may also carry a MutationBaseline (#300): on a target with a real suite it is scored
  // as a mutation percentage by scoreMutationBaseline, not by counting findings.
  // #360: "M4-diverged" is the near-miss security-clone pass (src/diverged-clones.ts) — same
  // split rationale as M5-knip/M5-slop: it shares M4's taxonomy prefix but is a different
  // detector with a different (review-tier, similarity-threshold) drift profile, so it gets its
  // own baseline instead of silently moving M4's.
  // "M8-intent" (#372, split here alongside #252) is detect-static's test-intent pass —
  // assertion-free/tautological/happy-path-only test shapes. It shares M8's taxonomy prefix but
  // is a static detector over test files, a different measurement from the mutation tier that
  // owns the plain "M8" key (MutationBaseline, the #224/#252 suite-absent finding, or not-run).
  // Without the split, a test-intent finding would read as evidence against an M8 MUTATION
  // not-run reason — the false "reason may be stale" alarm the 2026-07-17 drift runs showed on
  // saas-lite.
  // "M6-indicator" (#483) is detect-static's free-tier hand-rolled-shape pass (src/detectors/
  // handrolled.ts, #267) — findings taxonomied "M6 — Indicator: …". Every one is severity "Info"
  // BY DESIGN (#267's non-grading ruling), so `counted` here can't mean "non-Info count" the way
  // it does for every other module: that would score every target's M6-indicator baseline as a
  // permanent 0 and the drift check would never be able to fail, which is the opposite of #483's
  // point. countedFor special-cases this module to count every match regardless of severity —
  // `counted` and `total` are therefore always equal for this key.
  modules: Partial<Record<"M4" | "M4-diverged" | "M5-knip" | "M5-slop" | "M6-indicator" | "M7" | "M8-intent" | "M9" | "M10", ModuleBaseline | ModuleNotRun>>
    & { M8: ModuleBaseline | ModuleNotRun | MutationBaseline };
  // #300: the vendored Stryker config for targets scored by the M8 workflow. Absent means M8 is
  // either not-run (with a reason) or a zero-test target whose #224 finding is the measurement.
  m8?: M8CorpusConfig;
  // #322: per-module scan roots. A module listed here scans the named clone-relative subtree
  // instead of the repo root (today only M5-knip supports this — knip needs the tree that
  // actually carries the package.json). The cost this buys back is honesty-critical: the scoped
  // module measures a DIFFERENT tree than the whole-repo modules, so scoreExternalBaseline
  // stamps every scored row of such a target with its scanned scope — the disagreement is
  // recorded in the output, and cross-module comparisons on the target are scope-invalid.
  scanRoots?: { "M5-knip"?: string };
}

export function isNotRun(m: ModuleBaseline | ModuleNotRun | MutationBaseline): m is ModuleNotRun {
  return "reason" in m;
}

// #251: the Layer 2 job now runs `npm install` in each clone before quality-scan (installTargetDeps
// in src/cli/corpus-drift.ts), which is the prereq CLAUDE.md's M5 row names — so "needs the target's
// npm install" is no longer a reason for anything. Measured 2026-07-15 with deps installed: proposit
// (85) and boxyhq (12) now carry real baselines. #322's per-module scan root then gave
// mvp-boilerplate a scoped measurement over nextjs/ (see its entry). #544: saas-lite — the last
// M5-knip not-run — gained a measured baseline once #519 made knip run PER WORKSPACE (the old
// whole-repo run died loading apps/web's eslint config, which is what the retired
// M5_KNIP_ESLINT_PATCH_BROKEN reason recorded); NO M5-knip is not-run now. Installing is inert for
// the rest of the corpus: M4 reproduced byte-identically on all four installable targets, and the
// two M5-knip baselines that already scored without deps (subscription-payments 8,
// multi-tenant-starter 2) were re-measured WITH deps and did not move.

// #300: M8 on the targets WITH a real suite now runs for real, in .github/workflows/corpus-m8.yml —
// a per-target `npm install`, a vendored Stryker config (src/scan/m8-corpus.ts), and a timeout that
// matches the actual cost. Two of the four are scored; two remain blocked, each for a MEASURED
// reason below rather than the generic "no config" this constant used to assert for all four.
//
// #277 predicted boxyhq was blocked by its Playwright E2E specs needing a built app + browser.
// That was WRONG, and re-measuring rather than transcribing is what caught it: boxyhq's own
// jest.config.js already sets `testPathIgnorePatterns: ['<rootDir>/tests/e2e']`, so the jest runner
// never sees a Playwright spec. It scores 20% today (measured, 7/35). The targets WITHOUT a suite
// are different again — they need no Stryker at all, because #224's zero-coverage finding IS the
// measurement.
const M8_DOCKER_PER_MUTANT: ModuleNotRun = {
  reason: "This target's only suite (test/rls.test.mjs, run via `node --test`) spawns a Docker Postgres container per run — verified 2026-07-15 in the cloned tree (its `docker()` helper shells out to `docker run`). Stryker re-runs the suite per mutant, so scoring it means one container start per mutant: a cost no CI budget justifies for a single RLS test file. Recorded not-run rather than 0 — a 0 would read as 'no surviving mutants', the exact inversion of an unmeasured suite. Revisit only if the suite gains a container-reuse mode.",
};

const M8_E2E_ONLY_SUITE: ModuleNotRun = {
  reason: "Measured 2026-07-15 (re-verified 2026-07-17): this target's `turbo test` orchestrates apps/e2e, whose 3 specs are ALL Playwright E2E (account/auth/password-reset) needing a built app, a browser and a live Supabase stack. There is no unit suite to mutate — so unlike boxyhq (whose jest config ignores its E2E dir and scores fine), scoping a Stryker config here has nothing to point at. #252's decided rule agrees this is NOT 'suite absent' (that threshold is zero test files or a single placeholder spec; these are 3 real specs), so no M8-00 zero-coverage finding applies — the suite exists, it just isn't unit-mutable, and this stays not-run with the reason. The static test-intent tier is measured separately under M8-intent.",
};

// #279: shapes a schema-only PII/PHI/PCI classification pass into Finding[] so
// scoreExternalBaseline's taxonomy-prefix matching can count it like every other module here.
// No Finding-emitting adapter for tools/pii-classify.mjs existed anywhere in the codebase before
// this (src/cli/dry-run.ts writes the raw data map to a file; the M10 calibration corpus's own
// header calls a Finding adapter a documented, unimplemented follow-up) — this is scoped to
// exactly what corpus scoring needs: one Finding per table with >=1 classified column, at that
// table's own aggregate severity (buildDataMap's `severity`, which is never "Info" for a real
// hit — the lowest score a single low-confidence match produces is 0.3, which scoreToSeverity
// reads as "Low"). Every target's baseline below is therefore counted === total.
export function m10FindingsFromSchema(sql: string): Finding[] {
  return dataMapToM10Findings(classifyMigrationSql(sql).dataMap);
}

// #894: the Prisma-path targets declare a `schema.prisma` rather than a migrations dir, and
// classifyMigrationSql cannot read one — it parses CREATE TABLE SQL. #758 shipped the Prisma
// model/field parser; this is the same Finding adapter over that classifier, so a Prisma target's
// M10 is scored exactly like a SQL target's rather than recorded not-run for a reason that stopped
// being true when #758 landed.
export function m10FindingsFromPrismaSchema(schema: string): Finding[] {
  return dataMapToM10Findings(classifyPrismaSchema(schema).dataMap);
}

type M10Table = { infotypes: string[]; severity: string; columns: { column: string }[]; categories: string[] };

function dataMapToM10Findings(dataMap: Record<string, M10Table>): Finding[] {
  return Object.entries(dataMap).map(([table, t], i) => ({
    id: `M10-SCHEMA-${String(i + 1).padStart(2, "0")}`,
    title: `${table}: ${t.infotypes.join(", ")}`,
    severity: t.severity as Finding["severity"],
    confidence: "Confirmed",
    category: "Data classification",
    taxonomy: "M10 — Data classification",
    location: table,
    status: "Open",
    evidence: `${t.columns.length} column(s) classified: ${t.columns.map((c) => c.column).join(", ")}.`,
    impact: `${t.categories.join("/")} data on this table — needs the M10 protection review (encrypted at rest? RLS-scoped? reachable by the anon/authenticated key?).`,
    fix: "Confirm this data is encrypted at rest (pgsodium/Vault) or scoped behind RLS before it reaches an exposed schema/view.",
    value: 3,
    ease: 2,
    safety: 4,
    mechanical: true,
  }));
}

export const EXTERNAL_CORPUS: ExternalTarget[] = [
  {
    slug: "proposit",
    repo: "JakeLeoDev/proposit",
    commit: "82838cef3606a176c4bca0af0587c5ea6b08d3a0",
    license: "MIT",
    provenance: "ai-assisted",
    provenanceNote: "#413: Co-Authored-By: Claude Opus 4.7 trailers + CLAUDE.md + .claude/commands/, but a real 2-dev team with a product site, full CI/governance and no slop — a capable-dev-with-AI population, distinct from vibe-coding.",
    securityVerdict: "1 Critical (world-readable invitation tokens), 2 High (invite acceptance trusts client userId; member self-escalation to admin)",
    disclosureIssue: 214,
    schemaPath: "supabase/migrations",
    m8: M8_CORPUS_CONFIGS.proposit,
    modules: {
      M4: { counted: 73, total: 105, note: "5.27% (2749/52165 lines), 203 raw clone clusters — 104 individual cross-file findings, 73 counted, plus the #365 M4-00 small-clone disclosure (44 sub-10-line clones, Info) for 105 total. Re-measured 2026-07-16: counted 68->73 because #361 elevates security-path clones one tier — 5 sub-15-line clones in components/auth/* + lib/supabase/server.ts moved Info->Low (10 clones total carry the elevation, the other 5 were already counted). Was 9.75%/199 clones pre-#232; the drop is that fix excluding generated/demo paths, NOT the repo changing. Per #232 ~75% of what remains is genuine per-entity copy-paste (CRUD forms, per-entity tool/store/service files) — the corpus's strongest real M4 signal and a factory-refactor case. #251 measured the install step inert for M4." },
      "M4-diverged": { counted: 12, total: 12, note: "#360: measured 2026-07-16 — 20 security-path files, 1 diverged family (High, review tier). Small for the corpus's worst M4 target because its per-entity copies live under lib/ai/tools/* and lib/stores/*, which don't hit SECURITY_PATH_KEYWORDS — the pass is deliberately scoped to auth/guard/middleware/security paths. Re-measured 2026-07-17 (#399): 1->12 after widening file selection to ALSO admit files whose BODY scopes a supabase query by a tenant key (touchesTenantSupabasePath) — this target's file count went 20->57 (37 more admitted via content, mostly exactly the predicted lib/ai/tools/*-tools.ts and lib/*-service.ts per-entity vein), surfacing 11 more diverged families in that vein." },
      "M5-knip": { counted: 85, total: 85, note: "#251 measured this, #320 triaged it (2026-07-17, reproduced by cloning the pin + `npm install --legacy-peer-deps` + Harvey's own knip, exact reprint of 85: 83 Low + 2 Medium). VERDICT: none of the 85 are knip config/barrel-re-export artifacts — every spot-checked item is a real unreferenced file or export — but only ~41 are actionable dead code a client would expect from '85 findings': 8 unused files + 33 of the 77 unused-export files (incl. an orphaned 11-function/3-const pagination subsystem in lib/pdf-pagination.ts, live only via 2 of its 16 exports). The other 44 unused-export files are real-but-low-value from two mechanical, recurring shapes, not repo-specific slop: 19 are per-entity `FooService` classes whose singleton instance (`export const fooService = new FooService()`) is used everywhere but the class NAME itself never is — trivial to silence (drop `export` on the class), not code to delete; 25 are shadcn/ui (components/ui/*, 15) + Vercel ai-elements (components/elements/*, 10) generated component-kit sub-exports — the kit ships a full API surface, this app uses a subset, and this shape will recur on every shadcn/ai-elements corpus target. SECURITY (#226 cross-link): 2 of the 85 sit on auth-adjacent paths, called out per acceptance criteria, neither itself the live vuln — lib/supabase/middleware.ts (Medium, unused FILE) is the standard Supabase SSR session-refresh/redirect helper, fully unwired (the repo's actual middleware.ts only runs next-intl); auth is enforced per-page via lib/auth.ts's getUser() instead, so this isn't a live gap, but it is exactly the 'guard written, never wired in' shape #226 exists to catch. lib/auth.ts (Medium, 4 unused exports: getUserProfile/getUserOrganization/createUserProfile/createOrganisationMembership) are orphaned duplicates superseded by lib/users-service.ts and the real invitation-acceptance path (lib/actions/invitation-actions.ts) — createOrganisationMembership takes a caller-supplied `role` string, which reads alarmingly next to this repo's own disclosed High (member self-escalation to admin, #214) but is dead, so it is not that vector; still worth deleting so a future reviewer doesn't mistake it for the live authorization path." },
      "M5-slop": { counted: 28, total: 38, note: "Re-measured 2026-07-17: 6->28 counted after #391 added the unused-parameter/unused-import/single-use-helper/unreachable-branch classes — 22 'Single-use helper' + 3 'Single-call wrapper' + 3 'Else after return' counted; 10 'Narrating comment' Info. The single-use-helper vein is the same per-entity scaffolding M4/M5-knip already flag on this target." },
      "M6-indicator": { counted: 10, total: 10, note: "#483: MEASURED 2026-07-17 via detect-static's handrolled-shape pass — 4 'currency formatting', 2 'JSON deep-equal', 1 each of 'email-shape regex', 'cookie parsing', 'base64url conversion', 'raw-millisecond date math'. The corpus's highest reading — proposit's per-entity scaffolding (lib/ai/tools/*, lib/*-service.ts) reinvents several standard shapes by hand, consistent with its M4/M5-knip per-entity vein. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 42, total: 72, note: "Re-measured 2026-07-17: 49->42 counted under #248's React Compiler gate — the micro-render tail (5 inline-literal + 4 context-value + 2 index-key, judged ~0% real by #230) no longer emits at all with the compiler off. Counted: 26 'Unbounded select' (the real vein — growable request-path lists), 5 state sprawl, 4 raw <img>, 3 nested-loop join, 2 JSON deep-clone, 1 client fetch in useEffect, 1 oversized committed images. 30 exhaustive-deps Info." },
      M8: { mutationScore: 100, killed: 21, valid: 21, coveredScope: ["lib/pdf/launch.ts"], note: "#300/#319: MEASURED 2026-07-15 by the real wrapper (not transcribed) — 21/21 mutants killed on lib/pdf/launch.ts (its coveredScope), ~1s, via the vendored config in m8-corpus.ts after `npm install --legacy-peer-deps`. A perfect score on the corpus's THINNEST suite: this repo has exactly one spec, so 100% here means 'the one covered file is tested well', NOT that proposit is well-tested — its untested surface doesn't appear in this number at all. #319 makes that non-negotiable: coveredScope is required and formatMutationClaim prints it, so this can never be quoted as a repo-level '100% tested'. Useful as drift detection regardless: any drop means the suite or the launch.ts logic moved. #252's threshold keeps this scoreable: the one spec is MEANINGFUL (multiple real assertions — verified 2026-07-17 by the census not emitting M8-00 here), and only a single PLACEHOLDER spec counts as suite absent." },
      "M8-intent": { counted: 1, total: 1, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: 1 'Call-count-only test' (Medium) in the single spec. Split from the mutation-tier M8 key so a static test-intent finding can never read as evidence about the mutation baseline." },
      M9: { counted: 11, total: 11, note: "Re-measured 2026-07-17: 8->11 — the 4 'Server Action missing input validation' + 4 'Accidental dynamic rendering' plus #380/#381's new classes (1 'Missing server-only guard', 2 'SSR-only API misuse'). Distinct from the 4 M1 'Server Action missing authorization check' the same run emits — #231 routed the authz vein to M1/#221 rather than scoring it as M9 rendering, and this split is what that fix looks like on real code." },
      M10: { counted: 18, total: 18, note: "#279: measured 2026-07-15 via m10FindingsFromSchema over the cloned supabase/migrations (205 columns parsed, 39 PII-bearing across 18 tables — one Finding per table). Headline is organisations: Critical, ADDRESS+API_KEY+STORED_PASSWORD — the #233 must-not-miss plaintext ai_api_key/smtp_pass case, now scored as a real drift check instead of only a unit assertion." },
    },
  },
  {
    slug: "subscription-payments",
    repo: "vercel/nextjs-subscription-payments",
    commit: "bdd0813206e47e6b218d42f15a7976c8a0d3c3eb",
    license: "MIT",
    provenance: "professional",
    provenanceNote: "#413: Vercel official template, 7722★, 31 contributors (Lee Robinson, Stripe/Supabase engineers), 2020→2025, no AI files. One human 2024 refactor carries AI-style comments but the repo is human/professional.",
    securityVerdict: "1 Medium (client-controlled trial length -> arbitrarily long free subscription); otherwise sound — webhook sig verified, RLS scoped, service-role server-only",
    disclosureIssue: 215,
    schemaPath: "supabase/migrations",
    modules: {
      M4: { counted: 8, total: 9, note: "5.2% (309/5947 lines), 13 raw clusters -> 8 cross-file findings, 8 counted, plus the #365 M4-00 disclosure (4 small clones, Info) for 9 total. Re-measured 2026-07-16: counted 6->8, two sub-15-line clones in components/ui/AuthForms/* moved Info->Low under #361's security-path elevation. Down from the sweep's 6.13%/22 clones now #232 excludes `types_db.ts` (Supabase codegen was ~50% of this repo's clones)." },
      "M4-diverged": { counted: 2, total: 2, note: "#360: measured 2026-07-16 — 14 security-path files, 2 diverged families (High, review tier) in the AuthForms components." },
      "M5-knip": { counted: 8, total: 8, note: "Originally ran WITHOUT the target's `npm install` — knip resolved its config anyway (fixed #263: recorded as not-run on the assumption it couldn't, measured as 8). Re-measured 2026-07-15 WITH deps installed (#251): still 8 — the install step adds coverage elsewhere without disturbing this. 3 unused files + 5 unused-export files; the Medium is utils/supabase/middleware. If a future knip/config change makes this fail, it degrades to the M5-00 'did not run' finding (#223) and this baseline fails loudly rather than silently reading 0." },
      "M5-slop": { counted: 14, total: 16, note: "#278 started this split at a measured 10; re-measured 2026-07-17 after #391's new classes: 9 'Else after return' + 4 'Single-use helper' + 1 'Single-call wrapper' counted; 2 'Decorative emoji' Info." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 — a well-maintained Vercel example with no hand-rolled shapes to flag, consistent with this target's near-floor M7/M9 readings. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 2, total: 3, note: "One of the smallest surfaces in the corpus: 2 raw <img> + 1 Info exhaustive-deps (re-measured 2026-07-17, unchanged — this target never carried a micro-render tail, so #248's gate moved nothing here). A good FALSE-POSITIVE regression guard — a well-maintained Vercel example should stay near-silent; a jump here means a new over-match." },
      M8: { counted: 1, total: 1, note: "No test script and zero *.test.*/*.spec.* files at this commit, so mutation-scan needs no Stryker: it emits exactly #224's M8-00 zero-coverage finding (High), which IS the measurement. Recorded as 1 counted finding — the 0 previously here was a test-FILE count and would have read as 'no M8 problems' on a repo with no tests at all, inverting the finding's meaning (fixed #263)." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: zero test files to inspect, so a measured zero — the M8-00 zero-coverage finding above is this target's whole M8 story." },
      M9: { counted: 4, total: 4, note: "Re-measured 2026-07-17: 2->4 — the 2 'Accidental dynamic rendering' plus 2 'Missing server-only guard' from #380/#381's new M9 classes. Still a small stable surface and an FP guard alongside M7." },
      M10: { counted: 5, total: 5, note: "#279: 36 columns parsed from the cloned supabase/migrations. Re-measured 2026-07-17: 3->5 tables after #461 widened the PCI/payment dictionary — users: High (NAME/ADDRESS/PAYMENT_REF), customers: Medium (PAYMENT_REF), products/prices/subscriptions: Low." },
    },
  },
  {
    slug: "boxyhq",
    repo: "boxyhq/saas-starter-kit",
    commit: "abc9b686823cbfb4973c79bc36fea37a3244be6c",
    license: "Apache-2.0",
    provenance: "professional",
    provenanceNote: "#413: org product, 4868★, 39 contributors, 2022→2026, versioned releases, dependabot, no AI files.",
    securityVerdict: "1 Medium (team billing authz enforced only in UI), 1 Low (invite path bypasses the admins-cant-create-owners guard)",
    disclosureIssue: 216,
    m8: M8_CORPUS_CONFIGS.boxyhq,
    // #299: Prisma migrations, not supabase/migrations — nested one level deeper
    // (prisma/migrations/<name>/migration.sql) than Supabase's flat layout, which is why
    // corpus-drift.ts's readMigrationSql had to read recursively too, not just this parser.
    schemaPath: "prisma/migrations",
    modules: {
      M4: { counted: 47, total: 67, note: "4.93% (1148/23283 lines), 90 raw clusters -> 66 cross-file findings, 47 counted, plus the #365 M4-00 disclosure (3 small clones, Info) for 67 total. Re-measured 2026-07-16: counted 39->48, nine sub-15-line clones under pages/api/auth/*, pages/auth/*, components/auth/* (and one tests/e2e/auth spec) moved Info->Low under #361's security-path elevation. Re-measured again 2026-07-17 (#400): 48->47 — the tests/e2e/auth/idp-initiated.spec.ts clone no longer elevates, since a test/spec/e2e path merely naming 'auth' isn't a per-handler authorization drift risk (same exclusion the #360 diverged-clone pass's file selection already applied). Per #232 the real signal is the API-handler envelope (a `createHandler` extraction candidate), lower severity than proposit's. #251 measured the install step inert for M4." },
      "M4-diverged": { counted: 2, total: 2, note: "#360: measured 2026-07-16 — 38 security-path files, 2 diverged families (High, review tier). The larger family is the per-page getServerSideProps auth boilerplate (8 pages, one adjudication row thanks to family grouping — per-pair emission would have been 21 findings, the measured basis for grouping)." },
      "M5-knip": { counted: 12, total: 12, note: "#251: measured 2026-07-15 after `npm install --legacy-peer-deps` in the clone — 5 unused files + 7 files with unused exports. Modest for a 23k-line repo. #323: this used to add 'matching this target's reputation as the corpus's best-maintained one (it is also the M8 upper reference point)' — drop that framing, see the M8 note below: most test FILES in the corpus, LOWEST measured mutation score. Worth watching as an FP guard: a jump here on a well-kept repo is more likely a knip/config change than new dead code." },
      "M5-slop": { counted: 76, total: 77, note: "Re-measured 2026-07-17: 12->76 counted, almost entirely #391's new 'Single-use helper' class (64) on top of the prior 9 'Else after return' + 2 'Orphan TODO' + 1 'Single-call wrapper'; 1 'Narrating comment' Info. The corpus's highest single-use-helper reading — worth watching for precision drift on that class, but every prior class reproduced exactly." },
      "M6-indicator": { counted: 2, total: 2, note: "#483: MEASURED 2026-07-17 — 1 'email-shape regex' + 1 'cookie serialization' (both dep-gated classes: zod and no class-merge dep respectively confirm the gate reads this target's package.json correctly). All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 6, total: 6, note: "Re-measured 2026-07-17: 17->6 under #248's React Compiler gate — the 9 inline-literal + 3 index-key micro-render tail no longer emits with the compiler off. What remains is the real request-path vein: 3 'Await in loop (N+1)', the corpus's one genuine middleware stall ('Fetch in middleware hot path', kept by #230), 1 JSON deep-clone, 1 nested-loop join." },
      // #300: the manifest calls this target "the M8 upper reference point" — measurement says
      // otherwise, and that inversion is the whole reason to measure. It has the corpus's most
      // test FILES (8) but its jest suite is ONE unit spec; the other 7 are Playwright E2E.
      M8: { mutationScore: 20, killed: 7, valid: 35, tolerance: 1, coveredScope: ["lib/server-common.ts"], note: "#300/#319: MEASURED 2026-07-15 — 20% (7/35 valid mutants) on lib/server-common.ts (its coveredScope), the file boxyhq's one jest unit spec (__tests__/lib/server-common.spec.ts) covers. 2 survived, 26 NoCoverage: the spec exercises generateToken but leaves most of the file's exports untouched. #277 predicted the Playwright specs would block this and they do NOT — the target's jest.config.js already sets testPathIgnorePatterns: ['<rootDir>/tests/e2e'], so jest never loads them; the prediction was never tested against the config. Note this reverses the manifest's 'best-tested target' framing: most test files, LOWEST measured mutation score in the corpus (proposit's thin suite scores 100 on what it covers) — which is exactly why #319 requires coveredScope: one covered file out of a 23k-line tree is not a repo-level 20%. Test-file count was never test quality — which is #263's lesson restated. #432: CI measured 8/35 (22.9%) on PR #431 — re-run 4x on 2026-07-17 (cloning + installing fresh each time, not just re-scoring one report) and got 7/35 three times, 8/35 once. Diffing the two runs' surviving-mutant lists pins it to ONE mutant flip-flopping: lib/server-common.ts:18's MethodExpression on `tokenBytes.toString('hex').slice(0, length)`. generateToken's own spec has a 'random length' test (`Math.round(Math.random() * 10) + 1`, unseeded) — when that length lands EVEN, the mutant's un-sliced hex output happens to already be that length (Math.ceil(length/2) bytes -> length hex chars when length is even), so the assertion can't tell the mutant from the original and it survives; an ODD length always kills it. This is the target's OWN test being flaky by construction, not our wrapper or Stryker — tolerance: 1 absorbs the ±1 wobble instead of picking a point value that fails exactly as often as it passes." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: a measured zero across this target's jest unit spec and Playwright E2E specs — no assertion-free/tautological/happy-path-only shapes fired." },
      M9: { counted: 14, total: 14, note: "Re-measured 2026-07-17: 0->14, ALL of them #381's new 'SSR-only API misuse' class (browser-global reads reachable during SSR — lib/common.ts:9, five in lib/theme.ts, etc), which applies to Pages Router apps too. The #231 guard this baseline exists for is UNCHANGED and now scoped: the App-Router-only classes (accidental dynamic rendering, server-only guard, waterfall) still measure ZERO here, and any non-zero in THOSE is a straight regression of that fix — check the class breakdown before rebaselining." },
      M10: { counted: 9, total: 9, note: "#299: 95 columns parsed from the cloned prisma/migrations. Re-measured 2026-07-17: 8->9 tables after #461's dictionary widening added Price (Low). Headline is jackson_store: Medium (OPAQUE_ENCRYPTED_STORE, the must-not-miss SAML/SSO secret store also pinned directly in external-corpus.test.ts's classifyColumn assertion), plus Account/Session: High (AUTH_TOKEN) and User: High (NAME?/EMAIL/STORED_PASSWORD). Previously not-run — parseColumns matched unquoted \\w+ identifiers only and this target's Prisma-generated migration.sql double-quotes every one (\"Account\", \"userId\"); #299 extended the parser to read quoted identifiers too." },
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
    provenance: "unclear",
    provenanceNote: "#413: leans professional — single-dump initial commit (a mild AI tell) but the cleanest code of the set, deliberate WHY-comments, no AI fingerprints/trailers. Genuinely ambiguous; recorded as unclear rather than forced into a tier.",
    securityVerdict: "1 Critical (any authed user self-joins any tenant as owner), 1 High (cross-tenant invitation tampering) — both confirmed dynamically against a local self-hosted clone",
    disclosureIssue: 217,
    schemaPath: "supabase/migrations",
    modules: {
      M4: { counted: 1, total: 2, note: "0.35% (11/3167 lines), 6 raw clusters -> 1 cross-file finding, 1 counted, plus the #365 M4-00 disclosure (2 small clones, Info) for 2 total. Re-measured 2026-07-16: counted 0->1 — the single sub-15-line clone (app/dashboard/CreateTenantForm.tsx, paired against an auth-path file) moved Info->Low under #361's elevation. Still a MEASURED near-floor on the smallest target; the sweep's 2.95% was the pre-#232 denominator." },
      "M4-diverged": { counted: 0, total: 0, note: "#360: measured 2026-07-16 — 8 security-path files, ZERO diverged families. A measured zero on the repo whose dead requireTenantAccess guard (#217/#226) is the M5 headline: its guards were never wired, so they never got copy-pasted and drifted. Any non-zero here is a new detection or an over-match — look before rebaselining." },
      // The one target small enough (13 deps) to `npm install` cheaply, so M5-knip DID run here.
      "M5-knip": { counted: 2, total: 2, note: "Originally ran WITHOUT the target's node_modules — knip resolves this 13-dep repo's config either way (fixed #263: recorded as 1 finding, measured as 2 — knip reports the two files separately, it does not roll them into one). Re-measured 2026-07-15 WITH deps installed (#251): still 2, so the new install step did not move this baseline. Both REAL, and the first is security-weighted: `lib/security/guards.ts` exports requireTenantAccess/requireTenantAdmin and NOTHING calls them, on the same repo whose self-join Critical (#217) is a missing-authz bug. #226's security cross-link firing on real code: the dead guard IS the vulnerability's fingerprint. The second is unused exports in lib/supabase/server.ts." },
      "M5-slop": { counted: 2, total: 2, note: "Re-measured 2026-07-17: 0->2 from #391's new classes — 1 'Unused import' (app/dashboard/page.tsx) + 1 'Single-use helper' (middleware.ts). Still near the floor this 3.1k-line repo reads everywhere else; a jump beyond this is a new over-match." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 — same FP-floor role as this target's M4-diverged/M7 zeros, a 3.1k-line repo too small to carry any of the 13 hand-rolled shapes. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 0, total: 0, note: "MEASURED zero (re-confirmed 2026-07-17) — a 3.1k-line repo with no perf surface. A useful floor: any M7 finding appearing here is almost certainly a new over-match." },
      M8: M8_DOCKER_PER_MUTANT, // One hand-rolled `test/rls.test.mjs` run via `node --test` — detectNoTestSuite counts the `--test` script as a real suite (and #252's census agrees: the single spec has real assertions, so it is NOT a placeholder), so this needs Stryker too, and the per-mutant Docker cost is why #300 left it not-run rather than scoring it.
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: a measured zero — the one hand-rolled RLS spec drew no test-intent findings." },
      M9: { counted: 3, total: 3, note: "2 'Accidental dynamic rendering' + 1 'Data-fetching waterfall' (re-confirmed 2026-07-17 — no #381 SSR-only hits here)." },
      M10: { counted: 1, total: 1, note: "#279: measured 2026-07-15 via m10FindingsFromSchema over the cloned supabase/migrations (21 columns parsed, 1 PII-bearing table). tenant_invitations: Low (EMAIL) — the corpus's near-floor M10 reading, matching this target's otherwise-minimal M4/M7 surface." },
    },
  },
  {
    slug: "mvp-boilerplate",
    repo: "devtodollars/mvp-boilerplate",
    commit: "2aac5c2fcb45c35aa4a5f5eb9eb66645f0f84e70",
    license: "MIT",
    provenance: "ai-generated",
    provenanceNote: "#413: Co-Authored-By: Claude Opus 4.6 on recent commits, ships CLAUDE.md + agent-skills docs, AI over-commenting in original source. The corpus's clearest AI-generated data point among the six.",
    securityVerdict: "1 Low / latent (over-broad anon+authenticated grants on xmr_invoices, not exploitable today — RLS default-deny blocks it); base boilerplate otherwise sound, and the mechanical demo-key Criticals were the #210 FP",
    disclosureIssue: 218,
    // The app's own schema, not monero/supabase/migrations (the vendored payment-fork mirror
    // #232 already excludes from M4's duplication denominator for the same reason).
    schemaPath: "supabase/migrations",
    // #322: knip needs the tree that carries the Next app's package.json — this polyglot monorepo
    // (flutter/, monero/, nextjs/) has none at the root. M5-knip alone scans nextjs/; every other
    // module keeps the whole repo, and every scored row for this target states its scope.
    scanRoots: { "M5-knip": "nextjs" },
    modules: {
      M4: { counted: 5, total: 8, note: "1.35% (211/15684 lines), 11 raw clusters -> 7 cross-file findings, 5 counted, plus the #365 M4-00 disclosure (1 small clone, Info) for 8 total. Re-measured 2026-07-16: counted 4->5 — one sub-15-line clone (nextjs/app/api/auth_callback/route.ts) moved Info->Low under #361's security-path elevation. The sweep's headline '13.3%, highest in the corpus' was almost entirely `monero/patches/**` whole-file fork-mirrors. #232's vendored-path exclusion is what closed that ~12-point gap; this target is the regression guard for it." },
      "M4-diverged": { counted: 0, total: 0, note: "#360: measured 2026-07-16 — 4 security-path files, ZERO diverged families. Same FP-floor role as this target's M7/M5-slop zeros." },
      "M5-knip": { counted: 22, total: 22, note: "#322: MEASURED 2026-07-17 over the nextjs/ per-module scan root (npm install in nextjs/, knip run there) — previously not-run because this polyglot monorepo has no root package.json. 8 unused files + 14 files with unused exports; 15 of the 22 are shadcn/ui component-kit sub-exports (components/ui/*), the same recurring mechanical shape #320's proposit triage documented. The one security-adjacent row is utils/supabase/middleware.ts (Medium) — same standard-SSR-helper shape as subscription-payments' Medium. SCOPE CAVEAT: this number describes nextjs/ ONLY, while every other module here measures the whole repo — the scored rows carry the scope, and cross-module comparisons on this target are scope-invalid." },
      "M5-slop": { counted: 24, total: 29, note: "Re-measured 2026-07-17: 6->24 counted after #391's new classes — 17 'Single-use helper' + 5 'Else after return' + 1 'Orphan TODO' + 1 'Unused import'; 5 'Decorative emoji' Info." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 over the whole repo (this target's M5-knip alone scans nextjs/ per its scanRoots — M6-indicator, like M7/M9/M5-slop, measures the whole tree, so this zero is scope-consistent with those). All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 5, total: 6, note: "Re-measured 2026-07-17: 3->5 — #248's gate removed the 1 index-key, while 2 'Client fetch in useEffect' + 1 'Nested-loop join' (classes added since the 2026-07-15 baseline) now count alongside the 1 unbounded select + 1 state-sprawl; 1 exhaustive-deps Info." },
      M8: { counted: 1, total: 1, note: "No package.json at the repo root (it's a monorepo whose apps carry their own) and zero test files — mutation-scan emits #224's M8-00 zero-coverage finding (High), which IS the measurement. 1 counted, not the 0 test-FILE count previously recorded (fixed #263)." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: zero test files anywhere in the tree, so a measured zero — M8-00 above is the whole M8 story here." },
      M9: { counted: 1, total: 1, note: "1 'Data-fetching waterfall' (re-confirmed 2026-07-17)." },
      M10: { counted: 6, total: 6, note: "#279: 42 columns parsed from the cloned supabase/migrations. Re-measured 2026-07-17: 3->6 tables after #461 widened the PCI/payment dictionary — users High, customers Medium, products/prices/subscriptions/checkout_sessions Low. Same Stripe-billing template shape as subscription-payments, which moved 3->5 under the same widening." },
    },
  },
  {
    slug: "saas-lite",
    repo: "makerkit/nextjs-saas-starter-kit-lite",
    commit: "37def9c20b01a3514cf69b5b3383bef3e5ffbcb9",
    license: "MIT",
    provenance: "professional",
    provenanceNote: "#413: free tier of the commercial Makerkit product — Turborepo, versioned CHANGELOG, renovate/syncpack, no AI files.",
    securityVerdict: "1 Low (unauthenticated open redirect via the auth-callback `next` param); otherwise sound — RLS scoped on read AND write, service-role server-only",
    disclosureIssue: 219,
    // Monorepo: the app lives under apps/web, not the repo root.
    schemaPath: "apps/web/supabase/migrations",
    modules: {
      M4: { counted: 14, total: 17, note: "1.15% (318/27617 lines), 28 raw clusters -> 16 cross-file findings, 14 counted, plus the #365 M4-00 disclosure (9 small clones, Info) for 17 total. Re-measured 2026-07-16: counted unchanged by #361 — its security-path clones were already >=15 lines, so the elevation moved severities (Low->Medium) without crossing the Info/counted line. The sweep's 499-line identical `database.types.ts` copy is now excluded by #232. #251 measured the install step inert for M4. #544: RE-MEASURED 2026-07-18 at 14/17 — byte-identical to this baseline — after fixing a #519 REGRESSION. #519 ran jscpd PER WORKSPACE, which on this Turborepo silently dropped BOTH every cross-workspace clone AND every `packages/**` workspace (the shared discoverTargets glob did not then expand the `packages/**` double-star — since fixed in #548), collapsing M4 to 4 counted (apps/web-internal only) with NO gap disclosed — the silent under-count the coverage guard forbids. jscpd now runs whole-repo again: it has no workspace-resolution stage and does not hang (measured 1.9s over this monorepo), and whole-repo is the correct duplication scope. 9 of the 14 restored clones are the real cross-package/packages-internal auth vein (packages/features/auth <-> packages/features/accounts MFA/sign-in copy-paste), the corpus's strongest cross-workspace M4 signal." },
      "M4-diverged": { counted: 5, total: 5, note: "#360: measured 2026-07-16 — 52 security-path files, 5 diverged families (High, review tier): the auth pages (sign-in/sign-up/password-reset), the callback/confirm route GETs, and the ErrorAlert/SuccessAlert i18n-key drift — the corpus's largest near-miss surface, consistent with its packages/features/auth breadth." },
      "M5-knip": { counted: 10, total: 11, note: "#548: RE-MEASURED 2026-07-18 (cloned pin + `npm install` + Harvey's per-workspace knip) after expandGlob learned to expand `packages/**`: quality-scan now enumerates ALL 13 workspaces (was 6 — only apps/* + tooling/*), so the 7 `packages/**` workspaces are knip'd for the first time. 3->10 counted, 3->11 total. The prior 3 remain (tooling/eslint apps.js/base.js/nextjs.js, Low). The 7 NEW findings: 6 more `eslint.config.mjs` unused-FILE flags (packages/features/accounts + i18n + next + shared + supabase Low, packages/features/auth Medium) PLUS one genuine dead component — packages/features/auth/src/components/auth-link-redirect.tsx (Medium). HONEST CAVEAT (same shape as the original tooling/eslint 3): the eslint.config.mjs flags are a per-workspace-scoping artifact — each package DOES consume its own flat-config via its build tooling, but knip scanning a package in isolation (npm-installed, not pnpm workspace-linked) can't see that; auth-link-redirect.tsx is the one real find. STILL A PARTIAL: 3 of 13 scopes fail knip and are disclosed in M5-00 (#505, Info) — apps/web (the long-standing eslint-config-next patch error), apps/e2e (missing @playwright/test), and now packages/ui (@kit/eslint-config/base.js unresolved). Prior baselines: not-run (pre-#519) -> 3 (#544, per-workspace but packages/** still dropped) -> 10 (#548, packages/** now scanned). Re-verify if a dep bump makes those 3 scopes resolve." },
      "M5-slop": { counted: 79, total: 82, note: "Re-measured 2026-07-17: 23->79 counted, mostly #391's new 'Single-use helper' class (56) on top of the prior 22 'Redundant JSDoc' + 1 'Orphan TODO'; 3 Info (narrating comment, decorative emoji). Still the corpus's highest slop count — a well-maintained starter kit whose JSDoc/helper granularity habits trip the detectors, the corpus's main M5-slop FP-drift watch." },
      "M6-indicator": { counted: 2, total: 2, note: "#483: MEASURED 2026-07-17 — 2 'cookie serialization' in packages/features/auth. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 6, total: 7, note: "Re-measured 2026-07-17: 23->6 under #248's React Compiler gate — the 11 inline-literal + 6 index-key + 2 context-value micro-render tail no longer emits (this repo's `reactCompiler: ENABLE_REACT_COMPILER` is env-derived/unresolvable, which #248 treats as off; the Watch-severity 'React Compiler flag unresolvable' finding from #269 stays counted as the disclosure). Also counted: the corpus's other genuine request-path stall ('Blocking sync I/O in request handler' — the execSync-on-a-/version-route case #230 kept), 1 'Await in loop (N+1)', 2 'Nested-loop join', 1 raw <img>; 1 exhaustive-deps Info." },
      M8: M8_E2E_ONLY_SUITE, // `turbo test` script + 3 test files — ALL Playwright E2E (measured #300), so there is no unit suite for Stryker to mutate. #252's ruling (zero files or a single placeholder == absent) confirms this is a real-but-unmutable suite, not a zero-coverage case.
      "M8-intent": { counted: 1, total: 1, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: 1 'Happy-path-only tests on security-critical code' (Medium, apps/e2e/tests/authentication/auth.po.ts). This is the finding the 2026-07-17 drift runs mis-read as evidence that the M8 MUTATION not-run reason was stale — the split exists so the two measurements can never shadow each other again." },
      M9: { counted: 12, total: 12, note: "Re-measured 2026-07-17: 2->12 — the 2 'Accidental dynamic rendering' plus 10 of #381's new 'SSR-only API misuse' class, concentrated in packages/features/auth sign-in/sign-up components (browser-global reads reachable during SSR)." },
      M10: { counted: 1, total: 1, note: "#279: measured 2026-07-15 via m10FindingsFromSchema over the cloned apps/web/supabase/migrations (9 columns parsed, 1 PII-bearing table). accounts: Low (ambiguous NAME? + EMAIL) — the corpus's other near-floor M10 reading." },
    },
  },
  // ── #894: the Prisma app-layer tier (epic #756, shipped 2026-07-23) had NO real-code regression
  // baseline. The six targets above were all selected in the 2026-07-12 sweep; boxyhq carries a
  // schema.prisma but its baselines predate detectOrm routing, the Prisma tenant-scope/BOLA
  // detector (#760), M7's schema.prisma FK-index check (#761) and M10's Prisma classification
  // (#758). The four below are pinned and measured 2026-07-24 on this machine (clone at pin ->
  // `npm install --no-audit --no-fund` in the clone, exactly what corpus-drift --install does ->
  // detect-static + quality-scan + mutation-scan --detect-only + the M10 adapter). Licences are
  // AGPL-3.0/NOASSERTION: pinned-clone manifest only, never vendored — the Wallens11 rule at the
  // top of this file.
  {
    slug: "ghostfolio",
    repo: "ghostfolio/ghostfolio",
    commit: "7bd6ca6d48a2b88d454218dc1497536708e38c57",
    license: "AGPL-3.0",
    provenance: "professional",
    provenanceNote: "#894: org product with a CHANGELOG, versioned releases, an Nx monorepo and a large human contributor history; ships a skills-lock.json (agent tooling) but no AI commit trailers in the pinned tree. Recorded professional on that evidence.",
    securityVerdict: "NOT ASSESSED — #894 baselines the source-tier QUALITY modules only. No M1 semantic pass, no dynamic tier, and no disclosure has been filed. This field is deliberately not a clean bill of health.",
    // #758's Prisma classifier, via m10FindingsFromPrismaSchema — this target has no SQL migration
    // dir a CREATE TABLE parser could read, which is the whole point of pinning it.
    schemaPath: "prisma/schema.prisma",
    modules: {
      M4: { counted: 356, total: 508, note: "#894: MEASURED 2026-07-24 — 356 counted (151 Medium + 193 Low + 12 Medium security-path), 151 Info plus the #365 M4-00 small-clone disclosure for 508 total. The corpus's second-largest duplication surface; an Nx monorepo (apps/api NestJS + apps/client Angular + libs/*) whose per-entity service/DTO scaffolding is the vein." },
      "M4-diverged": { counted: 0, total: 0, note: "#894: MEASURED zero 2026-07-24 — the near-miss pass admits no diverged family here. A useful FP floor on a large repo: this target's 356 exact clones did NOT drag the diverged pass up with them, so a non-zero appearing later is a new detection or an over-match, not scale." },
      "M5-knip": { counted: 446, total: 447, note: "#894: MEASURED 2026-07-24 after `npm install` in the clone (2196 packages) — 413 'Unused file' (Low) + 21 'Unused security-relevant file' (Medium) + 11 unused-export files + 1 Info (#580 M5-99 'result may be unreliable for one or more scopes'). CAVEAT recorded with the number, not instead of it: 413 unused FILES on an Nx workspace is the shape knip produces when it cannot see Nx's project graph as the entry surface, so treat this as a DRIFT baseline (it must reproduce), not as a claim that ghostfolio has 413 dead files. The M5-99 uncertainty row is part of the baseline and is what says so in the output." },
      "M5-slop": { counted: 49, total: 50, note: "#894: MEASURED 2026-07-24 — 28 'Else after return' + 6 'Orphan TODO' + 6 'Placeholder stub' + 4 'Redundant boolean ternary' + 5 single-use helpers; 1 narrating-comment Info." },
      "M6-indicator": { counted: 5, total: 5, note: "#894: MEASURED 2026-07-24 — 5 hand-rolled-shape indicators. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 78, total: 78, note: "#894: MEASURED 2026-07-24 and the reason this target is pinned — 5 of the 78 are #761's Prisma `schema.prisma` UNINDEXED-FOREIGN-KEY findings (Account.platformId, AccountBalance.userId, Order.accountUserId, Order.symbolProfileId, SymbolProfile.userId), the first real-code regression baseline the Prisma M7 tier has ever had. The rest: 59 whole-library lodash imports, 8 nested-loop joins, 6 await-in-loop N+1." },
      M8: {
        reason: "#894: MEASURED 2026-07-24 — mutation-scan --detect-only DETECTS a real suite here (jest via apps/api/jest.config.ts; it even replicates the target-declared TZ=UTC env, #503), so #224's zero-coverage finding correctly does NOT apply and a finding count is the wrong unit. Scoring it needs a provisioned Stryker + runner plugin, which is corpus-m8.yml's job and needs a measured per-target M8_CORPUS_CONFIGS entry (a `mutate` scope narrowed to the files this Nx suite actually covers). Not attempted in #894: choosing that scope means running the target's jest suite to see what it covers, which is beyond a manifest change. Recorded not-run rather than 0 — a 0 would read as 'no surviving mutants' on a suite nobody has mutated.",
      },
      "M8-intent": { counted: 0, total: 0, note: "#894: MEASURED zero 2026-07-24 across this target's 31 spec files — no assertion-free/tautological/happy-path-only/mock-the-subject shape fired. A real FP floor for the test-intent pass on a professionally-maintained suite, and the direct contrast with inbox-zero's 305." },
      M9: { counted: 13, total: 16, note: "#894: MEASURED 2026-07-24 — 13 'SSR-only API misuse' (8 document, 4 window, 1 navigator) plus 3 Info #903 not-assessed rows (server→client data leak, cache config, waterfall — all 'data layer not supported'). This is an Angular client, not an App Router app: the App-Router-only classes measuring zero here is the correct answer and any non-zero in THOSE is a straight regression." },
      M10: { counted: 9, total: 9, note: "#894: MEASURED 2026-07-24 via m10FindingsFromPrismaSchema over the cloned prisma/schema.prisma (10,200 bytes) — the FIRST corpus target scored through #758's Prisma classifier rather than a CREATE TABLE parser. 9 PII-bearing models. Headline is a wealth-management schema (Access/Account/SymbolProfileOverrides et al) rather than a synthetic users table, which is why #894 called this the M10 pick." },
    },
  },
  {
    slug: "rallly",
    repo: "lukevella/rallly",
    commit: "a680798c542ec9613f68b7a05a639db8419500d9",
    license: "AGPL-3.0",
    provenance: "ai-assisted",
    provenanceNote: "#894: a real maintained product (versioned releases, i18n via Crowdin, CI) that ALSO ships a CLAUDE.md and a .claude/skills tree of tracked symlinks — the capable-dev-with-AI population, same tier as proposit.",
    securityVerdict: "NOT ASSESSED — source-tier quality baselines only (#894). No M1 semantic pass, no dynamic tier, no disclosure filed.",
    // The Prisma `prismaSchemaFolder` layout: schema.prisma is 9 lines of datasource/generator and
    // the models live in prisma/models/*.prisma, so the schema.prisma path classifies ZERO columns
    // (measured). The SQL migrations are the schema input that actually carries this target's data.
    schemaPath: "packages/database/prisma/migrations",
    modules: {
      M4: { counted: 160, total: 186, note: "#894: MEASURED 2026-07-24 — 160 counted (83 Medium + 65 Low + 6 Medium/6 Low security-path), 25 Info plus the #365 M4-00 disclosure (11 small clones) for 186. Measured identically before and after `npm install`, so the install step is inert for M4 here as it is for the rest of the corpus." },
      "M4-diverged": { counted: 2, total: 2, note: "#894: MEASURED 2026-07-24 — 2 High review-tier families, one of them a 5-function family. Small relative to the 160 exact clones, the same ratio the older targets show." },
      "M5-knip": { counted: 67, total: 68, note: "#894: MEASURED 2026-07-24 WITH `npm install` in the clone (67; the same run without deps read 69, recorded here so the delta is on the record). 17 unused files + 47 unused-export files + 1 Medium security-relevant. STILL A PARTIAL and the baseline says so: 4 of 16 scopes (apps/landing, apps/web, packages/database, packages/ui) ran in #810's reduced no-dependencies mode and are disclosed as the M5-98 Info row, because this is a pnpm workspace and `npm install` — what corpus-drift --install runs — resolves only the 219 ROOT packages, leaving every workspace without node_modules. Re-verify if the drift job ever gains a pnpm install path." },
      "M5-slop": { counted: 123, total: 177, note: "#894: MEASURED 2026-07-24 — 20 single-use helpers + 9 else-after-return + 1 single-call wrapper counted alongside the rest; 49 'Decorative emoji in a log call' + 4 narrating comments are the Info tail. The decorative-emoji vein is this target's signature and the thing to watch for precision drift." },
      "M6-indicator": { counted: 24, total: 24, note: "#894: MEASURED 2026-07-24 — 24 hand-rolled-shape indicators, the corpus's highest reading after inbox-zero's 51. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 17, total: 20, note: "#894: MEASURED 2026-07-24 — 9 await-in-loop N+1, 4 raw <img>, 1 nested-loop join, 1 whole-library lodash import, 1 sort-in-JSX, 1 oversized-committed-images roll-up (7 images, 9.3 MB); 3 hook-dep Info. NOTE for the Prisma tier: #761's unindexed-FK check contributes ZERO here — this target's schema.prisma carries no models (see schemaPath above), so the FK check has nothing to read. ghostfolio/documenso/inbox-zero are where that detector is baselined." },
      M8: {
        reason: "#894: MEASURED 2026-07-24 — a real suite IS detected (so #224's zero-coverage finding does not apply and a finding count is the wrong unit), but it cannot be mutation-scored through corpus-m8.yml's provisioning path: this is a pnpm workspace and `npm install` at the root installs only the 219 root packages, leaving apps/web (where the suite lives) with no node_modules at all — verified in the clone, apps/web/node_modules does not exist after the install the job runs. Scoring it needs a pnpm-aware install step the M8 job does not have. Recorded not-run with that reason rather than 0.",
      },
      "M8-intent": { counted: 8, total: 8, note: "#894: MEASURED 2026-07-24 — 4 'Call-count-only test' (Low), 2 'Asserts response shape, not business values' (Medium), 2 '`vi.hoisted` factory references non-hoisted binding' (Medium)." },
      M9: { counted: 14, total: 17, note: "#894: MEASURED 2026-07-24 — 13 SSR-only API misuse (11 window, 1 document, 1 navigator) + 1 'cookies() read in a page' (Medium, accidental dynamic rendering); 3 Info #903 not-assessed rows. A real App Router target, unlike ghostfolio/carbon." },
      M10: { counted: 22, total: 22, note: "#894: MEASURED 2026-07-24 via m10FindingsFromSchema over the cloned packages/database/prisma/migrations (137 SQL migrations). 22 PII-bearing tables, headline `accounts` Critical and `Account`/`license_validations` High. Deliberately NOT scored off schema.prisma: this target uses Prisma's prismaSchemaFolder split, so its schema.prisma declares no models and classifies zero columns — measured, not assumed." },
    },
  },
  {
    slug: "inbox-zero",
    repo: "elie222/inbox-zero",
    commit: "2b78f2b38576b7e69c77e5acf76676ff75fac75a",
    license: "none in-tree at this pin (GitHub reports NOASSERTION — all rights reserved by default)",
    provenance: "ai-assisted",
    provenanceNote: "#894: a real product with a large contributor history and CI, shipping CLAUDE.md + AGENTS.md + a skills/ tree — capable-dev-with-AI, not vibe-coded.",
    securityVerdict: "NOT ASSESSED — source-tier quality baselines only (#894). No M1 semantic pass, no dynamic tier, no disclosure filed.",
    schemaPath: "apps/web/prisma/schema.prisma",
    modules: {
      M4: { counted: 341, total: 537, note: "#894: MEASURED 2026-07-24 — 341 counted (72 Medium + 266 Low + 3 Medium security-path), 195 Info plus the #365 M4-00 disclosure (45 small clones) for 537." },
      "M4-diverged": { counted: 1, total: 1, note: "#894: MEASURED 2026-07-24 — 1 High review-tier diverged security-path family." },
      "M5-knip": { counted: 197, total: 198, note: "#894: MEASURED 2026-07-24 after `npm install` (108 root packages — a pnpm workspace, so the workspaces stay uninstalled; the M5-98 reduced-tier Info row is part of this baseline). 24 unused files + 2 Medium security-relevant unused-export files + the unused-export tail." },
      "M5-slop": { counted: 1420, total: 1439, note: "#894: MEASURED 2026-07-24 — the corpus's HIGHEST M5-slop reading by an order of magnitude, on the corpus's deepest test surface. This is the target to watch for slop-class precision drift: a large fraction of the count is the single-use-helper class (#391), the same class that moved boxyhq 12->76 and saas-lite 23->79 when it landed." },
      "M6-indicator": { counted: 51, total: 51, note: "#894: MEASURED 2026-07-24 — 51 hand-rolled-shape indicators, the corpus's highest. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 89, total: 106, note: "#894: MEASURED 2026-07-24 — 66 await-in-loop N+1 (the dominant vein), 22 nested-loop joins, 1 client fetch in useEffect, 1 state-sprawl component, 1 oversized-committed-images roll-up; 17 hook-dep Info. #761's unindexed-FK check contributes zero at this pin — recorded so a later non-zero is read as a schema change, not a detector regression." },
      M8: {
        reason: "#894: MEASURED 2026-07-24 — a real suite IS detected (586 test files; #224's zero-coverage finding correctly does not fire), but it is not mutation-scoreable through corpus-m8.yml as that job is built: pnpm workspace, `npm install` resolves 108 root packages only, so apps/web's vitest suite has no node_modules to run against. Same blocker as rallly and carbon, measured on this clone rather than assumed. #894 named this target the M8 pick precisely because 586 specs is the deepest public mutation surface available — realising that needs a pnpm-aware install in the M8 job first, which is the remainder work, not a reason to score 0.",
      },
      "M8-intent": { counted: 305, total: 305, note: "#894: MEASURED 2026-07-24 and the reason this target is pinned — 305 test-intent findings, 100x the corpus's previous maximum (saas-lite's 1). 161 'Call-count-only test', 121 '`vi.hoisted` factory references non-hoisted binding', 10 'Unrestored vi.spyOn leaks across tests', 6 'Test mocks the module it is testing', 2 assertion-free, 2 snapshot-only, 2 happy-path-only on money-critical files (payments.ts, refunds.ts). Every one of these classes now has a real-code drift baseline for the first time; the vi.hoisted class in particular had none." },
      M9: { counted: 52, total: 52, note: "#894: MEASURED 2026-07-24 — the corpus's largest App Router boundary surface: 18 'searchParams read directly in the route component' (Medium), 19 SSR-only API misuse, 7 forced-dynamic cookies()/headers() reads, 2 'Server-exclusive module missing server-only guard' (High) and 5 'Server Action has no input schema validation' (High). The Server-Action-validation class had no real-code baseline before this." },
      M10: { counted: 35, total: 35, note: "#894: MEASURED 2026-07-24 via m10FindingsFromPrismaSchema over apps/web/prisma/schema.prisma. 35 PII-bearing models; Account/Session/User are High (AUTH_TOKEN + credentials)." },
    },
  },
  {
    slug: "documenso",
    repo: "documenso/documenso",
    commit: "c02dfaba1a89f346db785879d39d35a04ec3450b",
    license: "AGPL-3.0",
    provenance: "professional",
    provenanceNote: "#894: org product, large contributor history, commitlint/husky/biome governance, versioned releases. Ships AGENTS.md and gitignores CLAUDE.md — agent tooling used, no AI authorship fingerprints in the pinned source.",
    securityVerdict: "NOT ASSESSED — source-tier quality baselines only (#894). No M1 semantic pass, no dynamic tier, no disclosure filed.",
    schemaPath: "packages/prisma/schema.prisma",
    modules: {
      // #894: this baseline was measured TWICE and the two runs disagreed — recorded here because
      // the disagreement is the finding. Cloned under a deep scratch path, quality-scan printed
      // "M4 duplication: 0% (0/0 lines) — 0 clone cluster(s)" on this 3,395-file repo; cloned by
      // corpus-drift into its own mkdtemp, the SAME pinned tree measures 835 counted / 1,256 total.
      // The number below is the corpus-drift one, because that is the environment the scorer runs
      // in. The zero is still a live product defect: runJscpd maps a missing jscpd report to a
      // synthetic zero-duplication report (#505's "<2 comparable files" branch), so a jscpd run
      // that analysed NOTHING is indistinguishable from a genuinely clone-free repo — the silent
      // under-count the coverage guard forbids. Filed as a follow-up with #894.
      M4: { counted: 835, total: 1256, note: "#894: MEASURED 2026-07-24 in corpus-drift's own clone — 835 counted (54 Medium + 736 Low + 29 Medium/16 Low security-path), 420 Info plus the #365 M4-00 disclosure (166 small clones) for 1,256. SECOND MEASUREMENT, and the first one is on the record above: the same pin cloned to a deeper scratch path produced `0% (0/0 lines) — 0 clone cluster(s)`, a clean bill of health from a run that analysed nothing, because runJscpd cannot distinguish 'jscpd wrote no report' from 'no clones exist'. Trust this number, watch for the zero." },
      "M4-diverged": { counted: 2, total: 2, note: "#894: MEASURED 2026-07-24 — 2 High review-tier diverged security-path clone findings. Notably these fired in BOTH runs, including the one where jscpd's exact-clone pass returned nothing — the diverged pass walks the tree itself instead of shelling out to jscpd, which is what first showed the M4 zero to be an invocation failure rather than a property of the repo." },
      "M5-knip": { counted: 1359, total: 1361, note: "#894: MEASURED 2026-07-24 after `npm install` (2127 packages). 1,311 unused files + unused-export files, with 1/16 scopes in #810 reduced mode (M5-98 Info) and 8/16 flagged uncertain (#580 M5-99 Info) — both disclosure rows are part of the baseline. Measured 1359 in corpus-drift's clone and 1360 in a scratch-path clone of the same pin; 1359 is recorded because that is the scorer's own environment, and the ±1 is on the record here rather than absorbed into a tolerance nobody would see. CAVEAT recorded with the number: 1,311 unused FILES on a turbo monorepo whose entry surface knip cannot fully resolve (8 uncertain scopes says so in the output) is a DRIFT baseline, not a claim that documenso has 1,311 dead files." },
      "M5-slop": { counted: 262, total: 267, note: "#894: MEASURED 2026-07-24." },
      "M6-indicator": { counted: 21, total: 21, note: "#894: MEASURED 2026-07-24 — 21 hand-rolled-shape indicators. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 127, total: 258, note: "#894: MEASURED 2026-07-24 — 127 counted with the corpus's largest Info tail (131 hook-dependency style notes), plus a 16-image/19.1 MB oversized-asset roll-up. The Info tail is itself worth pinning: #230 demoted that class rather than dropping it, and this is the target where the demotion carries the most weight." },
      M8: { counted: 1, total: 1, note: "#894: MEASURED 2026-07-24 — mutation-scan emits exactly one finding, #224's M8-00 zero-coverage finding ('No automated test suite', High). RECORDED WITH ITS KNOWN DEFECT, not as ground truth: this target ships 128 tracked *.spec.ts/*.test.ts files and packages/lib declares `\"test\": \"vitest run\"`, but the ROOT package.json has no `test` script and no test-runner dependency, which is all detectNoTestSuite looks at — so the finding is a FALSE zero-coverage claim on a repo that does have tests. Baselined at 1 because that is what the scanner does today and the drift check must notice when it changes; the fix is tracked in the follow-up issue filed with #894, and this note is what stops the 1 from being read as evidence about documenso." },
      "M8-intent": { counted: 1, total: 1, note: "#894: MEASURED 2026-07-24 — 1 'Call-count-only test' (Low). Note the tension this key exists to keep visible (the saas-lite lesson): a test-intent finding fires here while the mutation tier claims there is no suite at all — the split means neither reading can shadow the other." },
      M9: { counted: 0, total: 1, note: "#894: MEASURED 2026-07-24 — a single Info row, #903's 'M9 N/A — non-SSR SPA'. documenso moved to React Router/Remix, so the App Router boundary module is correctly not-applicable and says so in the output rather than reporting a silent zero. Any counted M9 finding appearing here is a framework-detection regression." },
      M10: { counted: 21, total: 21, note: "#894: MEASURED 2026-07-24 via m10FindingsFromPrismaSchema over packages/prisma/schema.prisma (38,062 bytes). 21 PII-bearing models; User is High, TeamProfile/Passkey Low." },
    },
  },
  // ── #897: the corpus had never seen a LARGE Supabase schema — every Supabase target above is a
  // starter kit with single- to low-double-digit migration counts, so M10's classification, M4's
  // duplication pass and M7's code tier had only ever been measured at small scale. carbon is 859
  // migrations / 4,110 TS files / 36 workspaces, an order of magnitude past anything else pinned.
  // The measurement (wall-clock per module, what degrades, what becomes unusable) is written up in
  // docs/design/carbon-scale-measurement.md; these are the baselines that completed.
  {
    slug: "carbon",
    repo: "crbnos/carbon",
    commit: "92e19c04417e7023a38264315d7846449fd5c4a1",
    license: "none in-tree at this pin (GitHub reports NOASSERTION — all rights reserved by default)",
    provenance: "ai-assisted",
    provenanceNote: "#897: a real commercial ERP/MES/QMS with Rust crates, patches/, a versioned release history and BACKWARD_COMPATIBILITY.md, that also ships CLAUDE.md + AGENTS.md + a .claude/skills tree. Capable-dev-with-AI.",
    securityVerdict: "NOT ASSESSED — #897 is a SCALE measurement, not an audit. The free-tier quick-scan does grade this target F (0/100) on 14 Critical secret findings, and every one inspected is a placeholder credential in self-hosting docs or an example docker-compose; that cry-wolf result is the product finding, recorded in docs/design/carbon-scale-measurement.md and in the follow-up issue, NOT a security verdict on carbon. No disclosure filed and none warranted from this pass.",
    schemaPath: "packages/database/supabase/migrations",
    modules: {
      M4: { counted: 3251, total: 4526, note: "#897: MEASURED 2026-07-24 — the corpus's largest M4 surface by 9x. jscpd completed whole-repo inside quality-scan's 39.4s: no timeout, no hang, no quadratic blow-up at 4,110 TS files. The finding VOLUME is the product finding (see the scale doc), not a scanner failure." },
      "M4-diverged": { counted: 0, total: 0, note: "#897: MEASURED zero 2026-07-24. The strongest FP-floor reading in the corpus: 3,251 exact clones and not one diverged security-path family, so the near-miss pass is not simply tracking repo size." },
      "M5-knip": { counted: 2773, total: 2775, note: "#897: MEASURED 2026-07-24 WITHOUT the target's deps — and that is reproducible in CI, not a local shortcut: `npm install` FAILS on this target with EUNSUPPORTEDPROTOCOL (`catalog:`, a pnpm-catalog dependency), which is exactly what corpus-drift's installTargetDeps swallows. So knip runs in #810's reduced no-dependencies mode across the 36 workspaces and the M5-98 Info row is part of this baseline. A DRIFT baseline, not a dead-code claim." },
      "M5-slop": { counted: 1125, total: 1263, note: "#897: MEASURED 2026-07-24." },
      "M6-indicator": { counted: 48, total: 48, note: "#897: MEASURED 2026-07-24 — 48 hand-rolled-shape indicators across an ERP (MIME-type tables, currency/date formatting, base64url, cookie parsing, random-string ids). All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 673, total: 841, note: "#897: MEASURED 2026-07-24 — the corpus's largest M7 surface. detect-static completed the whole tree in 19.8s." },
      M8: {
        reason: "#897: MEASURED 2026-07-24 — a real suite IS detected (so #224's zero-coverage finding does not apply), but it is not mutation-scoreable through corpus-m8.yml: `npm install` fails outright on this target (EUNSUPPORTEDPROTOCOL: `catalog:`), so no runner and no Stryker can be provisioned by the job as it exists. Same class of blocker as rallly/inbox-zero, one step worse — there the install succeeds but resolves only the root packages. Recorded not-run with the reason rather than 0.",
      },
      "M8-intent": { counted: 3, total: 3, note: "#897: MEASURED 2026-07-24 — 1 'Call-count-only test' (Low) and 2 'Happy-path-only tests on security/money-critical code' (Medium: no-legacy-rls.ts, build-payment-journal.ts). A striking ratio: 77 test files across 4,110 source files produce almost no test-intent signal, because there is barely any test surface to inspect." },
      M9: { counted: 0, total: 1, note: "#897: MEASURED 2026-07-24 — a single Info row, #903's 'M9 not assessed — React Router 7 (framework mode) (framework not supported)'. The App Router module correctly declares itself not-applicable on the largest target in the corpus INSTEAD of returning a silent zero, which is the #903 guard doing its job on real code." },
      M10: { counted: 154, total: 154, note: "#897: MEASURED 2026-07-24 over 859 Supabase migrations — 4,954,187 bytes of SQL classified in 0.1s, 154 PII-bearing tables. The headline scale result: no timeout and no quadratic degradation, the classifier is linear in schema size. The headline QUALITY result is the opposite way round and is recorded in the scale doc — on an ERP carrying employee, supplier and customer records the highest severity produced anywhere in 154 tables is Medium, so the severity model does not separate a real HR/supplier schema from a starter kit's users table." },
    },
  },
  // ── #895: the only Supabase-native PAIRED ground truth that exists — broken and fixed variants of
  // the same lab, side by side. `docs/test-targets.md` recorded "No DVWA-style intentionally-
  // vulnerable Supabase repo exists (confirmed)" on 2026-06-27; that was true then and false by
  // 2026-03 (the repo's own last update), and it sat unchallenged for a month. This entry is the
  // durable fix.
  //
  // THE LABELLING WAS VERIFIED BEFORE IT WAS TRUSTED (#895's step 1), by diffing the migrations AND
  // by standing the lab up live in both states with `pnpm dynamic-validate --execute`. Result and
  // method: docs/design/supabase-security-labs-paired-validation.md. Two things came out of it that
  // no static baseline would have shown: M2 discriminates the pair correctly (3 cross-tenant Highs
  // on `families` that vanish when the fix migration is applied, none introduced), and the lab's own
  // "fixed" variant STILL leaks `public.profiles` to anon — an unlabelled bug in the target's own
  // ground truth.
  //
  // Licence NONE (all rights reserved by default), same constraint as Wallens11: pinned-clone
  // manifest only, never vendored into targets/ and never distilled into a *.entries.ts.
  {
    slug: "supabase-security-labs",
    repo: "elamilutinovic-vibePep/supabase-security-labs",
    commit: "c8ac29b9c19c1064212bd296c3712909924f9b22",
    license: "none (no LICENSE file — all rights reserved)",
    provenance: "ai-generated",
    provenanceNote: "#895: an unstarred single-author teaching-lab repo that is mostly prose docs plus small SQL/Deno artefacts, with the uniform structure and narration of generated material. Recorded ai-generated on that evidence; the important point is that its LABELLING was verified independently rather than trusted (see the paired-validation doc), which is what #895 asked for.",
    securityVerdict: "N/A by construction — this target's vulnerabilities are DELIBERATE and documented by its own author. Nothing here is a disclosure candidate. What is recorded instead is the PAIRED result: Harvey's M2 tier proves the planted cross-tenant `families` leak live and clears it on the fixed variant, while the M1 static mechanical tier produces byte-identical output on both. Detail: docs/design/supabase-security-labs-paired-validation.md.",
    schemaPath: "rls-broken-lab/supabase/migrations",
    modules: {
      M4: { counted: 1, total: 5, note: "#895: MEASURED 2026-07-24 — 1 counted (Low) + 3 Info + the #365 M4-00 disclosure. A near-floor reading: this repo is prose docs plus a handful of small SQL and Deno files, so the source-tier quality modules are all at or near zero here BY CONSTRUCTION. Their value in the corpus is as an FP floor, not as a duplication signal; the target earns its place on the M1/M2 paired result, not on these numbers." },
      "M4-diverged": { counted: 0, total: 0, note: "#895: MEASURED zero 2026-07-24 — FP floor." },
      "M5-knip": { counted: 0, total: 1, note: "#895: MEASURED 2026-07-24 — zero counted, with the #505 M5-00 'did not complete for every workspace' Info disclosure present. That disclosure IS the baseline's honesty: there is no package.json here for knip to resolve entries from, and the run says so instead of reporting a clean zero." },
      "M5-slop": { counted: 0, total: 4, note: "#895: MEASURED 2026-07-24 — zero counted, 4 'Decorative emoji in a comment' Info. FP floor." },
      "M6-indicator": { counted: 0, total: 0, note: "#895: MEASURED zero 2026-07-24. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 0, total: 0, note: "#895: MEASURED zero 2026-07-24 — FP floor. Any M7 finding appearing on a repo of SQL and two 40-line Deno functions is almost certainly a new over-match." },
      M8: { counted: 1, total: 1, note: "#895: MEASURED 2026-07-24 — #224's M8-00 zero-coverage finding (High), which IS the measurement: zero test files, no test script. Correct here, unlike the same finding on documenso." },
      "M8-intent": { counted: 0, total: 0, note: "#895: MEASURED zero 2026-07-24 — no test files to inspect, so the M8-00 above is this target's whole M8 story." },
      M9: { counted: 0, total: 0, note: "#895: MEASURED zero 2026-07-24 — no Next.js app here at all." },
      M10: { counted: 2, total: 2, note: "#895: MEASURED 2026-07-24 over rls-broken-lab/supabase/migrations — profiles and posts, both Low. Chosen as the schemaPath over the other two labs' migration dirs because it is the one whose broken/fixed pair is the point of the target." },
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
  // #322: the tree this module's number describes — "whole-repo" unless the target declares a
  // per-module scan root. Recorded on every row of a target whose modules disagree on scope, so
  // two numbers over different trees can never sit side by side looking comparable.
  scope: string;
}

// #300: scores a REAL Stryker run against a target's recorded MutationBaseline. Exact equality on
// killed/valid is the DEFAULT (tolerance 0): the target tree is pinned, so a change in the count
// should mean something moved, and comparing counts (not just the rounded score) means a change
// that swaps a killed mutant for a survivor at a constant percentage still fails — that is a real
// test-quality movement, and the percentage alone would hide it.
//
// #432 corrected this comment's original claim that "the mutators are deterministic, so the same
// suite against the same code kills the same mutants" — that is false in general. boxyhq's suite
// includes a test that calls Math.random() itself (unseeded, in the TARGET's own spec, not in
// Stryker), so which of two adjacent mutants gets killed depends on whether that call happens to
// land even or odd — measured 2026-07-16 (issue #432) as a genuine ~50/50 split of 7/35 vs 8/35
// killed across 4 runs, never anything outside that pair. `tolerance` exists for exactly this:
// earned per-target by measuring instability across multiple runs, not applied defensively.
//
// A drift outside the tolerance band is EITHER the target's suite/config changing under us
// (rebaseline with the measured note) OR our wrapper mis-reading Stryker's report (a scanner bug).
// As everywhere else in this file, the scorer refuses to guess which — it just refuses to be quiet.
export function scoreMutationBaseline(
  slug: string,
  baseline: MutationBaseline,
  actual: { mutationScore: number; killed: number; valid: number },
): DriftRow {
  const pass = Math.abs(actual.killed - baseline.killed) <= (baseline.tolerance ?? 0) && actual.valid === baseline.valid;
  return {
    slug,
    module: "M8",
    expected: baseline.killed,
    actual: actual.killed,
    drift: actual.killed - baseline.killed,
    pass,
    scope: "whole-repo", // the mutate-glob subset is already stated in the claim itself (#319)
    // #319: even the drift line states the covered scope — the score never appears bare, so a
    // reader of the scorecard sees "20% over lib/server-common.ts", not a repo-level "20%".
    detail: pass
      ? `matches baseline: ${formatMutationClaim(baseline)}`
      : `DRIFT: expected ${formatMutationClaim(baseline)}, got ${actual.killed}/${actual.valid} (${actual.mutationScore}%) — the target's suite moved (rebaseline) or the wrapper mis-read the report (fix the scanner)`,
  };
}

// quality-scan's knip pass emits every M5 finding under this one literal taxonomy string; nothing
// else in the codebase uses it. #278: M5-slop is everything ELSE prefixed "M5 " (detect-static's
// 11 style classes — else-after-return, single-call wrapper, etc, src/detectors/slop.ts) — matched
// by exclusion rather than an enumerated list, so a new slop class detect-static adds later is
// still scored under M5-slop without this file needing an update to notice it.
const M5_KNIP_TAXONOMY = "M5 — Slop / dead code";

// The mutation tier's own finding taxonomies (src/mutation-scan.ts M8-00/M8-02, src/stub-check.ts
// M8-01) — a closed set, unlike detect-static's growing test-intent family, so "M8" enumerates
// these and "M8-intent" matches the rest of the "M8 " prefix by exclusion (the same open/closed
// pattern as M5-knip/M5-slop above: a new test-intent class is scored without touching this file).
const M8_MUTATION_TAXONOMIES = new Set([
  "M8 — No automated test suite",
  "M8 — Survives implementation deletion",
  "M8 — Denial/boundary path untested",
]);

// Exported for corpus-drift.ts's per-module scan-root pass (#322), which needs to swap one
// module's findings for its scoped run without disturbing any other module's.
export function moduleMatches(taxonomy: string, module: string): boolean {
  if (module === "M5-knip") return taxonomy === M5_KNIP_TAXONOMY;
  if (module === "M5-slop") return taxonomy.startsWith("M5 ") && taxonomy !== M5_KNIP_TAXONOMY;
  // #360: same shared-prefix split as M5 — the diverged-clone pass emits under an "M4 —" taxonomy
  // but drifts independently of jscpd, so it is scored as its own module.
  if (module === "M4-diverged") return taxonomy === M4_DIVERGED_TAXONOMY;
  if (module === "M4") return taxonomy.startsWith("M4 ") && taxonomy !== M4_DIVERGED_TAXONOMY;
  if (module === "M8") return M8_MUTATION_TAXONOMIES.has(taxonomy);
  if (module === "M8-intent") return taxonomy.startsWith("M8 ") && !M8_MUTATION_TAXONOMIES.has(taxonomy);
  // #483: handrolled.ts's indicators share M6's taxonomy prefix but are namespaced "M6 —
  // Indicator: …" specifically (there is no other "M6 " taxonomy in the codebase today) — matched
  // explicitly rather than by the generic prefix so a future non-indicator M6 class (the paid
  // triage tier) doesn't fall into this module by accident.
  if (module === "M6-indicator") return taxonomy.startsWith("M6 — Indicator:");
  return taxonomy.startsWith(`${module} `);
}

// #483: M6-indicator findings are ALL severity "Info" by construction (#267's non-grading
// ruling) — excluding Info the way every other module does would score this baseline's `counted`
// as 0 on every target forever, making the drift check permanently unable to fail. Every match
// counts here regardless of severity.
function countedFor(findings: Finding[], module: string): number {
  const includeInfo = module === "M6-indicator";
  return findings.filter((f) => moduleMatches(f.taxonomy, module) && (includeInfo || f.severity !== "Info")).length;
}

// #321: the coverage guard fails loud on SILENCE (a module omitted with no reason) but is trusting
// of stated REASONS — and a not-run reason is a claim about the world that decays. saas-lite's
// M5-knip is blocked by an upstream eslint-patch bug that may resolve on a dependency bump; boxyhq's
// M10 was recorded not-run for "Prisma unparseable" long after #299 made it parseable, and only got
// caught because someone happened to work the parser. Nothing re-tested these.
//
// This closes that blind spot cheaply: the drift run ALREADY re-attempts every source-tier module
// on each pass (quality-scan runs knip whether or not the manifest thinks it can). So a module
// recorded not-run that nonetheless PRODUCES real findings this run is a reason that has outlived
// its truth — the run now says so, loudly, as a failing row. The scheduled job installs each
// target's deps first (corpus-drift.yml --install), so saas-lite's knip is re-tested exactly when
// its dependency tree moves, which is #321's specific ask.
//
// "did not run" disclosures (knip's #223 M5-00, mutation-scan's #224 M8-00) are NOT evidence the
// module now runs — they are the tool reporting it still couldn't — so they don't count as output.
const DID_NOT_RUN_SENTINELS = new Set(["M5-00", "M8-00"]);

export function revalidateNotRunReasons(target: ExternalTarget, findings: Finding[]): DriftRow[] {
  return Object.entries(target.modules).flatMap(([module, baseline]) => {
    if (!isNotRun(baseline)) return [];
    const produced = findings.filter((f) => moduleMatches(f.taxonomy, module) && !DID_NOT_RUN_SENTINELS.has(f.id));
    if (produced.length === 0) return []; // reason still holds — the module produced no real output this run
    return [{
      slug: target.slug,
      module,
      expected: 0,
      actual: produced.length,
      drift: produced.length,
      pass: false,
      scope: scanScopeOf(target, module),
      detail: `NOT-RUN REASON MAY BE STALE: ${module} is recorded not-run ("${baseline.reason.slice(0, 90)}…") but this run produced ${produced.length} real ${module} finding(s) — the reason has outlived its truth. Re-verify, then measure a baseline for this module (replacing the not-run reason) or correct the reason.`,
    }];
  });
}

// #322: the tree a module's number describes. Only a target with declared scanRoots ever differs
// from "whole-repo"; on such a target the scope is appended to every scored row's detail so the
// modules' disagreement about what tree they measured can never be silent.
function scanScopeOf(target: ExternalTarget, module: string): string {
  return (target.scanRoots as Partial<Record<string, string>> | undefined)?.[module] ?? "whole-repo";
}

// Scores a real scan of `target`'s pinned commit against its recorded baseline. Exact equality:
// these are deterministic AST/text passes over a frozen tree, so any movement is a real change in
// scanner behavior and should be looked at — either a precision fix (update the baseline in the
// same PR) or a regression (fix the scanner). A tolerance band would just hide small drifts.
// Modules recorded as not-run are skipped, never scored 0 — a 0 would read as "clean".
export function scoreExternalBaseline(target: ExternalTarget, findings: Finding[]): DriftRow[] {
  const hasRoots = Object.keys(target.scanRoots ?? {}).length > 0;
  return Object.entries(target.modules).flatMap(([module, baseline]) => {
    if (isNotRun(baseline)) return [];
    // #300: an M8 MutationBaseline is a percentage, not a finding count — scoreMutationBaseline
    // scores it from the Stryker report. Counting findings here would score it 0 and read as
    // "no M8 problems" on a target whose suite was never mutated.
    if (isMutationBaseline(baseline)) return [];
    const actual = countedFor(findings, module);
    const drift = actual - baseline.counted;
    const scope = scanScopeOf(target, module);
    const scopeNote = hasRoots ? ` [scanned scope: ${scope}]` : "";
    return [{
      slug: target.slug,
      module,
      expected: baseline.counted,
      actual,
      drift,
      pass: drift === 0,
      scope,
      detail: (drift === 0
        ? `matches baseline (${baseline.counted} counted)`
        : `DRIFT ${drift > 0 ? "+" : ""}${drift}: expected ${baseline.counted} counted, got ${actual} — a precision fix (update the baseline) or a regression (fix the scanner)`) + scopeNote,
    }];
  });
}
