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
import type { Finding, Severity } from "../findings.js";
import type { QuickScanReport } from "../quick-scan.js";
import { DOC_CONTEXT_CREDENTIAL_TAXONOMY } from "./secrets.js";
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
//
// #1436 added `falsifier`, and the answer to that issue's "gains the structure or moves to where the
// registry can see it — decide which, and say why" is BOTH, because each half closes a hole the
// other leaves open.
//
// The reasons MOVE: every not-run below now carries a `REASON:`/`KIND:`/`PROVENANCE:`/`FALSIFIER:`
// block in the comment above it. `collectReasons` already reads every `.ts` file under `src/`, so
// that alone is what puts these claims inside `pnpm validate-reasons --revalidate` — no new plumbing,
// and the same convention every other recorded reason in the repo uses.
//
// The type ALSO gains the structure, because a comment can be deleted while the object stays, and
// then the module is silently unwatched again — the exact failure mode this issue exists to close.
// A required `falsifier` makes a reason-less not-run fail to compile, and
// external-corpus.test.ts's "#1436" block asserts every one of these strings appears verbatim as the
// `FALSIFIER:` of a parsed block in this file. Deleting the block therefore fails the suite rather
// than quietly un-watching the claim.
export interface ModuleNotRun {
  reason: string;
  /**
   * The command that EXITS 0 WHEN THIS BLOCKER IS GONE — the one-way contract from
   * src/recorded-reasons.ts. Non-zero = still blocked; 127 = could not be verified, which fails the
   * gate rather than passing as "still blocked" (#1426: a bare `grep` exits 2 and a broken pipe
   * exits 1, so every falsifier here ends in an explicit `exit 0` / `exit 1`).
   */
  falsifier: string;
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
  // "M1-boundary" (#1459) is the M9 boundary pass's own authorization output — server-mutation
  // missing-auth and client-supplied-owner-id — which #221 routes to an `M1 —` taxonomy. It shares
  // no prefix with any M9 baseline, so before this key those rows were scored by nothing at all and
  // the detectors producing them could be deleted without moving a number. It is scored on every
  // target for the same reason M5-slop and M6-indicator are: detect-static needs no install, so a
  // zero here is a real FP floor rather than an absent measurement.
  modules: Partial<Record<"M4" | "M4-diverged" | "M5-knip" | "M5-slop" | "M6-indicator" | "M7" | "M8-intent" | "M9" | "M10", ModuleBaseline | ModuleNotRun>>
    & { M8: ModuleBaseline | ModuleNotRun | MutationBaseline; "M1-boundary": ModuleBaseline | ModuleNotRun };
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
  // #1524: clone-relative directories DELETED from the disposable clone before any module scans
  // it — for a target that vendors another project's full source tree inside its own repo (a
  // reference copy, not application code). Without this, every whole-repo module counts the
  // vendored tree's own findings as this target's baseline: MEASURED on effective (this PR),
  // `repos/effect` (a full checkout of the Effect-TS monorepo, 1769 files / ~501k lines) produced
  // 2699 of 2713 static-detect findings (99.5%) and 2682 of 2699 quality-scan findings (99.4%) —
  // a baseline that would be almost entirely about a third-party library's own duplication/test
  // shapes, not this target's ~47-file app. `schemaPath` and `installTargetDeps` are unaffected:
  // both resolve against the clone ROOT, which this never touches.
  vendoredSubtrees?: string[];
}

export function isNotRun(m: ModuleBaseline | ModuleNotRun | MutationBaseline): m is ModuleNotRun {
  return "reason" in m;
}

// #251: the Layer 2 job now installs each clone's own dependency tree before quality-scan
// (installTargetDeps in src/cli/corpus-drift.ts), which is the prereq CLAUDE.md's M5 row names — so
// "needs the target's install" is no longer a reason for anything. #1268 (2026-07-28) made that
// install use the package manager the TARGET's own lockfile implies rather than always npm; #1404
// then re-measured the four M5-knip baselines that moved as a result (carbon, inbox-zero, rallly,
// saas-lite), all downward, all proven precision fixes by a controlled npm-vs-pnpm before/after on
// the identical pinned clone. Measured 2026-07-15 with deps installed: proposit
// (85) and boxyhq (12) now carry real baselines. #322's per-module scan root then gave
// mvp-boilerplate a scoped measurement over nextjs/ (see its entry). #544: saas-lite — the last
// M5-knip not-run — gained a measured baseline once #519 made knip run PER WORKSPACE (the old
// whole-repo run died loading apps/web's eslint config, which is what the retired
// M5_KNIP_ESLINT_PATCH_BROKEN reason recorded); NO M5-knip is not-run now. Installing is inert for
// the rest of the corpus: M4 reproduced byte-identically on all four installable targets, and the
// two M5-knip baselines that already scored without deps (subscription-payments 8,
// multi-tenant-starter 2) were re-measured WITH deps and did not move.

// #300: M8 on the targets WITH a real suite now runs for real, in .github/workflows/corpus-m8.yml —
// a per-target install (npm until #1268, the target's own lockfile-implied package manager since),
// a vendored Stryker config (src/scan/m8-corpus.ts), and a timeout that matches the actual cost.
// RE-DERIVED 2026-07-31 (#1693) from this file's own 17 entries, because the sentence here counted
// "5 suite-carrying targets" and then named seven, and the en-route fix that was meant to correct
// it wrote THREE in front of four names. The split, by what actually measures each target's M8:
// FIVE carry an M8_CORPUS_CONFIGS entry and are mutation-scored by corpus-m8.yml — proposit,
// boxyhq, inbox-zero, rallly (#1268 added the latter two) and multi-tenant-starter, the only one
// that does NOT score the target's own suite (#1496's vendored DB-free suite, below). SIX record an
// M8 not-run with a measured reason and a falsifier: saas-lite, carbon, ghostfolio, tanstack-com,
// cravab, flori-web — every one of them DOES carry a real suite, which is why "suite-carrying" was
// never the line the old sentence drew. The remaining SIX have no percentage to report at all: a
// finding IS their measurement (#224's M8-00 zero-coverage on five of them, #932's M8-04
// workspace measurement-gap on documenso). Counts go stale — re-derive them from `modules.M8`
// rather than quoting this comment.
//
// #277 predicted boxyhq was blocked by its Playwright E2E specs needing a built app + browser.
// That was WRONG, and re-measuring rather than transcribing is what caught it: boxyhq's own
// jest.config.js already sets `testPathIgnorePatterns: ['<rootDir>/tests/e2e']`, so the jest runner
// never sees a Playwright spec. It scores 20% today (measured, 7/35). The targets WITHOUT a suite
// are different again — they need no Stryker at all, because #224's zero-coverage finding IS the
// measurement.
//
// #1436 split multi-tenant-starter's old single not-run reason in two, because it ran a FACT and a
// BUDGET RULING together and gave the ruling the fact's authority: the empirical half (its only
// suite starts a Docker Postgres container per invocation, so Stryker's per-mutant re-invocation
// means one container start per mutant) is still true and still watched — see rls.test.mjs's own
// FALSIFIER below, unchanged. #1496 is where the DECISIONAL half was ASKED, and the 2026-07-31
// operator ruling did not pick "pay it" or "decline it" — it picked REWORK: stub the DB layer so
// mutants run without Docker at all, rather than scoring the RLS suite. src/scan/m8-corpus.ts's
// `extraFiles` (a NEW field, #1496) vendors a standalone vitest suite for
// lib/security/guards.ts's role-hierarchy authorization logic (requireAuth/requireTenantAccess/
// requireTenantAdmin) into the disposable clone before Stryker runs, stubbing the two calls that
// file makes into the DB layer (createServerSupabaseClient's .auth.getUser(), tenants.ts's
// getUserTenantRole) — never a real Postgres connection. See this target's M8 baseline below for
// the accepted trade and the measured numbers.
//
// REASON: multi-tenant-starter's ORIGINAL suite (test/rls.test.mjs) starts a throwaway Docker Postgres container in its own `before()` hook and stops it in `after()`, so every whole-suite invocation is one container start — Stryker's command runner would re-invoke the whole suite per mutant, which is why #1496's vendored suite (below) runs against a DIFFERENT, DB-free test file instead of this one
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-28 — re-read at the pin (dcc147c) and at upstream HEAD. test/rls.test.mjs lines 16-53: a `docker()` helper wrapping `spawnSync('docker', ...)`, `before()` running `docker run --rm -d ... postgres:15-alpine`, `after()` running `docker stop`. package.json `test` is still `node --test test/rls.test.mjs` and it is still the repo's only test file.
// FALSIFIER: sh -c 'command -v curl >/dev/null 2>&1 || exit 127; body=$(curl -fsS --max-time 20 https://raw.githubusercontent.com/Wallens11/supabase-multi-tenant-starter/HEAD/test/rls.test.mjs) || exit 127; case "$body" in *docker*) exit 1;; *) exit 0;; esac'
// TOUCHES: src/scan/m8-corpus.ts

// REASON: saas-lite has no unit suite for Stryker to mutate — every test file it ships is a Playwright E2E spec under apps/e2e, needing a built app, a browser and a live Supabase stack
// KIND: empirical
// PROVENANCE: MEASURED 2026-07-28 — re-tested rather than transcribed, at the pin (37def9c) and at upstream HEAD. The pinned tree holds exactly three `*.spec.ts`, all under apps/e2e/tests, and no vitest.config/jest.config anywhere; the root `test` script is `turbo test` and the only package declaring one is apps/e2e (`playwright test`). The upstream tree API returns the same three, still all under apps/e2e/.
// FALSIFIER: sh -c 'command -v curl >/dev/null 2>&1 || exit 127; t=$(curl -fsS --max-time 30 "https://api.github.com/repos/makerkit/nextjs-saas-starter-kit-lite/git/trees/HEAD?recursive=1") || exit 127; n=$(printf %s "$t" | tr "," "\n" | sed -n "s/.*\"path\": *\"\([^\"]*\)\".*/\1/p" | grep -v "^apps/e2e/" | grep -Ec "([.](test|spec)[.][jt]sx?$|(vitest|jest)[.]config)"); [ "$n" -gt 0 ] && exit 0 || exit 1'
// TOUCHES: src/scan/m8-corpus.ts
const M8_E2E_ONLY_SUITE: ModuleNotRun = {
  reason: "Measured 2026-07-15, re-verified 2026-07-17 and again 2026-07-28 (at the pin AND at upstream HEAD): this target's `turbo test` orchestrates apps/e2e, whose 3 specs are ALL Playwright E2E (account/auth/password-reset) needing a built app, a browser and a live Supabase stack. There is no unit suite to mutate — so unlike boxyhq (whose jest config ignores its E2E dir and scores fine), scoping a Stryker config here has nothing to point at. #252's decided rule agrees this is NOT 'suite absent' (that threshold is zero test files or a single placeholder spec; these are 3 real specs), so no M8-00 zero-coverage finding applies — the suite exists, it just isn't unit-mutable, and this stays not-run with the reason. The static test-intent tier is measured separately under M8-intent.",
  falsifier: "sh -c 'command -v curl >/dev/null 2>&1 || exit 127; t=$(curl -fsS --max-time 30 \"https://api.github.com/repos/makerkit/nextjs-saas-starter-kit-lite/git/trees/HEAD?recursive=1\") || exit 127; n=$(printf %s \"$t\" | tr \",\" \"\\n\" | sed -n \"s/.*\\\"path\\\": *\\\"\\([^\\\"]*\\)\\\".*/\\1/p\" | grep -v \"^apps/e2e/\" | grep -Ec \"([.](test|spec)[.][jt]sx?$|(vitest|jest)[.]config)\"); [ \"$n\" -gt 0 ] && exit 0 || exit 1'",
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
      "M1-boundary": { counted: 4, total: 4, note: "#1459: MEASURED 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — 4 High rows, and the split matters because it shows this key is not just the missing-auth class: 1 `M1 — Server Action missing authorization check` plus 3 `M1 — Client-supplied owner id trusted by unauthenticated service-role action` (create-organisation/actions.ts:45, invitation-actions.ts:40, user-actions.ts:22). The owner-id detector is the other half of the M9 boundary pass that #221 routes to an M1 taxonomy, and it was scored by nothing for exactly the same reason. NOT TRIAGED: a drift baseline for a class no baseline scored before today, not a defect count. #1434: RE-VERIFIED 2026-07-31, NO MOVE. This is the ONLY pinned target carrying `Client-supplied owner id` rows, so it is where #1434 could move a number at all. Controlled before/after `pnpm exec tsx src/cli/static-detect.ts <clone-of-82838ce>`, one variable (the #1434 diff, before arm run with app-router.ts restored from HEAD): both arms 131 findings, 0 rows only-before, 0 only-after, and the after arm reprints all 4 rows at the three locations named above. Load-bearing rather than a formality — #1434 both NARROWS (a resolvable denying auth helper now suppresses) and WIDENS (a comment or string literal no longer vouches), so a no-move says neither direction found a population here, not that the diff was inert. #1501: TRIAGED 2026-07-31, and the count does not move: 4/4, all still reported, all four READ AGAINST SOURCE. Unlike inbox-zero's and carbon's, THESE ARE REAL. All four are EXPORTED Server Actions in 'use server' modules. Three take a caller-supplied user id straight into a SERVICE-ROLE (RLS-bypassing) write with no authentication anywhere in the function: createOrganisationAction(userId, ...) inserts `organisation_users { user_id: userId, role: 'admin' }` (actions.ts:45); acceptInvitationAction inserts `organisation_users { user_id: userId, role: 'member' }` (invitation-actions.ts:40); updateUserProfileAction(userId, profileData) writes `users` `.eq('id', userId)` (user-actions.ts:22) - any caller can rewrite any user's profile. The fourth, updateOrganisationLogo (actions.ts:70), has no code-level authorisation either but uses the request-scoped `createClient()`, so RLS is the only control and whether it holds is a live-tier question this pass cannot answer. So this baseline stands behind 3 rows confirmed real and 1 row whose control is out of static reach and stated as such - a RECALL floor, not an FP floor." },
      M4: { counted: 100, total: 145, note: "5.27% (2749/52165 lines), 203 raw clone clusters — 104 individual cross-file findings, 73 counted, plus the #365 M4-00 small-clone disclosure (44 sub-10-line clones, Info) for 105 total. Re-measured 2026-07-16: counted 68->73 because #361 elevates security-path clones one tier — 5 sub-15-line clones in components/auth/* + lib/supabase/server.ts moved Info->Low (10 clones total carry the elevation, the other 5 were already counted). Was 9.75%/199 clones pre-#232; the drop is that fix excluding generated/demo paths, NOT the repo changing. Per #232 ~75% of what remains is genuine per-entity copy-paste (CRUD forms, per-entity tool/store/service files) — the corpus's strongest real M4 signal and a factory-refactor case. #251 measured the install step inert for M4. #1128: RE-MEASURED 2026-07-26 at 100/145 (was 73/105) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target proposit --install` reproduced 100 counted. (Discovered outside the issue's original 12-row table, which predates #1129 — the same cause CI's post-merge run surfaced on proposit/subscription-payments/boxyhq/multi-tenant-starter too.)" },
      "M4-diverged": { counted: 14, total: 14, note: "#360: measured 2026-07-16 — 20 security-path files, 1 diverged family (High, review tier). Small for the corpus's worst M4 target because its per-entity copies live under lib/ai/tools/* and lib/stores/*, which don't hit SECURITY_PATH_KEYWORDS — the pass is deliberately scoped to auth/guard/middleware/security paths. Re-measured 2026-07-17 (#399): 1->12 after widening file selection to ALSO admit files whose BODY scopes a supabase query by a tenant key (touchesTenantSupabasePath) — this target's file count went 20->57 (37 more admitted via content, mostly exactly the predicted lib/ai/tools/*-tools.ts and lib/*-service.ts per-entity vein), surfacing 11 more diverged families in that vein. #1128: RE-MEASURED 2026-07-26 at 14/14 (was 12/12) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 2 more such pairs now qualify. `pnpm corpus-drift --target proposit --install` reproduced 14 counted." },
      "M5-knip": { counted: 61, total: 61, note: "#940: RE-MEASURED 2026-07-24 at 57 (was 85) — a PRECISION FIX, not a regression, PROVEN by controlled before/after on the identical pinned clone: reverting the knip-runner changes to their pre-#694 state reprints exactly 85, the current code 57. Cause is the three knip-runner PRs that landed 2026-07-20 AFTER that morning's last-green scheduled run: #695 injects knip's `ignoreExportsUsedInFile: {interface,type}` so type/interface exports used within their own file (component Props exported by convention, etc.) are no longer reported as unused; #694 splits the remaining unused exported TYPES into a review-tier finding; #697 generates entry config for config-less scopes. Value-export dead-code detection is unchanged — the drop is confined to in-file-used type exports (correctly suppressed), not lost value dead code. New breakdown: 7 unused files + 47 unused value-export files + 2 exported-unreferenced-type (review) findings, 10 Review / 47 Confirmed confidence. Prior triage below is retained for context. #251 measured this, #320 triaged it (2026-07-17, reproduced by cloning the pin + `npm install --legacy-peer-deps` + Harvey's own knip, exact reprint of 85: 83 Low + 2 Medium). VERDICT: none of the 85 are knip config/barrel-re-export artifacts — every spot-checked item is a real unreferenced file or export — but only ~41 are actionable dead code a client would expect from '85 findings': 8 unused files + 33 of the 77 unused-export files (incl. an orphaned 11-function/3-const pagination subsystem in lib/pdf-pagination.ts, live only via 2 of its 16 exports). The other 44 unused-export files are real-but-low-value from two mechanical, recurring shapes, not repo-specific slop: 19 are per-entity `FooService` classes whose singleton instance (`export const fooService = new FooService()`) is used everywhere but the class NAME itself never is — trivial to silence (drop `export` on the class), not code to delete; 25 are shadcn/ui (components/ui/*, 15) + Vercel ai-elements (components/elements/*, 10) generated component-kit sub-exports — the kit ships a full API surface, this app uses a subset, and this shape will recur on every shadcn/ai-elements corpus target. SECURITY (#226 cross-link): 2 of the 85 sit on auth-adjacent paths, called out per acceptance criteria, neither itself the live vuln — lib/supabase/middleware.ts (Medium, unused FILE) is the standard Supabase SSR session-refresh/redirect helper, fully unwired (the repo's actual middleware.ts only runs next-intl); auth is enforced per-page via lib/auth.ts's getUser() instead, so this isn't a live gap, but it is exactly the 'guard written, never wired in' shape #226 exists to catch. lib/auth.ts (Medium, 4 unused exports: getUserProfile/getUserOrganization/createUserProfile/createOrganisationMembership) are orphaned duplicates superseded by lib/users-service.ts and the real invitation-acceptance path (lib/actions/invitation-actions.ts) — createOrganisationMembership takes a caller-supplied `role` string, which reads alarmingly next to this repo's own disclosed High (member self-escalation to admin, #214) but is dead, so it is not that vector; still worth deleting so a future reviewer doesn't mistake it for the live authorization path. #1128: RE-MEASURED 2026-07-26 at 61/61 (was 57/57) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories now surface. `pnpm corpus-drift --target proposit --install` reproduced 61 counted. #1404: RE-MEASURED 2026-07-28 at 61/61 — NO MOVE, and that is the load-bearing result, not a formality. This target is the CONTROL for #1404's four downward M5-knip drifts (carbon -2307, inbox-zero -13, rallly -6, saas-lite -6): it carries a pnpm-lock.yaml, so #1268 routes it to `pnpm install` too, but it declares no workspaces — so pnpm and npm resolve an identical tree and the count cannot move. Its stillness is what shows those four deltas are the workspace-member resolution and not a knip version or behaviour change. Zero reduced scopes and zero M5-98/M5-99 disclosure rows here, in both arms." },
      "M5-slop": { counted: 24, total: 34, note: "#1532: RE-MEASURED 2026-07-30 at 24/34 (was 28/38) — DRIFT -4, a PRECISION FIX taken against a NARROWED scanner, not a rebaseline around the regression. Cause is #370/#1447 (commit dfff5a8, merged 2026-07-30): `detectSingleUseHelper` now spares a helper that does no I/O of its own whose sole call site sits inside an async/awaiting function — the testability seam `briefs/quality-extras.txt` demands. That PR's corpus gate had NEVER EXECUTED (#1509's pipx cache bug killed the job at setup), so the exemption reached `main` unmeasured. MEASURED over all ten targets: it spares 653 candidates, up to 26% of a single target's M5-slop. A seeded random sample of 50 (mulberry32, seed 20260730, over the population sorted by target|file|line|helper) was READ AT SOURCE and graded against the exemption's own premise: 45 held, 5 did not, and all 5 failed the same half — the HELPER was doing the I/O, by a mechanism `await`-freedom structurally cannot see (`spawnSync`, `spawn`, `existsSync`, a hand-rolled `new Promise` over stream events). 10% wrongly spared, Wilson 95% CI [4.3%, 21.4%]. #1532's `doesOwnIo` closes that half and recovers 42 findings corpus-wide, including all 5 sampled defects; 0 of this target's 4 spared rows was in that class. The 4 still spared here are the exemption working as designed (all 4 read at source: 3x `topologicalSort`, `createTransporter`); 0 of the 45 remaining sampled rows corpus-wide was wrongly spared, one-sided 95% upper bound 6.4%. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-82838ce> --out f.json`. Two sub-populations are DISCLOSED, not narrowed, because the sample says neither is reliably a defect: 401 of 653 have a caller whose awaits never touch the helper's result, and 39 have a caller declared `async` that awaits nothing at all (mixed — #1533). Prior note: Re-measured 2026-07-17: 6->28 counted after #391 added the unused-parameter/unused-import/single-use-helper/unreachable-branch classes — 22 'Single-use helper' + 3 'Single-call wrapper' + 3 'Else after return' counted; 10 'Narrating comment' Info. The single-use-helper vein is the same per-entity scaffolding M4/M5-knip already flag on this target." },
      "M6-indicator": { counted: 10, total: 10, note: "#483: MEASURED 2026-07-17 via detect-static's handrolled-shape pass — 4 'currency formatting', 2 'JSON deep-equal', 1 each of 'email-shape regex', 'cookie parsing', 'base64url conversion', 'raw-millisecond date math'. The corpus's highest reading — proposit's per-entity scaffolding (lib/ai/tools/*, lib/*-service.ts) reinvents several standard shapes by hand, consistent with its M4/M5-knip per-entity vein. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      // #1261 — THE FIELD PRECISION RECORD for the whole M7 code tier. Read this before quoting any
      // M7 precision number anywhere.
      //
      // #816's acceptance asked for "a re-run of the 6-repo triage". PR #833 reported 84.6% -> 100%
      // on a labeled corpus THE SAME PR AUTHORED. CLAUDE.md rules that out — an answer key we wrote
      // measures internal consistency only — and the field instrument was one command away. So it
      // was re-run here, against the pins, 2026-07-28.
      //
      // (1) WHAT #816's FOUR GUARDS ACTUALLY DID IN THE FIELD: NOTHING. Controlled one-commit
      // before/after — `static-detect` at 17a6b7b^ and at 17a6b7b, same six pinned clones, one
      // variable — reprints IDENTICAL per-class counts on all six (64/97 both arms). The four
      // guards (for-of over a const list, sort of a static const list in JSX, `select("*").eq("id")`
      // PK lookup, module-scope JSON deep-clone) matched nothing on any of the six repos whose
      // triage produced the ~10% figure that motivated them. The 100% is a corpus movement only.
      //
      // (2) THE FIELD NUMBER, by triage rather than by property check. Every one of the 65 graded
      // (non-Info) M7 rows on the six repos was read against its own source: 47 hold, 18 do not —
      // 72.3%. Corroborated on the four largest pinned targets (rallly/inbox-zero/ghostfolio/carbon,
      // 858 graded rows) by a seeded random sample of 40, also read individually: 31/40 = 77.5%,
      // 95% Wilson CI 62.5-87.7%. Pooled 78/105 = 74.3%. The two agree; ~3 in 4 is the honest claim.
      //
      // Per class over the six (n, precision): unbounded select 27, 100% | client fetch in useEffect
      // 3, 100% | Prisma unindexed FK 2, 100% | fetch in middleware 1 | blocking sync I/O 1 | React
      // Compiler flag unresolvable 1 (a disclosure row, correct) | nested-loop join 7, 71% | JSON
      // deep-clone 3, 67% | raw <img> 7, 43% | await in loop 5, 40% | Prisma N+1 1, 0% | oversized
      // committed images 1, 0% | STATE SPRAWL 6, 0%.
      //
      // (3) THE FP FAMILIES, each MEASURED on a pin and each filed rather than fixed here (fixing
      // them in this PR would invalidate the number this PR records; see the issues for populations):
      //   - state sprawl (6/6 false): its evidence asserts "every setter triggers a full re-render",
      //     which React >=18 automatic batching makes false; all six repos are React 18.3-19.2.
      //   - dev/CLI/seed/CI scripts graded as request-path perf: boxyhq delete-team.js (an
      //     interactive `readline` admin CLI, `npm run delete-team`) carries 2 rows, prisma/seed.ts
      //     1, saas-lite's turbo generator template 1, carbon's ci/src/assembler.ts 1.
      //   - documented guards defeated by one level of indirection: saas-lite's MFA QR `<img>` is
      //     the `data:`/`blob:` guard's own named example ("MFA QR codes") and misses because the
      //     src arrives as `form.getValues('qrCode')`, not a literal.
      //   - static SVG sources: subscription-payments' only two graded M7 rows are `<img
      //     src="/vercel.svg">`/`/nextjs.svg` — no image pipeline saves bytes on an SVG, so the
      //     stated LCP impact does not obtain. Both false, on the target the corpus pins AS its
      //     false-positive floor.
      //   - `getServerSideProps` JSON round-trips graded as deep-clone: boxyhq switch.tsx:65 is the
      //     documented Next serialization idiom, not a copy.
      //   - house-style pagination wrappers unresolved: carbon's `setGenericQueryFilters` applies
      //     `.range(offset, offset+limit-1)`, so the select IS bounded one call away. Sample rows 25
      //     and 26 were read and confirmed. POPULATION IS AN ESTIMATE, NOT A TRIAGE: 136 of carbon's
      //     344 unbounded-select rows sit within 60 lines of that helper (or a literal
      //     `.range(`/`.limit(`) — a mechanical proxy, and only 2 of the 136 were read individually.
      //   - Vite `?url` imports graded as heavy client imports: carbon entry.client.tsx:1 imports
      //     `pdfjs-dist/build/pdf.worker.min.mjs?url`, which yields the asset URL string, not the
      //     module.
      //
      // (4) A HYPOTHESIS RAISED AND WITHDRAWN, recorded so nobody re-raises it: carbon declares no
      // `next` dependency, so all 60 of its raw-`<img>` rows looked framework-inapplicable. MEASURED
      // false — #872's isVite branch fires on all 60 and they carry the Vite title and the
      // `vite-imagetools` fix. Only the TAXONOMY STRING still reads "instead of next/image" on a
      // non-Next project, which is a label defect, not a false positive.
      //
      // (5) WHAT WAS NOT TRIAGED, so no reader mistakes this for a full census: the 33 Info
      // exhaustive-deps rows on the six repos (Info by #230's ruling, excluded from the graded
      // denominator by design) and 818 of the 858 graded rows on the four large targets. The ~10%
      // figure in docs/m7-performance.md is NOT directly comparable to the 72.3% here: it was a
      // different judge on a raw denominator. Same-denominator raw today is 47/98 = 48.0%, and the
      // movement from ~10% is attributable to #230's demotions and #248's React Compiler gate
      // (both 2026-07-17), NOT to #816 — see (1).
      M7: { counted: 36, total: 71, note: "#1488 CORRECTION 2026-07-30: of this target's 3 nested-loop join rows (members-tab.tsx:77, proposals-server.ts:82, multi-select.tsx:82 — noted only as a count of 3 below, not individually broken out), a third independent read holds the first two (both join collections that scale with real org/proposal data) but grades multi-select.tsx:82 false — `selected.includes(option.id)` is a UI selection array bounded by what a user clicked, not tenant/user data. See #1488's adjudication and the class's own #1488 comment in perf-code.ts's detectNestedLoopJoin; does not change `counted`. #1475-#1480: RE-MEASURED 2026-07-28 at 36/71 (was 42/72) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-82838cef> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 42/72 on the identical clone. -6 counted, -1 total. 5 State sprawl rows move Perf/Low -> INFO (#1475: the class asserted that every setter triggers a re-render, which React >= 18 automatic batching removed in 2022; this repo pins react 19.1.0) and so leave the counted set while staying in the deliverable. 1 raw <img> goes entirely: components/ui/authenticated-image.tsx:113 renders a runtime-signed Supabase Storage URL held in useState, the one-shot shape the data:/blob: guard was meant to cover and could not see through a binding (#1477). The oversized-image row is RE-WORDED not removed (#1480): public/Image.png is 717 KB and is named by no loaded source file — only by README.md — so it emits under `M7 — Unreferenced committed images` with a repo-bloat claim instead of a page-weight one, which is why total falls by 1 and not 2. Prior note: #1261: TRIAGED 2026-07-28 — 42/72 reproduces unchanged, and 35 of the 42 graded rows hold against source (83.3%), the corpus's best. All 26 'Unbounded select' hold: each is a tenant- or parent-scoped `select('*')` with an `.order()` and no limit over a table that grows with tenant activity — #230's 'real vein' is real. 22 of the 26 are one repeated `getX(organisationId)` service idiom, which is a rollup question, not a precision one. False: 5 state sprawl (React 19.1.0 — automatic batching falsifies the evidence sentence), 1 raw <img> (components/ui/authenticated-image.tsx:113, whose own comment records the decision and whose src is a runtime-signed Storage URL), 1 oversized committed image (public/Image.png, 717 KB, referenced by no source file — an unserved asset costs no page load). Prior note: Re-measured 2026-07-17: 49->42 counted under #248's React Compiler gate — the micro-render tail (5 inline-literal + 4 context-value + 2 index-key, judged ~0% real by #230) no longer emits at all with the compiler off. Counted: 26 'Unbounded select' (the real vein — growable request-path lists), 5 state sprawl, 4 raw <img>, 3 nested-loop join, 2 JSON deep-clone, 1 client fetch in useEffect, 1 oversized committed images. 30 exhaustive-deps Info." },
      M8: { mutationScore: 100, killed: 21, valid: 21, coveredScope: ["lib/pdf/launch.ts"], note: "#300/#319: MEASURED 2026-07-15 by the real wrapper (not transcribed) — 21/21 mutants killed on lib/pdf/launch.ts (its coveredScope), ~1s, via the vendored config in m8-corpus.ts after `npm install --legacy-peer-deps`. A perfect score on the corpus's THINNEST suite: this repo has exactly one spec, so 100% here means 'the one covered file is tested well', NOT that proposit is well-tested — its untested surface doesn't appear in this number at all. #319 makes that non-negotiable: coveredScope is required and formatMutationClaim prints it, so this can never be quoted as a repo-level '100% tested'. Useful as drift detection regardless: any drop means the suite or the launch.ts logic moved. #252's threshold keeps this scoreable: the one spec is MEANINGFUL (multiple real assertions — verified 2026-07-17 by the census not emitting M8-00 here), and only a single PLACEHOLDER spec counts as suite absent." },
      "M8-intent": { counted: 1, total: 1, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: 1 'Call-count-only test' (Medium) in the single spec. Split from the mutation-tier M8 key so a static test-intent finding can never read as evidence about the mutation baseline." },
      M9: { counted: 10, total: 11, note: "#1460/#1461/#1462: RE-MEASURED 2026-07-28 at 10/11 (was 11/12) — DRIFT -1, a PRECISION FIX with a single cause, verified by READING the row: lib/supabase/server.ts:44 was a `Missing server-only guard` High whose only client-reachability chain is accept-invitation-client.tsx ('use client') -> lib/actions/invitation-actions.ts ('use server') -> lib/supabase/server.ts. A Client Component importing a `\"use server\"` module gets an RPC reference, not the module body, so nothing bundles and the row was false. #1461 stops the reachability walk at that boundary. MEASURED via `pnpm exec tsx src/cli/static-detect.ts <clone>` on the identical pinned clone, pre- and post-change arms. Prior note retained below. PRIOR: #1262/#1292: RE-MEASURED 2026-07-28 at 11/12 (was 11/11) — the disclosure row only, no detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 11/11. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 11 counted (was 12) — the #964 M9 SSR-only-API-misuse precision fix dropped 1 FP: a `document.createElement` read inside a function in the non-component `.ts` util lib/utils.ts, which is not a component render body. The other 11 findings reproduce unchanged. Prior note: #940: RE-MEASURED 2026-07-24 at 12 (was 11) — a PRECISION FIX. The +1 is one new 'Missing Suspense boundary' finding (M9-16, app/[locale]/auth/signup/page.tsx: dynamic read + data fetch with no <Suspense>), from the M9 detector class added in #843-849 (2026-07-23, after the last-green scheduled run). Every prior M9 finding reproduced. Re-measured 2026-07-17: 8->11 — the 4 'Server Action missing input validation' + 4 'Accidental dynamic rendering' plus #380/#381's new classes (1 'Missing server-only guard', 2 'SSR-only API misuse'). Distinct from the 4 M1 'Server Action missing authorization check' the same run emits — #231 routed the authz vein to M1/#221 rather than scoring it as M9 rendering, and this split is what that fix looks like on real code." },
      M10: { counted: 19, total: 19, note: "#940: RE-MEASURED 2026-07-24 at 19 (was 18) — a dictionary-widening PRECISION/COVERAGE FIX. The +1 table is `embeddings` (FREE_TEXT_REVIEW), newly classified by #850-856's (2026-07-23, after the last-green run) low-confidence free-text-column flag for narrative-shaped columns (notes/comments/bio/description/body/content/…). Confirmed by re-running the pre-#850 dictionary over the same migrations: 18 tables, `embeddings` absent — the only delta. #279: measured 2026-07-15 via m10FindingsFromSchema over the cloned supabase/migrations (205 columns parsed, 39 PII-bearing across 18 tables — one Finding per table). Headline is organisations: Critical, ADDRESS+API_KEY+STORED_PASSWORD — the #233 must-not-miss plaintext ai_api_key/smtp_pass case, now scored as a real drift check instead of only a unit assertion." },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. It is a Next App Router target with Server Actions, so the pass is live, not skipped. An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 9, total: 12, note: "5.2% (309/5947 lines), 13 raw clusters -> 8 cross-file findings, 8 counted, plus the #365 M4-00 disclosure (4 small clones, Info) for 9 total. Re-measured 2026-07-16: counted 6->8, two sub-15-line clones in components/ui/AuthForms/* moved Info->Low under #361's security-path elevation. Down from the sweep's 6.13%/22 clones now #232 excludes `types_db.ts` (Supabase codegen was ~50% of this repo's clones). #1128: RE-MEASURED 2026-07-26 at 9/12 (was 8/9) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target subscription-payments --install` reproduced 9 counted. (Discovered outside the issue's original 12-row table — see proposit's note for why.)" },
      "M4-diverged": { counted: 4, total: 4, note: "#360: measured 2026-07-16 — 14 security-path files, 2 diverged families (High, review tier) in the AuthForms components. #1128: RE-MEASURED 2026-07-26 at 4/4 (was 2/2) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 2 more such pairs now qualify. `pnpm corpus-drift --target subscription-payments --install` reproduced 4 counted." },
      "M5-knip": { counted: 10, total: 10, note: "Originally ran WITHOUT the target's `npm install` — knip resolved its config anyway (fixed #263: recorded as not-run on the assumption it couldn't, measured as 8). Re-measured 2026-07-15 WITH deps installed (#251): still 8 — the install step adds coverage elsewhere without disturbing this. 3 unused files + 5 unused-export files; the Medium is utils/supabase/middleware. If a future knip/config change makes this fail, it degrades to the M5-00 'did not run' finding (#223) and this baseline fails loudly rather than silently reading 0. #1128: RE-MEASURED 2026-07-26 at 10/10 (was 8/8) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories now surface. `pnpm corpus-drift --target subscription-payments --install` reproduced 10 counted." },
      "M5-slop": { counted: 14, total: 16, note: "#278 started this split at a measured 10; re-measured 2026-07-17 after #391's new classes: 9 'Else after return' + 4 'Single-use helper' + 1 'Single-call wrapper' counted; 2 'Decorative emoji' Info." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 — a well-maintained Vercel example with no hand-rolled shapes to flag, consistent with this target's near-floor M7/M9 readings. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 0, total: 1, note: "#1475-#1480: RE-MEASURED 2026-07-28 at 0/1 (was 2/3) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-bdd08132> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 2/3 on the identical clone. Both graded rows were `<img src=\"/vercel.svg\">` / `/nextjs.svg` in a footer and a logo cloud. An SVG is passed through unoptimized by every pipeline this class recommends, so its stated bytes/format cost cannot arise (#1477). THIS TARGET IS THE CORPUS'S FALSE-POSITIVE FLOOR and it was measured at 0% M7 precision — the floor role rested on a guard that did not exist. It is now genuinely silent, which is what the role always claimed. Prior note: #1261: TRIAGED 2026-07-28 — 2/3 reproduces, and BOTH graded rows are FALSE (0/2). Footer.tsx:102 and LogoCloud/LogoCloud.tsx:10 are `<img src=\"/vercel.svg\">` / `/nextjs.svg` / `/stripe.svg` — static SVGs, on which no image pipeline saves a byte, so the finding's stated impact ('unoptimized bytes', 'no srcset') cannot obtain. The sub-claim about a missing layout box is fair; the class as emitted is not. This is the target the note below pins AS the corpus's false-positive floor, and it is currently sitting at 0% precision: the floor role now depends on a guard that does not exist (see the SVG-source family in proposit's #1261 record). Prior note: One of the smallest surfaces in the corpus: 2 raw <img> + 1 Info exhaustive-deps (re-measured 2026-07-17, unchanged — this target never carried a micro-render tail, so #248's gate moved nothing here). A good FALSE-POSITIVE regression guard — a well-maintained Vercel example should stay near-silent; a jump here means a new over-match." },
      M8: { counted: 1, total: 1, note: "No test script and zero *.test.*/*.spec.* files at this commit, so mutation-scan needs no Stryker: it emits exactly #224's M8-00 zero-coverage finding (High), which IS the measurement. Recorded as 1 counted finding — the 0 previously here was a test-FILE count and would have read as 'no M8 problems' on a repo with no tests at all, inverting the finding's meaning (fixed #263)." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: zero test files to inspect, so a measured zero — the M8-00 zero-coverage finding above is this target's whole M8 story." },
      M9: { counted: 2, total: 3, note: "#1460/#1461/#1462: RE-MEASURED 2026-07-28 at 2/3 (was 4/5) — DRIFT -2, same single cause as proposit's -1, both rows READ: utils/stripe/config.ts:4 and utils/supabase/admin.ts:17, each reachable only as CustomerPortalForm.tsx ('use client') -> utils/stripe/server.ts ('use server') -> the module. Traversing a `\"use server\"` boundary is not a client bundle path. MEASURED via `pnpm exec tsx src/cli/static-detect.ts <clone>` on the identical pinned clone, pre- and post-change arms. Prior note retained below. PRIOR: #1262/#1292: RE-MEASURED 2026-07-28 at 4/5 (was 4/4) — the disclosure row only, no detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 4/4. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: Re-measured 2026-07-17: 2->4 — the 2 'Accidental dynamic rendering' plus 2 'Missing server-only guard' from #380/#381's new M9 classes. Still a small stable surface and an FP guard alongside M7." },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. Prisma/next-auth; the boundary pass runs and the mutation collector finds no unguarded action. An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 50, total: 89, note: "4.93% (1148/23283 lines), 90 raw clusters -> 66 cross-file findings, 47 counted, plus the #365 M4-00 disclosure (3 small clones, Info) for 67 total. Re-measured 2026-07-16: counted 39->48, nine sub-15-line clones under pages/api/auth/*, pages/auth/*, components/auth/* (and one tests/e2e/auth spec) moved Info->Low under #361's security-path elevation. Re-measured again 2026-07-17 (#400): 48->47 — the tests/e2e/auth/idp-initiated.spec.ts clone no longer elevates, since a test/spec/e2e path merely naming 'auth' isn't a per-handler authorization drift risk (same exclusion the #360 diverged-clone pass's file selection already applied). Per #232 the real signal is the API-handler envelope (a `createHandler` extraction candidate), lower severity than proposit's. #251 measured the install step inert for M4. #1128: RE-MEASURED 2026-07-26 at 50/89 (was 47/67) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target boxyhq --install` reproduced 50 counted. (Discovered outside the issue's original 12-row table — see proposit's note for why.)" },
      "M4-diverged": { counted: 2, total: 2, note: "#360: measured 2026-07-16 — 38 security-path files, 2 diverged families (High, review tier). The larger family is the per-page getServerSideProps auth boilerplate (8 pages, one adjudication row thanks to family grouping — per-pair emission would have been 21 findings, the measured basis for grouping). #1128: RE-VERIFIED 2026-07-26 byte-identical at 2/2 despite #1095/PR#1129's same-file-pair widening (that widening rolls into the general M4 module here, not this security-path-only baseline — `pnpm corpus-drift --target boxyhq --install` reproduced 2 counted, no drift)." },
      "M5-knip": { counted: 14, total: 14, note: "#940: RE-MEASURED 2026-07-24 at 9 (was 12) — same knip-runner PRECISION FIX as proposit's M5-knip (#694/#695/#697's in-file-used type-export suppression + type-export review split), PROVEN by controlled before/after on this identical clone: pre-#694 knip code reprints exactly 12 (5 unused files + 7 unused-export files), current code 9 (4 unused files + 5 unused-export files). The drop is type exports used in-file, not value dead code. Original: #251: measured 2026-07-15 after `npm install --legacy-peer-deps` in the clone — 5 unused files + 7 files with unused exports. Modest for a 23k-line repo. #323: this used to add 'matching this target's reputation as the corpus's best-maintained one (it is also the M8 upper reference point)' — drop that framing, see the M8 note below: most test FILES in the corpus, LOWEST measured mutation score. Worth watching as an FP guard: a jump here on a well-kept repo is more likely a knip/config change than new dead code. #1128: RE-MEASURED 2026-07-26 at 14/14 (was 9/9) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories now surface. `pnpm corpus-drift --target boxyhq --install` reproduced 14 counted." },
      "M5-slop": { counted: 97, total: 98, note: "#1532: RE-MEASURED 2026-07-30 at 97/98 (was 104/105) — DRIFT -7, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`, shipped with its corpus gate never having run; 653 spared corpus-wide, 50-row seeded sample read at source, 5 wrongly spared, #1532's `doesOwnIo` recovers 42). All 7 spared here were read at source and all 7 hold: `generateCSP` (pure CSP string builder, caller awaits getToken/fetch), `generateUniqueApiKey` (pure crypto, caller awaits prisma.apiKey.create), `verifyWebhookSignature` (pure HMAC compare, caller awaits handleEvents) and 4 await-free builders in sync-stripe.js whose caller awaits `Promise.all`/`$transaction`. Note the shape of the three named: the pure security half of an I/O function is EXACTLY what the brief's MISSING SEAMS section asks a team to extract, so flagging them was the false positive. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-abc9b686> --out f.json`. Prior note: Re-measured 2026-07-17: 12->76 counted, almost entirely #391's new 'Single-use helper' class (64) on top of the prior 9 'Else after return' + 2 'Orphan TODO' + 1 'Single-call wrapper'; 1 'Narrating comment' Info. The corpus's highest single-use-helper reading — worth watching for precision drift on that class, but every prior class reproduced exactly. #1128: RE-MEASURED 2026-07-26 at 104/105 (was 76/77) — a precision fix from #1088/#1065 (commit c75186a, merged 2026-07-25): SOURCE_FILE widened to include plain js/cjs/mts/cts, and this target's repo-root tooling scripts (delete-team.js, sync-stripe.js, check-locale.js, find-dupe-locale.js, jest.config.js, next.config.js, tailwind.config.js, postcss.config.js, eslint.config.cjs, .prettierrc.js et al. — 12 files total, VERIFIED by direct file-scope diff on this pinned clone) are now genuinely scanned for the first time. `pnpm corpus-drift --target boxyhq --install` reproduced 104 counted." },
      "M6-indicator": { counted: 2, total: 2, note: "#483: MEASURED 2026-07-17 — 1 'email-shape regex' + 1 'cookie serialization' (both dep-gated classes: zod and no class-merge dep respectively confirm the gate reads this target's package.json correctly). All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note). #1128: RE-VERIFIED 2026-07-26 byte-identical at 2/2 despite the same-day SOURCE_FILE widening — `pnpm corpus-drift --target boxyhq --install` reproduced 2 counted, no drift." },
      M7: { counted: 6, total: 6, note: "#1488 CORRECTION 2026-07-30: the prior note below (from #1261) grades the products/prices O(n·m) join (products.ts:49) as Real. A third independent read of the class's 7 field rows disagrees: products/prices here are getAllServices()/getAllPrices() — this SaaS's own Stripe pricing catalog, a small fixed list, not tenant/user data that scales with account count. See #1488's adjudication and the class's own #1488 comment in perf-code.ts's detectNestedLoopJoin. This does not change `counted` (raw scanner output is unaffected) or this target's 60% headline (still 6 of 10 REPORTED rows hold under the ORIGINAL #1261 rubric applied consistently) — it corrects the class-level nested-loop-join tally the render.mjs M7 hedge draws on. #1475-#1480: RE-MEASURED 2026-07-28 at 6/6 (was 10/10) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-abc9b686> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 10/10 on the identical clone. -4, and 3 of them are the same file counted twice. delete-team.js is an interactive `readline` admin CLI wired to `npm run delete-team`; it was reported BOTH by the generic await-in-loop class and by #793's Prisma N+1 detector, and the #1128 note below recording that second detector's arrival as \"a precision fix\" was in fact measuring a duplicate false positive. prisma/seed.ts:129 is the `prisma.seed` faker seeder. Neither is a request path, and no path pattern can say so — the package.json script entry is what does (#1476). pages/teams/switch.tsx:65 is `JSON.parse(JSON.stringify(teams))` inside getServerSideProps' returned props, the documented Next idiom for serializing Prisma Dates; `structuredClone`, this class's own recommendation, would break it (#1480). The 2 surviving await rows are real: pages/api/auth/sso/verify.ts:148 and pages/api/teams/[slug]/webhooks/index.ts:81. Prior note: #1261: TRIAGED 2026-07-28 — 10/10 reproduces, 6 of the 10 hold (60%). Real: the SSO-verify N+1 (pages/api/auth/sso/verify.ts:148, `teamSSOExists` per team on a login path), the webhook event-type loop, the middleware `fetch('/api/auth/session')` on every request, the products/prices O(n·m) join, and BOTH Prisma unindexed-FK rows (verified in schema.prisma: Invitation carries only @@unique([teamId,email]) + @@index([email]), Price carries no @@index at all — Postgres does not auto-index a foreign key). False: 3 of the 4 remaining are dev scripts, not request paths — delete-team.js is an interactive `readline` admin CLI wired to `npm run delete-team` and carries BOTH the M7C-01 await-in-loop AND the PRISMA-M7-N1 row (the same script counted twice by two detectors), and prisma/seed.ts:129 is a faker seeder; the fourth is pages/teams/switch.tsx:65, where `JSON.parse(JSON.stringify(teams))` is the documented getServerSideProps serialization idiom, not a deep copy. CORRECTION TO THE #1128 NOTE BELOW: the SOURCE_FILE widening it records as 'a precision fix' added a SECOND detector's view of delete-team.js — measured here, that +1 is a duplicate FALSE positive, not a precision gain. Prior note: #940: RE-MEASURED 2026-07-24 at 9 (was 6) — a NEW-DETECTOR PRECISION FIX. The +3 are the Prisma perf detectors that first apply to this target (boxyhq carries a schema.prisma and routes Prisma): 2 unindexed-foreign-key findings from schema.prisma (Invitation.invitedBy, Price.serviceId — #761, 2026-07-23) + 1 Prisma N+1 pattern in delete-team.js (prisma.teamMember.findMany once per iteration — #793, 2026-07-23). All 6 prior findings reproduced unchanged. Re-measured 2026-07-17: 17->6 under #248's React Compiler gate — the 9 inline-literal + 3 index-key micro-render tail no longer emits with the compiler off. What remains is the real request-path vein: 3 'Await in loop (N+1)', the corpus's one genuine middleware stall ('Fetch in middleware hot path', kept by #230), 1 JSON deep-clone, 1 nested-loop join. #1128: RE-MEASURED 2026-07-26 at 10/10 (was 9/9) — a precision fix from #1088/#1065 (commit c75186a, merged 2026-07-25): the SAME SOURCE_FILE widening as M5-slop above newly scans delete-team.js's own N+1 pattern under the code-tier M7 detector too (previously found only via the Prisma-schema-specific #793 detector on the same file — this is a second, independent detector now also seeing the file). `pnpm corpus-drift --target boxyhq --install` reproduced 10 counted." },
      // #300: the manifest calls this target "the M8 upper reference point" — measurement says
      // otherwise, and that inversion is the whole reason to measure. It has the corpus's most
      // test FILES (8) but its jest suite is ONE unit spec; the other 7 are Playwright E2E.
      M8: { mutationScore: 20, killed: 7, valid: 35, tolerance: 1, coveredScope: ["lib/server-common.ts"], note: "#300/#319: MEASURED 2026-07-15 — 20% (7/35 valid mutants) on lib/server-common.ts (its coveredScope), the file boxyhq's one jest unit spec (__tests__/lib/server-common.spec.ts) covers. 2 survived, 26 NoCoverage: the spec exercises generateToken but leaves most of the file's exports untouched. #277 predicted the Playwright specs would block this and they do NOT — the target's jest.config.js already sets testPathIgnorePatterns: ['<rootDir>/tests/e2e'], so jest never loads them; the prediction was never tested against the config. Note this reverses the manifest's 'best-tested target' framing: most test files, LOWEST measured mutation score in the corpus (proposit's thin suite scores 100 on what it covers) — which is exactly why #319 requires coveredScope: one covered file out of a 23k-line tree is not a repo-level 20%. Test-file count was never test quality — which is #263's lesson restated. #432: CI measured 8/35 (22.9%) on PR #431 — re-run 4x on 2026-07-17 (cloning + installing fresh each time, not just re-scoring one report) and got 7/35 three times, 8/35 once. Diffing the two runs' surviving-mutant lists pins it to ONE mutant flip-flopping: lib/server-common.ts:18's MethodExpression on `tokenBytes.toString('hex').slice(0, length)`. generateToken's own spec has a 'random length' test (`Math.round(Math.random() * 10) + 1`, unseeded) — when that length lands EVEN, the mutant's un-sliced hex output happens to already be that length (Math.ceil(length/2) bytes -> length hex chars when length is even), so the assertion can't tell the mutant from the original and it survives; an ODD length always kills it. This is the target's OWN test being flaky by construction, not our wrapper or Stryker — tolerance: 1 absorbs the ±1 wobble instead of picking a point value that fails exactly as often as it passes." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: a measured zero across this target's jest unit spec and Playwright E2E specs — no assertion-free/tautological/happy-path-only shapes fired." },
      M9: { counted: 0, total: 4, note: "#1262/#1292: RE-MEASURED 2026-07-28 at 0/4 (was 0/3) — the disclosure row only, no detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 0/3. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 0 counted / 3 total (3 Info not-assessed rows) — the #964 M9 SSR precision fix dropped all 14 prior 'SSR-only API misuse' findings as FALSE POSITIVES. Every one was a browser-global read inside a plain client-only util function in a `.ts` file (lib/common.ts's `copyToClipboard` → navigator.clipboard, lib/theme.ts's `applyTheme` → document/localStorage/window.matchMedia): utilities invoked from event handlers/theme toggles, never a component render body and never on the SSR render path (a component needs JSX, i.e. a `.tsx` module). The App-Router-only classes (accidental dynamic rendering, server-only guard, waterfall) remain ZERO, so the #231 guard this baseline exists for still holds — any non-zero in THOSE is a straight regression. Prior note: Re-measured 2026-07-17: 0->14, ALL of them #381's new 'SSR-only API misuse' class." },
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
    m8: M8_CORPUS_CONFIGS["multi-tenant-starter"],
    schemaPath: "supabase/migrations",
    modules: {
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here.  An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 1, total: 2, note: "0.35% (11/3167 lines), 6 raw clusters -> 1 cross-file finding, 1 counted, plus the #365 M4-00 disclosure (2 small clones, Info) for 2 total. Re-measured 2026-07-16: counted 0->1 — the single sub-15-line clone (app/dashboard/CreateTenantForm.tsx, paired against an auth-path file) moved Info->Low under #361's elevation. Still a MEASURED near-floor on the smallest target; the sweep's 2.95% was the pre-#232 denominator." },
      "M4-diverged": { counted: 2, total: 2, note: "#360: measured 2026-07-16 — 8 security-path files, ZERO diverged families. A measured zero on the repo whose dead requireTenantAccess guard (#217/#226) is the M5 headline: its guards were never wired, so they never got copy-pasted and drifted. Any non-zero here is a new detection or an over-match — look before rebaselining. #1128: RE-MEASURED 2026-07-26 at 2/2 (was 0/0) — LOOKED BEFORE REBASELINING per the note above: #1095/PR#1129 (2026-07-26) added a same-file-pair comparison to the diverged pass (previously it only compared across DIFFERENT files) — this is a new comparison axis firing for the first time, not the cross-file near-miss pass this baseline's own caveat warns about. `pnpm corpus-drift --target multi-tenant-starter --install` reproduced 2 counted. (Discovered outside the issue's original 12-row table — see proposit's note for why.)" },
      // The one target small enough (13 deps) to `npm install` cheaply, so M5-knip DID run here.
      "M5-knip": { counted: 2, total: 2, note: "Originally ran WITHOUT the target's node_modules — knip resolves this 13-dep repo's config either way (fixed #263: recorded as 1 finding, measured as 2 — knip reports the two files separately, it does not roll them into one). Re-measured 2026-07-15 WITH deps installed (#251): still 2, so the new install step did not move this baseline. Both REAL, and the first is security-weighted: `lib/security/guards.ts` exports requireTenantAccess/requireTenantAdmin and NOTHING calls them, on the same repo whose self-join Critical (#217) is a missing-authz bug. #226's security cross-link firing on real code: the dead guard IS the vulnerability's fingerprint. The second is unused exports in lib/supabase/server.ts." },
      "M5-slop": { counted: 1, total: 1, note: "#1532: RE-MEASURED 2026-07-30 at 1/1 (was 2/2) — DRIFT -1, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it). The one spared row was read at source: `isPublicPath` (middleware.ts:12) is a pure `PUBLIC_PATHS.some(startsWith)` matcher whose sole caller awaits `supabase.auth.getUser()` — the textbook seam. This target's floor is now 1, and the old note's warning still stands: a jump beyond it is a new over-match. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-dcc147c0> --out f.json`. Prior note: Re-measured 2026-07-17: 0->2 from #391's new classes — 1 'Unused import' (app/dashboard/page.tsx) + 1 'Single-use helper' (middleware.ts). Still near the floor this 3.1k-line repo reads everywhere else; a jump beyond this is a new over-match." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 — same FP-floor role as this target's M4-diverged/M7 zeros, a 3.1k-line repo too small to carry any of the 13 hand-rolled shapes. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 0, total: 0, note: "#1261: re-confirmed zero 2026-07-28 — the only corpus target with no M7 row to triage, so it contributes to neither numerator nor denominator of the field precision number. Prior note: MEASURED zero (re-confirmed 2026-07-17) — a 3.1k-line repo with no perf surface. A useful floor: any M7 finding appearing here is almost certainly a new over-match." },
      M8: { mutationScore: 95.7, killed: 22, valid: 23, coveredScope: ["lib/security/guards.ts"], note: "#1496: MEASURED 2026-07-31, reproduced identically across three consecutive runs — 95.7% (22/23 valid mutants). This target's ORIGINAL suite (test/rls.test.mjs) is still not what this score measures: it starts a Docker Postgres container per invocation, which Stryker's per-mutant re-invocation would pay for every mutant (#1436's M8_DOCKER_PER_MUTANT, still recorded above as the reason THIS suite isn't scored directly). The 2026-07-31 operator ruling on #1496 chose to REWORK rather than pay that cost or leave the target unscored: src/scan/m8-corpus.ts vendors a NEW, DB-free vitest suite (test/security-guards.vitest.test.ts, written into the disposable clone via the new `extraFiles` field, never committed upstream) covering lib/security/guards.ts's role-hierarchy authorization logic (requireAuth/requireTenantAccess/requireTenantAdmin) — the same file #226's M5-knip note already flags as the self-join Critical's fingerprint (exported, security-relevant, and until this suite, untested by ANYTHING). The DB layer is stubbed at exactly two call sites (createServerSupabaseClient's .auth.getUser(), tenants.ts's getUserTenantRole), never a real Postgres connection. COST, RE-MEASURED 2026-07-31 (#1693) because the `~3-6s` recorded here first named neither a phase nor a machine: three consecutive runs of the full production path (`pnpm corpus-drift --target multi-tenant-starter --install --m8`, i.e. network clone + install + Stryker) on one developer laptop took 17.5s / 10.5s / 9.8s end to end, the first paying a cold npm cache; Stryker's own mutation phase reported `Done in 1 second.` over 23 mutants on all three. The figure that actually sizes the monthly job is the RUNNER's, and it is ~3x the laptop's: MEASURED on a GitHub runner the same day (PR #1693, job 91187639590, the corpus-m8 step this target was wired into by #1692), the same command reported `multi-tenant-starter: 30s` and reproduced 95.7% (22/23). Quote the phase and the machine or re-run the command, do not quote a bare second-count from here. Either way it is nowhere near one Docker container start per mutant for the original suite. THE ACCEPTED TRADE (stated because a stubbed suite may score differently from the real one it stands in for, per the ruling): this measures how well 11 new hand-written tests exercise guards.ts's OWN logic, not how well the target's own test authors covered it — unlike every other M8 corpus entry, whose suite is the target's own. The 1 surviving mutant (StringLiteral, guards.ts:36 — requireTenantAccess's `minimumRole: TenantRole = 'guest'` default replaced with `''`) is LIKELY EQUIVALENT rather than a real test gap: `ROLE_RANK['']` is `undefined`, and `rank < undefined` is always `false` for every real TenantRole value, so a '' default and a 'guest' default (rank 1, the lowest real rank) are behaviorally identical for every value the type system allows through — not verified by exhausting every possible runtime value, just by this rank-table reasoning." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: a measured zero — the one hand-rolled RLS spec drew no test-intent findings." },
      M9: { counted: 2, total: 4, note: "#1438/#1441: RE-MEASURED 2026-07-28 at 2/4 (was 2/3) — the #1441 waterfall scope row only, no detection change. MEASURED by a controlled before/after `static-detect` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at e7e3d1e reprints 2/3. The +1 total is `M9 — Data-fetching waterfall — scope`, reading '1 of 1 adjacent query pair excluded by policy' — that pair is lib/supabase/tenants.ts:151, the duplicate-invitation FP #1292 correctly removed. The suppression is right; its SILENCE was not, and the row is what a client now reads instead of a bare zero. Info, so `counted` is unchanged. Prior note: #1262/#1292: RE-MEASURED 2026-07-28 at 2/3 (was 3/3) — one waterfall FALSE POSITIVE removed, plus the disclosure row. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 3/3. The -1 counted is #1292: lib/supabase/tenants.ts:151, where `if (existing) return existing` sits between the invitation lookup and the INSERT. No value flows, so the old single-hop test called the pair independent and told the client to run them in `Promise.all` — which would insert a duplicate invitation on every re-invite. A hard FP whose recommended fix was a bug. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: 2 'Accidental dynamic rendering' + 1 'Data-fetching waterfall' (re-confirmed 2026-07-17 — no #381 SSR-only hits here)." },
      M10: { counted: 1, total: 1, note: "#279: measured 2026-07-15 via m10FindingsFromSchema over the cloned supabase/migrations (21 columns parsed, 1 PII-bearing table). tenant_invitations: Low (EMAIL) — the corpus's near-floor M10 reading, matching this target's otherwise-minimal M4/M7 surface." },
    },
  },
  // #1372: the seventh target, and the one the manifest had been missing for a stated reason that
  // was false. `docs/test-targets.md` recorded launch-mvp as "still unaudited … ships 0 migrations
  // in-tree, so an M2 stand-up needs a hand-built schema". Both clauses were false the day they
  // were written and re-measured false 2026-07-28: it has been disclosed twice (#168, #774), and it
  // ships a 104-line root-level `initial_supabase_table_schema.sql` with 4 CREATE TABLEs that #770's
  // discoverSchemaFiles resolves without help (measured: 2 schema files found over 7 probed
  // locations). That unconventional layout is exactly why schemaPath is "." here rather than the
  // conventional supabase/migrations — the schema is at the repo root and under supabase/scripts.
  //
  // What it buys the corpus that no existing target does: it is the only member with an
  // UNAUTHENTICATED service-role IDOR at Critical (#774 — `app/api/user/delete/route.ts` takes a
  // userId from the query string and soft-deletes that account through the service-role client, no
  // auth call in the file). #1473, CLOSED 2026-07-31: it is now IN FREE_TIER_EXPECTATIONS below,
  // carrying `mustBeLoud: "graded"` — measured grade F (51/100) with 0 review-tier tenant-isolation
  // indicators, which is why all three values of the older `mustRaiseLoudIndicator` stated something
  // false about it: its known Criticals land in the graded set, not in the indicator channel that
  // field scores. The channel-agnostic assertion is what let it into the gate.
  // MEASURED 2026-07-28 during the #1174 re-scan: the free tier now emits 3 High/Confirmed "tenant
  // predicate populated from the request" rows on it, and the same scan on the 2026-07-26 scanner
  // (d1da2e4) emitted ZERO — a real-code detection this manifest would otherwise have no baseline
  // for.
  {
    slug: "launch-mvp",
    repo: "ShenSeanChen/launch-mvp-stripe-nextjs-supabase",
    commit: "513a8f0ca6e405725dcf98eab1fc5cd6468b5f10",
    license: "MIT",
    provenance: "unclear",
    provenanceNote: "#1372: recorded honestly rather than forced into a tier. Solo maintainer (37 commits across two author spellings of the same person), a live hosted app, a YouTube series and a Discord — none of the org/CI signals `professional` names, and none of the AI fingerprints `ai-generated` names either: no Co-Authored-By trailers in 40 commits, no CLAUDE.md, and the only `.cursor` content is an `mcp.json.example`.",
    securityVerdict: "2 Critical (unauthenticated account deletion and subscription cancellation through the service-role client), 4 High (unauth reactivate/sync; no server-side route protection — no middleware.ts at all), 3 Medium (debug endpoint leaks the Stripe key prefix; open redirect in the OAuth callback; Resend API key reused as the inbound auth secret with a non-constant-time compare). Every one re-verified in source at this pin on 2026-07-28 (#1174).",
    disclosureIssue: 774,
    // "." because this target's schema is NOT under supabase/migrations — see the note above.
    schemaPath: ".",
    modules: {
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping. Measured when #1472 pinned this target and the required key made its absence a compile error rather than a silent gap." },
      M4: { counted: 5, total: 10, note: "#1372: MEASURED 2026-07-28 by `pnpm corpus-drift --target launch-mvp --install` against this pin — 1.34% (135/10056 lines), 11 clone clusters. 5 counted: 2 self-file clones inside the React-email templates (CancellationConfirmationEmail, WelcomeEmail), 2 cross-file clones across the three `supabase/functions/send-*-email` Deno handlers, 1 across ForgotPasswordModal ↔ app/reset-password/page. The 5 Info: 2 sub-15-line import-header clones among the api/stripe + api/user/delete routes, the #365 M4-00 small-clone row, the #1080/#1095 M4-SELF-00 row, and the M4-97 diverged-coverage row (the diverged pass covered 2 of 65 eligible files here). Never transcribed — the number came from the tool." },
      "M4-diverged": { counted: 0, total: 0, note: "#1372: MEASURED ZERO 2026-07-28 — 2 security-path files eligible, no diverged family. An FP floor on a small tree, and a useful one on THIS target specifically: its five unauthenticated service-role handlers are near-identical in shape, so a diverged-clone over-match would show up here first." },
      "M5-knip": { counted: 29, total: 29, note: "#1372: MEASURED 2026-07-28 with the target's own `npm install` (package-lock.json → npm per #1268) — 15 unused files, 6 files with unused exports, 10 unused dependencies. The dominant vein is an entire PostHog analytics subsystem wired to nothing (PostHogContext, PostHogPageView, PostHogErrorBoundary, utils/posthog.ts, utils/analytics.ts) plus the three `supabase/functions/send-*-email` Deno handlers, which knip cannot see an entry point for because they are deployed by the Supabase CLI, not imported. That second group is a known shape, not dead code — worth watching as an FP guard if the count moves." },
      "M5-slop": { counted: 6, total: 8, note: "#1372: MEASURED 2026-07-28 — 3 'Single-use helper', 1 'Orphan TODO' + 1 'Placeholder stub' (both app/verify-email/page.tsx:34, the same unfinished handler), 1 'Unused import'; 2 Info (1 decorative emoji, 1 narrating comment). A small, clean reading for a solo-maintained template." },
      "M6-indicator": { counted: 1, total: 1, note: "#1372: MEASURED 2026-07-28 — 1 'hand-rolled ErrorBoundary' (components/PostHogErrorBoundary.tsx:13). All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 2, total: 5, note: "#1372: MEASURED 2026-07-28 — 2 counted: 'Await in loop (N+1)' at app/api/user/delete/route.ts:32 (a per-subscription `stripe.subscriptions.cancel` inside a loop) and 'Client fetch in useEffect' at app/dashboard/page.tsx:164. 3 Info 'Missing hook dependencies'. The N+1 sits inside the #774 Critical's own handler, which makes it a useful cross-module anchor: a change that silences M1 there should not silence M7 there." },
      M8: { counted: 1, total: 1, note: "#1372: MEASURED 2026-07-28 — ZERO test files and no `scripts.test`, so mutation-scan emits #224's M8-00 zero-coverage finding (High), which IS the measurement. Not a mutation baseline and not a not-run: 1 counted, per #263's rule that a test-FILE count is not the finding." },
      "M8-intent": { counted: 0, total: 0, note: "#1372: MEASURED ZERO 2026-07-28 — no test files anywhere in the tree, so the #372 test-intent pass has nothing to inspect. M8-00 above is the whole M8 story here." },
      M9: { counted: 0, total: 1, note: "#1372: MEASURED 2026-07-28 at 0 counted / 1 total. The single row is #1262's `M9 — Uncapped retry/fan-out — scope` disclosure (Info, 8 route/edge handlers checked). A measured zero on the counted classes — this is an App Router app, so an App-Router-only class appearing here later is a new detection or an over-match, never scale." },
      M10: { counted: 1, total: 1, note: "#1372: MEASURED 2026-07-28 via m10FindingsFromSchema over `schemaPath: \".\"` — the root-level initial_supabase_table_schema.sql plus supabase/scripts/**. 1 PII-bearing table. This row is the durable proof of #1372's second falsified clause: the target was recorded as shipping '0 migrations in-tree, so an M2 stand-up needs a hand-built schema', and the classifier reads its schema straight out of the tree with no hand-building at all." },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here.  An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 6, total: 13, note: "1.35% (211/15684 lines), 11 raw clusters -> 7 cross-file findings, 5 counted, plus the #365 M4-00 disclosure (1 small clone, Info) for 8 total. Re-measured 2026-07-16: counted 4->5 — one sub-15-line clone (nextjs/app/api/auth_callback/route.ts) moved Info->Low under #361's security-path elevation. The sweep's headline '13.3%, highest in the corpus' was almost entirely `monero/patches/**` whole-file fork-mirrors. #232's vendored-path exclusion is what closed that ~12-point gap; this target is the regression guard for it. #1128: RE-MEASURED 2026-07-26 at 6/13 (was 5/8) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too, both previously excluded entirely. `pnpm corpus-drift --target mvp-boilerplate --install` reproduced 6 counted." },
      "M4-diverged": { counted: 1, total: 1, note: "#360: measured 2026-07-16 — 4 security-path files, ZERO diverged families. Same FP-floor role as this target's M7/M5-slop zeros. #1128: RE-MEASURED 2026-07-26 at 1/1 (was 0/0) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and one such pair now qualifies. `pnpm corpus-drift --target mvp-boilerplate --install` reproduced 1 counted." },
      "M5-knip": { counted: 23, total: 23, note: "#940: RE-MEASURED 2026-07-24 at 20 (was 22) over the nextjs/ scan root — same knip-runner PRECISION FIX as proposit/boxyhq (#694/#695's in-file-used type-export suppression + type-export review split), PROVEN by controlled before/after on this identical clone's nextjs/ subtree: pre-#694 knip code reprints exactly 22, current code 20. Original: #322: MEASURED 2026-07-17 over the nextjs/ per-module scan root (npm install in nextjs/, knip run there) — previously not-run because this polyglot monorepo has no root package.json. 8 unused files + 14 files with unused exports; 15 of the 22 are shadcn/ui component-kit sub-exports (components/ui/*), the same recurring mechanical shape #320's proposit triage documented. The one security-adjacent row is utils/supabase/middleware.ts (Medium) — same standard-SSR-helper shape as subscription-payments' Medium. SCOPE CAVEAT: this number describes nextjs/ ONLY, while every other module here measures the whole repo — the scored rows carry the scope, and cross-module comparisons on this target are scope-invalid. #1128: RE-MEASURED 2026-07-26 at 23/23 (was 20/20) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories (unlisted/unresolved/duplicates/enumMembers/optionalPeerDependencies/catalog/binaries) now surface as findings instead of being silently absorbed at the type boundary. `pnpm corpus-drift --target mvp-boilerplate --install` reproduced 23 counted over the nextjs/ scope." },
      "M5-slop": { counted: 24, total: 29, note: "#1533: RE-MEASURED 2026-07-31 at 24/29 (was 23/28) — DRIFT +1, a RECOVERED FALSE NEGATIVE, not a new over-match. The row is the one the previous note enumerated as the disclosed `async`-caller-with-no-await boundary: `generateGameOfLifePattern` (nextjs/app/api/og/route.tsx:15), a pure grid computation whose caller `GET` is declared `async`, contains ZERO awaits and returns `new ImageResponse(...)` — constructed synchronously, so the exemption's premise (\"the caller does the I/O\") is false. #1533 reads the caller's RETURNS through the cross-file resolver `buildImportGraph` is built on and fires only when every one of them is provably synchronous, so the sibling shape that stopped this being narrowed before — inbox-zero utils/outlook/mail.ts:408, whose await-free caller returns a local `async` function's promise — is still correctly spared. This target's baseline is now the SAME number it read before #1532/#1447 (24/29), reached by a different and narrower route. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2aac5c2f> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 23/28 (was 24/29) — DRIFT -1, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it). Prior note: Re-measured 2026-07-17: 6->24 counted after #391's new classes — 17 'Single-use helper' + 5 'Else after return' + 1 'Orphan TODO' + 1 'Unused import'; 5 'Decorative emoji' Info." },
      "M6-indicator": { counted: 0, total: 0, note: "#483: MEASURED zero 2026-07-17 over the whole repo (this target's M5-knip alone scans nextjs/ per its scanRoots — M6-indicator, like M7/M9/M5-slop, measures the whole tree, so this zero is scope-consistent with those). All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 4, total: 6, note: "#1488 CORRECTION 2026-07-30: the prior note below (from #1261) grades the Stripe products x prices O(n·m) join (supabase/functions/_shared/stripe.ts:151) as Real. A third independent read of the class's 7 field rows disagrees: `initPricesAndProducts()` joins `stripe.products.list()`/`stripe.prices.list()` — the same small fixed Stripe pricing catalog as boxyhq's products.ts, not tenant/user data. See #1488's adjudication and the class's own #1488 comment in perf-code.ts's detectNestedLoopJoin. Does not change `counted` (raw scanner output) or this target's own 80% headline (still 4 of 5 REPORTED rows hold under the ORIGINAL #1261 rubric) — it corrects the class-level nested-loop-join tally the render.mjs M7 hedge draws on. #1475-#1480: RE-MEASURED 2026-07-28 at 4/6 (was 5/6) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2aac5c2f> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 5/6 on the identical clone. -1 counted, total unchanged: the single State sprawl row (nextjs/components/misc/AuthForm.tsx:23) moves to Info under #1475. It still ships. Prior note: #1261: TRIAGED 2026-07-28 — 5/6 reproduces, 4 of the 5 hold (80%). Real: both 'Client fetch in useEffect' rows (the landing-page Pricing section fetches products client-side on mount instead of server-rendering them — a genuine HTML->JS->data waterfall), the unbounded `xmr_invoices` select, and the Stripe products x prices O(n·m) join in the edge function. False: 1 state sprawl (AuthForm.tsx, 8 useState, React 19.2.3 — automatic batching falsifies the evidence sentence). SCOPE NOTE worth reading before comparing this target to any other: 2 of the 5 rows sit under `monero/patches/`, a patch overlay rather than shipped code, and one of them (Pricing.tsx:129) is the same defect as the live nextjs/ copy reported twice. Prior note: Re-measured 2026-07-17: 3->5 — #248's gate removed the 1 index-key, while 2 'Client fetch in useEffect' + 1 'Nested-loop join' (classes added since the 2026-07-15 baseline) now count alongside the 1 unbounded select + 1 state-sprawl; 1 exhaustive-deps Info." },
      M8: { counted: 1, total: 1, note: "No package.json at the repo root (it's a monorepo whose apps carry their own) and zero test files — mutation-scan emits #224's M8-00 zero-coverage finding (High), which IS the measurement. 1 counted, not the 0 test-FILE count previously recorded (fixed #263)." },
      "M8-intent": { counted: 0, total: 0, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: zero test files anywhere in the tree, so a measured zero — M8-00 above is the whole M8 story here." },
      M9: { counted: 1, total: 2, note: "#1438/#1441: RE-MEASURED 2026-07-28 at 1/2 (was 0/1) — the target's single waterfall is BACK, and it is a true positive. MEASURED by a controlled before/after `static-detect` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at e7e3d1e reprints 0/1. #1441 splits #1292's guard rule by what the guard DOES: monero/supabase/functions/xmr_webhook/index.ts:114 is `if (!price) throw` between an independent prices READ and a subscriptions READ — the throw ends the request, so nothing downstream observes the second result and `Promise.all` is safe. Triaged against source, not property-checked. The +1 total is that finding; this target has 1 adjacent pair, 0 now excluded, so it emits NO waterfall scope row (the row discloses a limitation, not a status). Prior note: #1262/#1292: RE-MEASURED 2026-07-28 at 0/1 (was 1/1) — the target's only counted M9 finding was a waterfall FALSE POSITIVE. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 1/1. The -1 is #1292: monero/supabase/functions/xmr_webhook/index.ts:114, a guarded pair. This target now reads 0 counted with the disclosure row as its only M9 output — a legitimate zero, stated rather than silent. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: 1 'Data-fetching waterfall' (re-confirmed 2026-07-17)." },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here.  An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 17, total: 22, note: "1.15% (318/27617 lines), 28 raw clusters -> 16 cross-file findings, 14 counted, plus the #365 M4-00 disclosure (9 small clones, Info) for 17 total. Re-measured 2026-07-16: counted unchanged by #361 — its security-path clones were already >=15 lines, so the elevation moved severities (Low->Medium) without crossing the Info/counted line. The sweep's 499-line identical `database.types.ts` copy is now excluded by #232. #251 measured the install step inert for M4. #544: RE-MEASURED 2026-07-18 at 14/17 — byte-identical to this baseline — after fixing a #519 REGRESSION. #519 ran jscpd PER WORKSPACE, which on this Turborepo silently dropped BOTH every cross-workspace clone AND every `packages/**` workspace (the shared discoverTargets glob did not then expand the `packages/**` double-star — since fixed in #548), collapsing M4 to 4 counted (apps/web-internal only) with NO gap disclosed — the silent under-count the coverage guard forbids. jscpd now runs whole-repo again: it has no workspace-resolution stage and does not hang (measured 1.9s over this monorepo), and whole-repo is the correct duplication scope. 9 of the 14 restored clones are the real cross-package/packages-internal auth vein (packages/features/auth <-> packages/features/accounts MFA/sign-in copy-paste), the corpus's strongest cross-workspace M4 signal. #1128: RE-MEASURED 2026-07-26 at 17/22 (was 14/17) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target saas-lite --install` reproduced 17 counted." },
      "M4-diverged": { counted: 5, total: 5, note: "#360: measured 2026-07-16 — 52 security-path files, 5 diverged families (High, review tier): the auth pages (sign-in/sign-up/password-reset), the callback/confirm route GETs, and the ErrorAlert/SuccessAlert i18n-key drift — the corpus's largest near-miss surface, consistent with its packages/features/auth breadth. #1128: RE-VERIFIED 2026-07-26 byte-identical at 5/5 despite #1095/PR#1129's same-file-pair widening (that widening rolls into the general M4 module here, not this security-path-only baseline — `pnpm corpus-drift --target saas-lite --install` reproduced 5 counted, no drift)." },
      "M5-knip": { counted: 37, total: 38, note: "#1404: RE-MEASURED 2026-07-28 at 37/38 (was 43/44) — DRIFT -6, a PRECISION FIX. PROVEN by controlled before/after on the identical pinned clone with the install path as the only variable: an `npm install --no-audit --no-fund` arm reprints EXACTLY 43/44, the pnpm arm reads 37/38. Mechanism is #1268's pnpm-aware installTargetDeps — reduced scopes fall from 3 of 13 (apps/e2e, apps/web, packages/ui) to 2 of 13 (apps/web, packages/ui); apps/e2e leaves the reduced set because `@playwright/test` now resolves. 6 rows dropped, ZERO appeared, and every one of the 6 is an artifact of a workspace member without node_modules rather than dead code: a Medium 'Unlisted import(s) in apps/e2e/eslint.config.mjs', a Medium 'Unresolved import(s) in tooling/prettier/package.json', and 4 'Unused binary/binaries' rows (apps/e2e, apps/web, packages/ui, tooling/prettier). Command: `pnpm corpus-drift --target saas-lite --install` (2026-07-28). STILL A PARTIAL: 2 of 13 scopes stay in #810's reduced no-dependencies mode and are disclosed as the M5-98 Info row, which is the one disclosure row this target emits today — the M5-00 framing in the older prose below is history, not the current output (MEASURED 2026-07-28 in both arms). Prior notes: #940: RE-MEASURED 2026-07-24 at 12 counted / 13 total (was 10/11) — a PRECISION FIX, PROVEN by controlled before/after on this identical clone: pre-#694 knip code reprints exactly 10, current code 12. This target moved UP (unlike the other three) because #810 (2026-07-23) added the reduced-mode fallback: the packages/ui scope that previously FAILED knip entirely (M5-00, contributing 0) now re-runs with plugins disabled and surfaces review-tier unused-FILE findings (authenticity-token, lazy-render, mobile-navigation-*, shadcn/index, progress under packages/ui), disclosed as an M5-98 Info row (hence total 13 = 12 counted + 1 M5-98). #695's in-file type-export suppression pulls the other direction; net +2. The M5-98 disclosure and the review-tier confidence keep these entry-graph-contingent findings honest. Original: #548: RE-MEASURED 2026-07-18 (cloned pin + `npm install` + Harvey's per-workspace knip) after expandGlob learned to expand `packages/**`: quality-scan now enumerates ALL 13 workspaces (was 6 — only apps/* + tooling/*), so the 7 `packages/**` workspaces are knip'd for the first time. 3->10 counted, 3->11 total. The prior 3 remain (tooling/eslint apps.js/base.js/nextjs.js, Low). The 7 NEW findings: 6 more `eslint.config.mjs` unused-FILE flags (packages/features/accounts + i18n + next + shared + supabase Low, packages/features/auth Medium) PLUS one genuine dead component — packages/features/auth/src/components/auth-link-redirect.tsx (Medium). HONEST CAVEAT (same shape as the original tooling/eslint 3): the eslint.config.mjs flags are a per-workspace-scoping artifact — each package DOES consume its own flat-config via its build tooling, but knip scanning a package in isolation (as it did under the npm-only install path this job used until #1268) could not see that; auth-link-redirect.tsx is the one real find. STILL A PARTIAL: 3 of 13 scopes fail knip and are disclosed in M5-00 (#505, Info) — apps/web (the long-standing eslint-config-next patch error), apps/e2e (missing @playwright/test), and now packages/ui (@kit/eslint-config/base.js unresolved). Prior baselines: not-run (pre-#519) -> 3 (#544, per-workspace but packages/** still dropped) -> 10 (#548, packages/** now scanned). Re-verify if a dep bump makes those 3 scopes resolve. #1128: RE-MEASURED 2026-07-26 at 43/44 (was 12/13) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories (unlisted/unresolved/duplicates/enumMembers/optionalPeerDependencies/catalog/binaries) now surface. `pnpm corpus-drift --target saas-lite --install` reproduced 43 counted." },
      "M5-slop": { counted: 73, total: 76, note: "#1532 RESIDUAL: RE-MEASURED 2026-07-31 at 73/76 (was 74/77) — DRIFT -1, a FALSE POSITIVE #1532 introduced and this pass removes, restoring the pre-#1532 reading. `doesOwnIo` matched its bare `child_process` spawner names on a METHOD call as well, so `pattern.pattern.exec(input)` in `matchUrlPattern` (apps/web/middleware.ts:160) read as spawning a process — a row THIS TARGET'S OWN prior note lists among the 5 it read at source and graded genuine seams, while the shipped fix was firing on it. The names now match a bare identifier only, which is how all three sampled rows called them (`import { spawn } from 'child_process'`); `execSync` is still caught by the `Sync` suffix rule. Corpus-wide the narrowing restores 3 rows (this one, inbox-zero chat-sdk/bot.ts:1863 `extractConnectCode`, tanstack-com scripts/check-docs-menu-links.ts:554 `getLinkTarget`), all three regex matchers read at source. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-37def9c2> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 74/77 (was 79/82) — DRIFT -5, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 1 finding here, so the pre-fix reading was 73). All 6 originally-spared rows were read at source. 5 hold — `getClassName` (pure className computation, caller `RootLayout` awaits i18n + the theme cookie), `matchUrlPattern`, `setRequestId`, `captchaTokenGetter`, `shouldIgnoreError` (pure error-message classifier, caller awaits `signInWithOtp`). 1 is the `async`-caller-with-no-await boundary #1533 narrowed but could not reach here: `getPaths` (apps/web/app/sitemap.xml/route.ts:24) builds a static path list for a `GET` that awaits nothing, and that `GET` returns `getServerSideSitemap(...)` — imported from `next-sitemap`, i.e. outside the cloned tree, so no source-level pass can say whether it produces a promise. RE-READ 2026-07-31, correcting #1533's own issue body, which called this caller synchronous: it is UNREADABLE, not proven sync, and the exemption's conservative direction keeps it spared. Not the same disposition as mvp-boilerplate's row, which fires as of #1533. This target is the corpus's declared M5-slop FP-drift watch, so its residual is enumerated rather than summarised. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-37def9c2> --out f.json`. Prior note: Re-measured 2026-07-17: 23->79 counted, mostly #391's new 'Single-use helper' class (56) on top of the prior 22 'Redundant JSDoc' + 1 'Orphan TODO'; 3 Info (narrating comment, decorative emoji). Still the corpus's highest slop count — a well-maintained starter kit whose JSDoc/helper granularity habits trip the detectors, the corpus's main M5-slop FP-drift watch." },
      "M6-indicator": { counted: 2, total: 2, note: "#483: MEASURED 2026-07-17 — 2 'cookie serialization' in packages/features/auth. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 4, total: 5, note: "#1475-#1480: RE-MEASURED 2026-07-28 at 4/5 (was 6/7) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-37def9c2> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 6/7 on the identical clone. -2. The raw <img> at packages/features/accounts/src/components/mfa/multi-factor-auth-setup-dialog.tsx:412 is the MFA QR code the data:/blob: guard's OWN comment names as its motivating example: `<QrImage src={form.getValues('qrCode')} />` renders `<img src={src}>` one prop hop away, so no data: literal is ever in view (#1477). turbo/generators/templates/package/generator.ts:57 is a plop scaffolding template (#1476). Prior note: #1261: TRIAGED 2026-07-28 — 6/7 reproduces, and only 2 of the 6 hold (33.3%), the corpus's WORST M7 precision. Real: the 'React Compiler flag unresolvable' disclosure row (factually correct — the flag really is env-derived) and the /version route's `execSync('git log …')`, #230's kept genuine request-handler stall. False, all four with a decisive cause: the MFA QR `<img>` (multi-factor-auth-setup-dialog.tsx:412) is the `data:`/`blob:` guard's OWN NAMED EXAMPLE and escapes it only because the src arrives as `form.getValues('qrCode')` rather than a literal — the value is Supabase's `data.totp.qr_code` data URI; the await-in-loop is in turbo/generators/templates/package/generator.ts, a plop scaffolding template that never runs at request time; and both nested-loop joins (is-route-active.ts:96, app-breadcrumbs.tsx:65) iterate URL PATH SEGMENTS against URL path segments — both collections are bounded by URL depth at well under ten, so there is no refactor behind either, which is #230's own standard for noise. Prior note: Re-measured 2026-07-17: 23->6 under #248's React Compiler gate — the 11 inline-literal + 6 index-key + 2 context-value micro-render tail no longer emits (this repo's `reactCompiler: ENABLE_REACT_COMPILER` is env-derived/unresolvable, which #248 treats as off; the Watch-severity 'React Compiler flag unresolvable' finding from #269 stays counted as the disclosure). Also counted: the corpus's other genuine request-path stall ('Blocking sync I/O in request handler' — the execSync-on-a-/version-route case #230 kept), 1 'Await in loop (N+1)', 2 'Nested-loop join', 1 raw <img>; 1 exhaustive-deps Info." },
      M8: M8_E2E_ONLY_SUITE, // `turbo test` script + 3 test files — ALL Playwright E2E (measured #300), so there is no unit suite for Stryker to mutate. #252's ruling (zero files or a single placeholder == absent) confirms this is a real-but-unmutable suite, not a zero-coverage case.
      "M8-intent": { counted: 1, total: 1, note: "#372 test-intent pass, measured 2026-07-17 at the M8/M8-intent split: 1 'Happy-path-only tests on security-critical code' (Medium, apps/e2e/tests/authentication/auth.po.ts). This is the finding the 2026-07-17 drift runs mis-read as evidence that the M8 MUTATION not-run reason was stale — the split exists so the two measurements can never shadow each other again." },
      M9: { counted: 6, total: 7, note: "#1460/#1461/#1462: RE-MEASURED 2026-07-28 at 6/7 (was 9/10) — DRIFT -3, all three in the #1460 SSR helper family and all three READ: cookie-banner.tsx:103, mode-toggle.tsx:129 (`setCookeTheme`, a module-level lowercase helper whose one in-file call site is an event handler) and sidebar.tsx:285. The 4 that REMAIN include cookie-banner.tsx:111 — same file, different row — which is the precision evidence: the fix is per-read and per-call-site, not per-file. MEASURED via `pnpm exec tsx src/cli/static-detect.ts <clone>` on the identical pinned clone, pre- and post-change arms. Prior note retained below. PRIOR: #1293: RE-MEASURED 2026-07-28 at 9/10 (was 10/11) — DRIFT -1, a PRECISION FIX, and the single row is a clean confirmation of the mechanism rather than a rounding: packages/ui/src/makerkit/authenticity-token.tsx:13, where `useCsrfToken()` opens with `if (typeof window === 'undefined') return '';` and then reads `document.querySelector`. That guard is a preceding SIBLING statement, not an ancestor, so the ancestor-only guard walk could not see it — while the finding's own evidence asserted no such guard existed. Fixed by #1293's early-return guard rule (corpus pair M9C-SSR-EARLYRET-POS/NEG, proven able to fail by reverting the rule). The other 9 rows are byte-identical across the arms. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at a91c2f9 reprints 10/11. Prior note: #1262/#1292: RE-MEASURED 2026-07-28 at 10/11 (was 10/10) — the disclosure row only, no detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 10/10. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 10 counted (was 12) — the #964 M9 SSR precision fix dropped 2 'SSR-only API misuse' FPs: a `window?.location` optional-chained read in a .tsx component (sign-in-methods-container.tsx — the author's absent-guard) and a `document.querySelector` read in the non-component `.ts` hook use-csrf-token.ts. Residual 10: 8 SSR-only + 2 accidental dynamic rendering. Prior note: Re-measured 2026-07-17: 2->12 — the 2 'Accidental dynamic rendering' plus 10 of #381's 'SSR-only API misuse' class in packages/features/auth sign-in/sign-up components." },
      M10: { counted: 1, total: 1, note: "#279: measured 2026-07-15 via m10FindingsFromSchema over the cloned apps/web/supabase/migrations (9 columns parsed, 1 PII-bearing table). accounts: Low (ambiguous NAME? + EMAIL) — the corpus's other near-floor M10 reading." },
    },
  },
  // ── #894: the Prisma app-layer tier (epic #756, shipped 2026-07-23) had NO real-code regression
  // baseline. The six targets above were all selected in the 2026-07-12 sweep; boxyhq carries a
  // schema.prisma but its baselines predate detectOrm routing, the Prisma tenant-scope/BOLA
  // detector (#760), M7's schema.prisma FK-index check (#761) and M10's Prisma classification
  // (#758). The four below are pinned and measured 2026-07-24 on this machine (clone at pin ->
  // `npm install --no-audit --no-fund` in the clone, which is what corpus-drift --install did at
  // the time — since #1268 it installs with the target's own lockfile-implied package manager, and
  // #1404 re-measured every baseline that moved as a result ->
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here.  An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 435, total: 657, note: "#894: MEASURED 2026-07-24 — 356 counted (151 Medium + 193 Low + 12 Medium security-path), 151 Info plus the #365 M4-00 small-clone disclosure for 508 total. The corpus's second-largest duplication surface; an Nx monorepo (apps/api NestJS + apps/client Angular + libs/*) whose per-entity service/DTO scaffolding is the vein. #1128: RE-MEASURED 2026-07-26 at 435/657 (was 356/508) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target ghostfolio --install` reproduced 435 counted." },
      "M4-diverged": { counted: 2, total: 2, note: "#894: MEASURED zero 2026-07-24 — the near-miss pass admits no diverged family here. A useful FP floor on a large repo: this target's 356 exact clones did NOT drag the diverged pass up with them, so a non-zero appearing later is a new detection or an over-match, not scale. #1128: RE-MEASURED 2026-07-26 at 2/2 (was 0/0) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 2 such pairs now qualify. `pnpm corpus-drift --target ghostfolio --install` reproduced 2 counted." },
      "M5-knip": { counted: 456, total: 457, note: "#894: MEASURED 2026-07-24 after `npm install` in the clone (2196 packages) — 413 'Unused file' (Low) + 21 'Unused security-relevant file' (Medium) + 11 unused-export files + 1 Info (#580 M5-99 'result may be unreliable for one or more scopes'). CAVEAT recorded with the number, not instead of it: 413 unused FILES on an Nx workspace is the shape knip produces when it cannot see Nx's project graph as the entry surface, so treat this as a DRIFT baseline (it must reproduce), not as a claim that ghostfolio has 413 dead files. The M5-99 uncertainty row is part of the baseline and is what says so in the output. #1128: RE-MEASURED 2026-07-26 at 456/457 (was 446/447) — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories now surface. `pnpm corpus-drift --target ghostfolio --install` reproduced 456 counted." },
      "M5-slop": { counted: 51, total: 52, note: "#894: MEASURED 2026-07-24 — 28 'Else after return' + 6 'Orphan TODO' + 6 'Placeholder stub' + 4 'Redundant boolean ternary' + 5 single-use helpers; 1 narrating-comment Info. #1128: RE-MEASURED 2026-07-26 at 51/52 (was 49/50) — a precision fix from #1088/#1065 (commit c75186a, merged 2026-07-25): the detector's SOURCE_FILE filter widened from ts/tsx/jsx/mjs to also include plain js/cjs/mts/cts, so 2 more genuinely-scanned files surface. `pnpm corpus-drift --target ghostfolio --install` reproduced 51 counted." },
      "M6-indicator": { counted: 5, total: 5, note: "#894: MEASURED 2026-07-24 — 5 hand-rolled-shape indicators. All Info/non-grading (#267); counted === total by construction (see the manifest's M6-indicator note)." },
      M7: { counted: 78, total: 78, note: "#1479: RE-MEASURED 2026-07-31 at 78/78 — UNCHANGED, and that is the expected result: #1479 RE-WORDS the whole-library class for a server-only module rather than suppressing it, and a re-worded row is still counted. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-7bd6ca6d> --out f.json`. THE SPLIT, replacing the by-location ESTIMATE the prior note left standing: of the 59 whole-library rows, 20 now carry the server-side claim ('A request entry point in this tree imports this module and no client entry point does … the visitor-bundle cost stated by this class does NOT apply', severity Low) and 39 keep the original visitor-bundle claim with the evidence disclosing that client-reachability 'was not established'. By location the 59 are apps/api 27 (20 re-worded, 7 not), libs 20 (0 re-worded) and apps/client 12 (0 re-worded) — so #1261's 27-under-apps/api figure reproduces exactly, and 20 of those 27 are the population the fix reached. RESIDUAL, measured not assumed: NO file under apps/client or libs imports `@ghostfolio/api/*` (the tsconfig.base.json alias for apps/api/src/*) — 0 hits over 511 .ts files, `grep -ra`, and no TS/JS file under those trees is binary-classified — so all 27 apps/api rows are server-only IN FACT and the guard reaches 20 of them. The 7 it misses split into two named causes: object.helper.ts:3, models/rule.ts:11 and portfolio/calculator/roai/portfolio-calculator.ts:23 import no server runtime of their own (they fail `importsServerRuntime`), while the three data-provider services and twitter-bot.service.ts DO import @nestjs/common but their only importers are `*.module.ts` files, which `REQUEST_ENTRY_PATH` does not treat as a request entry, so `requestReachableModules` never reaches them. Nest's provider wiring is not an import edge from a controller — carried as #1666 rather than widened here, because widening REQUEST_ENTRY_PATH also feeds the sync-I/O tier and the dev-tooling subtraction and cannot be settled without a corpus-wide re-measure. Prior note: #1261: 78/78 reproduces 2026-07-28; 2 rows drawn into the 40-row seeded sample (seed 1261) and read against source — 1 holds, 1 does not. SAMPLED, NOT CENSUSED: 76 rows untriaged, and this target is the corpus's worst place to generalise from because 59 of its 78 rows are ONE class (whole-library lodash import). The sampled false row is from that class: `import { isEmpty } from 'lodash'` in apps/api/src/services/queues/data-gathering/data-gathering.service.ts:34, a NestJS SERVER module, where the finding's stated impact ('dead code in the bundle … parse/execute cost on every visitor') cannot obtain — server code ships no bundle. By location, 27 of the 59 sit under apps/api and 20 under libs, so the population that may share this defect is large; it is UNMEASURED beyond the one row read, and is filed rather than asserted. Prior note: #894: MEASURED 2026-07-24 and the reason this target is pinned — 5 of the 78 are #761's Prisma `schema.prisma` UNINDEXED-FOREIGN-KEY findings (Account.platformId, AccountBalance.userId, Order.accountUserId, Order.symbolProfileId, SymbolProfile.userId), the first real-code regression baseline the Prisma M7 tier has ever had. The rest: 59 whole-library lodash imports, 8 nested-loop joins, 6 await-in-loop N+1." },
      M8: {
        // REASON: ghostfolio is not mutation-scoreable because no M8_CORPUS_CONFIGS entry exists for it — the blocker is our own backlog, not the target
        // KIND: empirical
        // PROVENANCE: MEASURED 2026-07-24 (#894), re-checked 2026-07-28: `mutation-scan --detect-only` detects a real jest suite, and src/scan/m8-corpus.ts has entries for proposit, boxyhq, rallly and inbox-zero — none for ghostfolio. What is missing is a `mutate` scope narrowed to the files this Nx suite covers, which means running the target's own suite to see what it covers.
        // FALSIFIER: sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q "^  \"\{0,1\}ghostfolio\"\{0,1\}:" src/scan/m8-corpus.ts && exit 0 || exit 1'
        // TOUCHES: src/scan/m8-corpus.ts
        reason: "#894: MEASURED 2026-07-24 (re-checked 2026-07-28) — mutation-scan --detect-only DETECTS a real suite here (jest via apps/api/jest.config.ts; it even replicates the target-declared TZ=UTC env, #503), so #224's zero-coverage finding correctly does NOT apply and a finding count is the wrong unit. Scoring it needs a provisioned Stryker + runner plugin, which is corpus-m8.yml's job and needs a measured per-target M8_CORPUS_CONFIGS entry (a `mutate` scope narrowed to the files this Nx suite actually covers). Not attempted in #894: choosing that scope means running the target's jest suite to see what it covers, which is beyond a manifest change. This blocker is OURS, not the target's — the falsifier above exits 0 the moment an M8_CORPUS_CONFIGS entry lands. Recorded not-run rather than 0 — a 0 would read as 'no surviving mutants' on a suite nobody has mutated.",
        falsifier: "sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q \"^  \\\"\\{0,1\\}ghostfolio\\\"\\{0,1\\}:\" src/scan/m8-corpus.ts && exit 0 || exit 1'",
      },
      "M8-intent": { counted: 0, total: 0, note: "#894: MEASURED zero 2026-07-24 across this target's 31 spec files — no assertion-free/tautological/happy-path-only/mock-the-subject shape fired. A real FP floor for the test-intent pass on a professionally-maintained suite, and the direct contrast with inbox-zero's 305." },
      M9: { counted: 6, total: 10, note: "#1262/#1292: RE-MEASURED 2026-07-28 at 6/10 (was 6/9) — the disclosure row only, no detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 6/9. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 6 counted / 9 total (3 Info not-assessed rows) — the #964 M9 SSR precision fix dropped 7 'SSR-only API misuse' FPs, all browser-global reads inside functions in non-component `.ts` files (apps/client/src/main.ts + 6 in libs/common/src/lib/helper.ts — matchMedia/documentElement/navigator.language in plain helpers, not component render bodies). This is an Angular client, not an App Router app: the App-Router-only classes measuring zero here is the correct answer and any non-zero in THOSE is a straight regression. Prior note: #894: MEASURED 2026-07-24 — 13 'SSR-only API misuse' (8 document, 4 window, 1 navigator) plus 3 Info #903 not-assessed rows." },
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
    m8: M8_CORPUS_CONFIGS.rallly,
    modules: {
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. A large real Next App Router monorepo, so the zero is a meaningful floor rather than an artefact of a thin tree. An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      M4: { counted: 196, total: 280, note: "#894: MEASURED 2026-07-24 — 160 counted (83 Medium + 65 Low + 6 Medium/6 Low security-path), 25 Info plus the #365 M4-00 disclosure (11 small clones) for 186. Measured identically before and after `npm install`, so the install step is inert for M4 here as it is for the rest of the corpus. #1404 (2026-07-28) re-confirmed that inertness against the install path itself, not just its presence: 196/280 reproduces byte-identically under BOTH the npm arm and a full `pnpm install`, so the -6 M5-knip move below did not touch M4. #1128: RE-MEASURED 2026-07-26 at 196/280 (was 160/186) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target rallly --install` reproduced 196 counted." },
      "M4-diverged": { counted: 2, total: 2, note: "#894: MEASURED 2026-07-24 — 2 High review-tier families, one of them a 5-function family. Small relative to the 160 exact clones, the same ratio the older targets show. #1128: RE-VERIFIED 2026-07-26 byte-identical at 2/2 despite #1095/PR#1129's same-file-pair widening (that widening rolls into the general M4 module here, not this security-path-only baseline — `pnpm corpus-drift --target rallly --install` reproduced 2 counted, no drift)." },
      // #1436 criterion 4 — rallly's partial has a blocker that is cheap to re-test and WILL dissolve
      // when the target bumps dotenv, which is exactly the shape that decays unnoticed. It lives in a
      // `note` rather than a ModuleNotRun (the module DID run, at 147/148), so the type-level
      // falsifier does not reach it; the registry block does.
      //
      // REASON: 3 of rallly's 16 knip scopes stay reduced because the target's own dotenv@17 prints a `[dotenv@17.x]` banner to stdout, which knip then tries to parse as JSON when loading its config
      // KIND: empirical
      // PROVENANCE: MEASURED 2026-07-28 (#1404) — `pnpm corpus-drift --target rallly --install` reads 147/148 with apps/web, packages/database and packages/screenshots reduced; the failure is stdout pollution, not a missing dependency tree, and it is disclosed as this baseline's M5-98 Info row.
      // FALSIFIER: sh -c 'command -v curl >/dev/null 2>&1 || exit 127; b=$(curl -fsS --max-time 20 https://raw.githubusercontent.com/lukevella/rallly/HEAD/apps/web/package.json) || exit 127; c=$(printf %s "$b" | tr -d "\042 "); case "$c" in *dotenv:^17*) exit 1;; *) exit 0;; esac'
      // TOUCHES: src/quality-scan.ts src/cli/quality-scan.ts
      "M5-knip": { counted: 147, total: 148, note: "#1404: RE-MEASURED 2026-07-28 at 147/148 (was 153/154) — DRIFT -6, a PRECISION FIX. PROVEN by controlled before/after on the identical pinned clone with the install path as the only variable: an `npm install --no-audit --no-fund` arm reprints EXACTLY 153/154, the pnpm arm reads 147/148. Mechanism is #1268's pnpm-aware installTargetDeps — reduced scopes fall from 4 of 16 (apps/landing, apps/web, packages/database, packages/ui) to 3 of 16. 8 rows dropped, 2 appeared. Dropped, all of them entry-resolution artifacts of a workspace with no node_modules: a Medium 'Unused security-relevant file: apps/landing/src/i18n/middleware.ts', apps/landing/instrumentation-client.ts, apps/landing/src/proxy.ts, packages/database/prisma/seed.ts, packages/database/prisma/seed/data.ts, packages/ui/vitest.config.mts, and 2 'Unused binary/binaries' rows (apps/docs, packages/screenshots). Appeared: a Medium 'Unlisted import(s) in apps/landing/postcss.config.mjs' and 'Unused dependencies declared in packages/screenshots/package.json'. Command: `pnpm corpus-drift --target rallly --install` (2026-07-28). STILL A PARTIAL and the baseline still says so, but for a DIFFERENT, newly-measured reason: the 3 remaining reduced scopes (apps/web, packages/database, packages/screenshots) now fail knip's config load because the target's own dotenv prints a `[dotenv@17.x]` banner onto stdout that knip then tries to parse as JSON — a stdout-pollution failure, not a missing dependency tree. That is disclosed as the M5-98 Info row and is part of this baseline. Prior notes: #894 MEASURED 2026-07-24 at 67/68 (the same run without deps read 69, recorded so the delta is on the record); #1128 RE-MEASURED 2026-07-26 at 153/154 — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25) surfacing knip's six previously-dropped IssueRecords categories, most visibly `unlisted`/`unresolved` given the partial-install shape it then had." },
      "M5-slop": { counted: 113, total: 167, note: "#1532: RE-MEASURED 2026-07-30 at 113/167 (was 123/177) — DRIFT -10, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 1 finding here, so the pre-fix reading was 112). 11 spared, 1 of them the disclosed `async`-caller-with-no-await boundary (`verifySha256`, apps/web/src/features/api-keys/utils.ts:113 — #1533). The seeded 50-row corpus sample drew 1 row from this target (`isOutdated`, trpc/routers/system.ts:25, a pure version comparison whose caller awaits prisma + a release fetch): graded a genuine seam. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-a680798c> --out f.json`. Prior note: #894: MEASURED 2026-07-24 — 20 single-use helpers + 9 else-after-return + 1 single-call wrapper counted alongside the rest; 49 'Decorative emoji in a log call' + 4 narrating comments are the Info tail. The decorative-emoji vein is this target's signature and the thing to watch for precision drift." },
      "M6-indicator": { counted: 24, total: 24, note: "#894: MEASURED 2026-07-24 — 24 hand-rolled-shape indicators, the corpus's highest reading after inbox-zero's 51. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 14, total: 17, note: "#1353: RE-MEASURED 2026-07-28 at 14/17 (was 12/15) — +2, PURELY ADDITIVE, re-run against a pristine-main control worktree at 11ef7e2 (i.e. AFTER #1461 and #1490, so neither of those is credited here). Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-a680798c> --out f.json`; a pristine-main control worktree at c597012 reprints EXACTLY 12/15 on the identical clone. The two restored rows are packages/utils/src/encryption.ts:23 and :86 (`crypto.pbkdf2Sync`), which #1353 recorded as SILENCED by #1344's reachability gate: resolveImport could not follow the `@rallly/utils` workspace specifier through that package's `exports` wildcard (./* -> ./src/*.ts), so a shared package was unreachable from the app's routes and the generic sync-I/O tier stayed quiet. NOTE for a reader reconciling this against #1306: that issue's four seed/build-script N+1 removals are ALREADY in the 12/15 control — #1490's #1476 dev-tooling gate is a superset of the path exclusion #1306 asked for, so this row shows no subtraction. Prior note: #1475-#1480: RE-MEASURED 2026-07-28 at 12/15 (was 17/20) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-a680798c> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 17/20 on the identical clone. -5. 4 await-in-loop rows are packages/billing/src/scripts/* and packages/database/prisma/seed.ts (#1476). 1 raw <img> is apps/landing/src/app/api/og-image/route.tsx:35 — an SVG logo inside a Satori OG-image route, carrying the repo's own `biome-ignore ... it's ok to use img here` (#1477). The oversized-image row is re-worded to Unreferenced (#1480), so total falls by 3 and not 5. Prior note: #1261: 17/20 reproduces 2026-07-28. This target was IN the sample frame for the 40-row seeded draw (seed 1261) over the four large targets and drew ZERO rows — 17 of 858 is ~2% of the frame, so an empty draw is expected, not a skip. Its M7 precision is therefore UNMEASURED, not clean. Prior note: #894: MEASURED 2026-07-24 — 9 await-in-loop N+1, 4 raw <img>, 1 nested-loop join, 1 whole-library lodash import, 1 sort-in-JSX, 1 oversized-committed-images roll-up (7 images, 9.3 MB); 3 hook-dep Info. NOTE for the Prisma tier: #761's unindexed-FK check contributes ZERO here — this target's schema.prisma carries no models (see schemaPath above), so the FK check has nothing to read. ghostfolio/documenso/inbox-zero are where that detector is baselined." },
      M8: {
        mutationScore: 53.33, killed: 16, valid: 30, coveredScope: ["src/lib/datetime/utils.ts"],
        note: "#1268: MEASURED 2026-07-28 — the pnpm-aware install closes this target's #894 not-run reason directly: `pnpm install` (not npm) at the clone root resolves apps/web/node_modules in full (verified: the app's own 7-case vitest spec for src/lib/datetime/utils.ts runs clean). Unlike inbox-zero, no enableGlobalVirtualStore complication here — the pnpm-aware install alone was sufficient. A real Stryker run against src/lib/datetime/utils.ts (normalizeTimeZone/getCalendarDate/etc — pure timezone logic, no network/DB) scored 53.33% (16 killed + 0 timeout = 16 detected / 30 valid mutants; 4 Survived, 10 NoCoverage, 0 CompileError/RuntimeError/Ignored) — reproduced byte-identically across 2 consecutive runs, so no tolerance earned or applied (#432's precedent). NOT a whole-repo or whole-app claim (coveredScope is ONE file); `pnpm corpus-drift --target rallly --install --m8` reproduces it.",
      },
      "M8-intent": { counted: 8, total: 8, note: "#894: MEASURED 2026-07-24 — 4 'Call-count-only test' (Low), 2 'Asserts response shape, not business values' (Medium), 2 '`vi.hoisted` factory references non-hoisted binding' (Medium)." },
      M9: { counted: 5, total: 10, note: "#1460/#1461/#1462: RE-MEASURED 2026-07-28 at 5/10 (was 12/17) — DRIFT -7, every one in the #1460 SSR helper family, all 7 in packages/ui/src/event-calendar/event-calendar-dnd.tsx (module-level pointer-gesture helpers reached only from listener callbacks). event-calendar-dnd.tsx:86 REMAINS, which is the scope control on the same file. This target also exercised two defects #1461's alias fix EXPOSED rather than caused, both fixed in this PR and neither visible in the final number: a type-only `import type { AppRouter }` in the 'use client' tRPC provider made the whole server router tree read as client-reachable (3 spurious `Missing server-only guard` Highs), and the reachability walk crossed `\"use server\"` boundaries (the remaining 2). Net M9 `Missing server-only guard` here is 0 before and after. MEASURED via `pnpm exec tsx src/cli/static-detect.ts <clone>` on the identical pinned clone, pre- and post-change arms. Prior note retained below. PRIOR: #1262/#1292: RE-MEASURED 2026-07-28 at 12/17 (was 12/15) — +2 total, NEITHER of them a detection change. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 12/16. Read the arithmetic carefully: the before arm on this PR's base commit already reads 12/16, not the 12/15 recorded here — a PRE-EXISTING undisclosed drift of +1 Info that this PR did not cause and is correcting in passing. Its cause is #1051's `M9 — Cross-user cache bleed — not assessed` row, which joined the three #903 not-assessed rows on this non-Supabase target and was never folded into this baseline. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 12 counted / 15 total (3 Info not-assessed rows) — the #964 M9 SSR precision fix dropped 2 'SSR-only API misuse' FPs: a `document.createElement` read in the non-component `.ts` util apps/web/src/lib/image-processing.ts and a `navigator.userAgent` read in the non-component `.ts` hook packages/ui/src/hooks/use-platform.ts. Residual 12: 11 SSR-only + 1 accidental dynamic rendering (cookies() read). Prior note: #894: MEASURED 2026-07-24 — 13 SSR-only API misuse (11 window, 1 document, 1 navigator) + 1 'cookies() read in a page'." },
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
    m8: M8_CORPUS_CONFIGS["inbox-zero"],
    modules: {
      "M1-boundary": { counted: 5, total: 5, note: "#1459: MEASURED 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — 5 High rows. NOT TRIAGED (drift baseline, not a defect count). #1434: RE-VERIFIED 2026-07-31, NO MOVE — controlled before/after `static-detect` on <clone-of-2b78f2b>, one variable (the #1434 diff): both arms 1618 findings, 0 rows only-before, 0 only-after. The 5 are all `M1 — Server Action missing authorization check` (categorize.ts:150/162, organization.ts:269, rule.ts:391/395), so this target's M1-boundary population is entirely the sibling detector's — the class #1434 changes has a population of ZERO here, which is the reason to state it rather than imply coverage. #1501: TRIAGED 2026-07-31, and the count does not move: 5/5, all still reported, all five READ AGAINST SOURCE and all five FALSE POSITIVES with ONE named cause. Every flagged node is a NON-EXPORTED helper inside a 'use server' module - deleteCategory (categorize.ts:150), upsertCategory (:162), acceptInvitation (organization.ts:269) and two nested deleteRule/upsertRule closures (rule.ts:391/395). Only an EXPORTED function in a 'use server' module is an RPC endpoint, so none of these is reachable by a client at all; each is called by an exported next-safe-action `actionClient(...).action(...)` whose middleware supplies an already-authorised `ctx.emailAccountId`, and each Prisma call is scoped by that id (`where: { id: categoryId, emailAccountId }`). acceptInvitation additionally calls getInvitation, which throws SafeError('You are not the recipient of the invitation'). So this baseline stands behind 5 rows KNOWN FALSE with a measured cause, not 5 unexamined rows. The narrowing (flag only exported functions in a 'use server' module) is deliberately NOT made in the #1501 PR: it would move this key on several targets at once and make that PR's carbon movement unattributable to one variable. Tracked as a follow-up." },
      M4: { counted: 703, total: 1170, note: "#894: MEASURED 2026-07-24 — 341 counted (72 Medium + 266 Low + 3 Medium security-path), 195 Info plus the #365 M4-00 disclosure (45 small clones) for 537. #1128: RE-MEASURED 2026-07-26 at 703/1170 (was 341/537) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too — the largest M4 swing in the corpus, consistent with this target's deep single-file test-setup/mock-chain vein (#1080's own measured sample). `pnpm corpus-drift --target inbox-zero --install` reproduced 703 counted." },
      "M4-diverged": { counted: 5, total: 5, note: "#894: MEASURED 2026-07-24 — 1 High review-tier diverged security-path family. #1128: RE-MEASURED 2026-07-26 at 5/5 (was 1/1) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 4 more such pairs now qualify. `pnpm corpus-drift --target inbox-zero --install` reproduced 5 counted." },
      "M5-knip": { counted: 199, total: 199, note: "#1404: RE-MEASURED 2026-07-28 at 199/199 (was 212/213) — DRIFT -13 counted, -14 total, a PRECISION FIX. PROVEN by controlled before/after on the identical pinned clone with the install path as the only variable: an `npm install --no-audit --no-fund` arm reprints EXACTLY 212/213, the pnpm arm reads 199/199. Mechanism is #1268's pnpm-aware installTargetDeps — under npm, 3 of 13 scopes (apps/web, packages/api, packages/cli) ran in #810's reduced no-dependencies mode; under `pnpm install` (MEASURED 17s) ZERO do, so the M5-98 reduced-tier Info row is GONE from this baseline entirely (that row is the -14th, which is why counted and total now coincide). 16 rows dropped, 2 appeared. Dropped: 4 apps/web unused-FILE flags that were pure entry-resolution artifacts (its own __tests__/setup.ts, instrumentation-client.ts, mdx-components.tsx, vitest.config.mts), 1 unused-export in apps/web/utils/__mocks__/email-provider.ts, 9 'Unused binary/binaries'/'Unused devDependencies' rows across workspace members that had no node_modules to check against, and the M5-98 row. Appeared: 2 'Unused dependencies' rows (apps/image-proxy, apps/image-proxy-aws), newly readable once those members resolve. Command: `pnpm corpus-drift --target inbox-zero --install` (2026-07-28). Prior notes: #894 MEASURED 2026-07-24 at 197/198 with a root-only install (108 packages); #1128 RE-MEASURED 2026-07-26 at 212/213 — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25) surfacing knip's six previously-dropped IssueRecords categories." },
      "M5-slop": { counted: 1098, total: 1123, note: "#1532 RESIDUAL: RE-MEASURED 2026-07-31 at 1098/1123 (was 1093/1118) — DRIFT +5, net of 6 RECOVERED FALSE NEGATIVES and 1 false positive removed. The 6 come from `doesOwnIo` now following a callee it can RESOLVE one hop: `parseOptions` (apps/web/scripts/migrate-microsoft-provider-account-ids.ts:110) and `parseSetupOptions` (apps/web/scripts/setup-telegram-bot.ts:31) both reach `process.exit` through `printHelpAndExit`; `resolveBaseUrl` (packages/api/src/main.ts:319) reaches `existsSync`/`readFileSync` through `loadConfig`; `getCopilotWorkspaceDir` (packages/cli/src/setup-aws.ts:1242) and `resolveOutputDir` (packages/cli/src/setup-terraform.ts:402) reach `existsSync` through `findCopilotRoot`/`findRepoRoot`; `buildBaseUrl` (scripts/dev-setup.ts:543) reaches `lstatSync` through `isLinkedWorktree`. All six read at source. The 1 removed is `extractConnectCode` (apps/web/utils/messaging/chat-sdk/bot.ts:1863), a pure `CONNECT_COMMAND_REGEX.exec(trimmed)` matcher that the over-wide spawner match was reading as spawning — see saas-lite's note for that fix. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2b78f2b3> --out f.json`. Prior note: #1533: RE-MEASURED 2026-07-31 at 1093/1118 (was 1090/1115) — DRIFT +3, three RECOVERED FALSE NEGATIVES on the `async`-caller-with-no-await boundary the prior note enumerated as 20 rows and left disclosed. All three read at source: `createRegistry` (app/api/v1/openapi/route.ts:64, caller returns `new NextResponse(...)`), `parseAndValidateDriveState` (utils/drive/handle-drive-callback.ts:216, caller returns an object literal) and `repairObjectText` (utils/llms/index.ts:1505, caller returns a property of a locally-computed value) — none of their callers does any async work. The 17 that REMAIN on that boundary include the counterexample that governs the whole class, `convertTextToHtmlParagraphs` (utils/outlook/mail.ts:408), whose caller returns `sendEmailWithHtml(...)`; and `getWorkerConfig`/`parseWorkerQueues` (apps/worker/src/runtime.mjs:115,144), which the FIRST cut of #1533 wrongly fired on — `startWorkerRuntime` returns a plain object literal but opens a Redis connection and hands BullMQ an `async` job handler, which is why the shipped rule also refuses to fire when the caller schedules nested async work. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2b78f2b3> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 1090/1115 (was 1430/1455) — DRIFT -340, the corpus's largest M5-slop movement and a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 31 findings here — 74% of the 42 recovered corpus-wide — so the pre-fix reading was 1059). 371 spared, 26% of this target's entire M5-slop reading: the single number that made the leading hypothesis a regression rather than a precision fix, and the reason the 653 rows were sampled and read instead of rebaselined. 20 sit on the disclosed `async`-caller-with-no-await boundary (#1533), one of which — `convertTextToHtmlParagraphs`, utils/outlook/mail.ts:408 — is the GENUINE-SEAM counterexample that stopped that axis being narrowed: its caller awaits nothing but does its I/O by returning `sendEmailWithHtml(...)`. The seeded 50-row corpus sample drew 25 rows here; 22 graded genuine seams, and 3 were corpus-wide defects now firing (`requireVercelLogin` and `getServiceUrl`, both `spawnSync` over a CLI; `hasLinkedProject`, an `existsSync`). This target's CLI packages are where the wrongly-spared class concentrates — a setup script's helpers are I/O by nature and were being read as pure. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2b78f2b3> --out f.json`. Prior note: #894: MEASURED 2026-07-24 — the corpus's HIGHEST M5-slop reading by an order of magnitude, on the corpus's deepest test surface. This is the target to watch for slop-class precision drift: a large fraction of the count is the single-use-helper class (#391), the same class that moved boxyhq 12->76 and saas-lite 23->79 when it landed. #1128: RE-MEASURED 2026-07-26 at 1424/1449 (was 1420/1439) — a precision fix from #1088/#1065 (commit c75186a, merged 2026-07-25): the detector's SOURCE_FILE filter widened to include plain js/cjs/mts/cts, surfacing 4 more genuinely-scanned files. #1136: RE-MEASURED 2026-07-26 at 1430/1455 (was 1424/1449) — DRIFT +6, attributed to #1136's isGeneratedSource fix un-excluding apps/web/utils/ai/assistant/tools/rules/update-rule-tool.ts (see M6-indicator below for why that file is back in scope): 6 new Low 'Single-use helper' findings, all in that one file. VERIFIED by direct before/after `detectSlopFindings` diff on this pinned clone's copy of the file (this PR): 0 findings pre-fix (file excluded) -> 6 post-fix, at update-rule-tool.ts:362,429,463,476,527,571 — exactly the drift. `pnpm corpus-drift --target inbox-zero` reproduced 1430 counted." },
      "M6-indicator": { counted: 51, total: 51, note: "#894: MEASURED 2026-07-24 — 51 hand-rolled-shape indicators, the corpus's highest. All Info/non-grading (#267); counted === total by construction. #1128: RE-MEASURED 2026-07-26 at 50/50 (was 51/51) — DRIFT -1, attributed to #1088/#1065 (commit c75186a, merged 2026-07-25)'s isGeneratedSource exclusion: apps/web/utils/ai/assistant/tools/rules/update-rule-tool.ts carries a >1000-character line (a long LLM tool-description string literal, not vendored/minified code) and now trips the generated-source heuristic, dropping its one 'JSON deep-equal' M6 indicator along with the rest of the file. VERIFIED by direct before/after `static-detect` diff on this pinned clone (this PR): old 3 JSON-deep-equal findings -> new 2, the missing one at exactly that file:line. A disclosed side effect of a heuristic that is a net precision win elsewhere (see carbon's M5-slop/M7/M9), not a detector bug to fix. #1136: RE-MEASURED 2026-07-26 at 51/51 (was 50/50) — DRIFT +1, this specific one-file-with-one-long-aside false exclusion is exactly the defect #1136 fixes: isGeneratedSource is now relative to the file (an outlier line over 1000 chars AND lines over 500 chars must be >=30% of the file's bytes), not 'any line over 1000 chars' — update-rule-tool.ts's one 1081-char line is 5.7% of its bytes, so it now stays in scope and its one 'JSON deep-equal' indicator is back. `pnpm corpus-drift --target inbox-zero` reproduced 51 counted." },
      M7: { counted: 83, total: 101, note: "#1475-#1480: RE-MEASURED 2026-07-28 at 83/101 (was 90/107) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-2b78f2b3> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 90/107 on the identical clone. -7. 4 await rows are apps/web/scripts/* and scripts/dev-setup.ts (#1476); 2 are sequential BY DESIGN (#1480) — packages/cli/src/setup-ports.ts:112 scans candidate ports and returns the first free one, apps/web/utils/meeting-briefs/gather-context.ts:132 carries its own `if (allThreads.length >= maxThreads) break;` — and 1 nested-loop row is apps/web/scripts/eval-report/aggregate.ts. The State sprawl row moves to Info (#1475), and the oversized-image row splits: one asset is referenced and keeps the page-weight claim, one is not and moves to Unreferenced (#1480). Prior note: #1261: 90/107 reproduces 2026-07-28; 9 rows drawn into the 40-row seeded sample (seed 1261) and read against source — 7 hold, 2 do not. SAMPLED, NOT CENSUSED: the other 81 rows are untriaged. The dominant await-in-loop vein is largely real here (per-thread `getThreadMessages`, per-draft `getDraft`, per-tracker label reads — all independent per-item awaits a `Promise.all` would fix). The 2 false rows are both loops that are SEQUENTIAL BY DESIGN, a shape no current guard covers: packages/cli/src/setup-ports.ts:112 scans ports until the first free one (parallelising is meaningless), and meeting-briefs/gather-context.ts:132 carries its own `if (allThreads.length >= maxThreads) break` cap that parallelising would defeat. Prior note: #1344: RE-MEASURED 2026-07-27 at 90/107 (was 89/106) — DRIFT +1, and the ONLY survivor of #1203's generic sync-I/O tier once #1344 gated it on import-reachability. VERIFIED true positive: apps/web/utils/api-key.ts:10 hashes an API key with `scryptSync` (a deliberately CPU-expensive KDF) inside `hashApiKey`, an exported function the v1 API routes import for per-request API-key auth — the textbook event-loop stall this class exists for. The 17 OTHER hits #1203 produced here were all in packages/cli (a published `bin`, never loaded by a server) and are gone. Prior note: #894: MEASURED 2026-07-24 — 66 await-in-loop N+1 (the dominant vein), 22 nested-loop joins, 1 client fetch in useEffect, 1 state-sprawl component, 1 oversized-committed-images roll-up; 17 hook-dep Info. #761's unindexed-FK check contributes zero at this pin — recorded so a later non-zero is read as a schema change, not a detector regression." },
      M8: {
        mutationScore: 76, killed: 80, valid: 125, coveredScope: ["utils/similarity-score.ts"],
        note: "#1268: MEASURED 2026-07-28 — the pnpm-aware install #894's own M8 not-run reason named as the remainder work. `pnpm install` (not npm) at the clone root resolves apps/web's node_modules (verified: apps/web/node_modules exists and its own vitest suite runs — 55/55 passing on utils/similarity-score.test.ts alone). Stryker itself then needed a SECOND fix beyond the pnpm-aware install: this target's own pnpm-workspace.yaml sets `enableGlobalVirtualStore: true`, which stores the resolved package graph outside the project — Stryker resolves its own plugins/typescript via Node's node_modules walk relative to wherever ITS OWN file physically lives, and that walk never reaches the project's node_modules under a global virtual store, so even an explicitly-named plugin (#1284's scaffoldStrykerConfig fix) still failed to resolve until corpus-drift.ts's installTargetDeps disabled the setting for the disposable clone (never the target's own repo). With both fixes, a REAL Stryker run against utils/similarity-score.ts (a small dependency-free fuzzy-match module with a fast, deterministic, 55-case spec — chosen the same way proposit/boxyhq scope to one well-tested file) scored 76.00% (80 killed + 15 timeout = 95 detected / 125 valid mutants; 3 NoCoverage, 0 CompileError/RuntimeError/Ignored, so valid === totalMutants here) — reproduced byte-identically across 2 consecutive runs (80/15/27/3 both times), so no tolerance is earned or applied here (#432's precedent), despite 15 Timeout mutants being the shape most exposed to real machine-speed variance. NOT the whole-suite measurement #894 originally asked for (586 spec files across the whole app is a materially larger undertaking this job does not attempt yet) — this is real drift-detection coverage over ONE file, not a repo-level claim; formatMutationClaim's coveredScope disclosure makes that explicit wherever this baseline is printed. `pnpm corpus-drift --target inbox-zero --install --m8` reproduces it.",
      },
      "M8-intent": { counted: 305, total: 305, note: "#894: MEASURED 2026-07-24 and the reason this target is pinned — 305 test-intent findings, 100x the corpus's previous maximum (saas-lite's 1). 161 'Call-count-only test', 121 '`vi.hoisted` factory references non-hoisted binding', 10 'Unrestored vi.spyOn leaks across tests', 6 'Test mocks the module it is testing', 2 assertion-free, 2 snapshot-only, 2 happy-path-only on money-critical files (payments.ts, refunds.ts). Every one of these classes now has a real-code drift baseline for the first time; the vi.hoisted class in particular had none." },
      M9: { counted: 39, total: 41, note: "#1460/#1461/#1462 + #1441, MERGED: RE-MEASURED 2026-07-28 at 39/41 on the tree with BOTH PRs applied. The arithmetic closes exactly: 43 (the shared base) −8 from this PR (7 in the #1460 SSR helper family, all READ: app/utm.tsx's `setUtmCookies`/`hasCookie` and components/ConversionAnalytics.tsx; plus 1 `Missing server-only guard`, apps/web/utils/llms/model.ts:165, whose only client chain is ColdEmailList.tsx ('use client') -> utils/actions/cold-email.ts ('use server') -> …, which bundles nothing) +4 from #1441's restored waterfall true positives. Neither PR's number is the answer on its own — this is the measured combination, not an arithmetic guess. PRIOR: #1460/#1461/#1462: RE-MEASURED 2026-07-28 at 35/36 (was 43/44) — DRIFT -8, two causes, all 8 rows READ. (1) 7 in the #1460 SSR helper family: app/utm.tsx (`setUtmCookies`/`hasCookie`, called once from a useEffect — `hasCookie` is called only from `setUtmCookies`, so the recursive call-site walk decides it) and components/ConversionAnalytics.tsx. (2) 1 `Missing server-only guard`: apps/web/utils/llms/model.ts:165, reachable only as ColdEmailList.tsx ('use client') -> utils/actions/cold-email.ts ('use server') -> … . apps/web/env.ts:197 REMAINS, the scope control for that class. MEASURED via `pnpm exec tsx src/cli/static-detect.ts <clone>` on the identical pinned clone, pre- and post-change arms. Prior note retained below. PRIOR: #1262/#1292: RE-MEASURED 2026-07-28 at 43/44 (was 55/55) — 12 waterfall FALSE POSITIVES removed, plus the disclosure row. MEASURED by a controlled before/after `detect-static` on the identical pinned clone, one variable (this PR's M9 diff): the before arm at 564bded reprints 55/55. The -12 counted is #1292, and every one is the same shape read against the source: an existence check on the first result that THROWS before the second query runs — utils/actions/organization.ts:49 (`if (existingMembership) throw new SafeError(...)` between two findUnique calls), sso.ts:48, rule.ts:598, messaging-channels.ts:224 and eight more. `Promise.all` hoists the second query above the guard, so the fix the finding recommended would run a lookup the sequential code never reaches. The 1 surviving waterfall is a genuinely independent pair. The +1 total is #1262's `M9-RETRY` scope row — a counted not-assessed row disclosing the three uncapped retry/fan-out sub-shapes the new AST detector does not reach, emitted on any target that has route/edge handlers at all. Info, so `counted` is unchanged. Prior note: #1344: RE-MEASURED 2026-07-27 at 55 counted (was 40) — DRIFT +15, root-caused to #1237-#1240 (commit 14cdfe3) teaching isDbQueryChain the Prisma/repository MODEL-READ vocabulary (`prisma.user.findUnique(…)`, `db.getUser(…)`). Before it, M9's three DB-reading classes recognised ONLY the Supabase `.from().select()` chain, so on a Prisma app they were structurally blind — this is a closed measured gap, not an over-match, and each of the 15 was read against the source: 13 data-fetching waterfalls (e.g. utils/user/merge-account.ts:28 — findMany(emailAccount by userId) then findUnique(user by id), independent point lookups that Promise.all covers), 1 server→client leak (reply-zero/Resolved.tsx:59 — `prisma.threadTracker.findMany` with NO `select`, so every column of the row is handed to the <ReplyTrackerEmails> client component), 1 missing Suspense (reply-zero/page.tsx — searchParams + cookies() + an awaited emailAccount read with no boundary, on a route that sets maxDuration=300). #1344 also FIXED a pre-existing false positive in the same pass: the waterfall independence test compared only the first query's bound name against the second statement's text, so a dependence laundered through an intermediate (utils/organizations/ownership.ts:43 — memberships -> organizationIds -> `id: { in: organizationIds }`) read as independent; 2 such rows dropped here. Prior note: #964: RE-MEASURED 2026-07-24 (this PR) at 40 counted (was 52) — the #964 M9 SSR precision fix dropped 12 'SSR-only API misuse' FPs (19->7), all browser-global reads inside functions in non-component `.ts` util files: apps/web/utils/{cookies,auth-cookies,redirect,schedule-after-page-load,analytics/client-conversions}.ts (document.cookie, window.location, dispatchEvent, addEventListener — client-only helpers, not component render bodies). The other classes are unchanged and confirm the validation fix did NOT over-suppress: the 5 High 'Server Action missing input validation' all reproduce (none uses the validator()/.validate() idiom). Residual 40: 26 accidental dynamic rendering (searchParams + forced-dynamic reads), 7 SSR-only, 5 High Server-Action-validation, 2 High server-only guard. Prior note: #894: MEASURED 2026-07-24 — 18 searchParams, 19 SSR-only, 7 forced-dynamic, 2 server-only, 5 Server-Action-validation." },
      M10: { counted: 55, total: 55, note: "#968/#936: RE-MEASURED 2026-07-24 (this PR) at 55 PII-bearing models — was 35 (#894). The #936 camelCase-tokenization fix classifies 20 previously-invisible camelCase PII tables (emailAccountId, stripeCustomerId, fromEmail/fromName, guestName/guestEmail, folderName, invoiceEmailSentAt …) that the snake_case-anchored matcher had classified NONE; diffed against the pre-#936 classifier over the same cloned schema — 20 added, 0 removed, so precision does not regress. Measured via m10FindingsFromPrismaSchema over apps/web/prisma/schema.prisma: 55 counted === 55 total, 1 Critical / 8 High / 7 Medium / 39 Low. Headline McpConnection Critical (AUTH_TOKEN+API_KEY+EMAIL); Account/Session/User/Premium/CalendarConnection/DriveConnection/MessagingChannel/McpIntegration High." },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here.  An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
      // #948 (root-caused #931's own ask #2, RE-MEASURED 2026-07-24 against a fresh clone of the
      // SAME pinned commit): the "empty file list at some absolute paths" was TWO compounding
      // cwd/path-relativity bugs in how quality-scan invoked jscpd (src/cli/quality-scan.ts),
      // never a property of documenso or an unfixable environment split.
      //   1. jscpd resolves its `.jscpd.json` AND a separate, less-anchored `.gitignore` read
      //      (its own src/init/ignore.ts) from `process.cwd()` of the CHILD PROCESS, not the
      //      scanned dir — so without an explicit `cwd`, it could pick up an unrelated repo's
      //      config entirely (fixed: `cwd: dir`).
      //   2. Independent of (1): scanning an ABSOLUTE path makes fast-glob (inside
      //      @jscpd/finder) match gitignore-derived ignore globs against the FULL absolute
      //      path. documenso's own `.gitignore` has a bare `tmp` entry — correctly, per git
      //      semantics for a no-slash name, converted to an any-depth "**/tmp/**" glob — which
      //      then also matches any ANCESTOR directory literally named "tmp". A scratch clone
      //      under Linux's `os.tmpdir()` (`/tmp`) sits inside exactly such a directory, so the
      //      WHOLE tree got silently excluded; macOS's `os.tmpdir()` (`/var/folders/.../T`) does
      //      not contain a "tmp" segment, which is exactly the ubuntu-vs-macOS split #931
      //      measured (fixed: scan "." instead of the absolute dir, now that cwd anchors it).
      // MEASURED 2026-07-24 against the pinned commit re-cloned into a `/private/tmp`-prefixed
      // scratch path (the collision case) with the fix applied: 835 counted / 1,256 total — an
      // EXACT match to the one lucky non-colliding macOS run #931 recorded, confirming that
      // number was always the correct one and the zero was purely an invocation defect.
      M4: { counted: 1136, total: 1779, note: "#948: MEASURED 2026-07-24 (re-clone of the pinned commit, deliberately under a tmp-collision scratch path) after fixing quality-scan's jscpd invocation (cwd: dir + scan \".\" instead of an absolute path, src/cli/quality-scan.ts) — 835 counted / 1,256 total, reproducing #931's one working macOS measurement exactly. No longer environment-dependent. #1128: RE-MEASURED 2026-07-26 at 1136/1779 (was 835/1256) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target documenso --install` reproduced 1136 counted." },
      "M4-diverged": { counted: 4, total: 4, note: "#894: MEASURED 2026-07-24 — 2 High review-tier diverged security-path clone findings, reproduced in all three runs including both in which jscpd's exact-clone pass returned nothing. That invariance is what showed the M4 zero to be an invocation failure rather than a property of the repo (#931). #1128: RE-MEASURED 2026-07-26 at 4/4 (was 2/2) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 2 more such pairs now qualify. `pnpm corpus-drift --target documenso --install` reproduced 4 counted." },
      "M5-knip": { counted: 1801, total: 1803, note: "#894: MEASURED 2026-07-24 after `npm install` (2127 packages). 1,311 unused files + unused-export files, with 1/16 scopes in #810 reduced mode (M5-98 Info) and 8/16 flagged uncertain (#580 M5-99 Info) — both disclosure rows are part of the baseline. ±1 ACROSS ENVIRONMENTS, recorded rather than absorbed into a tolerance nobody would see: 1360 on ubuntu-latest under `corpus-drift --install` AND on macOS under a scratch path, 1359 on macOS in corpus-drift's mkdtemp. This was recorded alongside the M4 environment split observed the same day, but #948 root-caused THAT split to a jscpd-specific cwd/path-relativity bug (fixed) — knip is a separate tool with its own config resolution, so this ±1 is not shown to share that cause; re-measure it independently before assuming #948 also explains it. 1360 is recorded because it is what the scheduled scorer's own environment produces. CAVEAT recorded with the number: 1,311 unused FILES on a turbo monorepo whose entry surface knip cannot fully resolve (8 uncertain scopes says so in the output) is a DRIFT baseline, not a claim that documenso has 1,311 dead files. #1128: RE-MEASURED 2026-07-26 — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25): knip's six previously-dropped IssueRecords categories now surface — this target's largest single M5-knip swing in the corpus (#1128's issue named it explicitly, CI's ubuntu-latest run measured 1360->1801). Recorded at 1801/1803, matching the CI/scheduled-scorer environment per this baseline's own ±1-across-environments precedent above; `pnpm corpus-drift --target documenso --install` on macOS (this PR) independently reproduced the same order of magnitude at 1800, one under, consistent with that pre-existing ±1 split rather than a new source of drift." },
      "M5-slop": { counted: 233, total: 238, note: "#1533: RE-MEASURED 2026-07-31 at 233/238 (was 231/236) — DRIFT +2, two RECOVERED FALSE NEGATIVES, both on the `async`-caller-with-no-await boundary the prior note enumerated: `hashData` and `placeholderSize` (packages/ee/server-only/signing/csc/signers/capture-signer.ts:79,97). Read at source: their sole caller is `CscCaptureSigner.sign()`, which carries a `biome-ignore lint/suspicious/useAwait: intentional` of its own and returns `new Uint8Array(...)` — the target itself documents that this method does nothing asynchronous. The other 2 rows on that boundary (server/context.ts:35,39) stay spared: their caller returns `next()`, a parameter, which no source-level pass can read. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-c02dfaba> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 231/236 (was 262/267) — DRIFT -31, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 2 findings here, so the pre-fix reading was 229). 33 spared, 4 of them on the disclosed `async`-caller-with-no-await boundary (server/context.ts:35 and :39, csc/signers/capture-signer.ts:79 and :97 — #1533). The seeded 50-row corpus sample drew 7 rows from this target (`mapLocalRecipientsToRecipients`, `serializeOperators`, `parseDomainsInput`, `parseBody`, `generateNonce`, `createImageContentParts`, `createCronRunId`): all 7 read at source, all 7 graded genuine seams — pure mappers, parsers and hashes whose callers await network, PDF or prisma work. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-c02dfaba> --out f.json`. Prior note: #894: MEASURED 2026-07-24." },
      "M6-indicator": { counted: 21, total: 21, note: "#894: MEASURED 2026-07-24 — 21 hand-rolled-shape indicators. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 112, total: 249, note: "#1353: RE-MEASURED 2026-07-28 at 112/249 (was 111/248) — +1, purely additive, against a pristine-main control worktree at 11ef7e2. The single restored row is packages/signing/transports/google-cloud.ts:62 (`fs.writeFileSync`), reachable again once a `@documenso/*` workspace specifier resolves to its member. Read the shrinkage honestly: #1353's measured table listed THREE silenced rows for this target and rallly, and by the time this landed #1461's per-config tsconfig scoping had already restored packages/lib/server-only/cert/cert-status.ts:21 on its own — it is in the control arm, so this row does not claim it. Prior note: #1461 + #1475-#1480, MERGED: RE-MEASURED 2026-07-28 at 111/248 on the tree with BOTH PRs applied. Neither PR's number is the answer alone: #1490 measured 114 and this PR measured 128 against the older 127, and the merged result is 111. Verified against a PRISTINE-MAIN CONTROL WORKTREE at c597012 rather than computed — same clone, same command, 114 there and 111 here — and the 5 moved rows were diffed by location: -4 `Heavy import in client bundle` (packages/lib/server-only/pdf/render-audit-logs.ts:4,5 and render-certificate.ts:5,6, the `konva` / `konva/skia-backend` imports) and +1 `Blocking sync I/O in request handler` (packages/lib/server-only/cert/cert-status.ts:21). THE -4 ARE FALSE POSITIVES REMOVED, and the mechanism is #1479's own rule rather than a new one: `serverOnlyModules` drops a module only on THREE conditions — a request entry reaches it, no client entry does, and it names a server runtime itself. These files import `node:fs` and `konva/skia-backend`, so condition 3 always held, and MEASURED on both arms the client closure does NOT contain them, so condition 2 always held. What this PR's alias fix supplies is condition 1: with carbon-style per-workspace aliases resolving, a request entry now transitively reaches them through generate-certificate-pdf.ts. Flagging a `node:fs`+skia module as a heavy CLIENT-bundle import was wrong; it never ships to a browser. The +1 is a RECALL RESTORATION and is the row #1353 predicted by name — one of the three true positives it recorded as silenced by the import graph's blind spots, now reachable, with the finding's own evidence naming apps/remix/app/routes/api+/certificate-status.ts as the entry point. This satisfies #1353's second acceptance criterion for one of its three rows; the workspace-package half stays open. PRIOR: #1475-#1480: RE-MEASURED 2026-07-28 at 114/251 (was 127/258) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-c02dfaba> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 127/258 on the identical clone. -13. 5 await rows are packages/prisma/seed/* and packages/app-tests/e2e/fixtures (#1476); 6 State sprawl rows move to Info (#1475); 1 heavy-import row is packages/lib/server-only/konva/skia-backend.ts, which imports node: builtins, is reached by a request entry and by no client entry, and therefore ships to no visitor (#1479); the oversized-image row re-words to Unreferenced (#1480). ALL 20 raw <img> rows change TAXONOMY to `M7 — Raw <img> without dimensions or lazy-loading` (#1480's label fix) — 18 remain, 2 had SVG-only sources. WORTH RECORDING because it is the shape that nearly cost recall: an earlier build of #1479 required POSITIVE client-reachability and silently dropped 9 further field-renderer modules that `apps/remix/app/components/**` imports across a `@documenso/lib/...` workspace specifier the import graph cannot follow (#1353). Requiring the module to name a server runtime ITSELF is what restored them. Prior note: #894: MEASURED 2026-07-24 — 127 counted with the corpus's largest Info tail (131 hook-dependency style notes), plus a 16-image/19.1 MB oversized-asset roll-up. The Info tail is itself worth pinning: #230 demoted that class rather than dropping it, and this is the target where the demotion carries the most weight." },
      M8: { counted: 1, total: 1, note: "#932: RE-MEASURED 2026-07-24 after the fix — mutation-scan now emits the M8-04 measurement-gap finding ('Test suites live in workspaces — root-level mutation scan could not reach them', Medium), naming packages/app-tests, packages/lib, packages/signing. Previously this was #224's M8-00 zero-coverage finding (High) — a FALSE 'no automated test suite' claim on a repo that ships 128 tracked *.spec.ts/*.test.ts files, because detectNoTestSuite only read the ROOT package.json (no test script/runner dep there) and never checked the workspaces that actually carry the suites. detectWorkspaceTestSuites (src/mutation-scan.ts) now checks them before falling through to M8-00. Still 1 counted / 1 total — same shape, correct content: a disclosed measurement gap, not a false clean-vs-zero claim either way." },
      "M8-intent": { counted: 1, total: 1, note: "#894: MEASURED 2026-07-24 — 1 'Call-count-only test' (Low). Note the tension this key exists to keep visible (the saas-lite lesson): a test-intent finding fires here while the mutation tier claims there is no suite at all — the split means neither reading can shadow the other." },
      M9: { counted: 0, total: 1, note: "#894: MEASURED 2026-07-24 — a single Info row, #903's 'M9 N/A — non-SSR SPA'. documenso moved to React Router/Remix, so the App Router boundary module is correctly not-applicable and says so in the output rather than reporting a silent zero. Any counted M9 finding appearing here is a framework-detection regression." },
      M10: { counted: 30, total: 30, note: "#968/#936: RE-MEASURED 2026-07-24 (this PR) at 30 PII-bearing models — was 21 (#894). The #936 camelCase-tokenization fix classifies 9 previously-invisible camelCase PII tables (ipAddress, emailReplyTo/emailId, signatureImageAsBase64, clientSecret, publicDescription …) that the snake_case-anchored matcher had classified NONE; diffed against the pre-#936 classifier over the same cloned schema — 9 added, 0 removed, so precision does not regress. Measured via m10FindingsFromPrismaSchema over packages/prisma/schema.prisma (38,062 bytes): 30 counted === 30 total, 1 Critical / 4 High / 1 Medium / 24 Low. Headline Account Critical (AUTH_TOKEN+STORED_PASSWORD); User/Session/EmailDomain/OrganisationAuthenticationPortal High." },
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
    securityVerdict: "NOT ASSESSED — #897 is a SCALE measurement, not an audit. The free-tier quick-scan originally graded this target F (0/100) on 14 Critical secret findings, every one a placeholder credential in self-hosting docs or an example docker-compose; #934 reclassified that class (re-measured 2026-07-24: all 14 now Low/informational with the reason stated, 0 graded — see FREE_TIER_EXPECTATIONS below). #996 then resolved the remaining 11 graded Highs (7 bare-wildcard CORS on intended-public endpoints → non-grading confirm-intent informational; 3 GitHub-Actions workflow findings → the non-grading CI/CD pipeline hygiene section; 1 postMessage wildcard → non-grading informational) — re-measured 2026-07-24 post-change: grade A (97/100), graded set 1 Low (unpinned deps), all 11 former Highs still fully reported. NOT a security verdict on carbon; no disclosure filed and none warranted from this pass.",
    schemaPath: "packages/database/supabase/migrations",
    modules: {
      "M1-boundary": { counted: 6, total: 6, note: "#1501: TRIAGED AND RE-MEASURED 2026-07-31 at 6/6 (was 113/113) - DRIFT -107, a PRECISION FIX, and the triage this baseline was filed owing. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04> --out f.json`; a control arm with ONLY src/workspaces.ts reverted reprints EXACTLY 113 on the identical clone, and `corpus-drift --target carbon` on that arm reports every other module matching (M4 3568, M5-slop 841, M6 48, M7 536, M8-intent 3, M9 104, M10 214), so the movement is one variable and one taxonomy. Row-level: 107 only-before, 0 only-after, total findings 1975 -> 1868. ROOT CAUSE, MEASURED not hypothesised. #1501 guessed the workspace-package blind spot and named #1353 - but #1353 HAD already shipped (PR #1450/#1497) and did not move this number, so that hypothesis was false as stated. The real residual is narrower: `exportsWildcards` (src/workspaces.ts) read only `exports` keys containing a `*`, and carbon packages/auth declares eleven LITERAL keys such as \"./auth.server\": \"./src/services/auth.server.ts\". `resolveImport(..., \"@carbon/auth/auth.server\")` returned UNRESOLVED while packages/auth/src/services/auth.server.ts was present in the loaded tree, so #1263's GateResolver could not follow `requirePermissions` and every route action gated by it read as ungated. `exportsExact` fixes it. BLAST RADIUS MEASURED across all 17 pinned targets rather than assumed: 12 declare no exact-exports subpath at all and are inert by construction; saas-lite, rallly, inbox-zero and effective do declare them and were re-run before/after with 0 rows moved on each (91/91, 226/226, 1626/1626, 2713/2713). Only carbon moved. WHAT THIS BASELINE NOW STANDS BEHIND, per row rather than as a count. 107 rows are recorded FALSE with the named cause above, corroborated by a supporting property, stated at the granularity it was actually measured at: the FILE containing 111 of the original 113 rows references a carbon gate helper somewhere in it (requirePermissions in 106 files, assertIsPost in 47, and — NOT a gate, recorded here only because the same file-level sweep counted it — getCarbonServiceRole, the RLS-BYPASSING service-role client, in 45). A file-level predicate is weaker than the per-row claim it supports: it says the gate vocabulary is present in that file, not that the enclosing action calls it. The stronger enclosing-function form was NOT attempted this round (it needs the 113 rows reproduced on a control clone with src/workspaces.ts reverted, then each row's enclosing block read) — the per-row evidence this baseline rests on is the named root cause plus the six read against source below, not this count. The 6 that REMAIN were each READ AGAINST SOURCE and they are not all real. (1) apps/academy/app/routes/lesson+/$id.tsx:41 is FALSE - the action calls `getOrRefreshAuthSession(request)`, returns 401 when it is absent, and scopes the insert to session.userId; the helper name is outside the guard vocabulary (#1300's class). (2) apps/mes/app/routes/x+/proxy.$.tsx:7 is FALSE and a DIFFERENT defect - there is no database write in that file at all; the mutation collector matched `headers.delete(\"host\")` on a `Headers` object. Tracked as a follow-up. (3) apps/erp/app/routes/_oauth+/register.ts:50 is an RFC 7591 dynamic client-registration endpoint, deliberately public, writing through the service role - true to the detector definition, by design in the target. (4) apps/erp/app/routes/_oauth+/token.tsx:60 authenticates by client_secret/PKCE inside the handler rather than by session, so the row is true to the shape and the control does exist. (5)(6) apps/erp/app/routes/api+/sales.digital-quote.$id.tsx:19 and purchasing.digital-quote.$id.tsx:18 are gated only by `assertIsPost` and then convert a quote to an order through the service role, keyed on an externally supplied id, with no caller authentication - the two rows a client would actually want to see. So: 109 false, 4 true-to-shape, 2 of those 4 worth acting on. NOT ONE ROW IS UNVERIFIED. It is a DRIFT baseline either way, not a defect count. PRIOR NOTE, retained as the record this corrects: #1459: MEASURED 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — 113 High `M1 — route action missing authorization check` rows, ALL of them previously scored by nothing at all: this target's M9 baseline (109) and the 113 are disjoint populations under different taxonomy prefixes. **NOT TRIAGED, and 113 is far too large to read as 113 defects** — carbon's route actions gate through `requirePermissions(request, …)` imported from `@carbon/auth/auth.server`, a WORKSPACE PACKAGE that #1263's resolver cannot follow (it resolves relative and tsconfig-aliased specifiers only), so the expected verdict on triage is that most are false. Recorded as a drift baseline anyway, because the alternative is what this issue was filed about: no number moving when the detector breaks. Triage is tracked separately. #1434: RE-VERIFIED 2026-07-31, NO MOVE — controlled before/after `static-detect` on <clone-of-92e19c0>, one variable (the #1434 diff): both arms 1974 findings, 0 rows only-before, 0 only-after, M1 113/113 and M9 114/114 in both. This target and inbox-zero are the two #1434's own acceptance names as 'the ones with volume in this class'; MEASURED, the volume here is entirely the sibling missing-auth detector and the owner-id class has a population of ZERO, which is the honest answer to that criterion rather than a re-measured number that moved." },
      M4: { counted: 3568, total: 5080, note: "#897: MEASURED 2026-07-24 — the corpus's largest M4 surface by 9x. jscpd completed whole-repo inside quality-scan's 39.4s: no timeout, no hang, no quadratic blow-up at 4,110 TS files. The finding VOLUME is the product finding (see the scale doc), not a scanner failure. #1128: RE-MEASURED 2026-07-26 at 3568/5080 (was 3251/4526) — a precision fix from #1095 (PR #1129, merged 2026-07-26): M4 now scores self-file clones and the diverged-clone pass compares same-file pairs too. `pnpm corpus-drift --target carbon --install` reproduced 3568 counted, at a time when that install still failed with EUNSUPPORTEDPROTOCOL (npm refusing this workspace's pnpm-catalog dependency) — inert for M4/M7/M9, which don't need the target's deps. #1404: RE-CONFIRMED 2026-07-28 that the install step is genuinely inert here — 3568/5080 reproduces byte-identically in BOTH arms of the #1404 before/after (npm, which still fails to install, and a full `pnpm install`), so the -2307 M5-knip move below did not touch M4." },
      "M4-diverged": { counted: 3, total: 3, note: "#897: MEASURED zero 2026-07-24. The strongest FP-floor reading in the corpus: 3,251 exact clones and not one diverged security-path family, so the near-miss pass is not simply tracking repo size. #1128: RE-MEASURED 2026-07-26 at 3/3 (was 0/0) — #1095/PR#1129 (2026-07-26): the diverged pass now also compares same-file pairs, and 3 such pairs now qualify. `pnpm corpus-drift --target carbon --install` reproduced 3 counted." },
      "M5-knip": { counted: 572, total: 574, note: "#1404: RE-MEASURED 2026-07-28 at 572/574 (was 2879/2881) — DRIFT -2307, the largest single move this corpus has recorded, and a PRECISION FIX rather than lost detection. PROVEN by controlled before/after on the identical pinned clone, one variable (the install path): an `npm install --no-audit --no-fund` arm reprints EXACTLY 2879/2881 (that install still fails on this workspace's pnpm `catalog:` dependency, so knip gets no deps at all), while the pnpm arm reads 572/574. Mechanism: with no deps, knip fell back to #810's reduced no-dependencies mode in 12 of 33 scopes (apps/academy, apps/erp, apps/mes, apps/starter, both contrib/building examples, packages/config, glossary, kv, lib, logger, stripe) and, resolving entry points by inference, reported nearly every source file as unused; `pnpm install` (MEASURED 36s) resolves the tree and only 2 of 33 scopes stay reduced (packages/kv, packages/logger — each fails to load its OWN vitest.config.ts). Class-level delta: 'Unused file' 2491->212 (-2279) plus 'Unused security-relevant file' 9->0 (-9) are 2288 of the 2307; 'Unused exports' 226->206, devDependencies 26->19, binaries 35->33, unlisted imports 4->3. Three classes moved UP as newly-resolvable scopes became readable — dependencies 21->25, duplicate exports 16->21, exported-but-unreferenced types 47->49. By scope: apps/erp 2289->217, apps/mes 186->41, apps/academy 47->11. Commands: `pnpm corpus-drift --target carbon --install` (2026-07-28). STILL A DRIFT BASELINE, NOT A DEAD-CODE CLAIM, and still a PARTIAL that says so in the output: the #810 M5-98 reduced-mode row and the #580 M5-99 uncertainty row are both part of this baseline, the latter now reading packages/database 74/105 (70%) source files unused, down from 78% under the no-deps arm. #1436: the 2-of-33 residual is the SAME root cause as this target's M8 not-run — packages/kv and packages/logger each fail to load their own vitest.config.ts, which re-exports @carbon/config/vitest, which packages/config/package.json maps to a built ./dist/vitest.mjs. It is watched by that reason block's falsifier rather than restated here, so one re-test covers both claims. Prior notes (historical, superseded by the pnpm install path): #897 MEASURED 2026-07-24 at 2773/2775 with no deps at all — reproducible in CI, not a local shortcut, because `corpus-drift --install` ran npm on every target at that time and installTargetDeps swallowed the failure. #1128: RE-MEASURED 2026-07-26 at 2879/2881 — a precision fix from #1094/#1080 (commit 4469338, merged 2026-07-25) surfacing knip's six previously-dropped IssueRecords categories, still in the same reduced no-deps mode." },
      "M5-slop": { counted: 841, total: 979, note: "#1532 RESIDUAL: RE-MEASURED 2026-07-31 at 841/979 (was 840/978) — DRIFT +1, one RECOVERED FALSE NEGATIVE and the row that motivated the residual fix. It was DRAWN in the 30-row re-check of the corrected scanner (mulberry32, seed 20260731, over the 597 then spared sorted by target|file|line|helper) and graded wrongly spared on reading: `depsInSync` (packages/dev/src/services/apps.ts:367) stats a lockfile against a node_modules marker via `isAtLeastAsNew`, i.e. `existsSync` + `statSync` one call away, so it was never the pure half. `doesOwnIo` now follows a callee it can resolve, one hop. This row also needed the `.js`-specifier fallback: the import is `from '../helpers.js'`, which the shared resolver appends extensions to verbatim and therefore resolved to nothing. 1 wrongly spared in 30, Wilson 95% CI [0.6%, 16.7%]. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 840/978 (was 948/1086) — DRIFT -108, a PRECISION FIX taken against a NARROWED scanner. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 3 findings here, so the pre-fix reading was 837). 111 spared, 12% of this target's M5-slop; only 1 sits on the disclosed `async`-caller-with-no-await boundary (#1533), so this target's residual is almost entirely the intended class. The seeded 50-row corpus sample drew 8 rows here: 7 graded genuine seams (`stampToolReadableIds`, `stampMaterialReadableIds`, `prepareVisionCropRect`, two copies of `getQuoteMethodTreeArrayToTree`, `extendStackTrace`, `getNotificationEvent`), and `streamToBuffer` (packages/jobs/src/inngest/functions/tasks/print-job/renderers.tsx:179) was one of the 5 corpus-wide defects — a hand-rolled `new Promise` over stream events is real async I/O written without `await`, so the helper was never the pure half — and now fires. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04> --out f.json`. Prior note: #897: MEASURED 2026-07-24. #1128: RE-MEASURED 2026-07-26 at 948/1086 (was 1125/1263) — DRIFT -177, the corpus's largest downward move, individually root-caused rather than blanket-rebaselined: #1088/#1065 (commit c75186a, merged 2026-07-25) added an isGeneratedSource exclusion (filename matching `.min.[cm]?jsx?` OR any line over 1000 characters) so vendored/minified bundles committed into a repo don't swamp the slop detectors now that plain .js is read at all. VERIFIED by direct before/after `static-detect` diff on this pinned clone (this PR): 100% of the swing is one file, apps/erp/public/pdf.worker.min.mjs — a vendored, minified pdf.js worker bundle that was already in-scope pre-#1088 (.mjs matched the OLD filter too) and whose single-letter minified parameter names were producing 115 'Unused parameter' + 61 'Single-use helper' + 1 'Placeholder stub' = 177 false positives on non-product code. Now correctly excluded by its `.min.mjs` filename. A precision fix, not a regression." },
      "M6-indicator": { counted: 48, total: 48, note: "#897: MEASURED 2026-07-24 — 48 hand-rolled-shape indicators across an ERP (MIME-type tables, currency/date formatting, base64url, cookie parsing, random-string ids). All Info/non-grading (#267); counted === total by construction. #1128: RE-VERIFIED 2026-07-26 byte-identical at 48/48 — `pnpm corpus-drift --target carbon --install` reproduced 48 counted, no drift." },
      M7: { counted: 536, total: 718, note: "#1475-#1480: RE-MEASURED 2026-07-28 at 536/718 (was 673/841) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 673/841 on the identical clone. -137, the corpus's largest M7 movement, and the composition matters more than the number. 92 Unbounded select rows (344 -> 252): 89 are paginated one call away through this repo's house-style `setGenericQueryFilters(query, args, ...)` (apps/erp/app/utils/query.ts:137, a `.range()` on the query it was handed) and 3 are in ci/. METHOD, stated rather than implied: 2 rows were READ INDIVIDUALLY against source (people.service.ts getTimecardEntries, accounting.service.ts getAccounts) and the other 87 were classified MECHANICALLY by the property that decides the question — the enclosing exported function passes the flagged query to that helper — which resolves for 89 of 89 with zero unexplained. #1478's issue text put 136 of 344 'within reach' of the wrapper; that was a 60-line proximity PROXY and this replaces it with a measurement of 89. 23 raw <img> files were SVG-only (#1477); the other 37 change taxonomy to the Vite label (#1480). 14 State sprawl -> Info (#1475). 6 await rows are ci/, packages/checks and packages/database seeders, plus one FIFO cost-layer loop in a Supabase edge function whose `if (remainingToConsume <= 0) break;` is loop-carried accumulation, read individually (#1476/#1480). 2 heavy-import rows are `pdfjs-dist/.../pdf.worker.min.mjs?url`, where Vite's `?url` yields the asset URL and pulls nothing into the chunk (#1479). The 12 SURVIVING heavy-import rows (monaco/three in packages/viewer and apps/erp) are the recall control: an earlier build of #1479 required positive client-reachability and deleted all 14, because RR7 discovers routes through `routes.ts` and framework routing is not an import edge. Prior note: #1261: 673/841 reproduces 2026-07-28, and 29 of its rows were drawn into the 40-row seeded random sample (seed 1261) over the 858 graded rows of the four large targets; each was read against source. SAMPLED, NOT CENSUSED — 644 of these 673 rows are untriaged and this note asserts nothing about them. Of the 29 read: 23 hold, 6 do not. The false ones each have a decisive cause, and two are large families: (a) `setGenericQueryFilters` (apps/erp/app/utils/query.ts:137) applies `.range(offset, offset+limit-1)`, so a `select('*')` that reaches it IS bounded one call away — sample rows getTimecardEntries and getSalesOrders were read and confirmed, and a MECHANICAL PROXY (not a triage) puts 136 of the 344 unbounded-select rows within 60 lines of that helper or a literal `.range(`/`.limit(`; (b) entry.client.tsx:1's `pdfjs-dist/build/pdf.worker.min.mjs?url` is a Vite `?url` import yielding the asset URL string, not the module, so 'heavy import in client bundle' is false there. Also false: ci/src/assembler.ts's unbounded select (a CI deploy script, not a request path), the SalesOrderLineForm state-sprawl row (carbon is React 18.3.1 — automatic batching falsifies that class's evidence sentence), and the login.tsx raw `<img>` (a static SVG logo). HYPOTHESIS TESTED AND WITHDRAWN: carbon declares no `next` dependency, so its 60 raw-`<img>` rows looked framework-inapplicable — MEASURED false, #872's isVite branch fires on all 60 and they carry the Vite title and the vite-imagetools fix; only the taxonomy STRING still says 'instead of next/image', a label defect. Prior note: #1344: RE-MEASURED 2026-07-27 at 673/841 (was 672/840) — DRIFT +1, the single survivor of #1203's generic sync-I/O tier after #1344 gated it on import-reachability from a request entry point. VERIFIED true positive: apps/erp/app/modules/production/assembly-debug.server.ts:14 `appendFileSync` per server-action hit, to a HARDCODED absolute path under a developer's home directory, in a file whose own comment says \"TEMPORARY debugging instrumentation … Remove once resolved\". The other 31 hits #1203 produced here were all in packages/dev (a `crbn` CLI), packages/checks and packages/harness — dev tooling no request ever loads — and are gone. Prior note: #897: MEASURED 2026-07-24 — the corpus's largest M7 surface. detect-static completed the whole tree in 19.8s. #1128: RE-MEASURED 2026-07-26 at 672/840 (was 673/841) — DRIFT -1, same cause and same file as M5-slop's -177 above: #1088/#1065's isGeneratedSource exclusion drops apps/erp/public/pdf.worker.min.mjs, which was also good for one 'Await in loop (N+1)' false positive in the vendored bundle. VERIFIED by the same before/after `static-detect` diff." },
      M8: {
        // #1268 RE-VERIFIED 2026-07-28 (corrects the #897 reason below, which cited npm's
        // EUNSUPPORTEDPROTOCOL failure — that is now FALSE): `pnpm install` (not npm) resolves this
        // target's install in full, MEASURED, 1m7s, no protocol error. But the target's OWN vitest
        // configs (e.g. packages/utils/vitest.config.ts) import a WORKSPACE-INTERNAL package
        // (@carbon/config) by its BUILT output (`@carbon/config/dist/vitest.mjs`), and a bare
        // `pnpm install` does not run this monorepo's build step — TRIED running vitest directly
        // against packages/utils's own spec after install: `Cannot find module
        // '.../packages/utils/node_modules/@carbon/config/dist/vitest.mjs'`. This is a NEW,
        // narrower blocker than the old "can't install at all" — the install now works, and the
        // gap is "needs this monorepo's own build pipeline run before any workspace member's tests
        // are loadable", which corpus-m8.yml/m8-corpus.ts do not attempt. Not chased further in
        // THIS PR (inbox-zero/rallly, #1268's two required real baselines, did not need a build
        // step — this is carbon-specific, population of one target so far). Recorded not-run with
        // the corrected reason rather than 0.
        //
        // #1436 RE-VERIFIED 2026-07-28 and corrected one detail: the import is not literally
        // `@carbon/config/dist/vitest.mjs`. packages/utils/vitest.config.ts reads
        // `export { default } from "@carbon/config/vitest"`, and it is packages/config/package.json's
        // own `exports` map that sends `./vitest` to `./dist/vitest.mjs`. Same blocker, one level
        // down — and the manifest is the durable place to watch it, which is what the falsifier does.
        // The SAME root cause is why this target's M5-knip stays partial at 2 of 33 scopes
        // (packages/kv, packages/logger each fail to load their own vitest.config.ts); that note
        // points here rather than repeating the claim, so one falsifier watches both.
        //
        // REASON: carbon is not mutation-scoreable because its workspaces load their vitest config from a workspace-internal package's BUILT output — packages/config exports `./vitest` as `./dist/vitest.mjs`, which only this monorepo's own build step produces, and corpus-m8.yml runs an install but no build
        // KIND: empirical
        // PROVENANCE: MEASURED 2026-07-28 — `pnpm install` resolves the tree in full (1m7s, no EUNSUPPORTEDPROTOCOL), then running vitest against packages/utils's own spec fails with `Cannot find module .../packages/utils/node_modules/@carbon/config/dist/vitest.mjs`. Re-read at the pin (92e19c0) and at upstream HEAD: packages/config/package.json still maps `"./vitest": "./dist/vitest.mjs"` in both.
        // FALSIFIER: sh -c 'command -v curl >/dev/null 2>&1 || exit 127; b=$(curl -fsS --max-time 20 https://raw.githubusercontent.com/crbnos/carbon/HEAD/packages/config/package.json) || exit 127; case "$b" in *dist/vitest.mjs*) exit 1;; *) exit 0;; esac'
        // TOUCHES: src/scan/m8-corpus.ts
        reason: "#897: MEASURED 2026-07-24, re-verified 2026-07-28 — a real suite IS detected (so #224's zero-coverage finding does not apply), but it is not mutation-scoreable through corpus-m8.yml TODAY: a pnpm-aware install (#1268) now resolves this target's node_modules in full (no more EUNSUPPORTEDPROTOCOL), but its workspaces load their vitest config from a workspace-internal package's BUILT output — packages/utils/vitest.config.ts re-exports `@carbon/config/vitest`, which packages/config/package.json maps to `./dist/vitest.mjs`, a file only this monorepo's own build step produces and corpus-m8.yml does not attempt. A materially narrower gap than the old 'can't install at all', but still not-run rather than 0. Same root cause as this target's 2-of-33 partial M5-knip scopes.",
        falsifier: "sh -c 'command -v curl >/dev/null 2>&1 || exit 127; b=$(curl -fsS --max-time 20 https://raw.githubusercontent.com/crbnos/carbon/HEAD/packages/config/package.json) || exit 127; case \"$b\" in *dist/vitest.mjs*) exit 1;; *) exit 0;; esac'",
      },
      "M8-intent": { counted: 3, total: 3, note: "#897: MEASURED 2026-07-24 — 1 'Call-count-only test' (Low) and 2 'Happy-path-only tests on security/money-critical code' (Medium: no-legacy-rls.ts, build-payment-journal.ts). A striking ratio: 77 test files across 4,110 source files produce almost no test-intent signal, because there is barely any test surface to inspect." },
      // #964: BASELINED at the measured, FP-cleared number. The #916-918 RR7 ports first produced 347
      // non-Info M9 findings carrying a reproduced FP population; #964's detector precision fix removed 106
      // FPs and the residual 241 were individually confirmed real (see the note). Framework detection is and
      // stays CORRECT — carbon is @react-router/dev, ssr:true, analysed on the boundary model.
      // #1293 — THE INTEGRITY CORRECTION. What this note used to say, and why it was wrong, is
      // recorded here rather than deleted. A baseline that overstates its own verification does
      // more damage than one that claims nothing, because it reads as settled.
      //
      // #964's note asserted "Residual 241 verified real" and named four classes. A verification
      // METHOD was given for two of them. The other two — 56 data-fetching waterfall and 3
      // server→client leak — were the rows #964's own body had called "not individually verified",
      // and the assertion swallowed that. #1128 then re-measured to 233 and root-caused the -8
      // meticulously while re-stating the same sentence: drift discipline verified the delta and
      // inherited the base.
      //
      // ALL FOUR CLASSES HAVE NOW BEEN VERIFIED INDIVIDUALLY (2026-07-28, method and result per
      // class below). The headline arithmetic, and it closes: of the 194 rows the previous baseline
      // stood behind, 109 triaged FALSE (105 SSR + 3 leak + 1 waterfall) and 85 confirmed real
      // (66 validation + 16 waterfall + 3 SSR). The largest class — the one whose stated method
      // ("116 SSR-only by file type") this issue had ACCEPTED as adequate — was 105/108 false. That
      // method confirmed each row was WHERE ITS EVIDENCE SAID IT WAS; it never asked whether the row
      // was a defect. A mechanical property check is not a triage, and reading one as the other is
      // how 241 came to be called "individually confirmed".
      M9: { counted: 104, total: 114, note: "#1460/#1461 + #1438/#1441, MERGED: RE-MEASURED 2026-07-28 at 104/114 on the tree with BOTH PRs applied — 109 (shared base) −7 from this PR (6 SSR helper rows + 1 waterfall) +2 from #1441. THE WATERFALL ROW #1461 TARGETED IS STILL PRESENT, and that is a finding, not an oversight: `maintenance+/$dispatchId.events.tsx:54` now clears #1461's mechanism (the `throw redirect(…)` inside `requireUnlocked` IS resolved and seen) but is then reported anyway by #1438's later relaxation, which suppresses an ABORTING guard only when one of the two queries writes. Both of these are reads. On the merits #1438 is right and #1461's 'false positive' label was wrong: hoisting two reads above a `throw redirect()` changes no state and the user is redirected either way, so the pair is a genuine parallelisation opportunity. Recorded on #1461. The 20 SSR rows that remain are classified in this PR's own note below and in #1502. PRIOR: #1460/#1461: RE-MEASURED 2026-07-28 at 102/111 (was 109/118) — DRIFT -7, a PRECISION FIX, and it CLOSES TWO of the three families #1293 left open with their issues. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04>`; the pre-change arm on the identical clone reprints EXACTLY 109/118. (a) SSR-only, 26 -> 20. #1460's rule suppresses a browser-global read in a module-level, lowercase-named, JSX-free helper ONLY when it has at least one in-file call site and no such call site is itself on the render path. Six rows cleared, each READ against source: InspectionDocumentEditor.tsx:446/450, ModelPreview.tsx:491/494, PinInOverlay.tsx:22/33 — the four helpers #1460 named. CORRECTING #1460's OWN POPULATION FIGURE, which said 23 of the 26 residual rows were this family: they are not. The 20 that remain classify as — 7 in COMPONENT render bodies (capitalised enclosing function: MobileNav ×2, Zoomable, SetupInstructions ×2 in jira/linear config, ImageResizer, GetStartedStartRoute); 6 in the `isBrowser ? window.x : y` house-style-guard family that #1460's own text says is probably its own fix (slack/config.tsx ×5, packages/env/src/index.ts:265 at module top level); 3 kept by the acceptance criterion's own condition that a helper with NO in-file call site stays flagged (`handleCommandNavigation` in slash-command.tsx, exported; `subscribe` in useCustomerPreview.tsx ×2, passed to useSyncExternalStore as a VALUE and never called in-file); and 2 that are the confirmed TRUE POSITIVES this fix had to keep, ActionBar.tsx:345/346 (`useWindowDimensions`, a hook the render body calls) plus image-resizer.tsx:34 in the component list above. So the family was ~9 rows, not 23, and 6 of them are gone. (b) Data-fetching waterfall, 17 -> 16, exactly as #1461 predicted: the removed row is maintenance+/$dispatchId.events.tsx:54 and the other 16 are unchanged, verified by location-level diff. (c) A finding this PR made rather than inherited: #1263's callee resolution had been running on this target with an essentially EMPTY alias table. `collectPathAliases` stopped at the shallowest tsconfig declaring `paths` — here `docs/tsconfig.json` — so `~/*` was never resolved in apps/erp, apps/mes, apps/starter or apps/academy, the four workspaces that declare it. The 66 route-action validation rows were RE-MEASURED with the alias table repaired and are STILL 66: the previous note's claim that #1263's resolution independently corroborated them was made on weaker evidence than it read, and now it holds on the real evidence. WHAT THIS BASELINE STANDS BEHIND: 102 counted = 84 confirmed real by reading (66 validation + 16 waterfall + 2 SSR) + 18 recorded FALSE and tracked (the 20 SSR residual above minus its 2 true positives). NOT ONE ROW IS UNVERIFIED. Note this target ALSO carries 113 `M1 — route action missing authorization check` rows which THIS baseline has never scored and still does not — they are scored by the new M1-boundary key (#1459), whose own note states their untriaged status. PRIOR: #1293: RE-MEASURED 2026-07-28 at 109/118 (was 194/203) — DRIFT -85, a PRECISION FIX. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-92e19c04> --out f.json`; the pre-change arm at a91c2f9 reprints EXACTLY 194/203 on the identical clone. PER-CLASS VERIFICATION, which is what this issue was filed to get — the method is stated for EVERY class, and where a class is not individually verified it says so instead of asserting it. (1) SSR-only API misuse, 108 -> 26. METHOD, stated per family rather than as one word, because the whole defect this entry corrects is a property check being reported as a triage: all 108 were classified into families, and within each family the evidence differs. 32 residual rows (every row not in a mechanically-decidable family) were READ INDIVIDUALLY against source. The 59 clientAction rows were classified by resolving each row's enclosing top-level export programmatically, with one read against source to confirm the shape. The 14 shadowed-`document` rows: 2 read against source, the other 12 classified by member name (`document.type/path/name/size/error/data/version` — none is a member of the DOM `Document` interface, so the receiver cannot be the global). The 3 `entry.client.tsx` rows are classified by filename. So: 35 rows read individually, 73 classified mechanically by a property that decides the question, and this sentence says which is which. RESULT: 3 true positives, 105 false, in five families: 59 `window.clientCache` inside `clientAction` (a React Router 7 route export that runs ONLY in the browser); 14 where `document` is a DESTRUCTURED PROP or query result, not the DOM global (a `DocumentType` prop in DocumentView.tsx, a loader's row in quality-document/$id.tsx) — the shadowing rule existed and read only the identifier-shaped binding; 3 in `entry.client.tsx`; 6 behind an EARLY-RETURN `typeof window === \"undefined\"` guard that the ancestor-only guard walk could not see, while the finding's own evidence asserted no such guard existed; and 23 in module-level plain helper functions that happen to live in a `.tsx` file. The first four families are FIXED in this PR (-82), each with its own corpus pair and each proven able to fail by reverting it (`src/scan/calibration.test.ts`). The fifth is the 23 of the 26 residual: tracked as #1460, NOT fixed here because the recall-safe form needs the helper's call sites checked. The 3 confirmed TRUE positives are ActionBar.tsx:345/346 (`useState({ x: window.innerWidth })` — an initializer that really does run during SSR) and tiptap/image-resizer.tsx:34 (`document.querySelector` in a JSX prop). (2) Route-action missing input validation, 66, UNCHANGED. METHOD: MEASURED — re-ran #964's stated method on this clone: all 66 rows are in 66 DISTINCT files, and grepping every one of those files for `validator(` / `.validate(` / `zod` / `safeParse` / `parseWithZod` / `valibot` / `yup.` / `ajv` returns ZERO hits; the only `.parse(` occurrences anywhere in the 66 are 16 `JSON.parse(`. Independently corroborated by #1263's callee resolution finding no house-style validator behind any of them. All 66 confirmed genuinely unvalidated. (3) Data-fetching waterfall, 17, UNCHANGED. METHOD: MEASURED — all 17 pairs read against source (#1292 had read 2). RESULT: 16 real, 1 FALSE — maintenance/$dispatchId.events.tsx:54, where `await requireUnlocked({ isLocked: isMaintenanceDispatchLocked(dispatchForLock.data?.status) })` sits between the awaits: it reads the first result and exits, but the exit is INSIDE the helper, so #1292's guard test (which looks for a syntactic return/throw in the block) cannot see it. Same class as #1292, one hop further out; tracked as #1461. (4) Server→client data leak, 3 -> 0. METHOD: MEASURED — all 3 read against source. RESULT: 3 of 3 FALSE, one root cause: every one is a `.select()` with an explicit narrow column list (4, 5 and 7 named columns — api+/items.materials.ts:21, quality+/_index.tsx:199, resources+/_index.tsx:123) under evidence reading `every field on the row ships to the browser`, which is simply false against a projected query. FIXED in this PR: a query whose own `.select()` names its columns has already projected — the same rule the detector already applied to `const { name } = row`, one step earlier in the chain. `*` anywhere (including an embed), a computed argument, or no argument at all still counts as raw. WHAT THIS BASELINE NOW STANDS BEHIND, and the arithmetic closes: 109 counted = 85 rows confirmed real by reading them (66 validation + 16 waterfall + 3 SSR) + 24 rows recorded FALSE and tracked (23 in the #1460 SSR helper family, 1 in the #1461 waterfall guard family). NOT ONE ROW IS UNVERIFIED. Where a class carries known-false rows this note says so and names the issue, rather than asserting the class real — which is the discipline #964 was filed to enforce and #1293 filed to restore. It is a DRIFT baseline either way, not a defect count. Prior notes, retained because they are the record this correction is against: #1262/#1292: RE-MEASURED 2026-07-28 at 194/203 (was 217/225) — 23 waterfall false positives removed by #1292's guard rule, on top of the 16 #1344 had removed: 40 waterfall rows -> 17. #1344: RE-MEASURED 2026-07-27 at 217/225 (was 233/241) — DRIFT -16, a precision fix in the waterfall independence test, which asked only whether the SECOND query's text mentions the FIRST query's bound name, so a dependence laundered through an intermediate binding scored as independent. #1128: RE-MEASURED 2026-07-26 at 233/241 (was 241/248) — DRIFT -8, #1088/#1065's isGeneratedSource exclusion dropping two enterprise-integration config files with 500-1400-character SVG path-data lines. #964: MEASURED 2026-07-24 at 241/248; the #916-918 RR7 ports produced 347 non-Info and #964's precision fix removed 106 reproduced FPs (36 route-actions validated through the `validator(schema).validate(...)` wrapper; 70 SSR-only FPs in non-component `.ts` modules). ITS 'residual 241 verified real' SENTENCE IS THE CLAIM THIS ENTRY RETRACTS." },
      M10: { counted: 214, total: 214, note: "#968/#936: RE-MEASURED 2026-07-24 (this PR) at 214 PII-bearing tables — was 154 (#897). The #936 camelCase-tokenization fix classifies 60 previously-invisible camelCase PII tables. Severity ceiling moved Medium → HIGH: company High 6.3 (taxId+address+phone+fax+email), oauthClient/printerRoute High 6.3 (name+apiKey), oauthToken High 6 (authToken). Measured via m10FindingsFromSchema over the 859 cloned supabase/migrations (4951 columns scanned, 177 PII-bearing across 214 tables): 214 counted === 214 total, 4 High / 14 Medium / 196 Low. This REPLACES the prior note's now-false claim that the highest severity anywhere in the schema was Medium." },
    },
  },
  // ── #1276: the first REAL TanStack Start application in this corpus. #918 shipped the TanStack
  // adapter graded only against six fixtures authored by the same PR, plus "verified against the
  // current docs" — which per CLAUDE.md measures internal consistency, not coverage, and the sibling
  // React-Router-7 adapter in that same PR then produced ≥36 confirmed false positives on the first
  // real target it met (#964, carbon). `grep -c -i tanstack src/scan/external-corpus.ts` was 0 until
  // this entry.
  //
  // WHY THIS TARGET: the framework's own maintainers wrote it, so its `createServerFn` conventions
  // are ground truth rather than our reading of the docs. It is a real application, not a demo —
  // Drizzle/Postgres, session auth, a role/capability system, MCP API keys, showcase moderation.
  // MEASURED on the pin: 142 `createServerFn` chains across 25 files, 21 of them DB-mutating. Two
  // other real candidates were scanned before choosing (Radionic/notesify, dosco/aithy — both real
  // TanStack Start + `createServerFn` apps); tanstack.com exercises the adapter hardest and all
  // three agreed on the adapter behaviour recorded below.
  //
  // WHAT MEETING A REAL TARGET ACTUALLY FOUND, which the six fixtures could not:
  //   1. A framework-true FP family — `createClientOnlyFn(fn)` and `createIsomorphicFn().client(fn)`
  //      are TanStack Start's own markers for "never runs on the server", and the SSR-only check
  //      fired inside them. 6 of 18 rows. FIXED in this PR, with a corpus pair
  //      (M9C-TANSTACK-CLIENTONLY-POS/NEG) that goes red if the rule is reverted.
  //   2. The adapter's own boundary machinery is REACHED and does fire — but under an `M1 —`
  //      taxonomy (`M1 — server function missing authorization check`, 12 rows here, 17 on notesify,
  //      13 on aithy). `moduleMatches` keys the M9 baseline on the `M9 ` prefix, so THOSE ROWS ARE
  //      NOT SCORED BY THIS OR ANY BASELINE. Stated because it bounds what the number below proves:
  //      the M9 baseline locks that the adapter is SELECTED and its shared checks run, not that its
  //      `createServerFn` mutation gates still work. Tracked as #1459.
  //   3. Those 12 M1 rows were triaged against the source and are FALSE POSITIVES, one root cause:
  //      every one sits behind `await requireAdmin()`, whose body reaches its real check through
  //      `await import('./auth.server-helpers')` — a DYNAMIC import, which #1263's GateResolver does
  //      not resolve. Two hops of static resolution would have reached `getCurrentUser` and matched.
  //      Tracked as #1462. NOT fixed here: the fix belongs with #1263's resolver and wants its own
  //      adversarial positives, not a rushed widening on the day the FP was found.
  {
    slug: "tanstack-com",
    repo: "TanStack/tanstack.com",
    commit: "6b61f4dcc19a950fe15f8b610925a4b74091313e",
    license: "none in-tree at this pin (GitHub reports no license — all rights reserved by default). Nothing is vendored: this corpus clones on demand, the same posture as carbon and multi-tenant-starter.",
    provenance: "ai-assisted",
    provenanceNote: "#1276: the TanStack org's own marketing/docs/application site — 1,059 stars, a large human contributor history, versioned deps, and a real Drizzle/Postgres data layer. Also ships CLAUDE.md + AGENTS.md. Capable-dev-with-AI, the same tier as carbon.",
    securityVerdict: "NOT ASSESSED — #1276 is an ADAPTER-COVERAGE measurement, not an audit. Only the source/mechanical tier ran (detect-static); no M1 semantic pass, no dynamic tier, no free-tier grade, and no disclosure filed or warranted from this pass. The 12 `M1 — server function missing authorization check` rows this target produces were triaged and are false positives (see #1462 above) — recorded here so that triage is not mistaken for a security verdict in either direction.",
    modules: {
      "M1-boundary": { counted: 6, total: 6, note: "#1459: MEASURED 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — 6 High `M1 — server function missing authorization check` rows, down from 12 before #1462's dynamic-import resolution landed in this PR. TRIAGE STATE, stated per row rather than as a count: all 12 pre-fix rows were read against source and all 12 are FALSE POSITIVES. The 6 this PR clears are the ones behind `requireAdmin()`, whose real check is bound by `await import('./auth.server-helpers')`. The 6 that REMAIN (showcase.functions.ts ×4, docFeedback.functions.ts ×2) sit behind `requireModerateShowcases`/`requireModerateFeedback`, and #1462's stated root cause does NOT cover them: their chain is action → require*() → requireCapability → getAuthGuards().requireCapability → getCurrentUser, four hops past GATE_DEPTH=2, with one hop bound by `await loadAuthServer()` (a function that wraps the dynamic import, not a direct `await import()`). So this baseline stands behind 6 rows KNOWN FALSE with a named and measured cause, tracked separately — not 6 unexamined rows. #1434: RE-VERIFIED 2026-07-31, NO MOVE — controlled before/after `static-detect` on <clone-of-6b61f4d>, one variable (the #1434 diff): both arms 679 findings, 0 rows only-before, 0 only-after, M1 6/6 and M9 16/16 in both. Included in the #1434 sweep because it is the only OTHER pinned target with a non-zero M1-boundary reached through a non-Next adapter, so a noun-specific regression would show here first." },
      M4: { counted: 278, total: 436, note: "#1276: MEASURED 2026-07-28 — 5.03% duplication (9,861 of 196,018 lines), 498 clone clusters over 782 eligible files. Reproduced byte-identically across two quality-scan runs, and identical in the no-deps and `pnpm install` arms — the install is inert for M4 here, same as carbon. Total-vs-counted gap is the Info tail (M4-00 sub-threshold, M4-SELF-00, M4-SCOPE-00, M4-97 coverage rows)." },
      "M4-diverged": { counted: 8, total: 8, note: "#1276: MEASURED 2026-07-28 — 8 diverged security-path clone pairs (review tier) from a same-file-pair-aware pass over 34 of 782 eligible files, the bound M4-97 discloses. Not triaged: this is a drift baseline, and #1276 is an M9-adapter measurement." },
      "M5-knip": { counted: 726, total: 727, note: "#1276: MEASURED 2026-07-28 WITH the target's own deps installed (`pnpm install` — this pin tracks a pnpm-lock.yaml, so #1268 routes it to pnpm and the tree resolves in full; knip does NOT fall back to #810's reduced no-deps mode, and no M5-98 row is emitted). Reproduced identically across two consecutive quality-scan runs. A NO-DEPS arm on the same clone reads 732/733, so the install moves it by 6. STILL A DRIFT BASELINE, NOT A DEAD-CODE CLAIM, and it says so in its own output: 679 of the 726 are 'unused file' rows and the target is a TanStack Start app with FILE-BASED ROUTING, whose route modules knip cannot infer as entry points — the #580 M5-99 uncertainty row is part of this baseline and flags the single scope as uncertain. Do not read 726 as 726 pieces of dead code." },
      "M5-slop": { counted: 454, total: 514, note: "#1532 RESIDUAL: RE-CONFIRMED 2026-07-31 at 454/514 — unchanged by the two residual fixes, and the confirmation is worth recording because one of them nearly moved it: the one-hop `doesOwnIo` briefly disqualified `getLinkTarget` (scripts/check-docs-menu-links.ts:554), and reading it at source showed the trigger was `/^framework…/.exec(docsPath)` inside `getExampleTarget` — a regex match the over-wide spawner vocabulary read as spawning a process. `isExternalUrl`, `removeSearchAndHash`, `replaceRouteParams`, `isSpecialDocsPath` and `getDocsPath` were read too; none touches a process or the filesystem. The vocabulary was narrowed to a bare identifier and this target settled back to #1533's number. #1533: RE-MEASURED 2026-07-31 at 454/514 (was 446/506) — DRIFT +8, the corpus's largest #1533 movement and eight RECOVERED FALSE NEGATIVES, every one on the `async`-caller-with-no-await boundary the prior note enumerated as 11 rows. All eight read at source: five in src/utils/application-starter.ts (`normalizeText`:580, `detectIntent`:584, `buildRecipe`:612, `getResultType`:1121, `buildRationale`:1160), whose shared caller `resolveApplicationStarterDeterministically` returns `composeStarterResult({...})` — an object literal, established only by following the call into another module, which is the cross-file hop #1533 exists for; plus `getManifestCatalog` (src/builder/api/create-worker.ts:386, caller `async () => getManifestCatalog()`), `generateRSSFeed` (src/routes/rss[.]xml.ts:15, caller returns `new Response(content)`) and `handleRedirects` (src/utils/blog.functions.ts:42, caller returns an object literal). This target is the corpus's declared M5-slop FP-drift watch, so the recovered rows are enumerated rather than summarised. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-6b61f4dc> --out f.json`. Prior note: #1532: RE-MEASURED 2026-07-30 at 446/506 (was 550/610) — DRIFT -104, a PRECISION FIX taken against a NARROWED scanner, and the corpus's second-largest M5-slop movement. Same cause and method as proposit's M5-slop note (#370/#1447's `isTestabilitySeam`; #1532's `doesOwnIo` narrows it and RECOVERS 4 findings here, so the pre-fix reading was 442). 108 spared — 20% of this target's entire M5-slop reading, which is what made a rebaseline-without-reading indefensible. 11 sit on the disclosed `async`-caller-with-no-await boundary (#1533). The seeded 50-row corpus sample drew 6 rows here (`isSafeGitRef`, `isAllowedRemoteJsonType`, `extractFrontMatterKeywords`, `dedupe`, `decodeBase64File`, `openBrowser`): 5 graded genuine seams, and `openBrowser` (scripts/auth-login.ts:37) was one of the 5 corpus-wide defects — it `spawn`s a subprocess, so it was never the pure half — and now fires. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-6b61f4dc> --out f.json`. Prior note: #1276: MEASURED 2026-07-28 via detect-static (no install prereq) — 540 single-use helper, 32 narrating comment, 28 decorative emoji, 5 single-call wrapper, 4 else-after-return, 1 unused import. The single-use-helper density (540) is the shape the 2026-07-28 breadth sweep flagged as a rollup candidate across 15/15 repos, not a property of this target." },
      "M6-indicator": { counted: 30, total: 30, note: "#1276: MEASURED 2026-07-28 — 30 hand-rolled-shape indicators (cookie serialization 8, base64url 6, composite timestamp-random id 5, cookie parsing 4, random-string id 2, hand-rolled ErrorBoundary 2, class-string merge, clipboard via execCommand, non-crypto string hash). All Info/non-grading (#267), so counted === total by construction." },
      M7: { counted: 119, total: 121, note: "#1475-#1480: RE-MEASURED 2026-07-28 at 119/121 (was 124/124) — a PRECISION FIX from the six false-positive families #1261's FIELD triage measured on this corpus. Command, reproducible: `pnpm exec tsx src/cli/static-detect.ts <clone-of-6b61f4dc> --out f.json`; a pristine-main control worktree at c882eee reprints EXACTLY 124/124 on the identical clone. -5 counted. 4 await rows are scripts/ (#1476); 2 State sprawl -> Info and 1 oversized-image row re-words to Unreferenced (#1475/#1480). All 46 raw <img> rows change taxonomy to `M7 — Raw <img> without dimensions or lazy-loading` (#1480) — this target declares no `next` dependency, so the old string told a Vite client to use next/image. Prior note: #1276: MEASURED 2026-07-28 — 46 raw `<img>`, 33 heavy import in client bundle, 21 nested-loop join, 14 await-in-loop (N+1), 4 unbounded select, 2 sort-in-render, 2 state sprawl, 1 client fetch in useEffect, 1 oversized committed image. Source tier only: no build artifact, so the [B] bundle tier did not run." },
      "M8-intent": { counted: 0, total: 0, note: "#1276: MEASURED ZERO 2026-07-28 across this target's 25 test files — no assertion-free / tautological / happy-path-only / mock-the-subject shape fired. An FP floor for the test-intent pass on a professionally-maintained suite, the same reading as ghostfolio's zero." },
      M8: {
        // REASON: tanstack-com is not mutation-scoreable because no M8_CORPUS_CONFIGS entry exists for it — the blocker is our own backlog, not the target
        // KIND: empirical
        // PROVENANCE: MEASURED 2026-07-28 (#1276), re-checked the same day for #1436: a real suite is detected (25 test files) and src/scan/m8-corpus.ts carries no tanstack-com entry. Choosing the `mutate` scope means running the target's own suite to see what it covers.
        // FALSIFIER: sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q "^  \"\{0,1\}tanstack-com\"\{0,1\}:" src/scan/m8-corpus.ts && exit 0 || exit 1'
        // TOUCHES: src/scan/m8-corpus.ts
        reason: "#1276: MEASURED 2026-07-28 — `mutation-scan --detect-only` DETECTS a real suite (25 test files), so #224's zero-coverage finding correctly does NOT apply and a finding count is the wrong unit. Scoring it needs a provisioned Stryker + runner plugin (corpus-m8.yml's job) and a measured M8_CORPUS_CONFIGS `mutate` scope, which means running the target's own suite to see what it covers — not attempted in this PR, which is an M9-adapter measurement. This blocker is OURS, not the target's — the falsifier above exits 0 the moment an M8_CORPUS_CONFIGS entry lands. Recorded not-run rather than 0: a 0 would read as 'no surviving mutants' on a suite nobody has mutated.",
        falsifier: "sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q \"^  \\\"\\{0,1\\}tanstack-com\\\"\\{0,1\\}:\" src/scan/m8-corpus.ts && exit 0 || exit 1'",
      },
      M9: {
        counted: 4,
        total: 16,
        note: "#1460/#1462: RE-MEASURED 2026-07-28 at 4/16 (was 12/24) — DRIFT -8, a PRECISION FIX, and every one of the 12 counted rows this baseline used to stand behind was a recorded FALSE POSITIVE, so the drop is the whole point rather than a loss. Command: `pnpm exec tsx src/cli/static-detect.ts <clone-of-6b61f4dc>`; the pre-change arm on the identical clone reprints EXACTLY 12/24. Framework still detected `tanstack-start`, ORM `drizzle`; the adapter is selected and its five supported checks run. SSR-only 12 -> 4, all 8 removals READ against source: LibraryLayout.tsx ×4 (`getPageScrollProgress` and neighbours, whose single in-file call site sits inside a `React.useEffect` callback), useApplicationBuilder.tsx ×2, AvatarCropModal.tsx, MermaidBlock.tsx. The 4 that REMAIN are NOT the #1460 family and this note corrects #1460's description of them as 'four DOM helpers in DocFeedbackProvider.tsx': all four sit in CAPITALISED component render bodies (BlockButton, NotePortal, CreatingFeedbackPortal), reached by `document.createElement`/`window.getComputedStyle` during render. They are the scope control for #1460's rule, not its residual, and they are untriaged. The 12 Info rows are unchanged disclosure rows (3 drizzle data-layer not-assessed + 9 `not assessed (TanStack Start)`). SEPARATELY, and no longer invisible: this target's 6 `M1 — server function missing authorization check` rows (12 before #1462) are now scored by the M1-boundary key (#1459) rather than by nothing — see that baseline's note for their triage state. PRIOR: #1276: MEASURED 2026-07-28 (this PR) by `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree. Framework detected `tanstack-start`, ORM `drizzle`; the adapter is selected and its five supported checks run. 12 counted are ALL `M9 — SSR-only API misuse` (Low); the 12 Info rows are disclosure rows — 3 data-layer not-assessed (drizzle routes the Supabase-shaped leak/cache/waterfall checks to explicit N/A rows, #844) and 9 `not assessed (TanStack Start)` rows for the checks this adapter does not implement. THE 12 COUNTED ROWS WERE READ AGAINST THE SOURCE, NOT COUNTED: all 12 are the SAME open FP family — a browser global inside a module-level plain helper function that happens to live in a `.tsx` file (`openPendingDeployWindow`, `navigatePendingDeployWindow`, `getPageScrollProgress`, `getIsDarkMode`, and DocFeedbackProvider's four DOM helpers). #964 already suppresses this shape in `.ts` modules on the reasoning that a component needs JSX; the same helper in a `.tsx` file is still flagged, which is incoherent. Tracked as #1460 with its measured population (12 here, 23 of carbon's 26 residual) — deliberately NOT fixed in this PR because the recall-safe form needs the helper's CALL SITES checked (a helper called from a render body really is on the SSR path), and that is call-graph work with its own fixtures, not a one-line widening. So this baseline is a DRIFT baseline, and 12 of its 12 counted rows are recorded FALSE POSITIVES rather than defects in the target. Before this PR's M9 diff the same clone reprinted 30 counted / 42 total — the -18 is #1293's four SSR fixes plus #1276's TanStack client-only wrapper fix, each proven by its own negative control in `src/scan/calibration.test.ts`.",
      },
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
      "M1-boundary": { counted: 0, total: 0, note: "#1459: MEASURED ZERO 2026-07-28 via `pnpm exec tsx src/cli/static-detect.ts <clone>` over the pinned tree — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. Prose docs plus SQL and two Deno functions — there is no Next/Remix/TanStack boundary here at all. An FP FLOOR, and the point of scoring it: this class is High/Likely, so a widening that lights it up on a clean target fails here instead of shipping." },
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
  // ── #1524 (#1325 remainder, #542): full corpus-drift baselines for the three AI_FREQUENCY_CORPUS
  // (#413) targets that until now were measured ONLY for M6 hand-rolled-shape frequency. Same pins
  // handrolled-frequency.ts already uses, so the two measurements agree on which tree they describe.
  {
    slug: "cravab",
    repo: "stoimera/Cravab",
    commit: "f0b355fe5e082b9f67bacf3593393e763f50acea",
    license: "AGPL-3.0",
    provenance: "ai-generated",
    provenanceNote: "#413: .cursor/rules mandating tenant_id isolation + AI-slop README; strong stack fit (tenant_id everywhere, RLS, migrations, App Router). AGPL — scan-only, never vendor.",
    securityVerdict: "NOT ASSESSED — #1524 baselines the source-tier QUALITY modules only, same posture as #894's ghostfolio/rallly/etc entries. No M1 semantic pass, no dynamic tier, and no disclosure has been filed. This field is deliberately not a clean bill of health.",
    schemaPath: "supabase/migrations",
    modules: {
      "M1-boundary": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 via `pnpm corpus-drift --target cravab --install` — the M9 boundary pass runs and produces no missing-auth / client-owner-id row here. An FP floor, same posture as every other target's M1-boundary reading." },
      M4: { counted: 130, total: 212, note: "#1524: MEASURED 2026-07-30 via `pnpm corpus-drift --target cravab --install` — 211 'Duplication' rows (130 counted Low/Medium, the rest Info below the significant-duplication floor) + 1 Info 'Diverged clone (whole-repo)'. Command reproducible: clone the pin, `npm install`, `pnpm exec tsx src/cli/quality-scan.ts <clone> --out f.json`." },
      "M4-diverged": { counted: 37, total: 37, note: "#1524: MEASURED 2026-07-30 — 37 diverged security-path clone families (High, review tier), the corpus's largest reading for this key. Consistent with the target's per-entity API-route scaffolding (src/app/api/**) that its .cursor/rules mandate." },
      "M5-knip": { counted: 160, total: 161, note: "#1524: MEASURED 2026-07-30 via `pnpm corpus-drift --target cravab --install` (npm, single package.json at the clone root) — 161 unused-file/unused-export findings, 160 counted (Low/Medium) + 1 Info M5-98/M5-99-family disclosure." },
      "M5-slop": { counted: 476, total: 575, note: "#1533: RE-MEASURED 2026-07-31 at 476/575 (was 467/566) — DRIFT +9, nine RECOVERED FALSE NEGATIVES, all in one file and all on the `async`-caller-with-no-await boundary #1533 narrowed. This target was added to the corpus by #1524 on 2026-07-30, AFTER #1532/#1533's population was measured, so it was outside that measurement and its movement first surfaced in CI rather than in the PR. Diffed head-vs-pre-#1533 on this pinned clone: 9 added, 0 removed, every added row `M5 — Single-use helper` in src/app/api/jarvis/chat/route.ts — `getAppointmentHelp`:203, `getClientHelp`:227, `getServiceHelp`:253, `getCallHelp`:279, `getSOPHelp`:304, `getNotificationHelp`:329, `getTutorialHelp`:354, `getTroubleshootingHelp`:423, `findFAQMatch`:488. All nine read at source: each is a pure help-text builder returning a template literal, and their sole caller `processMessage` (route.ts:117) is declared `async`, contains ZERO awaits and returns an object literal — so the exemption's premise (\"the caller does the I/O\") is false and these were never testability seams. The file's other three single-use helpers (`processMessage`:117, `getTutorialSteps`:382, `getTroubleshootingSteps`:451) already fired before this change. Command: `pnpm corpus-drift --target cravab --install`. Prior note: #1524: MEASURED 2026-07-30 — 327 'Unused import', 56 'Single-use helper', 49 'Unused parameter', 19 'Else after return', 7 'Orphan TODO', 5 'Placeholder stub', 4 'Rethrow catch' counted (Low); 68 'Decorative emoji' + 31 'Narrating comment' Info. The corpus's highest M5-slop reading by a wide margin — 'Unused import' alone (327) dominates and is UNTRIAGED beyond this count; a future precision pass on this class should read this target first." },
      "M6-indicator": { counted: 71, total: 71, note: "#1524: MEASURED 2026-07-30 — 48 'raw-millisecond date math' (heavily concentrated in src/app/api/reports/*), 5 each of 'composite timestamp-random id' and 'markdown-to-HTML by regex', 4 'random-string id', 3 'email-shape regex', plus small counts of 5 other indicator classes. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 55, total: 72, note: "#1524: MEASURED 2026-07-30 — 27 'Unbounded select', 16 'Client fetch in useEffect', 6 'Await in loop (N+1)', 3 'Nested-loop join', 2 'Blocking sync I/O in request handler', 1 'Raw <img>' counted (Perf); 10 'Missing hook dependencies' + 7 'State sprawl' Info. UNTRIAGED — no field precision read yet, recorded as the raw scanner output per #1524's acceptance." },
      M8: {
        // REASON: cravab is not mutation-scoreable because no M8_CORPUS_CONFIGS entry exists for it — the blocker is our own backlog, not the target
        // KIND: empirical
        // PROVENANCE: MEASURED 2026-07-30 — `mutation-scan --detect-only` over the pinned clone reports "test suite detected" (jest.config.js + jest.setup.js + 3 spec files), so #224's zero-coverage finding correctly does NOT fire and a finding count is the wrong unit. src/scan/m8-corpus.ts has no cravab entry.
        // FALSIFIER: sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q "^  \"\{0,1\}cravab\"\{0,1\}:" src/scan/m8-corpus.ts && exit 0 || exit 1'
        // TOUCHES: src/scan/m8-corpus.ts
        reason: "#1524: MEASURED 2026-07-30 — mutation-scan --detect-only DETECTS a real suite here (jest, 3 spec files), so #224's zero-coverage finding correctly does NOT apply and a finding count is the wrong unit. Scoring it for real needs a provisioned Stryker + jest-runner plugin and an M8_CORPUS_CONFIGS entry naming a `mutate` scope narrowed to the files the suite actually covers — corpus-m8.yml's job, not this manifest change. This blocker is OURS, not the target's — the falsifier exits 0 the moment an M8_CORPUS_CONFIGS entry lands. Recorded not-run rather than 0 — a 0 would read as 'no surviving mutants' on a suite nobody has mutated.",
        falsifier: "sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q \"^  \\\"\\{0,1\\}cravab\\\"\\{0,1\\}:\" src/scan/m8-corpus.ts && exit 0 || exit 1'",
      },
      "M8-intent": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 — the 3 spec files trip no assertion-free/tautological/happy-path-only/mock-the-subject shape. A real FP floor for the test-intent pass on this target's thin suite." },
      M9: { counted: 9, total: 10, note: "#1524: MEASURED 2026-07-30 — 6 'Accidental dynamic rendering', 2 'SSR-only API misuse', 1 'Data-fetching waterfall' counted; 1 Info M9-RETRY scope disclosure row." },
      M10: { counted: 27, total: 27, note: "#1524: MEASURED 2026-07-30 via m10FindingsFromSchema over supabase/migrations (one init migration) — 27 PII-bearing tables. Headline is tenants: Critical (email/phone/address plus plaintext-adjacent vapi_api_key_encrypted/twilio_phone_number/vapi_public_api_key — the same must-not-miss plaintext-credential-column shape #233 exists to catch), then 6 Medium (audit_logs, clients, invoices, payments, service_area_coverage, users), the rest Low. The corpus's largest M10 reading — a full CRM/call-center schema (clients, calls, appointments, invoices, payments, consent_records)." },
    },
  },
  {
    slug: "flori-web",
    repo: "flori-ai-kr/web",
    commit: "bead044955f069525edac4134696d0a8f1a3071b",
    license: "none (all rights reserved)",
    provenance: "ai-generated",
    provenanceNote: "#413: Co-Authored-By: Claude on ~40 commits + CLAUDE.md + .claude/; many RLS migrations, user-scoped tenancy. No license — clone-and-scan only, never vendor.",
    securityVerdict: "NOT ASSESSED — #1524 baselines the source-tier QUALITY modules only, same posture as #894's ghostfolio/rallly/etc entries. No M1 semantic pass, no dynamic tier, and no disclosure has been filed. This field is deliberately not a clean bill of health.",
    schemaPath: "supabase/migrations",
    modules: {
      "M1-boundary": { counted: 1, total: 1, note: "#1524: MEASURED 2026-07-30 via `pnpm corpus-drift --target flori-web --install` — 1 High 'Server Action missing authorization check'. Unlike the other two #1524 targets this is non-zero: a real finding, not just an FP floor." },
      M4: { counted: 160, total: 272, note: "#1524: MEASURED 2026-07-30 (pnpm install — this clone carries both a pnpm-lock.yaml and a stray package-lock.json; detectPackageManager prefers pnpm) — 271 'Duplication' rows (160 counted) + 1 Info 'Diverged clone (whole-repo)'. Command reproducible: clone the pin, `pnpm install`, `pnpm exec tsx src/cli/quality-scan.ts <clone> --out f.json`." },
      "M4-diverged": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 — no diverged security-path family found. An FP floor." },
      "M5-knip": { counted: 54, total: 54, note: "#1524: MEASURED 2026-07-30 via `pnpm corpus-drift --target flori-web --install` (pnpm; this clone declares no workspaces, so pnpm/npm resolution is not in play the way it is for the corpus's monorepo targets) — 54 unused-file/unused-export findings, all Low/Medium." },
      "M5-slop": { counted: 95, total: 108, note: "#1524: MEASURED 2026-07-30 — 89 'Single-use helper' counted (Low), plus small counts of 'Unused import'/'Else after return'/'Orphan TODO'; 11 'Decorative emoji' + 2 'Narrating comment' Info. 'Single-use helper' alone (89) is UNTRIAGED and dominates — the same per-entity-scaffolding vein #1532's `doesOwnIo` fix addressed corpus-wide (this target predates that measurement, not exempt from it)." },
      "M6-indicator": { counted: 24, total: 24, note: "#1524: MEASURED 2026-07-30 — 9 'raw-millisecond date math', 6 'manual date formatting', 4 'email-shape regex', 2 'base64url conversion', plus 3 singleton classes. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 8, total: 30, note: "#1524: MEASURED 2026-07-30 — 2 'Await in loop (N+1)', 1 each of 'Raw <img>'/'Sort in render body'/'Fetch in middleware hot path'/'JSON deep-clone'/'Oversized committed images'/'Unreferenced committed images' counted (Perf/Low); 20 'State sprawl' + 2 'Missing hook dependencies' Info (React 18+ automatic batching likely falsifies most of the 20 state-sprawl rows per #1261's field precedent — UNTRIAGED here, they are Info and excluded from `counted` either way)." },
      M8: {
        // REASON: flori-web is not mutation-scoreable because no M8_CORPUS_CONFIGS entry exists for it — the blocker is our own backlog, not the target
        // KIND: empirical
        // PROVENANCE: MEASURED 2026-07-30 — `mutation-scan --detect-only` over the pinned clone reports "test suite detected" (vitest, 118 spec/test files), so #224's zero-coverage finding correctly does NOT fire and a finding count is the wrong unit. src/scan/m8-corpus.ts has no flori-web entry.
        // FALSIFIER: sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q "^  \"\{0,1\}flori-web\"\{0,1\}:" src/scan/m8-corpus.ts && exit 0 || exit 1'
        // TOUCHES: src/scan/m8-corpus.ts
        reason: "#1524: MEASURED 2026-07-30 — mutation-scan --detect-only DETECTS a real suite here (vitest, 118 spec/test files — the corpus's largest test-file count among the three new targets), so #224's zero-coverage finding correctly does NOT apply and a finding count is the wrong unit. Scoring it for real needs a provisioned Stryker + vitest-runner plugin and an M8_CORPUS_CONFIGS entry naming a `mutate` scope narrowed to the files the suite actually covers — corpus-m8.yml's job, not this manifest change. This blocker is OURS, not the target's — the falsifier exits 0 the moment an M8_CORPUS_CONFIGS entry lands. Recorded not-run rather than 0 — a 0 would read as 'no surviving mutants' on a suite nobody has mutated.",
        falsifier: "sh -c 'test -f src/scan/m8-corpus.ts || exit 127; grep -q \"^  \\\"\\{0,1\\}flori-web\\\"\\{0,1\\}:\" src/scan/m8-corpus.ts && exit 0 || exit 1'",
      },
      "M8-intent": { counted: 56, total: 56, note: "#1524: MEASURED 2026-07-30 — 29 'Unrestored vi.spyOn' (Medium), 21 'Call-count-only test' (Low), 3 each of 'Happy-path-only tests on security-critical code' and 'vi.hoisted misuse' (Medium). The corpus's highest M8-intent reading — a large vitest suite (118 files) with a recurring mock-hygiene shape, UNTRIAGED beyond this count." },
      M9: { counted: 19, total: 20, note: "#1524: MEASURED 2026-07-30 — 16 'Accidental dynamic rendering' (Medium), 2 'SSR-only API misuse' (Low), 1 'Server Action missing input validation' (High) counted; 1 Info M9-RETRY scope disclosure row." },
      M10: { counted: 4, total: 4, note: "#1524: MEASURED 2026-07-30 via m10FindingsFromSchema over supabase/migrations (14 migration files) — 4 PII-bearing tables: recurring_expenses (High, item_name/payment_method/note), instagram_accounts (Low, username/display_name/notes), trend_articles + insight_scraps (Low). Smallest M10 reading of the three #1524 targets — an expense-tracking app with a narrower schema than cravab's CRM." },
    },
  },
  {
    slug: "effective",
    repo: "joshcoolman/effective",
    commit: "52744674ef83306bc58ecfc607aa840092137132",
    license: "MIT",
    provenance: "ai-assisted",
    provenanceNote: "#413: CLAUDE.md + Co-Authored-By: Claude, but higher-skill Effect TS and a thin schema — a capable-dev-with-AI contrast to the vibe-coded repos. Large tree (~500k LOC via a vendored repos/effect reference copy, stripped from every scan below — see vendoredSubtrees); the app itself is ~47 files under src/.",
    securityVerdict: "NOT ASSESSED — #1524 baselines the source-tier QUALITY modules only, same posture as #894's ghostfolio/rallly/etc entries. No M1 semantic pass, no dynamic tier, and no disclosure has been filed. This field is deliberately not a clean bill of health.",
    schemaPath: "supabase/migrations",
    vendoredSubtrees: ["repos"],
    modules: {
      "M1-boundary": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 via `pnpm corpus-drift --target effective --install` (post `repos/` removal, see vendoredSubtrees) — an FP floor on a small app." },
      M4: { counted: 3, total: 6, note: "#1524: MEASURED 2026-07-30 (with vendoredSubtrees' repos/ removed first — WITHOUT that removal quality-scan reads 485/1074, almost entirely repos/effect's own internal duplication; see vendoredSubtrees's comment for the static-detect-side split) — 3 counted Low self-file clone pairs + 3 Info rows (a CHANGELOG.md clone, the whole-repo M4 disclosure, and the whole-repo diverged-clone disclosure). Of the 3 COUNTED rows, only ONE is real app code (src/styles/tokens.css:60-75 <-> :1-17); the other TWO are self-file duplication inside vendored `.agents/skills/**` reference-rule markdown (server-parallel-fetching.md, advanced-effect-event-deps.md) — noise `vendoredSubtrees` does not reach because it only strips `repos/`, disclosed here rather than adding a second exclusion mechanism for 2 rows." },
      "M4-diverged": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 — FP floor." },
      "M5-knip": { counted: 8, total: 8, note: "#1524: MEASURED 2026-07-30 via `pnpm corpus-drift --target effective --install` (pnpm; this clone declares no workspaces) — 8 unused-file/unused-export findings across src/features/*, all Low/Medium." },
      "M5-slop": { counted: 12, total: 12, note: "#1524: MEASURED 2026-07-30 — 10 'Single-use helper' (src/features/core/server.ts x5, scripts/*.mjs x3, src/features/core/use-chat.ts, src/features/generate/server.ts) + 2 'Single-call wrapper' (src/app/api/turn/route.ts, src/proxy.ts), all Low. The corpus's smallest M5-slop reading, consistent with this target's thin ~47-file app tree." },
      "M6-indicator": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30. All Info/non-grading (#267); counted === total by construction." },
      M7: { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 — FP floor on a small app with no visible request-path perf anti-pattern." },
      M8: { counted: 1, total: 1, note: "#1524: MEASURED 2026-07-30 — ZERO test files outside the vendored repos/effect tree (the root `\"test\": \"vitest run\"` script has nothing to run against once repos/ is excluded), so mutation-scan emits #224's M8-00 zero-coverage finding (High), which IS the measurement. Not a mutation baseline and not a not-run: 1 counted, per #263's rule that a test-FILE count is not the finding." },
      "M8-intent": { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 — no test files to inspect, so the M8-00 above is this target's whole M8 story (same shape as supabase-security-labs)." },
      M9: { counted: 1, total: 2, note: "#1524: MEASURED 2026-07-30 — 1 'Accidental dynamic rendering' (Medium, src/app/login/page.tsx) counted; 1 Info M9-RETRY scope disclosure row." },
      M10: { counted: 0, total: 0, note: "#1524: MEASURED ZERO 2026-07-30 via m10FindingsFromSchema over supabase/migrations (one 'create_todos' migration) — no PII-bearing columns. Consistent with the provenanceNote's 'thin schema': a todo app, not a tenant-data product." },
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
/** Which channel of the free tier has to carry the "we did not stay quiet" promise (#1473). */
export type LoudChannel = "graded" | "indicator" | "either";

export interface FreeTierExpectation {
  slug: string;
  mustNotScoreF: boolean;
  // true  -> at least one non-Info tenant-isolation indicator (the app IS known-vulnerable)
  // false -> no such indicator (a decent repo must not be accused)
  // #934: OPTIONAL — undefined means the target's tenancy posture is NOT ASSESSED (carbon: no M1
  // semantic pass, no dynamic tier), so neither direction can honestly be asserted. An undefined
  // posture still emits an explicit "not asserted" row rather than silently scoring one fewer
  // check — an absent row never shows up in a tally (the coverage-guard rule, applied here).
  mustRaiseLoudIndicator?: boolean;
  // #1473 — the product promise, split off from the CHANNEL it used to be conflated with.
  //
  // `mustRaiseLoudIndicator` scores one presentation section: `report.indicators`, which by
  // construction (selectIndicators, #220) holds only REVIEW-tier "Multi-tenant security" rows. That
  // is a narrow claim, and it silently stood in for the wide one — "the free tier does not stay
  // quiet on a known-vulnerable repo" — for as long as every corpus member happened to satisfy both.
  //
  // launch-mvp separates them, MEASURED 2026-07-28 against ShenSeanChen/launch-mvp-stripe-nextjs-
  // supabase @ 513a8f0: `grade F 51`, `indicators: 0`, graded set 4 High + 1 Low, three of the Highs
  // being the unauthenticated service-role account-deletion route of #774 — Confirmed, category
  // "Broken access control", so they land in the GRADED set and never reach the indicator channel.
  // All three available values of `mustRaiseLoudIndicator` therefore produce a FALSE statement about
  // that repo: true fails with "STAYED QUIET" on a repo graded F; false asserts "must not accuse a
  // sound repo" about two unauthenticated Criticals; undefined emits "tenancy posture is NOT
  // ASSESSED" about a repo assessed twice (#168, #774). An invariant whose every value states
  // something false is not an invariant, so the target sat outside the gate entirely (PR #1472).
  //
  // `mustBeLoud` asserts the promise itself and names the channel that has to carry it:
  //   "graded"    — the free GRADE must be loud: a Critical or High in the graded set, or an F.
  //   "indicator" — the review-tier tenancy indicator channel must fire (same signal as
  //                 mustRaiseLoudIndicator: true, expressed as a channel).
  //   "either"    — loud SOMEWHERE. The right value when the target is known-bad but which channel
  //                 surfaces it is an implementation detail nobody should pin.
  // Both fields may be set: they answer different questions, and a target whose Criticals are graded
  // AND whose tenancy indicator fires can assert both.
  mustBeLoud?: LoudChannel;
  // #934: the scale invariant carbon broke — placeholder/default credentials in docs/example
  // deployment paths must be REPORTED (in the non-grading informational section) and must NOT
  // appear in the graded set. Two-sided on purpose: "not graded" alone would also pass if the
  // detector stopped firing entirely, which would be a recall regression wearing a pass.
  mustNotGradeDocContextCreds?: boolean;
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
    why: "The don't-stay-quiet case: any authed user self-joins any tenant as owner (#217 Critical, confirmed dynamically). If the free tier is silent here it has failed the promise. Measured 2026-07-15: 4 High RLS indicators. RE-MEASURED 2026-07-28 (#1473): grade B (89/100), 2 graded (0 Critical/High), 3 indicators of which 2 are loud — both public.tenants RLS semantic-review rows, i.e. the row still passes on the surface the #217 Critical is about, not on an unrelated signal. Its grade is deliberately unconstrained — the Critical is an indicator, never a graded hygiene verdict (#213/#220). RE-VERIFIED 2026-07-31 (#1473's 'was any existing row passing for the wrong reason?' check, run rather than inherited): identical — B (89/100), 3 indicators, the same 2 public.tenants rows loud.",
  },
  {
    slug: "proposit",
    mustNotScoreF: false,
    mustRaiseLoudIndicator: true,
    why: "The other don't-stay-quiet case: world-readable invitation tokens (#214 Critical). Measured 2026-07-15: 1 High RLS indicator on organisation_invitations — the very table the Critical is about. RE-MEASURED 2026-07-28 (#1473): grade C (77/100), 2 graded (1 Critical/High), 8 indicators of which 7 are loud — the organisation_invitations policy row is still first, the other six are SECURITY DEFINER caller-authorization reviews added since. Still passing for the right reason. RE-VERIFIED 2026-07-31 (#1473, re-cloned and re-scanned rather than inherited): identical — C (77/100), 8 indicators of which 7 loud, organisation_invitations still first.",
  },
  // #934: the first LARGE repo in this gate — the invariant had only ever been scored against
  // starter kits, and carbon is the target that broke it at scale (F (0/100), every Critical a
  // placeholder credential in self-hosting docs / example docker-composes).
  {
    slug: "carbon",
    // #996 (the #934 remainder): flipped to true on a fresh measurement, not on the recorded
    // numbers. Re-measured 2026-07-24 pre-change: F (0/100), graded set 11 High + 1 Low — the 11
    // Highs were 7 harvey-permissive-cors bare-wildcard hits, all intended-public endpoints
    // (OAuth .well-known discovery metadata — RFC 8414 REQUIRES public readability — an MCP
    // endpoint, a public file route, the documented Supabase edge-function corsHeaders idiom),
    // 3 registry GHA workflow findings (curl|sh ×2, run-shell-injection ×1), 1 postMessage
    // wildcard. Post-change (same day, same pin): the CORS-bare and postMessage classes route
    // non-grading informational, the GHA findings route to the non-grading CI/CD pipeline
    // hygiene section — measured grade A (97/100), graded set 1 Low, all 11 former Highs still
    // fully reported in the free output.
    mustNotScoreF: true,
    // No M1 semantic pass and no dynamic tier has ever run against carbon (securityVerdict: NOT
    // ASSESSED), so the indicator posture is unasserted — scoreFreeTierExpectation emits an
    // explicit "not asserted" row for it.
    mustNotGradeDocContextCreds: true,
    why: "#934's scale case: a professionally-maintained ERP whose self-hosting docs/contrib/dev-compose surface drew 14 'Critical' placeholder credentials and an F (0/100). The weekly assertions: the reclassification invariant (those hits stay REPORTED informational and OUT of the graded set) and, since #996, mustNotScoreF — measured 2026-07-24 post-#996 at A (97/100), graded set 1 Low (unpinned deps); the former 11 Highs (7 bare-wildcard CORS, 3 GHA workflow, 1 postMessage) are non-grading but still reported. Scored against a real 4k-file repo, not only starter kits. #1344: RE-MEASURED 2026-07-27 at C (74/100), graded set 2 High + 1 Low. The F (0/100) this run started from was 21 High 'Slopsquatted/hallucinated dependency' rows on carbon's OWN @carbon/* workspace packages — #1231 widened the registry existence check from the root manifest to every workspace member, and a member is resolved from inside the repo, so the registry 404s on it; #1344 excludes workspace-internal names and discloses them in SUP-SCOPE-00. The 2 residual Highs are NOT false positives and are deliberately left graded: #1210's Supabase `.eq()` sink correctly finds packages/database/supabase/functions/seed-company/index.ts scoping a service-role query on companyId AND userId taken straight from `req.json()`. The invariant this row asserts (must not score F) holds; the grade moving A -> C is a real new detection, not noise.",
  },
  // #1473 — the sixth member, and the one the invariant could not previously express. It is the
  // corpus's clearest known-vulnerable repo (two unauthenticated service-role Criticals, #774) and
  // it sat OUTSIDE this gate entirely because every value of `mustRaiseLoudIndicator` stated
  // something false about it. `mustBeLoud` is the field that fixed that, and this is its first
  // real user — until now it existed with a passing planted control and no corpus row, which is a
  // mechanism nothing exercises.
  {
    slug: "launch-mvp",
    // Deliberately NOT asserted, and not an oversight: this repo SHOULD grade badly. Asserting
    // "must not score F" here would be the #213 inversion in reverse.
    mustNotScoreF: false,
    // The promise, on the channel that actually carries it. MEASURED 2026-07-31 by cloning the pin
    // and running buildQuickScanReport(await runMechanicalScan({ dir })): grade F (51/100), graded
    // set 5 findings of which 4 are High, indicators 0 — reproducing #1473's original measurement
    // exactly. `mustRaiseLoudIndicator` is left unset on purpose; the "indicator posture" row then
    // says the loudness is asserted on the graded channel rather than calling this repo's tenancy
    // posture NOT ASSESSED, which would be false of a target disclosed twice (#168, #774).
    mustBeLoud: "graded",
    why: "#1473's separating case, and the reason `mustBeLoud` exists. MEASURED 2026-07-31 at the pinned commit 513a8f0: grade F (51/100), graded set 5 (4 High + 1 Low), indicators 0. Three of the four Highs are #1174's object-level-authz rows on app/api/user/delete/route.ts and app/api/email/send/route.ts — `tenant scope user_id is populated from the request` — i.e. the free tier surfaces #774's unauthenticated service-role account deletion as GRADED findings, at Confirmed confidence and category 'Broken access control', which is exactly why they never reach the review-tier indicator channel selectIndicators draws from. Under `mustRaiseLoudIndicator` all three values were false about this repo: true fails with 'STAYED QUIET' on a repo graded F, false asserts 'must not accuse a sound repo' about two unauth Criticals, undefined calls a twice-disclosed target NOT ASSESSED. The row passes because the graded channel is loud, and it would FAIL the day those three Highs stop firing — which is the regression this target was added to the corpus to catch (the same scan on the 2026-07-26 scanner emitted ZERO).",
  },
];

// Every free-tier expectation must name a target that is actually in the corpus, or nothing can
// ever clone and score it — the expectation becomes a promise no run can keep or break.
//
// At MODULE LOAD, beside the data, rather than in a consumer: corpus-drift's unscored guard scopes
// itself by slug to the targets a given run owns (#1586 — a `--shard` run owns a subset), and that
// scoping is only sound while this containment holds. Checked here, it holds for every consumer and
// fails before a run clones anything; checked in one CLI it would fire after the scan, and checked
// only by a test in another file it would be a cross-file coupling held together by a comment.
// Same posture, and the same reason, as FREE_RECALL_CORPUS's baseline check in free-recall-corpus.ts.
const orphanedFreeTierExpectations = FREE_TIER_EXPECTATIONS.filter((e) => !EXTERNAL_CORPUS.some((t) => t.slug === e.slug));
if (orphanedFreeTierExpectations.length > 0) {
  throw new Error(
    `free-tier expectation(s) name a target that is not in EXTERNAL_CORPUS, so no run can ever score them: ${orphanedFreeTierExpectations
      .map((e) => e.slug)
      .join(", ")}. Add the target to the corpus with a pinned commit, or drop the expectation — leaving it here silently costs the free tier a target.`,
  );
}

interface FreeTierRow {
  slug: string;
  check: string;
  pass: boolean;
  detail: string;
}

// #1473: the two channels a free scan can be loud on, measured separately so a row can say WHICH
// one carried the promise instead of implying both.
//
// The graded channel is loud on a Critical/High in the GRADED set, or on an F. Both, not just the
// grade: the grade is an arithmetic summary and a future re-weighting could move it off F while the
// same Criticals are still printed — the finding is the substance, the letter is the presentation.
//
// Deliberately NOT part of loudness: `report.informational` (#213 — seen, reported, non-grading by
// design) and the M6 handrolled rollup (#267). A target whose only signal is an informational note
// HAS stayed quiet in the sense this invariant means.
//
// Open product question, recorded rather than decided here (#1473): should a CONFIRMED
// object-level-authz finding ALSO appear in the indicator section? #220 frames indicators as
// UNCONFIRMED signals pointing at the deep scan, which argues no — a Confirmed row belongs in the
// graded set, which is where it is. Left as-is, and the invariant now measures the promise rather
// than the section, so the answer no longer changes whether a known-bad repo can be gated.
function measureLoudness(report: QuickScanReport): { graded: boolean; indicator: boolean; either: boolean; gradedHigh: number } {
  const gradedHigh = report.findings.filter((f) => f.severity === "Critical" || f.severity === "High").length;
  const graded = gradedHigh > 0 || report.grade === "F";
  const indicator = report.indicators.some((i) => i.severity !== "Info");
  return { graded, indicator, either: graded || indicator, gradedHigh };
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

  // #1473: the channel-agnostic promise. Scored FIRST because it is the one the product actually
  // sells; the indicator row below is a claim about one section of the output.
  if (expectation.mustBeLoud) {
    const loudness = measureLoudness(report);
    const fired = loudness[expectation.mustBeLoud === "either" ? "either" : expectation.mustBeLoud];
    rows.push({
      slug: expectation.slug,
      check: `must be loud on a known-vulnerable repo (${expectation.mustBeLoud} channel)`,
      pass: fired,
      // Both channels are named either way — a pass that does not say which channel carried it is
      // how a row starts passing for a reason nobody checked.
      detail: `${fired ? "" : "STAYED QUIET: "}graded channel ${loudness.graded ? "LOUD" : "quiet"} (grade ${report.grade} ${report.score}/100, ${loudness.gradedHigh} Critical/High of ${report.total} graded), indicator channel ${loudness.indicator ? "LOUD" : "quiet"} (${loud.length} non-Info of ${report.indicators.length})${fired ? "" : ` — the "${expectation.mustBeLoud}" channel carried nothing on a repo the corpus records as known-vulnerable`}`,
    });
  }

  // #934: an unasserted indicator posture (tenancy NOT ASSESSED for this target) is an explicit
  // passing row, never a silently-absent check.
  // #1473: the row now distinguishes the two reasons the indicator channel is unasserted. A target
  // carrying `mustBeLoud` HAS an asserted posture — just on another channel — and saying "NOT
  // ASSESSED" about it would be the false statement that kept launch-mvp out of this gate.
  if (expectation.mustRaiseLoudIndicator === undefined) {
    rows.push({
      slug: expectation.slug,
      check: "indicator posture",
      pass: true,
      detail: expectation.mustBeLoud
        ? `indicator channel not asserted for this target — its loudness is asserted on the "${expectation.mustBeLoud}" channel above (#1473); ${loud.length} non-Info indicator(s) observed`
        : `not asserted — this target's tenancy posture is NOT ASSESSED (no M1 semantic/dynamic pass), so neither "must raise" nor "must not accuse" can honestly be scored; ${loud.length} non-Info indicator(s) observed`,
    });
  } else {
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
  }

  // #934: the doc-context credential invariant, two-sided (see FreeTierExpectation). Graded rows
  // must carry none; the informational section must still carry them — the pinned carbon tree HAS
  // placeholder creds in its docs/contrib/dev-compose surface, so zero reported means the detector
  // regressed, not that the repo cleaned up (the tree is frozen at the pin).
  if (expectation.mustNotGradeDocContextCreds) {
    const graded = report.findings.filter((f) => f.taxonomy === DOC_CONTEXT_CREDENTIAL_TAXONOMY);
    const reported = report.informational.filter((f) => f.taxonomy === DOC_CONTEXT_CREDENTIAL_TAXONOMY);
    const pass = graded.length === 0 && reported.length > 0;
    rows.push({
      slug: expectation.slug,
      check: "doc/example placeholder creds reported but never graded",
      pass,
      detail: pass
        ? `${reported.length} doc-context credential(s) in the informational section, 0 in the graded set`
        : graded.length > 0
          ? `CRIED WOLF: ${graded.length} doc-context credential(s) reached the graded set — #934's reclassification regressed`
          : "GONE DARK: 0 doc-context credentials reported on a pinned tree known to contain them — the detector (not the repo) changed; a lost finding is a recall regression, not a pass",
    });
  }

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

// The mutation tier's own finding taxonomies (src/mutation-scan.ts, src/stub-check.ts) — a closed
// set, unlike detect-static's growing test-intent family, so "M8" enumerates these and "M8-intent"
// matches the rest of the "M8 " prefix by exclusion (the same open/closed pattern as M5-knip/M5-slop
// above). Because the M8-intent bucket is defined by exclusion, EVERY mutation-tier taxonomy must be
// listed here or it silently leaks into M8-intent: #940 — the #932 "Root-workspace test suite not
// reachable per-app" measurement-gap and #503's "Suite fails unmutated dry run" both landed without
// this set being updated, so documenso's M8 measurement-gap scored 0 as M8 and inflated M8-intent to
// 2. When mutation-scan/stub-check add a taxonomy, add it here too.
// #1100: found the same #940 gap recurring — #1076's noCoverageFindings ("M8 — Module has no
// mutation test coverage") landed without this set being updated either. Fixed inline alongside
// #1100's own new taxonomy (vacuousTestFindings) rather than left for a future drift run to hide.
const M8_MUTATION_TAXONOMIES = new Set([
  "M8 — No automated test suite",
  "M8 — Survives implementation deletion",
  "M8 — Denial/boundary path untested",
  "M8 — Root-workspace test suite not reachable per-app",
  "M8 — Suite fails unmutated dry run (env-fragile tests)",
  "M8 — Module has no mutation test coverage",
  "M8 — Vacuous test (executes code, kills zero mutants)",
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
  // #1459: the M9 boundary pass (src/detectors/app-router.ts) delivers its authorization findings
  // under an `M1 —` taxonomy BY DESIGN — #221 routes a no-auth server mutation to the M1
  // authorization class — while every M9 baseline is keyed on the `M9 ` prefix and the manifest had
  // no `M1` key at all. So those rows were produced by an M9 detector and scored by NO baseline:
  // MEASURED 2026-07-28, 125 of them across this corpus (carbon 113, inbox-zero 5, tanstack-com 6,
  // proposit 1), and gutting the TanStack adapter's `collectServerFns` moved no number in the whole
  // manifest. This key closes that hole. It is deliberately NOT "everything under M1 —": the
  // migration/RLS passes emit `M1 — Multi-tenant security` from an entirely different tier that
  // this drift job does not measure, and sweeping those in would silently merge two measurements.
  // Matched by structure rather than by a hard-coded noun list, because the noun is per-framework
  // ("Server Action" / "route action" / "server function") and a new adapter adds another; the
  // `#1459 M1-boundary covers every M1 taxonomy the boundary pass emits` test in calibration.test.ts
  // runs the real detector over the M9 fixtures and fails if any emitted `M1 —` row escapes this
  // rule — the #940 lesson (a taxonomy landing without its bucket being updated) made executable.
  if (module === "M1-boundary") {
    return taxonomy.endsWith(" missing authorization check") || taxonomy.startsWith("M1 — Client-supplied owner id");
  }
  return taxonomy.startsWith(`${module} `);
}

// #483: M6-indicator findings are ALL severity "Info" by construction (#267's non-grading
// ruling) — excluding Info the way every other module does would score this baseline's `counted`
// as 0 on every target forever, making the drift check permanently unable to fail. Every match
// counts here regardless of severity.
//
// Exported (not just counted) so a drift can be EXPLAINED, not just sized (#1564): the
// same filtered list that decides `actual` is what explainDrift below diffs against a prior run's
// snapshot to name which rows moved.
export function countedFindingsFor(findings: Finding[], module: string): Finding[] {
  const includeInfo = module === "M6-indicator";
  return findings.filter((f) => moduleMatches(f.taxonomy, module) && (includeInfo || f.severity !== "Info"));
}

function countedFor(findings: Finding[], module: string): number {
  return countedFindingsFor(findings, module).length;
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
// "did not run" disclosures (knip's #223 M5-00, mutation-scan's #224 M8-00, jscpd's #505/#931 M4-99)
// are NOT evidence the module now runs — they are the tool reporting it still couldn't — so they
// don't count as output. (M4-00, by contrast, is a REAL small-clone disclosure counted in totals,
// not a did-not-run sentinel — it must not be listed here.)
const DID_NOT_RUN_SENTINELS = new Set(["M5-00", "M8-00", "M4-99"]);

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

// Issue #1564: `scoreExternalBaseline` says a count moved; it does not say WHICH findings
// moved. Both 2026-07-30 drifts (carbon M7 -1, M5-slop -653 across ten targets) were resolved only
// by a human cloning the target and diffing the finding sets by hand — the run already computes the
// CURRENT finding set (`current`, the same list `countedFor` filters to reach `actual` above); what
// it does NOT hold is the finding set the PRIOR baseline run counted — only that run's bare integer
// was ever kept (`ModuleBaseline.counted`/`.total`), never its rows. So a true added/removed split
// needs a prior run's row-level output, which corpus-drift.ts's `--baseline-findings` flag supplies
// from a PREVIOUS run's own `--json` output (a file already produced for other reasons — the CI
// scorecard artifact) — never a second scan of this run. When no prior snapshot is available
// (`baseline` undefined: the first run ever, or a local ad-hoc run with no flag passed), the honest
// fallback is `current` itself — the module's present-day findings — disclosed as exactly that
// rather than silently printing an empty added/removed pair that would read as "nothing to explain".
export interface DriftFindingRow {
  location: string;
  taxonomy: string;
  severity: Severity;
}

export interface DriftExplanation {
  hasBaseline: boolean;
  added: DriftFindingRow[];
  removed: DriftFindingRow[];
  // Always populated with the module's current counted findings — the fallback rendering when
  // hasBaseline is false, and available either way so a caller never has to re-derive it.
  current: DriftFindingRow[];
}

function toDriftRow(f: Finding): DriftFindingRow {
  return { location: f.location, taxonomy: f.taxonomy, severity: f.severity };
}

// Findings carry no stable cross-run id (M9's #1461 note above shows two "identical-looking" rows
// can be genuinely different findings) — location + taxonomy is the same identity a human diffing
// two finding lists by hand would use, and is exactly what #1509's carbon incident named
// ("packages/react/src/MultiSelect.tsx:153").
function driftRowKey(f: Finding): string {
  return `${f.location} ${f.taxonomy}`;
}

export function explainDrift(module: string, current: Finding[], baseline: Finding[] | undefined): DriftExplanation {
  const currentSet = countedFindingsFor(current, module);
  if (!baseline) {
    return { hasBaseline: false, added: [], removed: [], current: currentSet.map(toDriftRow) };
  }
  const baselineSet = countedFindingsFor(baseline, module);
  const currentKeys = new Set(currentSet.map(driftRowKey));
  const baselineKeys = new Set(baselineSet.map(driftRowKey));
  return {
    hasBaseline: true,
    added: currentSet.filter((f) => !baselineKeys.has(driftRowKey(f))).map(toDriftRow),
    removed: baselineSet.filter((f) => !currentKeys.has(driftRowKey(f))).map(toDriftRow),
    current: currentSet.map(toDriftRow),
  };
}
