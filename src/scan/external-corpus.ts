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

import type { Finding } from "../findings.js";

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
  modules: Partial<Record<"M4" | "M5" | "M7" | "M8" | "M9" | "M10", ModuleBaseline | ModuleNotRun>>;
}

export function isNotRun(m: ModuleBaseline | ModuleNotRun): m is ModuleNotRun {
  return "reason" in m;
}

// knip needs the TARGET's own node_modules to resolve its config imports (CLAUDE.md's M5 row);
// none of the six are vendored with deps, so M5 is uniformly not-run here rather than falsely 0.
const M5_NEEDS_INSTALL: ModuleNotRun = {
  reason: "knip needs the target's own `npm install` to resolve config imports — not run in the source-only sweep (CLAUDE.md M5 prereq). Confirmed live: quality-scan emits its M5-00 'did not run' finding (#223) rather than a silent zero.",
};

// tools/pii-classify.mjs takes a live DB (SUPABASE_DB_URL) or an information_schema-shaped column
// list; it has no "point it at a migrations dir" CLI path, so M10 on these targets was a manual
// classifier pass over the schema, not a reproducible command. Recorded as not-run for drift
// purposes, with the must-not-miss columns asserted directly in external-corpus.test.ts instead.
const M10_NEEDS_SCHEMA_INPUT: ModuleNotRun = {
  reason: "M10 has no static-schema CLI entry point (tools/pii-classify.mjs wants SUPABASE_DB_URL or a column list) — classifier behavior on this target's real columns is asserted in external-corpus.test.ts instead. Wiring a schema-file path is tracked as a follow-up.",
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
      M4: { counted: 203, total: 203, note: "5.27% (2749/52165 lines), 203 clone clusters. Was reported 9.75%/199 clones pre-#232; the drop is that fix excluding generated/demo paths, NOT the repo changing. Per #232 ~75% of what remains is genuine per-entity copy-paste (CRUD forms, per-entity tool/store/service files) — the corpus's strongest real M4 signal and a factory-refactor case." },
      M5: M5_NEEDS_INSTALL,
      M7: { counted: 49, total: 79, note: "30 of the 79 are the exhaustive-deps class #230 demoted to Info (~0 real), leaving 49 counted. The real vein is 26 'Unbounded select' on growable request-path lists (low-sev latent scalability). Residual FP tail still counted: 5 inline-literal, 4 context-value-recreated, 2 index-key — the micro-render shapes #230 judged ~0% real (see follow-up)." },
      M8: { counted: 1, total: 1, note: "Harness but effectively no suite: `vitest run` script with a single *.test.* file at this commit. #224's zero-coverage finding is the expected M8 output, not a skip." },
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
      M4: { counted: 13, total: 13, note: "5.2% (309/5947 lines), 13 clusters — down from the sweep's 6.13%/22 clones now #232 excludes `types_db.ts` (Supabase codegen was ~50% of this repo's clones)." },
      M5: M5_NEEDS_INSTALL,
      M7: { counted: 2, total: 3, note: "One of the smallest surfaces in the corpus: 2 raw <img> + 1 Info exhaustive-deps. A good FALSE-POSITIVE regression guard — a well-maintained Vercel example should stay near-silent; a jump here means a new over-match." },
      M8: { counted: 0, total: 0, note: "No test script and zero *.test.*/*.spec.* files at this commit — #224's zero-coverage M8 finding is the expected output. `counted: 0` is a MEASURED absence of tests, not a module skip." },
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
      M4: { counted: 90, total: 90, note: "4.93% (1148/23283 lines), 90 clusters. Per #232 the real signal is the API-handler envelope (a `createHandler` extraction candidate), lower severity than proposit's." },
      M5: M5_NEEDS_INSTALL,
      M7: { counted: 17, total: 17, note: "Includes the corpus's one genuine middleware stall ('Fetch in middleware hot path') — one of the two real request-path finds #230 kept. The 9 inline-literal + 3 index-key are the residual micro-render tail." },
      M8: { counted: 8, total: 8, note: "Best-tested target in the corpus: real `jest` script + 8 test files at this commit (the sweep also noted playwright). The M8 upper reference point — regressions elsewhere are judged against this." },
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
      M4: { counted: 6, total: 6, note: "0.35% (11/3167 lines), 6 clusters — smallest target; the sweep's 2.95% was the pre-#232 denominator." },
      // The one target small enough (13 deps) to `npm install` cheaply, so M5 DID run here.
      M5: { counted: 1, total: 1, note: "Ran (target `npm install --ignore-scripts` succeeded): 0 unused files, 2 unused exports rolled into one M5-01 finding. REAL, and security-weighted — `lib/security/guards.ts` exports requireTenantAccess/requireTenantAdmin and NOTHING calls them, on the same repo whose self-join Critical (#217) is a missing-authz bug. #226's security cross-link firing on real code: the dead guard IS the vulnerability's fingerprint." },
      M7: { counted: 0, total: 0, note: "MEASURED zero — a 3.1k-line repo with no perf surface. A useful floor: any M7 finding appearing here is almost certainly a new over-match." },
      M8: { counted: 0, total: 0, note: "One hand-rolled `test/rls.test.mjs` run via `node --test`, no *.test.ts/spec files and no Stryker config — mutation-scan cannot run; #224's zero-coverage finding is the expected M8 output." },
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
      M4: { counted: 11, total: 11, note: "1.35% (211/15684 lines), 11 clusters — the sweep's headline '13.3%, highest in the corpus' was almost entirely `monero/patches/**` whole-file fork-mirrors. #232's vendored-path exclusion is what closed that ~12-point gap; this target is the regression guard for it." },
      M5: M5_NEEDS_INSTALL,
      M7: { counted: 3, total: 4, note: "1 unbounded select + 1 index-key + 1 state-sprawl counted, 1 exhaustive-deps demoted to Info." },
      M8: { counted: 0, total: 0, note: "No test script and zero test files at this commit — #224's zero-coverage M8 finding expected." },
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
      M4: { counted: 28, total: 28, note: "1.15% (318/27617 lines), 28 clusters — the sweep's 499-line identical `database.types.ts` copy is now excluded by #232." },
      M5: M5_NEEDS_INSTALL,
      M7: { counted: 22, total: 23, note: "Includes the corpus's other genuine request-path stall ('Blocking sync I/O in request handler' — the execSync-on-a-/version-route case #230 kept). The 11 inline-literal + 6 index-key + 2 context-value are the residual micro-render tail." },
      M8: { counted: 3, total: 3, note: "`turbo test` script + 3 test files at this commit — a partial suite, between boxyhq and the zero-test targets." },
      M9: { counted: 2, total: 2, note: "2 'Accidental dynamic rendering'." },
      M10: M10_NEEDS_SCHEMA_INPUT,
    },
  },
];

interface DriftRow {
  slug: string;
  module: string;
  expected: number;
  actual: number;
  drift: number;
  pass: boolean;
  detail: string;
}

function countedFor(findings: Finding[], module: string): number {
  return findings.filter((f) => f.taxonomy.startsWith(`${module} `) && f.severity !== "Info").length;
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
