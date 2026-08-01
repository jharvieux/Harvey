// REAL-CODE app-layer source-detector recall (#960, the remainder of #945). The scored gate
// (src/scan/source-recall.ts) answers "how much of the request→sink source-detector answer key
// fires" against PLANTED targets/calibration fixtures — code written to teach the detectors. That
// is a real number, but it is scored on our own fixtures; docs/design/source-detector-recall.md's
// own "Honest scope" section names the complementary tier as unmeasured: real, disclosed
// vulnerabilities in REAL third-party code, not code we wrote.
//
// This module is that complementary answer key. Each entry is a genuine, already-disclosed
// vulnerability (a filed responsible-disclosure GitHub issue in THIS repo, cross-linked below) in
// one of the SIX repos external-corpus.ts already pins by commit for the M4/M5/M6/M7/M8/M9/M10
// quality-drift baselines (#222/#263) — reusing the SAME "manifest, not vendored fixtures" doctrine
// that file documents: several of these repos ship no LICENSE (all-rights-reserved), so the only
// safe way to measure against them is to CLONE ON DEMAND (cloneAtPin, already built for
// corpus-drift.ts) and run the scanner, never to copy their source into this repo.
//
// MEASURED 2026-07-24, by actually cloning each pin and running runMechanicalScan against it (not
// assumed from the disclosure text): all three entries below are CURRENTLY UNCAUGHT — a real
// recall gap, not a placeholder. Each entry's note records WHY, because the reason is itself the
// finding:
//   - proposit's invitation-accept BOLA is a `.insert()` trusting a Server-Action PARAMETER
//     (`userId`), not a request/`.eq()`-filtered read — bola-owner.ts's pattern (service-rooted
//     `.eq(<ownership col>, <request-rooted value>)`) does not cover an insert whose tainted value
//     arrives as a function argument rather than a query filter.
//   - saas-lite's open redirect is a genuine request→sink taint flow, but the source and the sink
//     are in DIFFERENT PACKAGES of a Turborepo monorepo (packages/supabase/src/auth-callback.
//     service.ts's `searchParams.get('next')` returns to apps/web/app/auth/callback/route.ts's
//     `redirect(nextPath)` two imports away) — beyond the same-file/same-function taint scope
//     every current open-redirect rule assumes.
//   - subscription-payments' client-trusted trial length: CAUGHT since #1373, and this bullet used
//     to be the third standing example of a gap that had already closed. It said the shape needs
//     "should this field be re-read server-side?" business context and that no AST pattern separates
//     the vulnerable call from a benign one on syntax alone, citing the b14/m9-authz corpus as
//     corroboration — which was one guess quoted in two files, the exact laundering shape #1033
//     warns about, since that note was the ORIGIN of the claim rather than an independent check.
//     RE-MEASURED 2026-08-01 (#1684): semgrep 1.164.0 with src/scan/rules/semgrep/auth.yml over the
//     pinned clone fires `harvey-client-trusted-price` at utils/stripe/server.ts:69 and :76 — the
//     two lines P-REAL-SUBPAY-CLIENT-TRIAL's note names. What unlocked it was the RPC contract, not
//     business context: a `"use server"` export is an endpoint, so its parameters are client-
//     supplied by construction. The m9-authz header carrying the superseded sentence is corrected
//     in the same change.
//
// A recall gap is the measurement, not a gate failure (same discipline as the planted corpus's
// "none"-tier entries; source-recall.ts's own last gap, P-HOST-HEADER-URL, was closed by #1366 on
// 2026-07-31, so that half of this sentence is history, not a live example) — this file's number is expected
// to be low today. Its value is turning "real code is presumably harder" from an assumption into a
// measured, itemized, re-testable claim, and giving each gap a name a future detector change can
// close and re-measure against.
//
// Kept SEPARATE from CORPUS (calibration.ts) and from SOURCE_TIER_IDS (source-recall.ts) rather
// than merged in: both of those score a single shared Finding[] from ONE scan of ONE directory
// (targets/calibration); these entries each need their OWN clone of a DIFFERENT repo, so they are
// scored per-target and aggregated (mergeRealSourceRecall), never blended into the planted-fixture
// number — the same "three numbers, never blended" discipline #868 already requires.

import type { Finding } from "../findings.js";
import { buildCoverageMatrix, type CoverageMatrix } from "./calibration.js";
import type { CorpusEntry } from "./calibration/types.js";
import { detectionMetrics, type DetectionMetrics } from "./detection-metrics.js";

interface RealSourceRecallTarget {
  slug: string; // matches external-corpus.ts's slug for the same repo, where one is pinned there
  repo: string; // owner/name on GitHub
  commit: string; // pinned — fetched by exact commit, never HEAD (see corpus-clone.ts)
  disclosureIssue: number; // this repo's own responsible-disclosure issue documenting the finding
  entries: CorpusEntry[];
}

export const REAL_SOURCE_RECALL_TARGETS: RealSourceRecallTarget[] = [
  {
    slug: "proposit",
    repo: "JakeLeoDev/proposit",
    commit: "82838cef3606a176c4bca0af0587c5ea6b08d3a0",
    disclosureIssue: 214,
    entries: [
      {
        id: "P-REAL-PROPOSIT-BOLA-INVITE",
        kind: "positive",
        module: "REAL",
        cls: "invitation acceptance trusts a client-supplied userId for a service-role insert",
        location: "lib/actions/invitation-actions.ts",
        // #327 lesson applied: this file ALSO draws harvey-csrf-missing/harvey-server-action-noauth
        // (both OUT-of-scope absence-of-control classes, both co-located at the same line) — a bare
        // location match would have scored those as a false "caught". match: pins this entry to an
        // ACTUAL bola-owner/mass-assignment class landing on the file, not just any finding there.
        match: ["bola", "mass-assign"],
        note: "#214 High: acceptInvitationAction(token, userId) inserts { user_id: userId } into organisation_users via a service-role client (RLS bypassed) with no auth.uid()/email match against the caller's own session — userId is a Server Action parameter the CLIENT supplies. MEASURED 2026-07-24: uncaught (the file DOES draw harvey-csrf-missing + harvey-server-action-noauth, both absence-of-control classes explicitly OUT of the source-recall answer key — not this vulnerability). bola-owner.ts's pattern is a service-rooted `.eq(<ownership col>, <request-rooted value>)` READ filter; this is an `.insert()` whose tainted value is a function parameter, not a query filter — a real shape our BOLA/mass-assignment rules do not yet reach.",
      },
    ],
  },
  {
    slug: "saas-lite",
    repo: "makerkit/nextjs-saas-starter-kit-lite",
    commit: "37def9c20b01a3514cf69b5b3383bef3e5ffbcb9",
    disclosureIssue: 219,
    entries: [
      {
        id: "P-REAL-SAASLITE-OPEN-REDIRECT",
        kind: "positive",
        module: "REAL",
        cls: "auth-callback redirects to an unvalidated request-controlled `next` path across a package boundary",
        location: "apps/web/app/auth/callback/route.ts",
        match: ["open-redirect", "open redirect"],
        note: "#219 Low: packages/supabase/src/auth-callback.service.ts's exchangeCodeForSession reads searchParams.get('next') and returns it verbatim as nextPath, with no relative-path/host validation; apps/web/app/auth/callback/route.ts calls redirect(nextPath) two imports later. `GET /auth/callback?next=https://evil.com` redirects off-site. MEASURED 2026-07-24: uncaught — the taint crosses a MONOREPO PACKAGE boundary (source in @kit/supabase, sink in the app), beyond same-file/same-function taint scope.",
      },
    ],
  },
  {
    slug: "subscription-payments",
    repo: "vercel/nextjs-subscription-payments",
    commit: "bdd0813206e47e6b218d42f15a7976c8a0d3c3eb",
    disclosureIssue: 215,
    entries: [
      {
        id: "P-REAL-SUBPAY-CLIENT-TRIAL",
        kind: "positive",
        module: "REAL",
        cls: "checkout trusts a client-supplied price object to derive the subscription trial length",
        location: "utils/stripe/server.ts",
        match: ["payment-amount", "client-payment", "trial"],
        note: "#215 Medium: checkoutWithStripe (utils/stripe/server.ts:69,76 + utils/helpers.ts:52-68) trusts the client-supplied `price` object and re-derives trial_end from price.trial_period_days — a client can request an arbitrarily long free trial (the charge amount itself is not forgeable; Stripe validates the price id). MEASURED 2026-07-24: uncaught. CAUGHT at review tier since #1373 (MEASURED 2026-07-31, `validate-source-recall --real` 0/3 -> 1/3) by `harvey-client-trusted-price`. Its planted twin (P-CLIENT-PAYMENT-AMOUNT, b14-applogic.entries.ts) is a literal `amount: req.body.amount` grep shape; this real call has no req.* literal at the call site at all, which is what made it look unreachable. The key was not taint tracing but the RPC contract: a `\"use server\"` module's exported function is an endpoint, so `price` — an ordinary function PARAMETER — is client-supplied by construction. The m9-authz.entries.ts header carried the superseded claim ('the price/trial variant needs \"should this field be re-read server-side?\" business context no AST pass has') until #1684 corrected it on 2026-08-01, re-measuring against this same clone: `harvey-client-trusted-price` fires at utils/stripe/server.ts:69 and :76.",
      },
    ],
  },
];

// Scores ONE target's findings (from a scan of ITS OWN clone) against ITS OWN entries. Reuses
// buildCoverageMatrix — same scoring model as source-recall.ts and validate-calibration.ts, over a
// narrower, single-target corpus.
export function scoreRealSourceRecallTarget(findings: Finding[], target: RealSourceRecallTarget): CoverageMatrix {
  return buildCoverageMatrix(findings, target.entries);
}

interface RealSourceRecallSummary {
  positivesTotal: number;
  positivesCaught: number;
  positivesCaughtHigh: number;
  negativesTotal: number;
  negativesCleared: number;
  metrics: DetectionMetrics;
}

// Aggregates per-target matrices into ONE real-code recall number. Each target is scored against
// its OWN clone's findings (a positive from one repo can never be "relevant" to another repo's
// scan), so aggregation is a plain sum of counts, then a fresh detectionMetrics() over the summed
// confusion — never an average of percentages, which would let a 1-entry target's 0%/100% swing
// the total disproportionately.
export function mergeRealSourceRecall(matrices: CoverageMatrix[]): RealSourceRecallSummary {
  const sum = (f: (m: CoverageMatrix) => number): number => matrices.reduce((acc, m) => acc + f(m), 0);
  const positivesTotal = sum((m) => m.positivesTotal);
  const positivesCaught = sum((m) => m.positivesCaught);
  const negativesTotal = sum((m) => m.negativesTotal);
  const negativesCleared = sum((m) => m.negativesCleared);
  return {
    positivesTotal,
    positivesCaught,
    positivesCaughtHigh: sum((m) => m.positivesCaughtHigh),
    negativesTotal,
    negativesCleared,
    metrics: detectionMetrics({
      tp: positivesCaught,
      fn: positivesTotal - positivesCaught,
      fp: negativesTotal - negativesCleared,
      tn: negativesCleared,
    }),
  };
}
