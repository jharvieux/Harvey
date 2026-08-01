// #221 — server-side authorization & client-input-trust (broken function-level authz).
//
// The issue catalogued one class recurring four ways across the sweep. Its first shape — a server
// action mutating by a client-supplied owner id — was the first to become mechanical, and
// detectClientSuppliedOwnerId (src/detectors/app-router.ts) covers it.
//
// #1684, 2026-08-01 — THE OTHER TWO SHAPES ARE NO LONGER ONE STORY, and this paragraph used to tell
// them as one. As written it said both "stay semantic/paid-tier", and of the value half that it
// "needs 'should this field be re-read server-side?' business context no AST pass has". RE-MEASURED
// rather than reasoned about, and it is false:
//   - trusting client-supplied security-relevant values → MECHANICAL, at review tier, on all three
//     members. `pnpm exec tsx src/cli/validate-calibration.ts` (2026-08-01) prints PASS for
//     P-CLIENT-TRUSTED-ROLE, P-CLIENT-TRUSTED-PRICE (the price/trial member, harvey-client-trusted-
//     price, #1373), P-CLIENT-PAYMENT-AMOUNT and P-CLIENT-PRIV-HEADER, with N-SERVER-DERIVED-PRICE
//     — the same fields re-read server-side — cleared. It is not corpus-only either: semgrep
//     1.164.0 with src/scan/rules/semgrep/auth.yml over the pinned vercel/nextjs-subscription-
//     payments clone (bdd08132) fires harvey-client-trusted-price at utils/stripe/server.ts:69 and
//     :76 — the exact two lines src/scan/real-source-recall.ts records as this gap's real instance.
//     What made the shape reachable was not business context; it was the RPC contract, that a
//     `"use server"` module's exported function is an endpoint and its parameters are therefore
//     client-supplied by construction.
//   - permission checks present only in the UI → this half has since SPLIT too, and the paragraph
//     that named both its rows was true for one day. #1811 GRADUATED P-CLIENT-RENDER-AUTHZ to
//     `expectedTier: "review"` on detectClientRenderOnlyAuthz (src/detectors/app-router.ts).
//     P-MW-SOLE-AUTHZ is the one member still `expectedTier: "none"` with gapKind "measured-gap" —
//     planted, scanned, nothing of the class fired — OUTSTANDING WORK tracked on #1679.
// See docs/design/corpus-roadmap-to-100.md §4a for the original tier rationale; that document has
// NOT been re-read against the measurement above (docs are supervised for this batch), so treat its
// §4a as carrying the same superseded claim until someone checks.
//
// REASON: the middleware-sole-authorization check has no mechanical rule — P-MW-SOLE-AUTHZ was planted and scanned and nothing of the class fired, and the discriminating signal is cross-file (does a middleware.ts exist, and does its matcher actually cover this route), which nobody has built a pass for yet
// KIND: empirical
// PROVENANCE: MEASURED 2026-08-01 — `pnpm exec tsx src/cli/validate-calibration.ts` prints `GAP P-MW-SOLE-AUTHZ` and `No-mechanical-rule gaps (excluded from recall): 4/4 held — 3 by design, 1 measured-gap`. This block covered TWO rows until #1811 graduated P-CLIENT-RENDER-AUTHZ, and its falsifier tested only the graduated one, so it exited 0 and reasons-drift correctly reported STALE (run 30694879524) — half a reason had died and taken the whole claim's re-test with it. Narrowed to the row whose blocker holds; the graduated row's claim is deleted, not left to rot. New falsifier exercised both directions the same day: exit 1 as committed, exit 0 against a copy of the entry file with P-MW-SOLE-AUTHZ re-tiered to "review", exit 127 against a copy with the row absent.
// FALSIFIER: f=src/scan/calibration/b15-nextjs-authz.entries.ts; test -f "$f" || exit 127; grep -q 'id: "P-MW-SOLE-AUTHZ"' "$f" || exit 127; ! grep -q 'id: "P-MW-SOLE-AUTHZ".*expectedTier: "none"' "$f"
// TOUCHES: src/scan/calibration/b15-nextjs-authz.entries.ts
//
// It exits 0 on the RE-TIER rather than on a scan, deliberately and not as a proxy for convenience:
// since #1677 a mechanical rule reaching the row fails the graduation guard by name, so the row
// stops reading `none` the moment the class becomes detectable. The corpus tier is therefore a
// faithful reading of the world, and the check needs no scanner binaries in the daily reasons job.
// It is scoped to ONE row on purpose: a falsifier covering N rows dies the moment any ONE of them
// graduates, which is exactly how this block went stale.
//
// These entries carry `module: "M9"` because the detector runs in the static-detect AST pass
// (src/cli/static-detect.ts), NOT runMechanicalScan — the same arrangement M7/M10 use to stay
// out of validate-calibration.ts's `module === undefined` M1 gate, which would otherwise score
// them as spurious misses. The detector's own gate is app-router.test.ts, where every positive
// and negative below is pinned. (The pages/api surface of the same class is a SEPARATE pass that
// DOES run mechanically — src/scan/bola-owner.ts, scored via b15's P-BOLA-BODY-OWNER, #433. The
// surfaces are partitioned so a full audit never emits the same site from both probes.)
//
// #427 parity: the class is detected by ONE rule, but that rule has two configuration surfaces —
// MUTATION_PATTERN (insert/update/upsert/delete/rpc) and OWNERSHIP_COLUMN. Two positives
// exercising DIFFERENT surfaces (P-AUTHN-CLIENT-OWNER = update/user_id; P-AUTHN-CLIENT-OWNER-
// DELETE = delete/account_id) let the census fail on a PARTIAL regression of either surface,
// where a single positive fails only on a total outage. These are genuine distinct instances of
// the one real class, not fabricated new classes. This sentence used to end "— the other #221
// shapes stay semantic/paid-tier", the same superseded claim the header above corrects and the one
// PR #1683 flagged on 2026-07-31 and could not edit; RE-MEASURED 2026-08-01, the value shape is
// mechanical (`validate-calibration` prints `PASS P-CLIENT-TRUSTED-PRICE review`, N-SERVER-DERIVED-
// PRICE cleared) and the render shape is too (#1811), leaving P-MW-SOLE-AUTHZ as the only #221
// shape with no mechanical rule.
//
// #465 widening (operator ruling, 2026-07-17): the detector now also fires on the three shapes
// proposit's real instances take — bare `.eq("id", …)`, INSERT-value owner ids, and no-in-body-
// auth — but ONLY when the chain roots in the RLS-bypassing service/admin client (the measured
// precision boundary; on the RLS client the generic missing-auth finding owns the defect).
// MEASURED against proposit HEAD (286 source files): recall 3/3 on the #221-catalogued
// instances, 0 false positives; the RLS-client near-miss (updateOrganisationLogo) stays silent.
// The P-SVC-NOAUTH-* / N-* entries below pin those shapes; the no-auth positives also pin the
// #465 dedupe (the generic missing-auth finding is subsumed — one code defect, one finding).

import type { CorpusEntry } from "./types.js";

// Each entry gets its OWN fixture file: they share one taxonomy, so a single shared file would
// make every `match` keyword relevant to every entry and the negatives would collide with the
// positives' locations (the whole-corpus ambiguity guard in calibration.test.ts catches this).
export const m9AuthzEntries: CorpusEntry[] = [
  {
    id: "P-AUTHN-CLIENT-OWNER",
    kind: "positive",
    cls: "authenticated server action mutates rows scoped by a client-supplied owner id",
    module: "M9",
    location: "app/actions-owner.ts",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: `app/actions-owner.ts updateProfileName(): authenticates via getCurrentUser() and schema-parses its input, then updates .eq("user_id", userId) with the CLIENT's userId instead of currentUser.id — any signed-in user can rename any profile. Caught by detectClientSuppliedOwnerId at review tier (Likely): the AST proves the .eq() value roots in a parameter and that no session-vs-client comparison exists, but not that authorization is absent from code it can't see (a wrapper, middleware), so it is triage-tier, never free-count. Modelled on proposit's user-actions.ts (#221).`,
  },
  {
    id: "P-AUTHN-CLIENT-OWNER-DELETE",
    kind: "positive",
    cls: "authenticated server action deletes rows scoped by a client-supplied account id",
    module: "M9",
    location: "app/actions-delete.ts",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: `client-owner-id/positive-delete/app/actions.ts deleteAccount(): a SECOND real instance of the #221 class, distinct from P-AUTHN-CLIENT-OWNER's .update()/user_id shape — it exercises the DELETE verb and the account_id ownership column (both otherwise seen only on the negatives). It is N-AUTHN-OWNER-COMPARED minus its currentUser.id !== accountId guard, so that negative is exactly its boundary. Caught by detectClientSuppliedOwnerId at review tier; gated live by app-router.test.ts ("flags a second instance … delete verb and the account_id column"). Its purpose is PARITY (#427): two positives across different MUTATION_PATTERN/OWNERSHIP_COLUMN surfaces fail on a partial regression, where one positive fails only on a total outage.`,
  },
  {
    id: "P-SVC-NOAUTH-BARE-ID",
    kind: "positive",
    cls: "no-auth service-role mutation scoped by a bare client-supplied id",
    module: "M9",
    location: "app/actions-svc-bareid.ts",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: `app/actions-svc-bareid.ts updateUserProfile(): no auth call anywhere, the service-role client (RLS bypassed), and bare .eq("id", userId) with the CLIENT's userId picks the row — anyone can rename any user. The #465-widened bare-id shape, modelled on proposit's updateUserProfileAction (measured recall 3/3, 0 FP on proposit HEAD). Fires only on service-rooted chains; the RLS-client near-miss is N-RLS-CLIENT-BARE-ID. Also pins the #465 dedupe: the generic missing-auth finding for this action is subsumed by this more specific one.`,
  },
  {
    id: "P-SVC-NOAUTH-INSERT-OWNER",
    kind: "positive",
    cls: "no-auth service-role insert whose owner column value is client-supplied",
    module: "M9",
    location: "app/actions-svc-insert.ts",
    match: ["Client-supplied owner id"],
    expectedTier: "review",
    note: `app/actions-svc-insert.ts addMember(): no auth call, service-role client, and the new row's owner comes from the client (user_id: userId) — the caller says who the membership belongs to and nothing checks it. The #465-widened INSERT-value shape, modelled on proposit's acceptInvitationAction/createOrganisationAction. INSERT_OWNER_COLUMN restricts this shape to identity columns (user/owner/member/…): the client-chosen organisation_id on the same insert is deliberately NOT a hit. Near-miss: N-SVC-INSERT-SESSION-OWNER.`,
  },
  {
    id: "N-RLS-CLIENT-BARE-ID",
    kind: "negative",
    cls: "same bare-id syntax on the plain RLS client — policies still gate the write",
    module: "M9",
    location: "app/actions-rls-bareid.ts",
    match: ["Client-supplied owner id"],
    note: `app/actions-rls-bareid.ts updateOrganisationLogo(): identical no-auth + bare .eq("id", …) syntax as P-SVC-NOAUTH-BARE-ID but on the PLAIN (RLS-enforced) client — row policies still gate the write, so the widened shape stays silent (the service-root requirement is the measured precision boundary; proposit's updateOrganisationLogo is the real-world instance). The file's actual defect draws the generic missing-auth finding, which does not carry this entry's match keyword.`,
  },
  {
    id: "N-SVC-INSERT-SESSION-OWNER",
    kind: "negative",
    cls: "service-role insert whose owner id reads off the session",
    module: "M9",
    location: "app/actions-svc-insert-session.ts",
    match: ["Client-supplied owner id"],
    note: `app/actions-svc-insert-session.ts joinOrganisation(): identical service-role insert shape as the positive, but user_id reads off the session binding (user.id) — the caller can only add itself. Also pins INSERT_OWNER_COLUMN's boundary: the client-chosen organisation_id on the same insert is a container column, not an owner-identity column, and must not fire.`,
  },
  {
    id: "N-AUTHN-SESSION-OWNER",
    kind: "negative",
    cls: "mutation scoped by the session's owner id, not a client-supplied one",
    module: "M9",
    location: "app/actions-owner-session.ts",
    match: ["Client-supplied owner id"],
    note: `app/actions-owner-session.ts updateOwnProfileName(): identical imports, auth call, schema parse and .eq("user_id", …) mutation shape as the positive — the near-miss that pins the rule to the VALUE's origin rather than the shape. The id reads off currentUser.id, so collectSessionBoundNames marks it session-derived and nothing fires.`,
  },
  {
    id: "N-AUTHN-OWNER-COMPARED",
    kind: "negative",
    cls: "client-supplied owner id explicitly compared against the session's before mutating",
    module: "M9",
    location: "app/actions-owner-compared.ts",
    match: ["Client-supplied owner id"],
    note: `app/actions-owner-compared.ts closeOwnAccount(): the .eq("account_id", accountId) DOES read a client-supplied value — the literal shape the detector keys on — but currentUser.id !== accountId throws first, which IS the authorization check. hasOwnershipComparison clears it. Pins the FP behaviour a shape-only rule would get wrong.`,
  },
];
