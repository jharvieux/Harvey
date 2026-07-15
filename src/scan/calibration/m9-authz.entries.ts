// #221 — server-side authorization & client-input-trust (broken function-level authz).
//
// The issue catalogued one class recurring four ways across the sweep. Only its first shape —
// a server action mutating by a client-supplied owner id — proved mechanically detectable at
// acceptable precision, and detectClientSuppliedOwnerId (src/detectors/app-router.ts) now
// covers it. The other two shapes stay semantic/paid-tier and are already seeded in the corpus:
//   - trusting client-supplied security-relevant values → P-CLIENT-PAYMENT-AMOUNT / P-CLIENT-
//     PRIV-HEADER (b14-applogic.entries.ts); the price/trial variant needs "should this field
//     be re-read server-side?" business context no AST pass has.
//   - permission checks present only in the UI → P-CLIENT-RENDER-AUTHZ / P-MW-SOLE-AUTHZ
//     (b15-nextjs-authz.entries.ts); needs whole-program route-vs-gate reasoning.
// See docs/design/corpus-roadmap-to-100.md §4a for the tier rationale.
//
// These entries carry `module: "M9"` because the detector runs in the static-detect AST pass
// (src/cli/static-detect.ts), NOT runMechanicalScan — the same arrangement M7/M10 use to stay
// out of validate-calibration.ts's `module === undefined` M1 gate, which would otherwise score
// them as spurious misses. The detector's own gate is app-router.test.ts, where the two
// negatives below are pinned as near-misses.

import type { CorpusEntry } from "./types.js";

// Each entry gets its OWN fixture file: all three share one taxonomy, so a single shared file
// would make every `match` keyword relevant to every entry and the negatives would collide with
// the positive's location (the whole-corpus ambiguity guard in calibration.test.ts catches this).
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
