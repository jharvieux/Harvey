// M8 batch (#72, spec §M8) — StrykerJS mutation-testing corpus. M8-P-TAUTOLOGICAL is the
// planted weak test (happy-path-only, single assertion) that leaves surviving mutants on its
// source; M8-N-STRONG is the planted strong test (exhaustive over its truth table) that must
// NOT land on the false-confidence list. Fixtures: targets/calibration/test-quality/ — its own
// isolated npm project (vitest.config.ts, stryker.config.json, package.json), deliberately
// separate from targets/calibration/package.json, whose react-supabase-helpers dependency is a
// nonexistent slopsquat fixture that makes `npm install` fail at that level (see that
// package.json's description).
//
// mutation-scan.ts's summarizeMutationReport() returns a MutationSummary, not a Finding[], so —
// like M10's classifier output — these entries aren't scored by buildCoverageMatrix today; they
// document the answer key for the recorded-report assertions in src/mutation-scan.test.ts's "M8
// calibration corpus" block, which IS the Layer-1 gate for the Stryker pair and runs in
// `pnpm verify`. module: "M8" keeps them out of validate-calibration.ts's `module === undefined`
// filter regardless, so they can't spuriously break the M1 live gate.
//
// #427 parity: a second real M8 shape follows — the #373 stub-check (survives-implementation-
// deletion) pair M8-P-DELETION-SURVIVING / M8-N-DELETION-KILLED, whose gate is
// src/stub-check.test.ts (an EXECUTED transpile-and-run, not a recorded verdict). #1100 adds a
// THIRD shape, M8-P-VACUOUS-STRYKER (the testFiles/coveredBy/killedBy join), gated by
// src/mutation-scan.test.ts alongside the mutation pair. Three positives spread across the
// mutation, deletion, and vacuous-test-join shapes make the census fail on a partial M8
// regression in any one of them.

import type { CorpusEntry } from "./types.js";

export const m8Entries: CorpusEntry[] = [
  {
    module: "M8",
    id: "M8-P-TAUTOLOGICAL",
    kind: "positive",
    cls: "Weak test (happy-path-only / tautological) — false confidence",
    location: "discount.ts",
    match: ["denial/boundary path untested"],
    expectedTier: "high",
    note: "test-quality/discount.ts, covered only by discount.tautological.test.ts's single happy-path assertion. Live Stryker 9.6.1 run: 4 Survived + 2 NoCoverage of 15 mutants (60.0% mutation score) — ConditionalExpression/EqualityOperator mutants on the non-member branch, the negative-total guard, and the <100 boundary all survive because the weak test never exercises them.",
  },
  {
    module: "M8",
    id: "M8-N-STRONG",
    kind: "negative",
    cls: "Strong test — must NOT land on the false-confidence list",
    location: "authz.ts",
    note: "test-quality/authz.ts, covered by authz.strong.test.ts's exhaustive 2x2 role/action truth table (admin/member x read/delete, including the denial path). Live Stryker 9.6.1 run: 10/10 mutants Killed (100.0% mutation score) — zero surviving mutants, so it correctly clears the false-confidence list.",
  },

  // #427 parity: a SECOND real M8 shape — the #373 stub-check (survives-implementation-deletion),
  // distinct from the Stryker mutation shape above. Its gate is src/stub-check.test.ts, which
  // EXECUTES the covering suite against the real and stubbed source (not a recorded verdict). Two
  // positives across the two shapes let M8 fail on a partial regression (one shape breaks, the
  // other still fires), where the single Stryker positive fails only on a total outage.
  {
    module: "M8",
    id: "M8-P-DELETION-SURVIVING",
    kind: "positive",
    cls: "Test survives implementation deletion (calls the subject, asserts nothing)",
    location: "audit-log.ts",
    match: ["logauditevent"],
    expectedTier: "high",
    note: "test-quality/audit-log.ts, covered only by audit-log.deletion-surviving.test.ts, which calls logAuditEvent() but asserts nothing about the result. src/stub-check.test.ts stubs the body to `return undefined` and re-runs the covering suite by actual transpile-and-execute: the suite still passes, so stubSurvivalFindings emits an M8-01 (Survives implementation deletion) finding. Structurally dead coverage — a different defect from the Stryker weak-test shape.",
  },
  {
    module: "M8",
    id: "M8-N-DELETION-KILLED",
    kind: "negative",
    cls: "Weak-but-assertion-backed test — killed by deletion, must NOT land on the survival list",
    location: "discount.ts",
    match: ["applydiscount"],
    note: "test-quality/discount.ts, covered by discount.tautological.test.ts — the boundary that pins deletion-survival to STRUCTURAL deadness, not mere weakness. Stryker leaves survivors on it (M8-P-TAUTOLOGICAL), yet its single assertion DOES check applyDiscount's return value, so stubbing the body to `return undefined` turns the suite red (proven by execution in src/stub-check.test.ts's contrast case). It must clear the stub-survival list even though it is a weak test.",
  },

  // #1100: a THIRD real M8 shape — the testFiles/coveredBy/killedBy join (a vacuous-test
  // detector). Distinct from M8-P-TAUTOLOGICAL (leaves survivors on UNTESTED branches) and
  // M8-P-DELETION-SURVIVING (stub-check's deletion-survival, proven by execution): this one is a
  // test that DOES execute mutated code (real Stryker coveredBy) but kills zero mutants across
  // the whole run — "calls the subject, asserts nothing" surfaced from the mutation side rather
  // than the stub-check side. Its gate is src/mutation-scan.test.ts's "vacuousTestFiles /
  // vacuousTestFindings (#1100) — live Stryker capture" block (a recorded verbatim capture, same
  // convention as M8-P-TAUTOLOGICAL/M8-N-STRONG above), not buildCoverageMatrix.
  {
    module: "M8",
    id: "M8-P-VACUOUS-STRYKER",
    kind: "positive",
    cls: "Vacuous test (executes code via real Stryker coverage, kills zero mutants)",
    location: "vacuous.ts",
    match: ["kills zero mutants"],
    expectedTier: "high",
    note: "test-quality/vacuous.ts, covered only by vacuous.smoke.test.ts, which calls gradeScore(85) then asserts expect(true).toBe(true) — never inspecting the return value. Live Stryker 9.6.1 run (its own stryker.vacuous.config.json, kept separate from the discount.ts/authz.ts pair's config so that recorded result stays reproducible): 0/12 mutants Killed (0.0% mutation score) — the covering test appears in coveredBy for all 10 Survived mutants but in killedBy for none of them. vacuousTestFiles/vacuousTestFindings (src/mutation-scan.ts) flags vacuous.smoke.test.ts and emits an M8-06 finding.",
  },
];
