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
// calibration corpus" block, which IS the Layer-1 gate for this batch and runs in `pnpm verify`.
// module: "M8" keeps them out of validate-calibration.ts's `module === undefined` filter
// regardless, so they can't spuriously break the M1 live gate.

import type { CorpusEntry } from "./types.js";

export const m8Entries: CorpusEntry[] = [
  {
    module: "M8",
    id: "M8-P-TAUTOLOGICAL",
    kind: "positive",
    cls: "Weak test (happy-path-only / tautological) — false confidence",
    location: "discount.ts",
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
];
