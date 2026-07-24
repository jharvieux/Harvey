// M1 tenant-scope/BOLA precision corpus (#896) — the labeled answer key for
// detectPrismaTenantScopeFindings (src/scan/prisma-tenant-scope.ts), scored by
// src/scan/heuristic-precision.ts alongside the M7/M8 heuristic corpora.
//
// WHY THIS EXISTS. M1's negatives were planted-clean fixtures we wrote ourselves — code that is
// clean the way WE expect clean to look. That does not test the harder case: third-party code
// whose entire purpose is correct tenant scoping, written in idioms we did not anticipate. If
// Harvey fires a tenant-scope finding on a library that exists specifically to enforce tenant
// scoping, that is a precision bug, and before this corpus nothing would have caught it.
//
// MEASURED, NOT ASSUMED (2026-07-23, `pnpm quick-scan` over three MIT clones — s1owjke/prisma-rls
// @3393442, zenstackhq/zenstack @ef0db7f, Errorname/prisma-multi-tenant @16f7bff):
//   - 1031 M1 tenant-scope findings across the three repos;
//   - ZERO of them in any library's shipping source — the detector was silent on all three
//     correct implementations, which is the result the issue asked for;
//   - ALL 1031 in test / e2e / example / playground / docs paths, where an ORM suite is by-id
//     reads and writes by construction. Every one is a false positive under docs/fp-rules.txt's
//     scope rule ("test / fixture / seed / dev-script code is out of scope").
// The non-shipping gate in prisma-tenant-scope.ts is the fix; re-scanning the same three clones
// afterwards measured 0 findings on all three. The negatives below are that result as fixtures.
//
// Each negative is a distilled shape, vendored WITH its upstream MIT notice in the fixture header
// (see each dir under src/detectors/__fixtures__/m1-tenant-scope/) — the issue's sanctioned form,
// since all three libraries are MIT.

import type { HeuristicEntry } from "./types.js";

const M1 = "M1" as const;

export const m1TenantScopeEntries: HeuristicEntry[] = [
  // --- POSITIVE: the class must still fire on shipping code, or the exclusions below are a
  // blinding rather than a precision fix.
  {
    module: M1,
    id: "M1TS-P-UNSCOPED-ROUTE",
    kind: "positive",
    cls: "By-id read/write with no tenant predicate, in a shipping route handler",
    taxonomy: "Object-level authorization gap: Prisma query filtered by primary key with no tenant scope",
    dir: "m1-tenant-scope/unscoped-shipping-positive",
    note: "findUnique + update filtered by params.id alone in app/api — the cross-tenant BOLA the detector exists for. Its presence is what makes the four negatives a measured precision number instead of a measured silence.",
  },

  // --- NEGATIVES: correct tenant-scoping implementations, and non-shipping code.
  {
    module: M1,
    id: "M1TS-N-EXTENSION-SCOPING",
    kind: "negative",
    cls: "Tenant scoping enforced by a Prisma client extension ($allOperations rewrites every where)",
    dir: "m1-tenant-scope/extension-scoping-negative",
    note: "s1owjke/prisma-rls's idiom. Confirmed clean 2026-07-23: quick-scan over the whole repo produced 0 findings in src/. The scope never appears as a column at a call site, so a detector reading 'no tenant column in the where clause' has to get this right by not matching the shape at all.",
  },
  {
    module: M1,
    id: "M1TS-N-POLICY-FILTER",
    kind: "negative",
    cls: "Access-control layer conjoining a compiled policy filter into every query",
    dir: "m1-tenant-scope/policy-filter-negative",
    note: "zenstackhq/zenstack's idiom — the by-id update is `idConditions AND policyFilter`. Confirmed clean 2026-07-23 over the full 1,295-file repo: 0 findings outside test paths.",
  },
  {
    module: M1,
    id: "M1TS-N-PER-TENANT-CLIENT",
    kind: "negative",
    cls: "Tenancy enforced by a per-tenant database connection, so queries carry no tenant column at all",
    dir: "m1-tenant-scope/per-tenant-client-negative",
    note: "Errorname/prisma-multi-tenant's idiom. The hardest negative here: in this architecture the ABSENCE of a tenant column is correct by design, so a column-presence heuristic must not read it as a gap. Confirmed clean 2026-07-23.",
  },
  {
    module: M1,
    id: "M1TS-N-RELATION-SCOPED",
    kind: "negative",
    cls: "Correct scoping written through a relation or an AND combinator rather than a sibling key",
    dir: "m1-tenant-scope/relation-scoped-negative",
    note: "The detector's header claims a relational or AND/OR-nested scope clears the finding; this asserts it instead of assuming it, in the shapes the three libraries teach.",
  },
  {
    module: M1,
    id: "M1TS-N-NON-SHIPPING",
    kind: "negative",
    cls: "By-id reads and writes in test and docs/example paths",
    dir: "m1-tenant-scope/non-shipping-path-negative",
    note: "The measured 1031-false-positive class, as a regression guard. Covers both halves: a `.test.ts` suite (which the shared NON_PRODUCT matcher would also have caught) and a `docs/examples/**.js` service (which it would NOT — the reason this detector carries its own broader non-shipping gate).",
  },

  // --- #911: an APPLICATION built on one of the #896 libraries, not the library itself — the class
  // #896 recorded as unmeasured because no such application was scanned. MEASURED 2026-07-24: before
  // the wrapper gate, both fixtures below fired 1 finding each (the false positive the issue
  // describes); after the gate, both are silent while M1TS-P-UNSCOPED-ROUTE above (no wrapper
  // signal) still fires — the precision fix does not blind the detector generally.
  {
    module: M1,
    id: "M1TS-N-WRAPPER-DEPENDENCY",
    kind: "negative",
    cls: "By-id query in an app depending on a tenant-scoping wrapper package (ZenStack runtime)",
    dir: "m1-tenant-scope/wrapper-dependency-negative",
    note: "package.json declares @zenstackhq/runtime; the route calls a ZenStack enhance()-wrapped client by id alone, safe only because the wrapper injects the tenant predicate at runtime — invisible to the AST at the call site.",
  },
  {
    module: M1,
    id: "M1TS-N-WRAPPER-EXTENSION",
    kind: "negative",
    cls: "By-id query behind an in-tree $extends/$allOperations wrapper (prisma-rls idiom, vendored not imported)",
    dir: "m1-tenant-scope/wrapper-extension-negative",
    note: "No package dependency — the tenant-scoping extension is written in-tree using the same $extends(...).$allOperations idiom prisma-rls ships. A route calling the wrapped client by id alone is safe the same way; the gate must catch the vendored shape too, not only the named package.",
  },
];
