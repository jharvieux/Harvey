# M1 tenant-scope precision against correct implementations (#896)

**Date:** 2026-07-23. Every number below was produced by a run in this worktree on that date, not
transcribed. Re-run rather than quote: `pnpm exec tsx src/cli/validate-precision.ts`.

## The question

M1's negatives were planted-clean fixtures we wrote ourselves — code that is clean *the way we
expect clean to look*. That does not test the harder case: **third-party code whose entire purpose
is correct tenant scoping, written in idioms we did not anticipate.** If Harvey fires a tenant-scope
finding on a library that exists specifically to enforce tenant scoping, that is a precision bug,
and nothing would have caught it.

## What was scanned

Three MIT libraries, cloned and pinned:

| repo | commit | what it is |
|------|--------|-----------|
| `s1owjke/prisma-rls` | `339344231acc84f268e18142e6d146687ca611ce` | Prisma client extension for row-level security |
| `zenstackhq/zenstack` | `ef0db7fe129b0c3817266207bdb923235e79e6b5` | TypeScript data layer with built-in access control |
| `Errorname/prisma-multi-tenant` | `16f7bff72566ea4fa08acf3b7d7a7299237c6530` | Prisma as a multi-tenant provider |

Tool: `pnpm quick-scan --dir <clone> --findings-out <f>`. Note the issue proposed `pnpm
detect-static`; that runs M6/M7/M8/M9 and would have measured nothing here — the M1 tenant-scope /
BOLA detectors (`prisma-tenant-scope.ts`, `bola-owner.ts`, `job-tenant-scope.ts`, `pg-idor.ts`) run
inside `runMechanicalScan`, which is quick-scan.

## Result — 1031 findings, every one a false positive, none in shipping code

| repo | M1 tenant-scope/BOLA findings | in shipping source | in test/example/docs paths |
|------|------------------------------|--------------------|----------------------------|
| prisma-rls | 25 | 0 | 25 |
| zenstack | 1003 | 0 | 1003 |
| prisma-multi-tenant | 3 | 0 | 3 |
| **total** | **1031** | **0** | **1031** |

Two findings in one, and they point opposite ways:

- **The detector was silent on all three correct implementations.** Zero findings in any library's
  own source. The idioms it had to get right without ever having seen them: scoping via a
  `$extends`/`$allOperations` interceptor that rewrites `where` centrally (prisma-rls); a compiled
  policy filter conjoined into every query including by-id updates (zenstack); and tenancy enforced
  by a **per-tenant database connection**, where the absence of a tenant column is correct by design
  (prisma-multi-tenant). That is the publishable half.
- **Every one of the 1031 was in a test, e2e, example, playground or docs path.** An ORM or policy
  test suite is wall-to-wall `prisma.post.update({ where: { id } })` — that is the fixture setting
  up the case, not an authorization gap, and `briefs/fp-rules.txt` already rules test/fixture/seed/
  dev-script code out of scope. Triage verdict: **1031 FP, 0 TP.**

Each was classified by path and by reading the call site; the classification is recorded per class
in `src/scan/calibration/m1-tenant-scope.entries.ts`, which is also the regression guard.

## The fix

`detectPrismaTenantScopeFindings` now excludes non-shipping paths. It is deliberately broader than
the shared `NON_PRODUCT` matcher (`.test.`/`.spec.`/`__tests__`), which would still have passed
about twenty of these through — zenstack's `tests/**/typecheck.ts` and `.test-d.ts`,
prisma-multi-tenant's `docs/examples/**` and `tests/playground/**`. It is kept local to this
detector rather than widening `NON_PRODUCT`, because that constant also feeds M6/M7/M9 whose
external-corpus baselines are measured against its current meaning — widening it there is a
re-measurement, not a precision fix.

**Re-scanned all three clones after the fix: 0 M1 tenant-scope findings on each.**

## What is now in the precision gate

`pnpm exec tsx src/cli/validate-precision.ts` scores an `M1` module alongside M7/M8: one positive
(an unscoped by-id read/write in a shipping route handler, so the exclusions are measured as a
precision fix and not as a detector gone dark) and five negatives distilled from the three libraries
— the extension-scoping idiom, the policy-filter idiom, the per-tenant-connection idiom, correct
relation/AND-combinator scoping, and the non-shipping-path class. Each fixture carries its upstream
MIT notice; all three libraries are MIT, which is what makes vendoring a distilled shape legitimate.

## Known residual, not fixed here

An **application** that uses one of these libraries will still draw findings: `db.post.findUnique({
where: { id } })` on a prisma-rls-extended or zenstack-wrapped client is safe *because the wrapper
injects the predicate*, and the AST at the call site cannot see that. Nothing measured here proves
the size of that class — no such application was scanned — so it is recorded as an open question
rather than fixed on a guess. Filed as a follow-up; the finding is review-tier, so today it lands as
something a triage pass clears rather than a free-count false positive.

---

# The other three app-layer detectors (#1269, 2026-07-31)

#896 fixed `prisma-tenant-scope.ts` only. #911's body flagged that `pg-idor.ts`, `bola-owner.ts` and
`job-tenant-scope.ts` had never been measured for the same exposure, and its closing PR (#1006) did
not address it. Re-measured here. Every number below was produced by a run in this worktree on
2026-07-31; re-run rather than quote.

## Method

Same three MIT clones, same pins, fetched with `src/scan/corpus-clone.ts`'s `cloneAtPin` and
verified at HEAD. Tool: `pnpm quick-scan --dir <clone> --findings-out <f> --json`. Findings bucketed
by class prefix (`SEC-PG-IDOR-*`, `AUTH-bola-body-owner-*`, `AUTH-job-tenant-scope-*`) and by path
against the same `NON_SHIPPING_PATH`/`NON_SHIPPING_FILE` matchers `prisma-tenant-scope.ts` exports.

## Result — and the population, which is the more important half

| detector | files READ across the 3 clones | of those, non-shipping | findings | shipping | non-shipping |
|---|---|---|---|---|---|
| `pg-idor` (whole source tree) | 977 | 631 | **0** | 0 | 0 |
| `bola-owner` (`pages/api/**`) | **0** | 0 | 0 | 0 | 0 |
| `job-tenant-scope` (`JOB_PATH`) | **0** | 0 | 0 | 0 | 0 |

Total findings across all classes on the three clones: prisma-rls 37, zenstack 297,
prisma-multi-tenant 273 — none of them from these three detectors, and none from
`prisma-tenant-scope` either (its #896 gate holds).

**Two of the three rows above are populations of zero, so the corpus proves nothing about them.**
None of these three libraries is a Next.js app or ships a background-job directory, so
`bola-owner`'s and `job-tenant-scope`'s file filters admitted no file at all. A limit measured over
an empty population is a guess. The acceptance criterion asked for this exact scan and this is what
it can and cannot answer.

## What the corpus could not answer, answered by planting the shape

Each detector's own positive fixture, moved into a non-shipping path and re-run
(`detect*Findings([{ path, text }])`, 2026-07-31, before the fix):

| detector | non-shipping path | findings | shipping control | findings |
|---|---|---|---|---|
| `pg-idor` | `tests/orders.test.js` | 1 | `src/lib/orders.js` | 1 |
| `pg-idor` | `examples/basic/orders.js` | 1 | — | — |
| `bola-owner` | `e2e/pages/api/invoice.js` | 1 | `pages/api/invoice.js` | 1 |
| `bola-owner` | `examples/next-app/pages/api/invoice.js` | 1 | — | — |
| `job-tenant-scope` | `tests/jobs/import.test.ts` | 1 | `src/inngest/import.ts` | 1 |
| `job-tenant-scope` | `examples/inngest/import.ts` | 1 | — | — |

So the exposure is real for all three and it is structural, not corpus-dependent: `pages/api/` and
`jobs/` are path segments an example app or an e2e fixture tree carries just as readily as a product
does. `pg-idor` is the widest of the three — it reads the whole source tree, 631 of the 977 files it
read here being non-shipping.

## The fix

All three now apply the same exclusion `prisma-tenant-scope.ts` has carried since #896. Re-running
the planted-shape table above gives 0 for every non-shipping row and 1 for every shipping control.
`pnpm validate:precision` still passes.

Note what this fix is NOT observable in: the clone scan reports 0 both before and after, because
these classes produced nothing there to begin with. The guard is the ten new cases in
`src/scan/{pg-idor,bola-owner,job-tenant-scope}.test.ts`, each with a shipping scope control;
reverting any one of the three shipping lines fails 5, 5 and 4 of them respectively (measured, both
directions).
