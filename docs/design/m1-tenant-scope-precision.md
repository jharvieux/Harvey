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
  up the case, not an authorization gap, and `docs/fp-rules.txt` already rules test/fixture/seed/
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
