# Flaky-test policy

**Owner:** platform operator + every engineer
**Spec ref:** §30.10
**Audience:** anyone whose PR introduces or hits a flaky test

## What counts as flaky

A test that **fails intermittently across 3+ runs on the `main` branch
without code changes between runs**.

A test that fails consistently is a *broken* test (or a real regression).
A test that passed once and is now failing on every run is a *broken*
test. Flaky means non-deterministic.

A test that fails once on `main` and then passes the next run is **not
yet flaky** — but log the failure and watch for repeat. Three repeats =
flaky.

## When a flaky test is detected

The engineer who notices it (during PR review, CI failure investigation,
or a re-run that goes green) follows this in order:

1. **Quarantine immediately**, unless the root cause is identified, its fix
   has already merged, and the occurrences and supporting evidence are logged.
   In that case, keep the test enabled and proceed directly to step 4's
   **Fixed** branch. Otherwise add `.skip` (Vitest) or `test.skip`
   (Playwright) in a hotfix PR. Don't comment it out — `.skip` keeps the test
   discoverable. This exception follows the [operator's #1758 ruling](https://github.com/jharvieux/Harvey/issues/1758#issuecomment-5288590454).
2. **Open an issue** in the repo tagged `flaky-test` with:
   - Test file + name
   - First-observed run / commit
   - Symptoms (timeout? race? specific assertion?)
   - Best guess at root cause
   - **Date the test was quarantined** (the 7-day clock starts here)
3. **Assign the issue** to either:
   - The engineer who wrote the test (default)
   - The engineer who owns the area under test
   - The platform operator if neither is obvious
4. **Within 7 days**, the test is either:
   - **Fixed** — root cause identified and addressed; `.skip` removed; PR
     merged; issue closed.
   - **Deleted** — test no longer earns its complexity (e.g., the
     covered behavior has changed); PR merged; issue closed with rationale.

**There is no third option.** §30.10: "Quarantining indefinitely erodes
the test gate's signal value." A test that has been `.skip`ped for > 7
days is itself a CI failure.

## CI enforcement

The pre-merge CI pipeline runs `scripts/check-skipped-tests-stale.ts`
(follow-on script; not yet implemented). The check:

- Walks every `.test.ts` and `.spec.ts` in the repo
- Locates `it.skip(...)`, `test.skip(...)`, `describe.skip(...)`
- For each: extracts the surrounding comment block looking for
  `// flaky-since: YYYY-MM-DD` or `// quarantined: YYYY-MM-DD`
- Fails if any skipped test's quarantine date is more than 7 days old
- Allows-list: skipped tests that document a different reason (e.g.,
  `// skip-reason: requires testcontainers — opt-in via INTEGRATION_DB`)
  are exempt from the 7-day clock

The check is **not yet wired into CI** — the policy is in force as a
human discipline; the automated enforcement lands in the next test-infra
PR. Until then, the operator does a weekly sweep.

## Slow-test thresholds (§30.5)

Tests that exceed these targets are flagged for refactor (not auto-failed):

| Category | Target per test |
|---|---|
| Unit | 100 ms |
| Integration | 5 s |
| Playwright E2E | 60 s |

Tests above target appear in the CI summary as warnings. Refactor when
the warning recurs across runs.

## Watching for the pattern

A few classes of flake show up over and over:

- **Time-dependent**: `Date.now()` or `new Date()` without `vi.useFakeTimers()`
- **Order-dependent**: tests that pass in isolation but fail when run alongside another test (shared module state, missing `vi.resetModules()`)
- **Network-dependent**: tests that hit real external services (Anthropic, Stripe, Supabase) instead of using MSW / mocks
- **Database-state-dependent**: tests that leak rows between runs (use `withTestDatabase()` for cleanup)
- **JSDOM vs Node mismatches**: tests that rely on browser globals in a Node env, or vice versa

When quarantining, note which class the flake belongs to in the issue —
helps the next engineer see patterns across the repo.

## What this policy is NOT

- It is NOT permission to ignore real regressions disguised as "flaky."
  Investigate before quarantining; many "flaky" tests turn out to be
  actually-broken.
- It is NOT a way to mask test brittleness by lowering coverage. Every
  deleted test must have a "what behavior is no longer guarded" note in
  the deletion PR.

## Related

- §30.10 test maintenance discipline (source)
- `docs/testing-scope.md` for what is explicitly NOT tested
