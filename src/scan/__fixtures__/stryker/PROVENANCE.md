# Stryker M8 calibration captures — provenance

CAPTURED, not hand-written. These are real `@stryker-mutator/core` 9.6.1 JSON reports, consumed by
`src/mutation-scan.test.ts` as the M8 calibration corpus. Before #1150 the `m8Report` and
`vacuousReport` literals were TRANSCRIBED-FROM-RUN — rebuilt through the `mutant()` default-injector
helper, so they could never be mechanically re-diffed against a fresh capture. These files are the
raw reports (trimmed), pointed at directly.

**Do not hand-edit these files.** If they need to change, re-capture them.

## How they were captured

Both were produced against `targets/calibration/test-quality/` (that target's own isolated
`package.json`/`package-lock.json` dependency tree, `npm ci` then):

```
@stryker-mutator/core --version: 9.6.1
# stryker-9.6.1-m8-calibration.json
npx stryker run                              # → reports/mutation/mutation.json
# stryker-9.6.1-m8-vacuous.json
npx stryker run stryker.vacuous.config.json  # → reports/mutation-vacuous/mutation.json
```

Captured 2026-07-26. Both configs use `testRunner: "vitest"`, `coverageAnalysis: "perTest"`.

- `stryker-9.6.1-m8-calibration.json` scores `discount.ts` (planted weak test, M8-P-TAUTOLOGICAL)
  and `authz.ts` (planted strong test, M8-N-STRONG). Real run: `discount.ts` 9 killed / 15 valid =
  60.0%, `authz.ts` 10/10 = 100.0%, overall 19/25 = 76.0% — the scores the tests assert.
- `stryker-9.6.1-m8-vacuous.json` scores `vacuous.ts` alone, covered only by
  `vacuous.smoke.test.ts`'s assertion-free test (M8-P-VACUOUS-STRYKER). Real run: 0 killed, 10
  Survived + 2 NoCoverage of 12 = 0.0% — the answer key for the `testFiles`/`coveredBy`/`killedBy`
  vacuous-test join (#1100).

## What was elided, and what was not

Records were **dropped, never edited**. Three top-level keys were removed from each report because
they embed the capturing machine's absolute paths and the fully-resolved config (they are not read
by `mutation-scan.ts`):

- `config` — the resolved Stryker config, incl. absolute `projectRoot`/plugin paths.
- `framework` — the reporter framework banner.
- `projectRoot` — the capturing machine's absolute path.

Kept whole and byte-faithful: `schemaVersion`, `thresholds`, `testFiles` (incl. each test's real
`source`), and every `files[].mutants[]` record (`id`/`mutatorName`/`status`/`replacement`/
`static`/`coveredBy`/`location`) exactly as Stryker emitted them.

## What is NOT captured here, and why

The other `StrykerReport` literals in `src/mutation-scan.test.ts` — `report`, `untested`,
`whollyUntested`, `mostlyStaticReport`, `oneFile` — are **engineered unit inputs**, not stand-ins
for any single real run: each is a minimal report constructed to isolate one branch of the
summarizer (module bucketing, the no-coverage ratio thresholds, the #1100 static-majority
downgrade). No real target produces exactly those mutant sets, so they are not re-capturable and
stay hand-built by design; their comments already say so.
