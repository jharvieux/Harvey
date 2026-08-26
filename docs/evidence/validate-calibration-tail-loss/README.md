# #1758 evidence package

This is a mechanical, content-addressed subset for publication review. It does not determine acceptance or closure.

## Included provenance

- Three original failure diagnostic excerpts with retained subset hashes, their original full-log receipts/hashes, run/job identities, checkout identities, and source anchors: `incident-normalized.json` and `failure-tails/`.
- Fix PR #1768 merge identity and the verbatim operator ruling: `incident-normalized.json`.
- Historical and late run/attempt/job populations, all late heavy job identities and step outcomes, actual checkouts, raw receipt hashes, and retained literal classified log lines with offsets: `census-normalized.json`.
- Every historical calibration-passed job’s file, seeded, and unseeded pass lines with original line offsets and raw-log verification, plus all 139 historical checkout source-byte/hash checks and their actual first import at line 19: `historical-qualified-supplemental.json`. The same projection audit retains the corresponding 109 late calibration-passed rows and 98 late source guards.
- Current-source qualification rows, parser correction, the one incomplete late calibration, and refreshed cutoff receipts: `census-normalized.json`.
- The two original census/replay scripts as evidence/reproduction material only: `reproduction/`. They are not executed by this package.
- `reproduction/harvey-1758-build-v2.mjs` is the retained local requalification collector for the supplemental subset; its version receipt is in `manifest.json`. It verifies, rather than recreates, the already-captured hosted evidence.

## Exact windows and arithmetic

- Historical window: 2026-08-01T01:05:33Z through 2026-08-14T07:26:57Z; 156 runs, 157 attempts, 154 heavy shard-2 jobs, and 154 calibration passes (153 successful jobs plus 1 later-cancelled job).
- Late window: 2026-08-14T07:26:58Z through 2026-08-26T05:49:10Z; 123 runs, 123 attempts, 337 heavy jobs: 109 calibration-passed, 220 no-calibration-execution-result, 7 skipped, and 1 selected/cancelled-without-result.
- Combined retained census arithmetic: 279 runs, 280 attempts, 491 heavy jobs, 263 calibration-passed rows.

The late parser correction is retained verbatim in `census-normalized.json`: An EXCLUDED warning from the later shared-source test is not evidence that calibration was selected in this heavy job. Original parser-v1 receipts remain intact.

## Safety boundary

Raw hosted logs are not copied. The three retained diagnostic excerpts and all generated package text were scanned for common token, authorization, password, and JWT shapes before handoff; no match was found. Preserve the manifest's distinct original raw hashes and subset hashes when publishing.

## Current local execution

At `19f8f57c3dd698438d0ee0212daed4b9e48decb3`, the real calibration file passed 3/3 with no skips (process exit 0, 76.75s), including its expected seeded refusal and scanner-crash refusal. A separate light invocation passed all four stdio controls with no skips (exit 0, 6.53s). The heavy-filtered command did not execute the light stdio file. Exact commands, runtime/binary versions, source hashes, JSON test results and raw output are retained in `current-verification/`. These are local observations; they do not substitute for the historical denominator or the required final full/hosted checks.
