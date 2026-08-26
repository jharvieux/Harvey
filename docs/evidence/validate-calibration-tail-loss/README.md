# #1758 evidence package

This is a mechanical, content-addressed subset for publication review. It does not determine acceptance or closure.

## Included provenance

- Three original failure diagnostic excerpts with retained subset hashes, their original full-log receipts/hashes, run/job identities, checkout identities, and source anchors: `incident-normalized.json` and `failure-tails/`.
- Fix PR #1768 merge identity and the verbatim operator ruling: `incident-normalized.json`.
- Historical and late run/attempt/job populations, all late heavy job identities and step outcomes, actual checkouts, raw receipt hashes, and retained literal classified log lines with offsets: `census-normalized.json`.
- Current-source qualification rows, parser correction, the one incomplete late calibration, and refreshed cutoff receipts: `census-normalized.json`.
- The two original census/replay scripts as evidence/reproduction material only: `reproduction/`. They are not executed by this package.

## Exact windows and arithmetic

- Historical window: 2026-08-01T01:05:33Z through 2026-08-14T07:26:57Z; 156 runs, 157 attempts, 154 heavy shard-2 jobs, and 154 calibration passes (153 successful jobs plus 1 later-cancelled job).
- Late window: 2026-08-14T07:26:58Z through 2026-08-26T05:49:10Z; 123 runs, 123 attempts, 337 heavy jobs: 109 calibration-passed, 220 no-calibration-execution-result, 7 skipped, and 1 selected/cancelled-without-result.
- Combined retained census arithmetic: 279 runs, 280 attempts, 491 heavy jobs, 263 calibration-passed rows.

The late parser correction is retained verbatim in `census-normalized.json`: An EXCLUDED warning from the later shared-source test is not evidence that calibration was selected in this heavy job. Original parser-v1 receipts remain intact.

## Safety boundary

Raw hosted logs are not copied. The three retained diagnostic excerpts and all generated package text were scanned for common token, authorization, password, and JWT shapes before handoff; no match was found. Preserve the manifest's distinct original raw hashes and subset hashes when publishing.
