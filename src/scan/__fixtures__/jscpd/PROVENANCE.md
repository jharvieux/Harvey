# `jscpd-4.2.5-report.json` — provenance

CAPTURED, not hand-written. Real `jscpd --reporters json` output, consumed by the base
`jscpdToFindings` / `duplicationSummary` unit tests in `src/quality-scan.test.ts`. Before #1150 the
`jscpdReport` literal was TRANSCRIBED-FROM-RUN (its self-file and tiny-header entries hand-built);
its exact `tokens` counts and line bands were engineered rather than measured.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
jscpd --version: 4.2.5
jscpd <corpus>/src --reporters json --output <dir> --absolute --silent --noTips --no-gitignore --threshold 100
```

Captured 2026-07-26 against a purpose-built clone corpus (seven `.ts` files), engineered so jscpd
finds EXACTLY four clones, one per severity band the transform distinguishes:

| clone | files | lines | tokens | band |
| --- | --- | --- | --- | --- |
| `big1.ts` ↔ `big2.ts` | cross-file | 58 | 582 | Medium (≥ 50) |
| `selfclone.ts` ↔ `selfclone.ts` | **same file** | 17 | 362 | Low (15–49) |
| `small1.ts` ↔ `small2.ts` | cross-file | 10 | 136 | Info (10–14) |
| `tiny1.ts` ↔ `tiny2.ts` | cross-file | 8 | 138 | sub-threshold (< `MIN_SIGNIFICANT_LINES` = 10) → the M4-00 disclosure row |

Real run: `statistics.total.lines` 186, `duplicatedLines` 89, `percentage` 47.85 (jscpd's own count,
which includes the sub-threshold clone; `duplicationSummary` recomputes 45.7 over only the three
significant clones).

## What was elided, and what was not

Records were **dropped, never edited**, with one path substitution (the #1102 osv precedent): each
`firstFile.name`/`secondFile.name` was rewritten from the capturing machine's absolute path to
`src/<basename>` (jscpd was run with `--absolute`; the CLI's real run does the same relativization,
`runJscpdLive` in `quality-scan.test.ts`). Every `lines`/`tokens`/`fragment`/`start`/`end` and the
whole `statistics` object are byte-faithful, including the `startLoc`/`endLoc` fields on each file
ref that `JscpdReport` does not read.
