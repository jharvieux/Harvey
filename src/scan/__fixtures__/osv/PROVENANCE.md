# `osv-scanner-2.3.8-report.json` — provenance

CAPTURED, not hand-written. This is real tool output, kept because #1063 was caused by the
opposite: `src/scan/dependencies.test.ts` asserted against a `score: "7.5"` fixture invented from
Harvey's own TypeScript type. osv-scanner never emits a bare number there — OSV mandates
`severity[].score` be a CVSS **vector string** — so `severityFromCvss` produced `NaN` for every
real advisory and every dependency CVE shipped as Medium, while the test stayed green.

**Do not hand-edit this file.** If it needs to change, re-capture it.

## How it was captured

```
osv-scanner version: 2.3.8 (osv-scalibr 0.4.5)
osv-scanner --format json --lockfile targets/calibration/package-lock.json
```

Captured 2026-07-26 against `targets/calibration/package-lock.json`.

## What was elided, and what was not

The full report was 219 KB / 36 vulnerabilities across 8 packages. Records were **dropped, never
edited** — every `package`, `groups` and `vulnerabilities` object present here is byte-for-byte as
osv-scanner emitted it. Two changes beyond dropping:

- `results[].source.path` was shortened from the capturing machine's absolute path to
  `package-lock.json`.
- `braces` and `postcss` were dropped whole; `lodash` and `next` kept a subset of their
  `vulnerabilities` (and the matching `groups` entries).

What survives covers every branch `parseOsvFindings` has:

| package | advisory | `database_specific.severity` | CVSS types present |
| --- | --- | --- | --- |
| `elliptic` | GHSA-848j-6mx2-7j84 | LOW | CVSS_V3 + CVSS_V4 |
| `lodash` | GHSA-jf85-cpcp-j695 | CRITICAL | CVSS_V3 |
| `micromatch` | GHSA-952p-6rrq-rcjv | MODERATE | CVSS_V3 |
| `next` | GHSA-89xv-2m56-2m9x | HIGH | CVSS_V4 only |
| `next` | GHSA-c4j6-fc7j-m34r | HIGH | CVSS_V3 — in `CURATED_ADVISORY_IDS`, so it must be deduped away |
| `serialize-javascript` | GHSA-5c6j-r48x-rmvq | HIGH | CVSS_V3 |
