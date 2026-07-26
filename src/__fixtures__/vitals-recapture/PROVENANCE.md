# `src/__fixtures__/vitals-report.json` — provenance

CAPTURED, not hand-written (issue #1146, row 6 of #1130). This fixture is real
`vitals 0.2.0 report --json` output. It was HAND-WRITTEN before #1146 — self-declared "synthetic
paths/values" — and encoded values the real tool never emits: `churn_label: "MEDIUM"` (vitals only
emits `HIGH`/`MED`/`LOW`), `truck_factor: 3` for a 3-equal-author file (real vitals computes 2), and
that same multi-author file listed in `knowledge_risk` at all (vitals lists only `truck_factor ≤ 1`).
That is the #1063 defect class: a fixture standing in for a tool's output must be a real capture.

**Do not hand-edit the fixture.** Re-capture it: `python3 src/__fixtures__/vitals-recapture/seed.py`.

## Why a seed script, not a one-off run

`src/__fixtures__/vitals-report.json` doubles as the **M3 calibration-corpus plant**
(`src/scan/calibration/m3.entries.ts`, scored via `buildCoverageMatrix` in
`src/hotspot-scan.test.ts`). A faithful capture must reproduce every planted hotspot / truck-factor /
coupling / AI-provenance RELATIONSHIP from the tool's own output — so the capture is driven by a
purpose-built repo, not a keyboard. `seed.py` builds that repo and provenance DB, runs the pinned
vitals against it, and writes the capture. It edits INPUTS (git history + `.vitals` DB), never the
tool's OUTPUT.

## How it was captured

```
vitals version: Vitals v0.2.0   (~/.claude/plugins/cache/vitals/vitals/0.2.0/scripts/vitals_cli.py)
python3 vitals_cli.py report --json <seeded-repo>
```

Captured 2026-07-26. `0.2.0` is the pinned `EXPECTED_VITALS_VERSION` in `src/cli/hotspot-scan.ts`.

The seed backdates every commit RELATIVE TO NOW (churn commits inside the trailing 90 days, the
initial-free history all inside the 180-day coupling and 2-year authorship windows), so re-running
`seed.py` on any date reproduces the same relationships. Absolute dates in the committed fixture
(`last_change`, provenance epoch timestamps) are therefore a snapshot of the capture moment and shift
on re-capture — no test asserts on them.

## What the seed makes vitals emit (the planted relationships, MEASURED 2026-07-26)

| File | Seeded so that… | Plant entry | Observed in capture |
| --- | --- | --- | --- |
| `core/checkout.ts` | high churn (17) + deep/long complexity (score 81); in `.vitals` provenance | M3-P-HOTSPOT, M3-P-AIPROV | rank #1, `risk_score` 96.9, `churn_label` HIGH, in `ai_files` |
| `generated/schema.gen.ts` | highest RAW churn (18) but flat, low complexity (score 31); NOT in provenance | M3-N-CHURN-TRIVIAL, M3-N-AIPROV-HUMAN | rank #4 (out of top-3), highest `changes`, `churn_label` HIGH, absent from `ai_files` |
| `core/billing.ts` | sole author (alice), 14 commits | M3-P-TRUCK1 | `knowledge_risk` `truck_factor` 1, `author_count` 1 |
| `core/reporting.ts` | 3 balanced authors, 16 commits | M3-N-MULTIAUTHOR | `truck_factor` 2 → ABSENT from `knowledge_risk` |
| `core/a.ts` ↔ `core/b.ts` | always co-committed (5 joint days), never apart | M3-P-COUPLING | exactly one `coupling` edge, `coupling_strength` 1.0 |
| `lib/stable.ts` | AI-authored (in provenance) but only 2 commits | M3-N-AIPROV-STABLE | in `ai_files`, `churn_label` LOW |

`knowledge_risk` contains exactly one row (`core/billing.ts`); `coupling` contains exactly one edge
(`core/a.ts <> core/b.ts`); `provenance.ai_files` is `[core/checkout.ts, lib/stable.ts]` ordered by
`total_events` desc. Every planted entry was reproduced faithfully — nothing had to be split with a
recorded REASON. The 40 assertions in `src/hotspot-scan.test.ts` pass against this capture unchanged.

## Notes on vitals' scoring (why the seed is shaped the way it is)

- Complexity for non-Python files is INDENTATION-nesting driven (branch keywords are not counted), so
  "high complexity" = deep, long nesting; a file with nesting ≤ 2 scores 0 and is dropped from the
  hotspot table entirely. `schema.gen.ts` is deliberately nesting-3-with-flat-filler: gated IN, but
  HEALTHY, so its max raw churn does not make it a top-K hotspot.
- `risk_score = (10 - health) × changes × role_weight × centrality_boost`; churn is a linear
  multiplier, so keeping the max-churn file out of top-3 requires it to be genuinely healthy.
- There is no shared initial commit: a single-author creation commit tips every file toward that
  author and collapses `truck_factor` to 1. Files are created on first churn touch instead.
- On macOS, `$TMPDIR` is a `/var → /private/var` symlink; vitals resolves the repo root via git while
  scoping against the path handed to it, so the seed hands vitals the `realpath` of the repo.
