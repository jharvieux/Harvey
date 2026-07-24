# Ungraded breadth sweep — Bucket A/B at volume (#899, mechanical half)

**Date:** 2026-07-24
**Issue:** #899 (mechanical half; the graded/triage/disclosure remainder is #900).
**What this is:** the RAW, UNGRADED output of running Harvey's source/mechanical tier over ~15
Bucket A/B targets from `docs/test-targets.md`, at pinned commits, to answer the one question six
curated corpus targets cannot: *what does real code in the wild look like at volume, and where does
the mechanical tier crash / stall / go silent / over-fire?*

**2026-07-24 correction:** the sweep originally covered 16 targets including `documenso`. PR #939
(#894/#895/#897) subsequently baselined `documenso` into the GRADED corpus
(`src/scan/external-corpus.ts`) — a target is graded XOR ungraded, never both (see
`breadth-sweep.test.ts`'s invariant), and the graded baseline is strictly better coverage than an
ungraded scan. `documenso` was dropped from `BREADTH_SWEEP` and its row removed from this doc and
from `breadth-sweep/ungraded/INDEX.json`; every total below is RE-DERIVED from the remaining 15
rows in that artifact, not hand-adjusted.

## READ THIS FIRST — these numbers are CLAIMS, not facts

Every count in this document and in `breadth-sweep/ungraded/*.json` is an **unverified finding from
an untriaged volume sweep**. It is NOT a scored capability number. Do not quote any figure here as
recall, precision, or "Harvey catches N" — no finding here has been triaged, and an untriaged
finding is a claim (CLAUDE.md's coverage doctrine; #263's lesson that "a baseline no job ever scores
is a number nobody has checked"). The triage obligation that turns these claims into facts is #900,
item 2. The graded, scored, drift-checked tier is `src/scan/external-corpus.ts` + `pnpm
corpus-drift` — a *different* set of six repos, and nothing from this sweep may be added there as a
baseline (that would dilute the drift gate; #899 says so explicitly).

## Why this is structurally distinct from the graded corpus

The crux of #899/#900 is that an ungraded result must never read as a scored one. This sweep keeps
that line at three levels:

1. **Manifest.** `src/scan/breadth-sweep.ts` (`BreadthTarget`) carries pins + provenance and
   **no baseline field** — no `counted`, no `total`, no `MutationBaseline`. There is nowhere in it
   to write a number a scorer could grade against. `src/scan/breadth-sweep.test.ts` asserts this and
   that no target appears in both tiers.
2. **Artifact.** Every `breadth-sweep/ungraded/<slug>.json.gz` is stamped `"graded": false` with a
   `warning` string, and carries a `notRunTiers` list so an absent module reads as "not run here",
   never as "clean". (Per-target dumps are gzipped — the full raw findings total ~46 MB; `gunzip -c
   <slug>.json.gz` reads one. `INDEX.json` is the plaintext measurement.)
3. **This doc.** Titled, dated, and fenced with the CLAIMS-not-facts banner above.

## How each target was run

Runner: `pnpm exec tsx src/cli/breadth-sweep.ts` (`--clones-dir` for reuse, `--timeout 300` per
scanner — see the M1 scaling wall below for why 300s and not longer). Per target it clones the pin
(depth-1, exact commit), counts files, and runs the source-tier mechanical scanners:

- `pnpm quick-scan --dir <dir>` — M1 mechanical: semgrep `harvey-*` rules, gitleaks + trufflehog
  secrets, OSV dependency CVEs, dangerous-config, static RLS indicators. (Only the free-tier
  mechanical layer; the free letter-grade/diagnosis is NOT emitted here — just the raw Finding[].)
- `pnpm detect-static <dir>` — M1-static, M5-slop, M6-indicator, M7-code, M8-intent, M9 (AST).
- `pnpm quality-scan <dir>` — M4 (jscpd) + M5-knip (dead code; run WITHOUT the target's
  `npm install`, so knip degrades to its review/reduced tier — that is the honest source-tier state
  and a real observation, not a defect of the run).
- `pnpm mutation-scan <dir> --detect-only` — M8 suite-absent detection only (no Stryker). "empty"
  here means a test suite WAS present (the suite-absent finding correctly did not fire), not silence.
- M10 in-process — every `.sql` DDL file (migrations included) via `classifyMigrationSql`, every
  `schema.prisma` via `classifyPrismaSchema` (the CLI-independent fallback parser, no target install).

**Tiers deliberately NOT run** (stamped in every artifact): M1 semantic/live, M2 dynamic, M3
hotspot, M6 paid verdict, M7 DB advisors + Lighthouse, M8 mutation scoring, M10 live DB. This is the
source/mechanical tier only.

## MEASURED — the sweep (from `breadth-sweep/ungraded/INDEX.json`, 2026-07-24)

**15 targets scanned, 0 dropped. 33,476 files (23,617 `.ts/.tsx`). 36,785 ungraded findings.**
Per-target wall-clock 16–187 s (grida the slowest, at 3,496 `.ts`); no scanner hit the 300 s cap.
These numbers are the whole point of the ungraded warning above: 36,785 is a count of raw emissions,
**not** a count of real issues — a large fraction are duplicates across engines and false positives
that only triage (#900) can separate.

| Target | Bucket | Files (.ts) | Ungraded findings | Wall s | M1 | M4 | M5 | M6 | M7 | M8 | M9 | M10 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| priceai | supabase | 795 (360) | 2873 | 43.7 | 207 | 342 | 2089 | 24 | 62 | 1 | 111 | 37 |
| git-city | supabase | 915 (647) | 1821 | 49.3 | 566 | 453 | 390 | 57 | 195 | 1 | 126 | 33 |
| liam | supabase | 2175 (1470) | 1389 | 38.7 | 350 | 257 | 551 | 14 | 38 | 132 | 33 | 14 |
| grida | supabase | 5327 (3496) | 4060 | 187.2 | 665 | 870 | 1969 | 65 | 230 | 73 | 138 | 50 |
| wacrm | supabase | 442 (359) | 565 | 30.0 | 153 | 60 | 160 | 15 | 110 | 21 | 24 | 22 |
| atomic-crm | supabase | 737 (410) | 490 | 50.1 | 101 | 92 | 252 | 7 | 31 | 1 | 1 | 5 |
| onlook | supabase | 1695 (1290) | 1791 | 64.0 | 160 | 229 | 1142 | 15 | 146 | 0 | 89 | 10 |
| supabase-cms-kit | supabase | 144 (111) | 167 | 27.1 | 98 | 17 | 27 | 9 | 8 | 1 | 5 | 2 |
| open-scouts | supabase | 1116 (546) | 785 | 47.8 | 108 | 203 | 389 | 25 | 40 | 1 | 15 | 4 |
| elatoai | supabase | 391 (177) | 188 | 16.3 | 26 | 17 | 111 | 1 | 21 | 1 | 5 | 6 |
| hikari | supabase | 338 (164) | 330 | 37.6 | 119 | 28 | 157 | 5 | 9 | 1 | 5 | 6 |
| dub | prisma | 4290 (4078) | 4642 | 64.8 | 1683 | 1678 | 653 | 58 | 467 | 1 | 62 | 40 |
| hexclave | prisma | 3048 (2193) | 4419 | 93.0 | 971 | 12 | 2127 | 160 | 138 | 814 | 157 | 40 |
| cal-diy | prisma | 7693 (5025) | 8731 | 147.5 | 2077 | 1506 | 4377 | 126 | 222 | 210 | 123 | 90 |
| amplication | prisma | 4370 (3291) | 4534 | 146.6 | 714 | 968 | 2481 | 7 | 250 | 47 | 2 | 65 |

Per-module totals (raw emissions, ungraded): **M5 16,875 · M1 7,410 · M4 6,732 · M7 1,967 · M8
1,305 · M6 1,176 · M9 896 · M10 424.** Per-severity: **Low 23,178 · Medium 5,109 · Info 4,470 ·
High 2,570 · Perf 1,410 · Critical 48.** The 48 "Critical" rows are the sharpest illustration of the
warning: untriaged, they are worthless as a claim — some are real, most on this kind of volume sweep
are not, and which is which is exactly #900's triage.

## Failure classes surfaced (the thing breadth is uniquely good at)

Six curated corpus targets never stress these; a 15-repo volume sweep does. What it found:

- **CRASH — `mutation-scan` on 3/15 (`liam`, `dub`, `cal-diy`).** Same root cause each time:
  `walkRelPaths` (src/cli/mutation-scan.ts:259) calls `statSync(full).isDirectory()`, and `statSync`
  **follows symlinks** — a committed **dangling symlink** (liam: `frontend/apps/app/.env`; dub:
  an EE `LICENSE.md` symlink) throws `ENOENT` and aborts the whole M8 census. The breadth runner
  recorded each as `error` and continued (fail-loud worked); the scanner fix is filed as a follow-up.
  This is the headline result: a real, reproducible Harvey defect that only wild-repo shapes exposed.
- **TIMEOUT — none.** No scanner hit the 300 s cap. (An earlier pass showed `grida`'s M1 apparently
  hanging >900 s; that was CPU contention from concurrent work on the same machine, not intrinsic —
  re-measured idle, `grida`'s M1 completed in ~130 s. The cap exists to bound a genuinely pathological
  tree without waiting on it.)
- **SILENT-EMPTY — none that are real.** `mutation-scan` reads `empty` on 6/15, but that is the
  *correct* output: a test suite WAS present, so the suite-absent finding correctly did not fire.
  `quick-scan`, `detect-static`, `quality-scan` and `pii-classify` emitted on all 15 — no module
  went silently dark where output was expected.
- **OVER-FIRE candidates (for #900, not graded here).** M5 dominates every large repo (`cal-diy`
  4,377; `priceai`/`grida`/`amplication` each >1,900) and `hexclave`'s M8 test-intent
  fired 814 — both are exactly the "detector fires N-hundred times on one idiom" shape breadth is
  built to surface. Whether these are real signal, a recurring FP idiom, or a mechanization
  opportunity is a triage question (#900), NOT a conclusion this sweep is allowed to draw.

## What this feeds (all deferred to #900)

- **Mechanization candidates (#899 deliverable 3):** the recurring finding classes across unrelated
  repos are the input to a future mechanical-detector batch — but "recurs across repos" needs a
  definition that survives a monorepo counting the same shape N times (#900 item 3), and the
  clustering + ranking is a triage pass (#900 item 2). Not done here.
- **FP catalogue (#899 deliverable 4 → #900 item 5):** FP shapes distilled from the sweep are
  *proposed* to `docs/fp-rules.txt` — a supervised, human-owned file. Not touched here.
- **#882 population:** these are the population, not a sample — but no aggregate statistic may be
  stated until the triage pass completes (#900 item 2) and disclosure is handled (#900 item 4).

## Reproducing

Fully reproducible from the pins: `pnpm exec tsx src/cli/breadth-sweep.ts --clones-dir <dir>
--timeout 1200`. The commits in `src/scan/breadth-sweep.ts` are default-branch HEAD as of
2026-07-24; a re-run at a later HEAD is a different tree and its numbers will differ — that is
expected for an ungraded snapshot and is exactly why there is no drift gate here.
