# Semgrep determinism: the measurement, the cause, and the pinned invocation (#1710)

**MEASURED 2026-07-31, semgrep 1.164.0** (the exact version `.github/actions/mechanical-binaries`
pins for CI), on a 10-core darwin machine, against all 17 pinned corpus repos
(`src/scan/external-corpus.ts`) cloned at their pins. Invocation under test: the exact argv
`runSemgrep` (src/scan/semgrep.ts) passes — 6 registry packs + `src/scan/rules/semgrep/`,
`--disable-nosem --x-ignore-semgrepignore-files --json --verbose`. Raw per-run rows: the
measurement harness wrote one JSONL row per run (finding count, sha of the sorted
`(check_id, path, line)` list, `errors[]` timeout entries, wall seconds); the tables below
summarize them. Runs were serialized, never parallel with each other.

## 1. Population and amplitude (17 repos × 5 runs, default flags)

| slug | counts across 5 runs | distinct result sets | timeout errors per run | secs |
|---|---|---|---|---|
| boxyhq | 35 ×5 | 1 — STABLE | 0 | 7.0-7.2 |
| **carbon** | **512, 509, 501, 508, 510** | **5 — MOVES** | 2, 7, 24, 9, 5 | 73-253 |
| cravab | 93 ×5 | 1 — STABLE | 0 | 13-17 |
| **documenso** | **135, 135, 135, 134, 135** | **2 — MOVES** | 0 | 50-53 |
| effective | 53 ×5 | 1 — STABLE | 54, 23, 60, 49, 12 | 102-314 |
| flori-web | 33 ×5 | 1 — STABLE | 0 | 13-14 |
| ghostfolio | 23 ×5 | 1 — STABLE | 0 | 14-15 |
| inbox-zero | 168 ×5 | 1 — STABLE | 0 | 45-60 |
| launch-mvp | 39 ×5 | 1 — STABLE | 0 | 4.0-4.4 |
| multi-tenant-starter | 8 ×5 | 1 — STABLE | 0 | 3.6-5.2 |
| mvp-boilerplate | 11 ×5 | 1 — STABLE | 0 | 5.3-6.6 |
| proposit | 29 ×5 | 1 — STABLE | 0 | 8.2-9.1 |
| rallly | 63 ×5 | 1 — STABLE | 0 | 13.6-14.1 |
| saas-lite | 11 ×5 | 1 — STABLE | 0 | 5.2-6.5 |
| subscription-payments | 21 ×5 | 1 — STABLE | 0 | 3.7-4.0 |
| supabase-security-labs | 0 ×5 | 1 — STABLE | 0 | 3.3-3.4 |
| tanstack-com | 54 ×5 | 1 — STABLE | 0, 0, 1, 3, 1 | 21-45 |

15 of 17 repos were byte-stable at n=5. The two movers are the two with the largest single
source files (carbon's 2000+-line Supabase edge functions and ERP service modules; documenso's
2000-line e2e specs). `effective` is the caution row: 12-60 per-rule timeouts PER RUN, different
rule×file pairs each time, yet a stable finding count — the timed-out rule×file pairs happened to
carry no matches, so the coverage loss was real and the count never showed it. launch-mvp —
the repo #1709 observed moving 20↔22 under CI-load conditions — was stable at n=5 here;
amplitude depends on machine load, so a locally-stable repo is not a stable repo.

## 2. The cause — two distinct mechanisms, only one of them visible

Movers were identified by diffing the sorted `(check_id, path, line)` sets between runs.
**Every moving finding across every run was a taint-mode rule row** (`harvey-log-injection`,
`harvey-unchecked-mutation`) **on a 1500+-line file.**

**Mechanism A — per-rule-per-file timeouts (visible, load-dependent).** Default `--timeout 5`
kills a rule on a file after 5 wall-clock seconds, and `--timeout-threshold 3` skips the whole
file for all remaining rules after 3 such kills. Which rule×file pairs cross 5s varies with
machine load (carbon: 2-24 timeout errors across 5 identical runs). These ARE recorded in
`errors[]` (and disclosed in aggregate by SEM-ERR-00), but the disappearing findings did NOT
correlate 1:1 with the recorded warnings — the recorded timeouts were mostly on rule×file pairs
with no matches, while match-carrying losses often had no per-pair warning (consistent with the
threshold skip and with mechanism B).

**Mechanism B — the threaded engine silently drops taint findings (invisible).** With
`--timeout 0` (no timeouts possible, zero timeout errors recorded), carbon STILL produced 4
distinct result sets in 5 runs (508-513), and documenso still dropped its
`envelopes-api.spec.ts:528` row in 1 of 5 runs — **no `errors[]` entry, no stderr line, nothing
in `paths.skipped`**. Semgrep 1.164.0's default parallelism is shared-memory threads (`--jobs`
help text); the losses vanish under process isolation (below), so the shared state is the
suspect. This is the serious half: a finding lost with no trace is exactly the shape the
repo's fail-loud doctrine forbids, and no disclosure row can count what the engine never reports.

**The reference set.** `-j 1` runs produce 530 findings on carbon — a strict superset of every
parallel run measured (every parallel run was missing 17-29 of them, 100% of 10 runs). The
default mode is not "jittering around a mean": it is a silent 3-5% recall loss on large repos.

## 3. The matrix on the movers (carbon / documenso)

| variant | carbon result | documenso result | carbon secs |
|---|---|---|---|
| default (threads, -j9, t=5s) | 501-512, 5/5 distinct | 134-135, moves | 73-253 |
| `--timeout 0` (threads) | 508-513, 4/5 distinct, 0 timeout errors | 1 drop in 5 runs | 143-410 |
| `-j 1` (t=5s) | **530 — identical ×3**, same 2 timeouts each run | 135 — identical ×3 | 232-275 |
| `-j 1 --timeout 0` | 530 ×2, **529 ×1** (dropped one taint row, no trace) | 135 — identical ×3 | 272-397 |
| `--x-parmap` (processes, -j9, t=5s) | **528 — identical ×3** (4 identical timeouts each run) | 135 — identical ×3 | 99-101 |
| `--x-parmap --timeout 0` | **528 — identical ×4**, 0 timeout errors | 135 — identical ×3 | 123-130 |

Worst-case runtime check (`effective`, the repo with 12-60 timeouts/run at default):
`--x-parmap --timeout 0` ran 78-80s — FASTER than its own default runs (102-314s), same result
set. The feared `--timeout 0` blowup did not materialize on any measured repo.

## 4. The decision (what `runSemgrep` now pins, and why)

**Pinned: `--x-parmap --timeout 0`** (process-based parallelism at default job count, no
per-rule timeout), with a fallback of **`-j 1 --timeout 0`** if a future semgrep drops the
internal `--x-parmap` flag (same fallback pattern the `--x-ignore-semgrepignore-files` flag
already uses; the fallback must degrade to "slower, near-deterministic", never to the silently
lossy threaded default).

- Determinism: 7/7 identical carbon result sets across `--x-parmap` variants (3 with default
  timeout, 4 with `--timeout 0`); 6/6 on documenso; identical on effective/launch-mvp probes.
  Process isolation removes mechanism B; `--timeout 0` removes mechanism A.
- Recall: 528 of the 530-finding `-j 1` reference on carbon. The 2 rows it deterministically
  misses (`harvey-log-injection` at `packages/database/supabase/functions/post-shipment/index.ts`
  1114 and 1691 — Low-severity review-tier) are a **disclosed, stable bound**, against the
  default mode's 17-29-per-run silent random loss. One of those two lines (1691) is the same row
  a `-j 1 --timeout 0` run dropped once in six runs — the file is fragile under every parallel
  AND threaded mode; no measured mode is simultaneously full-recall and fully deterministic on it.
- Runtime: at or below the default mode's cost everywhere measured (carbon ~125s vs 73-253s
  default; documenso 39s vs 50s; effective 79s vs 102-314s) — so this does NOT conflict with
  #1586/#1574's corpus-drift runtime work; it measured cheaper than the mode it replaces on the
  heavy repos, and `-j 1 --timeout 0` (3-4× slower on carbon) was rejected FOR that cost plus
  its own measured 1-in-6 single-row dropout.

**What corpus-drift does about it: nothing beyond inheriting the pin — no tolerance band.**
The required gate's semgrep-derived rows (the free-tier invariant, `FREE_TIER_EXPECTATIONS`)
are threshold checks (grade ≠ F, Critical/High present, non-Info indicator present,
doc-context creds reported-not-graded), not exact counts, and every measured mover was a
review-tier row, a tier none of those thresholds read (MEASURED: all six targets' rows pass
under the pin, grades matching their recorded baselines exactly — A 92, A 97, B 89, C 77,
C 74, F 51). With the pinned invocation the underlying finding sets
are byte-stable, so count-exact semgrep baselines become possible for the first time — any
future one should cite this doc rather than re-earning the pin. A tolerance band was
considered and REJECTED: the measured residual under the pin is zero distinct result sets in
7 runs, so a band would absorb real one-finding regressions and protect against nothing.

## 5. Bounds of this measurement

- One machine (10-core darwin), one semgrep version (1.164.0, = CI's pin). CI amplitude was not
  measured directly; the mechanism (thread-shared state, wall-clock timeouts) transfers, and the
  pinned mode removes both inputs. Cross-machine identity of the parmap result set is NOT
  claimed — worker count differs (`-j` defaults to cores) and the 2-row carbon bound could
  shift with it. The corpus gate compares CI runs to CI-measured baselines, so this does not
  affect the gate; it affects quoting a local count against a CI count.
- n=5 per repo for the population table; a 1-in-6-run dropout (the `-j 1 --timeout 0` row)
  is exactly the kind of event n=5 can miss. "STABLE at n=5" is evidence, not proof, for the
  15 stable repos.
- The 2-row parmap recall bound was measured on carbon only (the only repo with a measured
  `-j 1` reference). Whether other large repos have analogous deterministic parmap misses is
  unmeasured.
- `--x-parmap` is deprecated/internal upstream. The day it is dropped, `runSemgrep`'s fallback
  keeps scans deterministic-ish but 3-4× slower on carbon-sized repos, and the
  `runSemgrep pins the deterministic invocation (#1710)` tests in src/scan/semgrep.test.ts hold
  the contract either way.
