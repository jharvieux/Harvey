# Semgrep determinism: the historical 1.164 measurement and the current 1.173 contract (#1710/#1954)

**HISTORICAL MEASUREMENT — 2026-07-31, semgrep 1.164.0** (the CI-pinned version at the
time; the current pin is 1.173.0), on a 10-core darwin machine, against all 17 pinned corpus repos
(`src/scan/external-corpus.ts`) cloned at their pins. The invocation under test was the exact argv
`runSemgrep` (`src/scan/semgrep.ts`) then passed — 6 registry packs +
`src/scan/rules/semgrep/`, `--disable-nosem --x-ignore-semgrepignore-files --json --verbose`.
Raw per-run rows recorded finding count, a hash of the sorted `(check_id, path, line)` population,
`errors[]` timeout entries, and wall seconds. Runs were serialized, never parallel with each other.
Sections 1–3 retain that 1.164.0 evidence because it established the two loss mechanisms; section 4
states the current 1.173.0 production contract and its newer Carbon evidence.

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

## 4. The current production contract

The 1.164.0 study established two durable requirements: use process isolation and disable the
per-rule wall-clock timeout. The original `--x-parmap --timeout 0` decision was therefore sound, but
later hosted replays showed that nine-worker parmap could still omit different
`harvey-log-injection` rows while diagnostics remained equal. A coincident pair of j9 results is not
sufficient evidence of recall.

**Current at semgrep 1.173.0:** every planned family uses `--x-parmap --timeout 0`.
`local-injection` is the exceptional topology. Each attempt scans the whole target twice in a fixed
order at `-j 1`: the `log` partition owns only `harvey-log-injection`, and the `complement`
partition owns the other 29 rules. Harvey canonically merges those two outputs, repeats the same
ordered pair exactly once, and compares both component receipts and the merged semantic receipt.
Findings, result hashes, errors, scanned paths, skipped paths, skipped rules, executed rule IDs, and
fixpoint timeouts must all agree before the output can be returned or enter the reusable family
cache. There is no retry-until-green and no fallback to threaded execution.

The successful execution-plan and family-cache artifact schema is 5. It binds the ordered partition
topology, disjoint rule ownership, derived-config content hashes, canonical argv, merge algorithm,
exact two-attempt policy, component receipts, merged receipts, and actual loaded-rule population. A
divergent pair is retained as a content-addressed `reusable: false` failure artifact under
`semgrep-family-failures/local-injection/`; successful cache resolution reads only
`semgrep-families/`, and a same-key rerun executes again. Schema-4 and malformed or invented schema-5
receipts are rejected.

The pinned inventory contains **1,033 rule entries / 846 unique rule IDs / 168 duplicated IDs**:
915 entries / 728 unique IDs from the six registry packs plus 118 local rules. The content-derived
ownership plan assigns every registry rule one execution owner while preserving every local rule.
The duplicated `direct-response-write` registry rule is excluded from both source packs and derived
once into its own paired `-j 1` family, bound to its semantic object hash. This prevents overlapping
packs from executing the same rule under different load and then losing source-family provenance
during merge.

**MEASURED 2026-08-22, semgrep 1.173.0, pinned Carbon tree:** each merged
`local-injection` attempt produced exactly **87 findings**, **26 errors**, **4,152 scanned paths**,
**32 skipped-path records**, **30 executed rule IDs**, and **10 distinct fixpoint timeouts**. The
`log` component produced **78 findings**, **1 error**, and **4 timeouts**; the 29-rule `complement`
produced **9 findings**, **26 errors**, and **6 timeouts**. Both prescribed fresh cold executions
produced those exact populations, and both inner attempts agreed component-by-component and after
merge.

The two cold executions initially stored different semantic hashes only because Semgrep embedded
each derived config's temporary cache-root namespace in `check_id`, executed-rule, and
timeout-message strings. The final ownership-bound canonicalizer removes that namespace only when
it resolves to exactly one declared owned rule. Replaying both retained raw execution artifacts
through the final production canonicalizer and schema-5 receipt builder makes every corresponding
component and merged receipt identical across the two runs. A known cache-root rename canonicalizes
equal; an unknown namespace or semantic rule-id mutation remains unequal. No third Carbon execution
was made: the post-fix evidence is retained-raw replay through the final code.

The current PartialParsing record for `TraceabilityGraph.tsx` is **79:1–79:2** on the unexpected
`}`; the older line-74 `import("./utils").IssueContainment` record is historical and a paired run
that substitutes it is rejected.

**Committed-artifact effect:** regeneration moved `dry-run/findings.json` from **811 to 789**.
A content comparison excluding renumbered IDs shows **22 removals**, all duplicate Semgrep SQL
placeholder findings, and **0 additions**. Two fresh post-fix regeneration epochs produced
byte-identical `findings.json`, `pii-data-map.json`, `scorecard.json`, and `findings-report.json`;
`findings-report.json.findings` is deeply equal to the standalone findings array. The artifact
delta is therefore exactly the 22 duplicate removals, not nondeterministic generated-config naming.

Interim #1954 notes that quote **52 skips**, **line 74**, **804 findings**, **6 merged timeouts**,
**schema 3/4**, a whole-family two-run topology, or **zero artifact delta** do not describe the
accepted 1.173.0 contract. The older 1.164.0 population and matrix above remain historical
measurements, not current production counts.

## 5. Historical corpus-drift consequence at 1.164.0

At the time of the original 1.164.0 pin, corpus-drift needed no tolerance band. Its semgrep-derived
rows (the free-tier invariant, `FREE_TIER_EXPECTATIONS`) were threshold checks (grade ≠ F,
Critical/High present, non-Info indicator present, doc-context credentials reported-not-graded), not
exact counts, and every measured mover was a review-tier row that none of those thresholds read.
MEASURED then: all six targets passed under the pin and their grades matched the recorded baselines
exactly — A 92, A 97, B 89, C 77, C 74, F 51. The pinned 1.164.0 result sets had zero residual
variation across the cited parmap runs, so a tolerance band would have hidden a real one-finding
regression without protecting against measured noise. That rationale is historical evidence for
fail-closed exact comparison; it is not a claim that 1.164.0 counts are current under 1.173.0.

## 6. Bounds of this measurement

- The population/matrix study used one machine (10-core darwin) and semgrep 1.164.0, which was CI's
  pin at the time, not the current 1.173.0 authority. CI amplitude was not measured directly; the
  mechanisms (thread-shared state and wall-clock timeouts) transfer, and the current topology still
  removes both inputs. Cross-machine identity of the historical parmap result set was not claimed.
  The current 1.173.0 Carbon evidence instead binds local-injection to two ordered whole-root j1
  rule partitions per attempt, compares both component and merged schema-5 semantic receipts across
  exactly two attempts, and fails closed if any field disagrees.
- n=5 per repo for the population table; a 1-in-6-run dropout (the `-j 1 --timeout 0` row)
  is exactly the kind of event n=5 can miss. "STABLE at n=5" is evidence, not proof, for the
  15 stable repos.
- The 2-row parmap recall bound was measured on carbon only (the only repo with a measured
  `-j 1` reference). Whether other large repos have analogous deterministic parmap misses is
  unmeasured.
- `--x-parmap` remains deprecated/internal upstream. A future Semgrep that rejects it does not fall
  back to an unproved threaded topology: the run fails closed as incomplete (`SEM-00`) and must be
  re-measured before a replacement execution policy is accepted. The schema-5 topology receipt,
  non-reusable failure artifacts, retained-raw replay controls, and paired-topology tests in
  `src/scan/semgrep.test.ts` and `src/scan/semgrep-family-cache.test.ts` hold that contract.
