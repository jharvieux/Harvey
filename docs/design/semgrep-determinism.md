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

**Current at Semgrep 1.173.0, schema 8:** every planned family uses process isolation and
`--timeout 0`. The schema-6 execution topology is retained: `local-injection` uses
`rule-and-size-routed-file-isolation-v1`, with `harvey-log-injection` split into the deterministic
whole-root remainder and 20 evidence-derived single-file scans, followed by the 29-rule whole-root
complement. Every component runs with `--x-parmap -j 1`; the ordered 22-component attempt is
repeated exactly once and must agree on every strict semantic field. `local-xss` and the derived
`direct-response-write` singleton remain paired cold at `--x-parmap -j 1`. Other families retain
their measured single process-isolated execution. There is no retry-until-green, union of attempts,
tolerance band, or fallback to threaded execution.

Schema 8 separates authoritative scan semantics from Semgrep's experimental fixpoint profiling.
Findings and their hashes/counts, errors, scanned and skipped paths, skipped rules, actual loaded
rules, config and ownership hashes, argv, topology, component boundaries, and merge receipts remain
exact and cache/readiness-significant. `time.fixpoint_timeouts` rows are not semantic equality rows:
retained identical-input runs moved their message summaries and row populations without moving any
of those strict fields. A non-empty timeout population instead deterministically marks the owning
family's complete loaded taint-rule subset **NotAssessed**. Harvey derives that candidate subset
from the pinned rule objects and actual loaded-rule receipt; it never attributes coverage from the
volatile message's count or first-rule summary. If paired attempts disagree on whether that family
is NotAssessed, the pair fails closed.

Every cold attempt retains its complete known-root-normalized raw timeout array, including path,
span, type, message, order, and multiplicity, in a content-addressed `reusable: false` telemetry
sidecar outside `semgrep-families/`. Timeout-only row drift can create different sidecars without
changing the semantic receipt when both attempts derive the same conservative family assessment.
Successful cache lookup neither reads nor depends on those sidecars: a warm hit replays the stable
schema-8 assessment and client disclosure from the reusable family artifact. A strict paired
mismatch still writes the complete attempts as a content-addressed `reusable: false` failure
artifact, and a same-key rerun executes again.

Fixpoint telemetry is no longer folded into `SEM-ERR-00`; that finding reports the exact retained
`errors[]` and `paths.skipped` populations. Each affected family instead emits one stable repo-wide
`SEM-TAINT-NA-<family>` coverage finding whose taxonomy is explicitly `not assessed`. It names the
family, exact loaded candidate taint-rule IDs, and examined scope, and explains that emitted findings
remain valid while the absence of additional taint matches is not clearance. This is disclosure,
not suppression: ordinary findings are preserved and each NotAssessed row is produced and delivered
through the conservation ledger.

The successful execution-plan and family-cache schema is 8; diagnostic evidence is schema 4 and the
enclosing phase cache is schema 5. The receipt binds `fixpoint-family-not-assessed-v1`, sorted
owned/loaded candidate taint-rule populations, the stable family assessment, routed/pairing topology,
derived-config hashes, actual argv, and every strict semantic population above. Schema-5, schema-6,
schema-7, planned-only, failed, malformed, or tampered artifacts reject before cache lookup. The pinned
inventory remains **1,033 rule entries / 846 unique rule IDs / 168 duplicated source IDs**, with
every registry ID assigned to one owner and the duplicated `direct-response-write` rule retained in
its paired singleton.

**MEASURED 2026-08-22 at `3fc7ac7d893b3beabae5daad70419a76f6c1ead9` / tree
`c87d882850313948f1d93e06023afd89c1e4f476`, Semgrep 1.173.0, pinned Carbon tree
`e00a835aacba7283925330853ee98873cda7c3a4`:** the two predeclared cold runs are
`/private/tmp/pr1954-schema8-exact-rebind-3fc7ac7/run-1.json` (SHA-256
`98e096f325f61867cfe0fff365afb829ff7b446bac42f1d3b28d17ea1517fa47`) and sibling
`run-2.json` (SHA-256
`bd47a362238f422c12c10c9686722e1be8e557147e1541f286ce14994efaaa90`). Each retained
**535 results**, **31 errors**, **6,056 scanned paths**, **37 skipped-path records**, **0 skipped
rules**, and **522 loaded rule IDs**. Their strict output, execution plan, and family-assessment
projections are identical. Both produce five family-level NotAssessed rows for
`registry-0-p-typescript`, `local-auth`, `local-base`, `local-injection`, and `local-xss`. Each raw
telemetry population contains 48 rows, retained only in 20 non-reusable sidecars; all 17 reusable
family artifacts are raw-timeout-free. The predeclared 6,181-input byte manifest remained exact
after both runs, artifact regeneration, and the final gate.

The current PartialParsing record for `TraceabilityGraph.tsx` is **79:1–79:2** on the unexpected
`}`; the older line-74 `import("./utils").IssueContainment` record is historical and a paired run
that substitutes it is rejected.

**Committed-artifact effect:** schema-8 regeneration at the accepted head preserves the already
corrected **789** findings: two complete epochs produced 789→789, 0 additions, 0 removals, 0
reclassifications, and 0 Semgrep NotAssessed rows on the calibration target. `findings.json`,
`pii-data-map.json`, `scorecard.json`, and `findings-report.json` are byte-identical across both
epochs and to the tracked files; `findings-report.json.findings` deeply equals the standalone array.
Across the full PR lineage, the earlier 811→789 movement remains exactly 22 removed duplicate SQL
placeholder renderings with no logical finding loss.

Interim #1954 notes that treat timeout rows as semantic equality evidence, parse
`[rules: N, first: ID]` into a stable receipt, include fixpoint rows in `SEM-ERR-00`, make reusable
cache hits depend on telemetry sidecars, retry or union attempts, quote schema 5/6/7 as current, or
quote 811 as the current finding count do not describe the accepted schema-8 contract. The older
1.164.0 population and matrix above remain historical measurements, not current production counts.

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
  The current schema-8 contract instead retains the schema-6 routed local-injection topology and
  paired local-xss/direct-response owners, compares strict non-timeout semantics exactly, and treats
  a fixpoint-timeout population as a family-level taint NotAssessed trigger with exact raw rows
  retained outside the reusable cache namespace.
- n=5 per repo for the population table; a 1-in-6-run dropout (the `-j 1 --timeout 0` row)
  is exactly the kind of event n=5 can miss. "STABLE at n=5" is evidence, not proof, for the
  15 stable repos.
- The 2-row parmap recall bound was measured on carbon only (the only repo with a measured
  `-j 1` reference). Whether other large repos have analogous deterministic parmap misses is
  unmeasured.
- `--x-parmap` remains deprecated/internal upstream. A future Semgrep that rejects it does not fall
  back to an unproved threaded topology: the run fails closed as incomplete (`SEM-00`) and must be
  re-measured before a replacement execution policy is accepted. The schema-8 topology receipt,
  strict paired-result controls, stable family-level NotAssessed disclosure, raw `reusable: false`
  telemetry sidecars, and retained failure artifacts hold that contract.
