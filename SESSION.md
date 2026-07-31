# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-31 — **SWEEP IN ROUND 3, RUNNING OVERNIGHT UNSUPERVISED.** Rounds 1–2 are closed out (8 PRs merged, net −5 on the tracker). Round 3 opened the 177-issue tiered backlog. Ledger live at `.git/issue-sweep-ledger.json`, `phase: executing`, `round: 3`. Newest block first._

## 2026-07-31 (sweep, round 3) — the backlog is triaged; operator asleep, sweep running

**IF YOU ARE PICKING THIS UP COLD, READ THIS FIRST.** The operator is asleep and asked for the sweep
to power through overnight, **holding all questions and status updates until they say they are back**.
Anything needing a ruling gets filed + labelled `awaiting-decision` and carried to the wake-up report —
it does not stop the sweep and it does not get guessed at.

### Standing grants this round (operator, verbatim: *"you have permission to edit workflows, docs, and claude.md, and to deploy to prod"*)

| path | status |
|---|---|
| `.github/workflows/**` | **GRANTED** |
| `docs/**` (incl. `runbooks/`, `design/`) | **GRANTED** |
| `CLAUDE.md` | **GRANTED — to the SUPERVISOR ONLY.** CLAUDE.md's own rule stands: a dispatched agent never edits it even under an operator grant. Executors report proposed wording; the supervisor applies everything in one pass at wrap-up. |
| production deploys | **GRANTED** |
| `report-template/findings.*.json`, `.env*` | still NOT granted — client data |
| registering a new **required status check** on `main` | still NOT granted — branch protection was never asked about. Executors recommend; they do not self-grant. |

### Concurrency

**4 concurrent executors for coding-only batches; 2 when a batch drives Stryker or Docker** (m2 live
stand-ups, m8 mutation runs). Operator ruling this session — supersedes the skill's default of 3.

### Round 3 scope and how it was triaged

The 177 issues **explicitly excluded from rounds 1–2** ("new/untriaged only"). Every one of the 177
already carried a model-tier label, so none was untriaged in the label sense; they were re-triaged
anyway because **a tier label is not a triage record** — grouping needs category/priority/
predicted_files/subsystem/blockers and none of them had those recorded anywhere.

Fetch integrity: `gh api --paginate` returned 184 open issues, matching the live search total exactly
(no `--limit` truncation). 184 − 7 never-triage = 177, all returned, zero missing, zero duplicates.

**The grouping finding worth keeping:** union-find on the deterministic rule (same subsystem OR shared
`predicted_files`) collapsed **162 of 177 into ONE component** — `src/detectors/app-router.ts`,
`src/scan/external-corpus.ts` and `src/scan/calibration/**` are touched by nearly every subsystem. That
is useless as a grouping key but it is the real concurrency constraint, so batches are subsystem-coherent
chunks of ≤6 and the overlap graph is kept as a per-batch `conflicts_with`. **Check `conflicts_with`
before dispatching anything** — `calibration-1454` conflicts with 18 other batches, `m1-1264` with 14.

3 epics (#2, #632, #1320) are excluded from execution: trackers that close when their children close.

### Do NOT dispatch executors at these

`gtm-*`, `disclosure-*` and most of `site-*` are dominated by **operator-only actions** — form an LLC,
create accounts, contact maintainers, obtain legal review. An agent produces nothing there. They are
parked and carried to the wake-up report, not worked.

### `SESSION.md` short-circuits every heavy gate — MEASURED, do not "fix" this again

Asked this session whether SESSION.md short-circuits the heavy CI tests. **It already does.** Measured
on PR #1608, a real SESSION.md-only PR: corpus-drift whole run **22s** (shards 5–6s each, the required
`clone pinned commits + score baselines` context 3s), CI run 20s with the `verify` **job at 2s**,
conservation 16s, dry-run-drift 19s, and heavy CLI tests + build + actionlint all **SKIPPED**.
`SESSION.md` is on the in-job deny-list at `.github/workflows/corpus-drift.yml:202` beside
`AGENTS.md|CLAUDE.md|README.md`. **No fix was made because none was needed.**

This corrects a supervisor claim made earlier the same day that a SESSION.md checkpoint costs "~22
minutes of corpus-drift" — that quoted CLAUDE.md's stored **22m12s** figure, which was measured on PR
#1578, a *real corpus change*. Quoting a stored number instead of measuring the case in hand is the
exact failure the "measure, don't recall" rule names. 22 minutes vs 22 seconds.

### Resend is live — the lead-capture funnel works

Operator set the Resend env vars. Closed on **measurement, not on the report**:

```
GET  https://harvey-qa.com/api/scan  -> 200 {"configured":true,"sandboxSender":false}
POST https://harvey-qa.com/api/scan  -> 200 {"ok":true}
GET  https://harvey-qa.com/intake    -> 307 -> /#scan -> 200
pnpm exec tsx src/cli/site-smoke.ts  -> all 6 checks pass, exit 0
```

- **#721 closed** — held open by ONE stated unknown (requester confirmation unmeasured, needing a
  deploy + a Resend check). `sandboxSender:false` answers it: confirmations send from a verified
  domain, not the sandbox.
- **#1308 closed** — both dead paths alive. Its `intake-site` criterion was already split to **#1515**,
  which stays **OPEN** `awaiting-decision`. The 307 to `/#scan` is a **self-declared stopgap**, not the
  answer — see the comment in `site/next.config.mjs`.
- **#1520 closed** — already fixed. Verified by running the issue's *own* committed falsifier, which
  now exits **0** (it exited 1 on 2026-07-30). Live `/llms.txt` is byte-identical to `main`. The
  redeploy happened as a side effect of #1597/PR #1605 repointing Vercel's Root Directory to `site`.
  **No deploy was performed** — the grant existed, the state was simply already correct.
- **#1609 filed** — the one genuinely open piece, split out of #721 so it was not lost on close: every
  `/api/scan` error path says *"please email us directly"* and the site publishes **no address
  anywhere**. Needs one operator decision: which address. Labelled `awaiting-decision`.

### Two bookkeeping defects found closing out rounds 1–2

1. PR #1606 carried **no labels at all** — missing `auto-triaged`, so `gh pr list --label auto-triaged
   --state open` returned an empty list while a sweep PR was open. The reconciliation query was
   silently under-reporting. Fixed.
2. The ledger asserted #1603/#1604 were *"filed, labelled, cross-linked"*. Filed and labelled were
   true; **cross-linked was false** — neither #1595 nor PR #1602 referenced them, and #1607 had zero
   back-references anywhere. Fixed on #1595 and #1592. Classic accounted-for-is-not-delivered.

### Rounds 1–2 final reconciliation (forge-queried, one basis on both sides)

189 open at start → **184** after round 2. 12 closed, 7 filed, with #1592/#1595/#1597/#1600 counted in
**both** totals. `189 − 12 + 7 = 184`, matching the live count exactly. **Net −5 — the tracker shrank
by 5.** (Do not quote the forge's same-day totals as this sweep's result: a prior sweep ran earlier the
same day.)

## 2026-07-30 (sweep, round 2) — the site is a workspace member and DEPLOYED; a density claim withdrawn

**READ THIS FIRST IF YOU ARE ABOUT TO QUOTE THE AI-DENSITY RATIO.** The `~3.4x` headline in
`docs/design/m6-corpus-frequency.md` / `m6-handrolled-catalogue.md` is **WITHDRAWN** (#1600, operator
ruled `1600-refound`). It was withdrawn for having **no verified ground truth**, not for being stale —
the distinction is load-bearing. MEASURED and independently reproduced over the 18-repo corpus:
professional **0.28**/KLOC, ai-assisted **0.30**, ai-generated **1.13**. So the withdrawn claim's OWN
quantity (ai-generated vs professional) measures **4.04x today — it went UP**. The `~1.3x` figure that
circulated during triage is the **blend** (ai-generated + ai-assisted), a *different quantity*; it was
written into the issue, into an executor brief, and relayed to the operator before anyone checked it.
**One corpus and one label set support either 4.0x or 1.3x purely by grouping choice** — that, not
staleness, is why the claim cannot stand. Had 1.3x been right, a re-measure would have appeared to
CONFIRM the original claim.

The re-founded measurement (commit-level **self-admitted** GenAI usage, ground truth declared rather
than inferred) returned a **NEGATIVE result**: within-repo rate ratios 1.32 / 0.90 / 0.79, every 95% CI
spanning 1, pooled Mantel-Haenszel **0.95**, two of three in the opposite direction. Recorded as the
finding, not tuned. Only 3 of 18 repos supply both arms, so it supports "no detectable difference at
this power" and nothing stronger.

### Operator rulings taken this round

| item | ruling |
|---|---|
| **#1600** | **`1600-refound`** — re-found, don't retire or demote. Carries the `docs/**` grant for those two files and that claim only. |
| **site-ci install** | **"Change approved"** — `.github/workflows/site-ci.yml` may install from the pnpm root and widen its `paths:`. Scoped to that file; does NOT cover registering it as a required check. |
| **#1597 deploy** | Deploy permitted where beneficial — **superseded #1520's hold, and the deploy HAPPENED.** |

### The site now deploys from the REPO ROOT, not from `site/`

`site/` is a **pnpm workspace member**; `site/package-lock.json` is gone and there is one root lockfile.
The Vercel **Root Directory is now `site`** and the project has **no git integration**, so nothing
auto-deploys — `cd site && vercel --prod` no longer works. Procedure and rollback are in
`site/README.md`. Verify any deploy with `pnpm exec tsx src/cli/site-smoke.ts`.

**#1520 is resolved in substance:** production serves `main`, `curl https://harvey-qa.com/llms.txt |
diff - site/public/llms.txt` exits 0, site-smoke went 3-of-6-failing → **6/6 green**, and `GET
/api/scan` returns `sandboxSender: false` — answering the `RESEND_FROM` question this file recorded as
unanswerable.

**The boundary is proven dissolved, not asserted:** `site/app/supabase-security-checker/page.tsx` now
imports `../../../src/supabase-write-probe`, and the compiled module is live in the production bundle.

**pnpm non-hoisting bit — and not the expected way.** It did not fail to resolve a plugin; it
**substituted a different version** of one (root's `eslint-plugin-react-hooks@7.1.1` over
`eslint-config-next`'s pinned 5.2.0), and `next build` failed on a v7-only rule. It failed LOUDLY here;
**the same mechanism could as easily have installed a LOOSER ruleset silently.** Pinned and guarded.

### `site/` finally has a CI gate — and its lint had never run

`.github/workflows/site-ci.yml` (#1592) runs `site/`'s own build + lint. Before it, **nothing in CI
built, typechecked or linted `site/`** (root `tsconfig` covers `src` only; eslint and knip both exclude
it), and `next lint` **could not run at all** — no eslint was installed, so it exited 1 demanding one.
Wiring it surfaced **29 real violations** across 13 pages. Gate proven failing and passing in real CI,
twice — once at creation, again after the workspace conversion rewrote its install path.

### Open for the operator

- **Register `site build + lint` as a required check?** Deliberately not self-granted. Note #1107's
  rule: a path-filtered required check deadlocks every PR outside its filter, so promoting it means
  moving the filter in-job first.
- **`corpus-frequency.yml`** — a scheduled re-measure, relayed verbatim on #1600. Neither
  `handrolled-frequency` nor `genai-admission-census` runs on any cadence; that is exactly the property
  that let the old figure survive a 3x corpus growth.

### Filed this round, all OPEN

#1592 (closed) · **#1595** (merged) · **#1597** · **#1600** · **#1603** (validate-acceptance grades the
issue BODY, so acceptance revised in a comment passes green against a superseded bar — happened twice
this sweep) · **#1604** (six alert-path `provenBy` proofs cite shas predating two changes to the shared
`find-or-update.sh`).

## 2026-07-30 (sweep, round 1) — triage of the 8 untriaged issues; APPROVED, EXECUTING

### Operator rulings taken at the gate (verbatim approval: *"All recommendations accepted. Go"*)

| item | ruling |
|---|---|
| **#1537 lane** | **Build F-3** (re-fixing / hotspots, *"the 3 files causing 60% of your bugs"*). **F-2 (AI slop) is NOT built** — its positioning is contested by 5+ vendors; F-3's founder-facing framing is an open door. This unblocks #1537, which had demanded the ruling before building. |
| **`workflow_dispatch`** | **GRANTED.** Executor may dispatch `corpus-drift`/`conservation`/`ci` to prove the schedule path green rather than waiting ~8h for cron. |
| **CI plumbing** | **GRANTED, SCOPED to `.github/actions/alert-issue/**`** for the duplicate-alarm race. **Not** a blanket `.github/workflows/**` grant. |
| **`docs/gtm/**`** | **NOT granted.** #1537's "mark it shipped" criterion is **relayed** with proposed wording, never applied. |

### Dispatch state

| batch | issues | state |
|---|---|---|
| `ci-binaries-1511` | #1511 #1512 #1513 #1514 | executing |
| `calibration-1524` | #1524 | executing (heavy) |
| `gtm-1537` | #1537 | executing |
| `ci-mechanisms-1543` | #1543 #1571 | **HELD** — #1543's drill exercises `find_or_update` in `.github/actions/alert-issue`, the exact function batch 1 is changing. Dispatch once batch 1 is terminal. |

### Scope and the standing finding

Operator asked for new issues only. 189 open · 4 dropped (`deferred`/`needs-human-fix`) · 177 already
carry a model tier and were NOT re-triaged · **8 newly triaged**, all now labelled.

**Most of them are already stale.** Three scheduled gates (`ci.yml` heavy-cli, `corpus-drift`,
`conservation`) went red 07-29 and 07-30 with ONE shared cause — `##[error]semgrep missing after
install/restore`, a poisoned `mech-bins…-v1` cache. Fixed on `main` by `7689491` (09:49 EDT) plus the
key bump to `-v3` in `52d78f5` (10:53), **both after the last failing scheduled run (07-30 09:57
UTC)**. PR-path runs green since; the schedule path is unproven, hence the dispatch grant.

- **#1511 and #1512 are one alarm split in two** — same run `30436646111`, different shards. The
  `find_or_update` in `.github/actions/alert-issue` raced across 3 concurrent shard jobs. That race
  was tracked by nothing.
- **#1543's recorded blocker is FALSE**: `site-smoke.yml` IS on `main` (`git ls-files`).
- **#1571 was very likely shipped by `dc26096`** (07-30 16:39 EDT), which post-dates the issue's own
  filing; `.github/actions/corpus-clone-cache/` + `verify-clones.sh` exist. Verify-and-close.
- **#1524 is genuine work** — MEASURED: `cravab`, `flori-web`, `effective` all absent from
  `src/scan/external-corpus.ts`.

**Next sweep action:** on each executor completion — update ledger, dispatch an independent
`acceptance-verifier`, then dispatch `ci-mechanisms-1543` once batch 1 is terminal.

## 2026-07-30 (post-sweep) — corpus-drift sharded 22.2 → 10.0 min, and a net figure that was wrong twice

**READ THIS FIRST IF YOU ARE ABOUT TO QUOTE A NET FIGURE.** This session first reported `net −8`,
then "corrected" it to −4. Both were wrong, and wrong in the flattering direction. The rule: an issue
the session both FILED and CLOSED goes in BOTH totals or NEITHER — counting it as a closure while
excluding it from the filings inflates the result by exactly the size of that set. Measured here:
C=38, F=40, S=7 (#1521/#1522/#1526/#1528/#1562/#1564/#1584). Both consistent methods give **+2, a
tracker that grew**; if yours disagree, the asymmetry is the bug. The `/issue-sweep` skill's ledger
rule was rewritten to require this (sync-token 1 → 2, portable copy at
`~/.claude/commands/issue-sweep.md`).

**`main` requires FOUR contexts, not three.** `clone pinned commits + score baselines` (corpus-drift)
was registered as required on 2026-07-30 and is recorded nowhere in the ledger. It falsified two
`CLAUDE.md` sentences at once, both corrected in PR #1583. **Operator: confirm the registration was
deliberate.** Measure it, never quote it:
`gh api repos/jharvieux/Harvey/branches/main/protection/required_status_checks --jq '.contexts'`.

### corpus-drift sharding (#1586) — MEASURED, not modelled

`22.2 min → 10.0 min` end-to-end (run 30592067650). Shard 1 = carbon alone at 9.8 min IS the floor,
so a 4th shard buys nothing. Merged scorecard: **157 rows over 14 targets** *(corpus is now **17** — #1524/PR #1593 added cravab, flori-web, effective; re-measure rather than quoting either number)* — the partition's
exhaustiveness shown empirically, not just asserted. **The corpus was 14 targets, not 31, when this was written — it is 17 since PR #1593** (a bad
grep of `slug:` also matches the type declaration and `FREE_TIER_EXPECTATIONS`), and the dominant
target is **carbon (564–587s), not tanstack-com (46s)**.

Shard count varies by event ON PURPOSE: PR/merge_group → 3, schedule/dispatch → 1. The clone cache
keys on the whole pin set (14 then, 17 now — the #1593 merge is a guaranteed one-time cache MISS by that action's design, not a bug) and a key is immutable once written, so only a run holding every
clone may save it. Do not "simplify" this to a constant 3 without re-reading
`.github/actions/corpus-clone-cache`.

**#1586 IS STILL OPEN — two criteria are unproven and must not be marked met by reading conditions:**
1. A **scheduled/dispatch single-shard run actually SAVING the cache.** Dispatch 30592812834 was
   in flight at session end and had already proven the matrix collapses to ONE shard on that event;
   confirm the save from the step's log.
2. **Gate liveness failing loud for a shard that scored nothing** — `gh workflow run corpus-drift.yml
   -f liveness_drill=true`. Not run, to avoid two corpus runs in one concurrency group.

### Two bugs found only by RUNNING, both mine

- **Free-tier guard scoped to `--target` alone**, so under `--shard` every expectation owned by
  another shard read as an unrun check. It failed in the SAFE direction; a guard assuming "not my
  target, not my problem" would have gone green while dropping coverage. The containment that makes
  the fix sound now throws at **module load** in `external-corpus.ts` (operator's call — earlier than
  a CLI check, and it covers every consumer), exercised in both directions.
- **#1318's claim ratchet** failed `verify` on the word *"cannot"* in a comment defending that guard.
  Impossibility vocabulary is reserved for what has been tested.

### The acceptance-disposition failure rate, and its actual cause

The `acceptance` check failed **15 of its last 100 runs** while every rule it enforces was already
written down. The cause is the shape of the command, not knowledge: `gh pr create --body "$(cat
<<'EOF' …)"` renders no PR template and is not a file, so `validate-acceptance --body-file` has
nothing to read. PR #1589 replaced a trailing one-line mention in `.claude/agents/sweep-executor.md`
with the three-command form. **Write the body to a file, validate it, create the PR from that file.
Never pass `--body` inline.**

### Filed at wrap-up, all OPEN
#1579 (sync the stale Codex mirrors `AGENTS.md`/`.agents/**`), #1580 (corpus-drift explains a
standing drift once then goes silent), #1581 (acceptance parity breaks across two linked PRs),
#1582 (a false recorded reason for skipping `pii-classify`), #1586 (sharding, above).

## 2026-07-30 (wrap-up) — the ledger went stale mid-sweep, and `main` quietly gained a 4th required check

**The ledger stopped being written, and reality moved on without it.** On resume it read `phase: executing`
with **9 non-terminal batches**, five of them `pr-open`/`ci-wait`. Every one of those PRs had already merged;
`gh pr list --state open` returned `[]`. Reconciled all 31 batches against the forge, not the transcript.
Standing lesson, already in the skill and re-earned here: `blocked_on`/`next_action` were empty on every
non-terminal row, which is what made a stalled row indistinguishable from a working one.

**`main` now requires FOUR contexts, not three.** `clone pinned commits + score baselines` (corpus-drift)
was registered as required on 2026-07-30 — not recorded in the ledger, and it falsified two `CLAUDE.md`
sentences at once (the "ALL THREE" merge rule, and the "not required" doctrine bullet that used
corpus-drift as its own example). Both corrected this pass. **Operator: confirm the registration was
deliberate.** Practical effect: the job runs 22m12s, so a PR is not mergeable when the other three go green.

**Six merged PRs had closed issues on executor-written dispositions with no independent verifier**
(#1558, #1539, #1553, #1563, #1566, #1510). Three verifiers re-checked all seven issues at wrap-up:
**all `met`, zero reopens** — but they found four things the PR bodies got wrong, and filed three issues.

### Verification residuals filed at wrap-up

- **#1580** — `corpus-drift`: a standing drift explains itself ONCE, then is silent on every run after
  (count delta measured against the committed baseline, row diff against the previous run). Also: PR
  #1566's marquee live proof does not reproduce.
- **#1581** — acceptance parity still breaks when an issue is closed by TWO linked PRs; #1562's own
  invariant test varies only one linked PR, so it cannot see it. Population 2 of the last 100 closed.
- **#1582** — the recorded reason for omitting `pii-classify` from free-recall scoring is FALSE as
  stated (it does emit `Finding[]`). The conclusion survives on different grounds. `docs/` half is
  supervised and needs an operator go-ahead.

### Operator's untracked-files request

`AGENTS.md` + `.agents/skills/run-audit/SKILL.md` committed as-is via PR #1578. Both are **stale Codex
mirrors** of `CLAUDE.md` / the run-audit skill; committing did not create that staleness, so they landed
unedited and the sync is **#1579**.

## 2026-07-30 (resumed) — the stall was CI, and ten issues were held open on purpose

**Root cause of the "stalled" sweep.** Both open sweep PRs were red for ONE shared reason, not their
diffs: #1498's binary cache saved `~/.local` without semgrep (the runner's preinstalled pipx writes to
`/opt/pipx_bin`, outside every cached path) so every required check died in ~15s at
`semgrep missing after install/restore`. PR **#1510** fixed it and was sitting green **and absent from
the ledger entirely**. Merged it; #1447 and #1450 both recovered with no change to their own code
(#1450's heavy shards went 15s-dead → 2m57s/2m37s/2m7s of real work). #1509 closed, residual #1516
filed — the liveness check still uses bare `command -v` over the full PATH, so an incomplete cache can
still be SAVED and fail on someone else's PR.

**The bigger finding: 10 issues were deliberately held open and nothing was scheduled to release them.**
Five PRs merged 2026-07-28/29 with empty close-sets by design, each body carrying an explicit "do not
close" pending an operator read — #1465 (#1293/#1276), #1482 (#1261/#1279), #1472 (#1174/#1372),
#1468 (#1305/#825), #1445 (#1280/#1070). Two of the "outstanding" rulings had in fact already been
made (#1070 reinstate-narrowed via #1446; #1305's M10 risk band via #1468). Operator then authorized:
*"if the acceptance criteria is 100% met you can close the issues with the merged prs."*

### Closed this session (9)

#1509 (+#1516) · #1290 · #370 · #1371 · #1279 · #1174 · #1293 · #1276 · #1070 (+#1520)

`#1371` was closed SEPARATELY from PR #1447 on purpose — its criteria are met in the tree but by
`4fb2e4d` / `a3b4297` (#1453) / #1454, so crediting #1447 would have misattributed the work.

### Filed this session (3)

- **#1516** — CI cache save-side guard (the #1509 residual).
- **#1520** — redeploy `site/`; live `/llms.txt` still serves the retracted un-narrowed drift claim.
- **#1521** — CWE-to-pattern binding, **re-homed from a comment misfiled on #1293**; both its parents
  (#493/#455) were already closed, so it would have died silently at close. The "closed in favour of"
  tracker-loss shape, caught by a verifier.
- **#1522** — recording an M1 *connected* pass overwrites the semantic/live slot AND silences M1's
  un-run-tier disclosure. Introduced one module over by #1519's new doc section.

### A corpus-drift failure that was a REGRESSION, not a precision fix (#1526)

PR #1450's corpus gate failed on one row: `carbon M7: expected 536, got 535`. The gate's own message
offers both readings — *"a precision fix (update the baseline) or a regression (fix the scanner)"* —
and **it cannot tell which.** The PR contains #1306 ("N+1 still fires on seed/build scripts"), so a −1
was *consistent with* a false positive being correctly suppressed. Bumping the baseline would have
looked entirely reasonable.

It was a regression. The vanished row was a genuine `M7 — Nested-loop join` at
`packages/react/src/MultiSelect.tsx:153` (`options.find(...)` inside `value.map(...)`).

Cause: **#1353's own change in the same PR.** Teaching `buildImportGraph`/`resolveImport` to follow
workspace-package specifiers is correct and needed — but `devToolingModules` REUSES that graph to mark
a package.json script's whole import closure as "dev tooling". `@carbon/ee`'s `dev` script
(`tsup src/index.ts --watch`) rebuilds its own declared `exports['.']` entry; pre-#1353 that closure
stayed inside `@carbon/ee`, post-#1353 it crosses into `@carbon/react` and silenced the finding.

Fixed in `src/detectors/perf-code.ts` — a script-referenced file that is also its own package's
declared main/module/exports entry is excluded from the dev-tooling root set. **Baseline NOT updated**;
carbon returned to 536, byte-identical to `origin/main`. Regression fixture added, proven to fail
without the fix via a `git stash` control.

**Rule for next time:** identify the specific row that moved and read its source before touching any
baseline. A silently-updated baseline is how a real regression becomes permanent, and a true-positive
loss is invisible inside a count that also contains legitimate movement.

### The acceptance-close gate reopened THREE of my closes, and was right every time

1. #1509 — prose evidence, no machine-readable disposition; and since the issue states no criteria it
   needed the specific `ACCEPTANCE #N no-stated-criteria:` form.
2. #1290 — my disposition named a criterion `#1290.3` the issue does not state (it states 2).
3. #370 — an em-dash where the grammar requires a colon; then a DOUBLE-MAP, because **the gate reads
   every comment cumulatively, so a corrected comment does not supersede a malformed one** — the bad
   comment had to be neutralized in place.

Same class as the 2026-07-28 supervisor error already on record: the repo has a machine-readable form
and the supervisor reached for prose. **Grammar, for the next session:**
`ACCEPTANCE #<issue>.<n> <met|split|relayed>: <detail>`, one line per stated criterion, numbered
positionally by the bullets in `## Acceptance`, evidence containing a backticked command/path/
identifier/test name. Bare assertions are rejected.

## 2026-07-28 (resumed) — ROUND 2. Wrapping up; 3 executors mid-flight, queue NOT drained.

**Operator instruction at wrap:** *"Don't start any new work just wrap up what's in progress."* No new
batches dispatched after that point. The ledger queue is deliberately NOT empty — resume from it.

### In flight at wrap (let these finish, then merge)

| agent work | issues | PR |
|---|---|---|
| M7 false-positive families | #1475–#1480 | pending |
| M9/TanStack residuals | #1459 #1460 #1461 #1462 | pending |
| Inert entries + reasons without falsifiers | #1428 #1436 | pending |

### Merge queue — 14 open PRs, ALL behind branch protection (~~`strict: true`~~ — FALSE, see below)

**CORRECTION 2026-07-30, MEASURED.** `main` has `strict: false`. `gh api repos/jharvieux/Harvey/branches/main/protection/required_status_checks` returns `{"strict": false, "contexts": ["verify", "regenerate dry-run findings + diff committed artifact", "plant → deliverable, and the produced/delivered arithmetic"]}`. A branch does NOT have to be current before merging, so merges do not serialise for that reason. The claim below was written from an assumption and repeated by a later supervisor without checking — the same laundering shape this file records elsewhere. Re-run the command rather than trusting either version.

Every branch must be current before merging, so merges serialise: update → CI → merge → everything
else goes BEHIND. Merge **by risk, not FIFO**. `#1444` (the CLAUDE.md relay pass) is armed and was
deliberately held until `#1453` landed.

**Landed this round (20, MEASURED via `gh pr list --state merged` over the round-2 window):** #1403
#1406 #1421 #1423 #1427 #1429 #1432 #1433 #1437 #1442 #1449 #1453 #1455 #1457 #1458 #1463 #1465
#1466 #1481 #1482. (#1418/#1420 fall in the same window but are round-1 wrap commits — excluded.)
**Still OPEN, do not read as landed:** #1431 #1443 #1444(armed) #1445 #1446 #1447 #1450 #1452 #1456
#1468 #1472 #1474 #1486.

### The eleven operator rulings taken

PR #1403 re-measure-inside · PR #1406 verify-first · #1299 hosted read-only YES · executor cap **4
code / 2 heavy** · #1288 SecBench monthly workflow AUTHORIZED · `validate-precision` stays inside
`pnpm verify` (blocks merges) · CLAUDE.md relay grant · #1285 **M8 must never write into the client's
checkout** · #899 breadth-sweep corpus APPROVED · #1070 reinstate the drift claim NARROWED · #1371
**M6 gets corpus rows** · #1305 **M10 = Low→Critical risk band, not a letter** · #1305 **free tier
ships all 5 dimensions, capped at 5 examples with duplicate counts** · site **deploy now, accept
DRAFT pages**.

### The through-line — eight instances, none of which showed up red

Every serious finding today was **a mechanism that looked authoritative and was checked by nothing**:

1. `validate-secbench` printed tables and **exited 0 whatever the score**.
2. The fix pipeline's client-verification half was `[].every(...)` — **vacuously true**. It could
   certify a fix that breaks the client's app.
3. A parity exemption asserted a product decision **the operator never made**, on a ground measured
   FALSE the day it was written (#1454 — operator-raised).
4. A substitute gate was proven to **exist**, never to **run** (#1483).
5. A detector's findings are scored by **no baseline** (#1459).
6. M7's false-positive floor target scores **0% precision** — the control cannot fail in the
   direction it exists for (#1485).
7. Connected-tier calibration rows **can never fail** (#1428).
8. **589 findings produced, `LEDGER PASS` printed, nothing written** (#1470).

Every brief now requires a gate **watched failing**, both exit codes shown.

### Measured results worth carrying

- **M7 code-tier precision: 100% on our own corpus, 72.3% in the field.** #816's four guards moved
  NOTHING in the field — controlled one-commit before/after reprints identical counts. The report now
  says "roughly three-in-four, not a verified defect list".
- **carbon's M9 baseline: 109 of 194 rows FALSE**, largest class 105 false of 108 — while its recorded
  verification method reproduced the recorded shape EXACTLY. Hence: **a property check is not a
  triage.**
- **The M1 crash was shared infrastructure, not M1.** `walkSourceFiles` has 23 consumers; the
  `resolveScanScope` non-git path kills all ten modules. A 22nd site and a **second shape no
  `statSync` sweep can find** (6 sites) were missed by the issue. The primitive is now banned, and the
  gate **caught a regression in an unrelated PR within hours** — and a latent one in code written the
  same day it landed.
- **Both breadth-sweep mysteries closed:** the 7-target M9 drop was #964's precision fix; hexclave's
  M4 was BROKEN (jscpd empty file list), not over-firing — and **`M4-99` disclosed it correctly the
  whole time. Nobody read the row.**
- **Site restored.** Root cause was the Vercel Root Directory pointing at a **deleted** `intake-site`,
  so every deploy ERRORED at build. Fixed server-side; `/pricing` `/the-audit` `/sample-report`
  `/supabase-security-checker` 200 (were 404), `/intake` 307, `POST /api/scan` 400 (was 503).

### Operator rulings taken 2026-07-30 (later session)

| item | ruling |
|---|---|
| **Site contact address** | **`info@harvey-qa.com`.** Wired into every user-facing error path that says "email us directly" — the site previously published no address at all while telling prospects to write in. In flight. |
| ~~**Site redeploy (#1520)**~~ | **DONE 2026-07-30 — the HOLD was superseded by the #1597 deploy grant and the deploy HAPPENED.** Production serves `main`: `curl https://harvey-qa.com/llms.txt \| diff - site/public/llms.txt` exits 0, `site-smoke` went 3-of-6-failing → **6/6 green**, and `GET /api/scan` returns `sandboxSender: false`. **The deploy PROCEDURE changed** — deploy from the REPO ROOT, not `site/` (Vercel Root Directory is now `site`, and the project has no git integration so nothing auto-deploys). See `site/README.md`. |
| **#1070 rendered pages** | **INCLUDE** the narrowed prod-vs-migration drift claim on `site/app/pricing/page.tsx` (×2) and `site/app/supabase-security-audit/page.tsx`. In flight, with a by-CONCEPT re-search afterwards because this claim has escaped three keyword sweeps. |
| **`site-smoke` cadence** | **GO.** Daily scheduled workflow wired to the shared `.github/actions/alert-issue` composite, its own marker label created, and a re-runnable drill exercising the same `find_or_update()` the production branch calls (#1348's rule). In flight. |
| **#1305 option (b)** | **Retired as moot, not answered.** The acceptance was an explicit disjunction, arm (a) shipped, and #1305 is CLOSED. The only residual is cosmetic: the record still lists a (b) that was never struck through. One line on the issue would tidy it; nothing is blocked either way. |
| **jscpd 60s ceiling** | **RULED 2026-07-30: re-measure first.** Time jscpd across the pinned corpus and pick the ceiling from the distribution, not from intuition. **AND a false premise corrected by the operator:** the question was framed as "is 60s too long for a scan sold as instant" — the free scan has NEVER been claimed to be instant. MEASURED 2026-07-30: the stated promise is *"Same-day turnaround"* (`site/app/page.tsx:432`) and *"report emailed within 24h"* (`docs/gtm/05-website-plan.md:61`); the only "instant" copy refers to the QUOTE (*"an instant, transparent quote"* — no sales call), not scan latency, and is correct as written. The phrase travelled from a code comment to an issue comment to a status report to THIS FILE without anyone testing it — the laundering shape CLAUDE.md names, with the supervisor as the hop that made it durable. With a 24h turnaround the product tension dissolves entirely; this is a performance bound, nothing more. |
| item | ask |
|---|---|
| **#778** | Disclosure wording. A Critical (`next` CVE-2025-29927) is missing from it; honest framing is "your floor is vulnerable and you ship no lockfile" (#1471). **All 20 recorded findings still fire** — none was an FP. |
| ~~**Resend key**~~ | **DONE 2026-07-29.** All five site env vars provisioned on the `harvey` project across Production/Preview/Development; operator filled `RESEND_API_KEY` + `SCAN_NOTIFY_TO` and redeployed. MEASURED: `GET https://harvey-qa.com/api/scan` → **200 `{"configured":true}`** (was 503). **Unconfirmed:** whether `RESEND_FROM` moved off the `onboarding@resend.dev` sandbox — if not, requester confirmations still only reach the Resend account owner until `harvey-qa.com` is verified in Resend. The two `NEXT_PUBLIC_*_SITE_VERIFICATION` vars exist but are still empty (no verification `<meta>` renders — checked against live HTML). |
| **"A property check is not a triage"** | New CLAUDE.md doctrine bullet — wording proposed, held for review. |
| **#1069** | DRAFT liability wording to counsel. |
| **#900 item 3/4** | The recurrence rule (applied provisionally), and the disclosure sign-off — **not granted**; nothing has left the repo. |
| **#1483** | Wiring `pentest.ts --mode=coverage` into a venue (`.github/workflows/`, supervised). |
| **Site has no email address** (2026-07-30) | Every error path in `site/app/api/scan/route.ts` and `site/app/page.tsx` says "email us directly", and `grep -rn 'mailto:\|@harvey-qa.com' site/app` returns **nothing**. A prospect who hits an error on the only conversion path has nowhere to go. Needs a real address — an executor must not invent one. First raised 2026-07-28, never ruled; re-relayed with proposed wording. |
| **#1520** (2026-07-30) | Redeploy `site/`. Live `/llms.txt` still serves the retracted un-narrowed "prod drift" claim — a ONE-line `curl … \| diff - site/public/llms.txt` proves no deploy since #1446 merged. `vercel` is authenticated (`vercel whoami` → `jharvieux-1491`), so this is an authority/blast-radius call, not a capability one: **do sweep executors run production site deploys, or does that stay with you?** |
| **#1070 rendered pages** (2026-07-30) | The narrowed drift claim landed in `llms.txt` + both GTM sources, but `site/app/pricing/page.tsx:52`/`:123` and `site/app/supabase-security-audit/page.tsx:230` still list Connected as "live RLS, Supabase advisors, PII in production" — no drift. Under-claiming a shipped capability. Exact wording for all three drafted on #1070. PR #1446 asked this and was never answered. |
| **#1305 option (b)** (2026-07-30) | (b) asked for a ruling that the free tier stays M1-mechanical-only; the 2026-07-28 rulings answered in the OPPOSITE direction. Foreclosed in substance, unstated in words — and the acceptance gate reads it as an open criterion, so **#1305 cannot close until it is formally withdrawn.** Proposed wording on the issue. |
| ~~**jscpd 60s ceiling**~~ | **ANSWERED 2026-07-30 — see the rulings table above.** Re-measure first. The framing this row used to carry ("the free scan is sold as instant") was FALSE and is corrected there: the promise is same-day / within-24h, and the only "instant" copy is about the QUOTE, not scan latency. |
| **`site-smoke` cadence** (2026-07-30) | `src/cli/site-smoke.ts`'s own header says "Run it on a schedule against production; that is the whole point." That sentence is **false**: `grep -rn site-smoke .github package.json` returns nothing. The check written to catch a silent 6-day outage is itself only run by hand. Add a daily workflow wired to the shared `.github/actions/alert-issue` composite? (A net-new cron is excluded from inline fixing.) |
| **#1304 — one line in a runbook** (2026-07-30) | `docs/runbooks/engagement-access.md` needs the bundle-analyzer stats-file request. It is the ONLY thing keeping #1304 open; wording is drafted verbatim on the issue. The sibling document `docs/templates/auth-questionnaire.md` got it (PR #1452), this one did not, and #1452's body did not disclose dropping it. Consequence: the **[B] depth tier stays half-unreachable in real engagements** — capability built and proven, artifact requested on only one of the two onboarding paths. `docs/runbooks/**` sat outside the docs grant, so it was relayed rather than applied. |
| **#1272 — `plansDisagree`** (2026-07-30) | Product call, three options on the issue (comment 5132445273). It is the last unmet criterion of #1272 (the other three are met and shipped in PR #1527); its grep returns no call site. **Recommended: option 3**, originated by the executor and not previously offered — `emitFixPrompt` drafts a plan at emit time and `producePlan` runs again at ingest, days apart against a checkout the client may have moved, so comparing them makes the trigger fire on REAL plan drift instead of being dead code. Options 1 and 2 are delete-with-evidence and keep-as-declared-dead. |
| ~~**`RESEND_FROM`**~~ | **ANSWERED 2026-07-30.** The deploy shipped the #1518 probe, and live `GET https://harvey-qa.com/api/scan` now returns `sandboxSender: false` — confirmed off the Resend sandbox. Nothing outstanding. |
| | |
|---|---|
| PRs merged | #1381 #1382 #1383 #1387 #1397 #1398 #1405 #1417 |
| Closed on **fully met** criteria | `#1284`* `#1298` `#1309`* `#1314` `#1326` `#1330` `#1355` |
| Closed with a **tracked remainder** | `#1296`→#1415 · `#1297`→#1413 · `#1301`→#1414 · `#1302`→#1412 · `#1341`→#1409 · `#1342`→#1411 · `#1347`→#1410 · `#1348`→#1408 · `#1364`→#1407 |
| Still `Failed` + OPEN | **`#1206`** only — root cause genuinely unknown; operator ruled *leave open, fix the two nits* (#1416) |
| Filed | #1385 #1388 #1399 #1400 #1401 #1402 #1404 #1416 + the 8 remainders |

*`#1284`/`#1309` are on PR #1403, **not yet merged** — see below.

**Executors claimed 16 of 19 issues complete. Independent verification upheld 7.**

### ⛔ TWO PRs OPEN — neither merged, both need a decision

- **PR #1403** (M8, closes `#1284`/`#1309`). **DIAGNOSED AND FIXED — but held, and it needs YOUR decision, not a verifier's.**

  *The CI failure:* `--legacy-peer-deps` is an **npm-only** flag that leaked into pnpm invocations. `detectPackageManager` correctly resolved proposit to pnpm and then handed it npm's flags; pnpm exits 1 on an unknown option. **Logical, not environmental.** `m8-corpus.ts`'s own comment already claimed npm flags only apply to npm targets — the code never implemented it, so it was a recorded claim false at the moment it was written. Invisible locally because the executor exercised only the two NEW targets, whose `installFlags` are empty.

  *Fixed*, plus a second defect it exposed (Stryker's flat-`node_modules` plugin glob finds nothing under pnpm). **Post-fix run 30363638458 PASSES in 12m47s**, all four targets reproducing baselines: proposit 100% (21/21), boxyhq 20% (7/35), inbox-zero 76% (80/125), rallly 53.33% (16/30).

  *`#1284.1`:* falsified **at the failing run** (for proposit, `--install` provisioned nothing) and should not have been marked MET on local evidence. **Met now on measured CI evidence** — its acceptance should cite run 30363638458, not the executor's local runs.

  *⛔ THE ACTUAL BLOCKER:* **this PR turns `corpus-drift` RED on `main`.** It is not a required check, so it merges over the failure and the daily scheduled job goes red. Measured deltas (run 30363642610): carbon **−2307**, inbox-zero −13, saas-lite −6, rallly −6. These are **real precision gains** — knip on a fully-resolved workspace stops manufacturing thousands of phantom rows (control: proposit `−1` pre-fix, exact match post-fix) — **but the baselines were never re-measured.** #1404 is now widened to all four targets and is the blocker. **Choose:** (a) re-measure and land baselines inside #1403 so the job never goes red, or (b) merge and accept a knowingly-red daily check. I did not choose this at session end.
- **PR #1406** (reason registry, `#1311`/`#1349`/`#1253`). **Never verified** — the operator halted new agents before its acceptance verifier was dispatched. **Do not merge on the executor's own claim**; every other PR this sweep had a verifier and 12 of 19 issue-verdicts moved as a result.

### The gate fired on its own supervisor — the best result of the sweep

`acceptance-close.yml` (shipped by `#1341` in PR #1387) had **never fired**; an `issues`-event workflow only dispatches from the default branch. Minutes after it merged, the supervisor closed 10 issues with prose-only split explanations and **it reopened all ten** inside 35 seconds: *"0/6 criteria dispositioned."* Re-closed with machine-readable `ACCEPTANCE #N.n <met|split>:` + `remainder: #N` lines, all nine held.

That is both directions, on the production path, unstaged — materially stronger evidence than the `gh workflow run` dispatch #1409's criterion asks for. Recorded there.

### Four supervisor errors, all caught by re-querying state

1. **Closed `#1296` by writing "Neither issue closes: #1296" into a merge body.** The parser is negation-blind. → merge commits carry bare `#N` only; verify close-sets by state query, never by reading prose.
2. **Ledger written from intent, not observation** — twice a batch was marked `executing` with no agent (`4c` never dispatched at all). → reconcile against `gh pr list` / `git worktree list` at every wave boundary.
3. **Tightened an operator grant in downstream briefs** — excluded `docs/runbooks/**` from a granted docs permission and blanket-banned targets the operator had authorised; two of `#1299`'s criteria were reported blocked as a result. → now doctrine in `CLAUDE.md`.
4. **Closed 10 issues with prose, not dispositions** (above). → after any close, verify the state; the command's exit code is not the outcome.

### Operational notes for the next run

- **Three executors is too many on this machine.** Load averages hit **34–46 on 10 cores**, causing unrelated vitest RPC-ack timeouts that look like real failures. Two is the practical cap.
- **The claim ratchet breaches on nearly every rebase** (#1401) — four times this session, two mechanisms: *inherited* rows (another PR's lines) vs *authored* rows (your own prose newly censused). Budget a repair round per PR touching source comments. The CLAUDE.md PR breached on its own doctrine bullets, which are *about* impossibility vocabulary and therefore full of it.
- **`pnpm install` inside an agent worktree is unsafe here** — aborts with `ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY` and can rewrite the primary checkout's `node_modules`. Symlink and invoke `./node_modules/.bin/*`.
- **`validate-acceptance` is checkout-sensitive** — run it from a worktree at the PR head, never from `main`. And it rejects `.json` evidence paths as `.js` (#1400), which is a required gate degrading the evidence it exists to raise.
- **Check `run_attempt` before calling a cited CI run false.** `#1206`'s evidence run reports `conclusion=success` on attempt 2; the failing evidence exists only under `--attempt 1`. A verifier nearly recorded a fabricated-citation finding.

### Awaiting the operator

- **`#1299`** — its last criterion needs one read-only Management API call against a **hosted** Supabase project. Notes record `supabase-aop` as operator-owned with a standing connected-tier read-only audit authorization (2026-07-18), but that is a recalled memory being used to justify a live call against a production project. **Needs an explicit yes.** The other blocked criterion (`docs/runbooks/dry-run-calibration.md`) was mine and is now unblocked.
- **PR #1403 / #1406** merge decisions above.

### Open operator decisions — MEASURED 2026-07-28, not inherited

The prior log carried a list of ten "operator decisions still open". **Eight were already closed** when re-queried, so it was mostly stale — but this section was truncated wholesale in the wrap-up rather than triaged, and these are the ones that survive:

| item | what is being asked |
|---|---|
| **#1069** (`awaiting-decision`) | Route the report's DRAFT limitations/liability wording to counsel and replace it. The product's own output currently ships DRAFT wording. |
| **#899 / #900** | Ungraded breadth sweep — corpus approval, and the ruling on how ungraded results may be presented / disclosed. |
| **PR #1403** | Merge and accept a knowingly-red daily `corpus-drift`, **or** widen #1404 to all four targets and land re-measured baselines inside the same PR. |
| **PR #1406** | Merge on the executor's claim alone, **or** hold for the acceptance verifier it never received. |
| **#1299** | May a read-only Management API call be made against a **hosted** Supabase project? Notes record `supabase-aop` as operator-owned with standing connected-tier read-only authorization (2026-07-18), but that is a recalled memory being used to justify a live call against production. |

Closed since the old list was written, do not re-litigate: #946, #893, #888, #1084, #1072, #904, #1056, #861, #934.

**Label discipline (operator ruling 2026-07-26, still current):** `deferred` is ONLY for intentional parks — it is dropped at fetch and never resurfaces. Anything awaiting an operator ruling gets **`awaiting-decision`**, which still reaches triage.

### Next sweep action

Resume the ledger: 18 batches queued in plan order, starting **4b** (M8 environment), **4c** (M9 detection — never dispatched, reset to `queued`), **4d**, **4e**, **4f**. Wave 10 (`#1377`/`#1378`/`#1328`, discovery) runs **LAST** per operator ruling. Doc + workflow corrections are granted; `docs/runbooks/**` is included in that grant.

## 2026-07-27 (evening) — CI cost reviews and the Akido comparison

Conservation drift-checks re-tiered (#1226); **heavy-cli sharded, 236s → 112s (#1228)**. **External-scanner comparison (Akido vs Harvey on ATC)**: 6 Harvey issues + 1 ATC security issue filed, **2 of my own claims measured FALSE** (Harvey *does* detect unpinned GitHub Actions — 68 findings on ATC; CI config *is* deliberately assessed, not undisclosed). Root cause of both: a partial semgrep config fails silently and is indistinguishable from a coverage gap. **Always re-measure with the full invocation from `src/scan/semgrep.ts` and include a control you expect to FIRE.**

Open, needs a run not an argument: the last assembled ATC deliverable has **zero** CI/workflow and zero license rows while the detector produces 68 CI rows today. That artifact is curated and predates the conservation work, so it is not proof of a drop — but "produces 68, delivers 0" is the produced-vs-delivered shape. **One fresh full run against ATC would settle it.**
