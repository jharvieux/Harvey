# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-16 (the coverage-honesty + calibration issue-sweep, below — it CLOSED the 2026-07-15 "START HERE" items #349/#350/#351/#352. The M6 #267/#406 build-out is further down and still stands.)_

## 2026-07-16 issue-sweep — coverage honesty, calibration hardening, detection rules (14 PRs merged, 30 issues closed)

A full `/issue-sweep` (operator-approved) cleared the P1 coverage-honesty backlog and most of the P2/P3 calibration work. Net-negative on the tracker. Highlights of what changed on `main`:

- **The 2026-07-15 engagement-path defects are CLOSED.** #350 (probes trusting `exit 0`) — M5/M8/M9 now derive status from the tool's machine-readable output; zero-file scans record `partial`/`requires-live-run`, never `ran`. #351 (M6 packet clears never-run alarm) — M6 reports `partial` until a reviewed verdict exists. #349 (ledger no path to report) — `run-audit --findings-out` assembles the derived ledger into findings.json and `report-template` renders per-module coverage; a never-run module shows a "Not run" row, not silence. #352 (`assertComplete` unwired) — wired into `pentest --mode=coverage`. #311/#356/#314 (M1/M2/M3 flag-vs-evidence) resolved (M1 permanently `partial`, M2 `requires-live-run` under the orchestrator).
- **Calibration/scorecard hardening:** per-module census + a **parity minimum of 2 positives/module enforced in the gate** (#341/#427); tier-aware scorecard summary — review-tier catches are no longer laundered as asserted verdicts (#342); detector findings now require `precisionTier` (#327); the **dry-run detection is unified onto the single gated corpus** — the parallel hand-keyed matcher is gone, and a new `ExpectedTier "none"` scores an intended mechanical gap that flips loud if a rule ever catches it (#339/#425). WEBHOOK-REPLAY is the sole `none` entry; UPDATE-UNSCOPED and COUNTER-RACE **graduated to mechanical review-tier rules** with benign siblings (#353), plus P-MW-MATCHER-EXCLUDES-API and P-DRAFTMODE-NO-SECRET (#354).
- **Secrets:** finding evidence now **redacts the matched secret value** to a short prefix+length at construction (#308), so findings never quote a live credential into `dry-run/`, `report-template/`, or a rendered report.
- **Dry-run drift guard:** a scheduled CI check (`dry-run-drift.yml`, operator-approved) regenerates and diffs `dry-run/findings.json`, so a rule/fixture landing without a regeneration can no longer silently age it (#336/#343/#355).
- **Measured, not recalled:** the live gate now reads **153/157 static positives, 137/137 negatives, GATE PASS** (was 147/153 on 2026-07-15) — still ~85% M1 by design; run `validate-calibration.ts`, never quote this.

### Still open after the sweep (queued for the operator / future work)
- **#416** — orchestrator derive-`ran`-from-artifact mechanism for the M1/M2/M3/M6 paid/live passes (operator deferred; blocked on those passes writing durable artifacts).
- **#420 remainder → #434/#435/#436** — M1/M2/M6/M10 findings still surface as coverage rows, not captured findings; M3/M8 capture + explicit non-collection landed.
- **#433** — P-BOLA-BODY-OWNER: mechanically achievable but needs M9 wired into the mechanical gate.
- **#432** — boxyhq M8 mutation baseline drift (committed 7/35 vs CI 8/35) — decide stable-rebaseline vs flaky-tolerance.
- **#320** — proposit's 85 M5-knip findings: needs a machine with the corpus checkouts to triage honestly (self-gated, not faked).
- **Operator/manual:** GitGuardian dashboard-side ignores for the fake fixture paths (#70, operator closed after handling). CLAUDE.md was updated this sweep (operator-authorized) to reconcile the `assertComplete`, exit-0/ledger "Known gaps", `#321`, `147/153`, and `moduleRan` sentences the sweep falsified.

## M6 build-out (2026-07-16) — #267 closed out, #406 executed, M6 now has a measured mechanical tier

Eleven PRs (#404–#412, #414 + the operator-authorized CLAUDE.md row fix #407), all merged green:

- **#267's remaining scope is DONE**: the 106-pattern catalogue (`docs/design/m6-handrolled-catalogue.md` — 76 of 106 do NOT graduate, that number is the finding), the volume/rollup rule, and the free-report wiring (`pnpm quick-scan` now renders a second non-grading "Looks hand-rolled" section, #227-style; rollup per class per file, caps disclosed out loud, --json keeps every location). Issue left open only for the operator to close.
- **#406 items 1–4 all executed** (three parallel agents + one batch-2 agent, every PR supervisor-reviewed): corpus frequency MEASURED (`pnpm handrolled-frequency`, signatures gate-tested against their own examples); the 7 catalogue boundary checks settled by probing (74 → BOUNDARY→M7); `depGatePresent` per-library gate + central WHY-comment suppression in `makeIndicator`; **batch 2 shipped — M6 is now 13 fixture-gated indicator classes** (batch 1 #395 + eight measured-nonzero: date-math ms-constants, MIME tables, currency-toFixed, email-regex-on-zod, formatDate concat, query-string build, base64url, cookie serialization). Dogfood: 0 indicators on Harvey src (one true positive on our own frequency-tool source, resolved via its designed WHY-comment mechanism) and 0 on targets/calibration; per-class corpus fire counts reconciled against the measurement with every difference explained.
- **The measurement's headline (→ #413, operator-shaped):** 36 of 55 measured shapes — incl. 17 of 25 YES entries — have ZERO corpus presence. The 6-repo corpus is curated starter kits, not the AI-generated population the M6 wedge targets. The 17 measured-zero YES entries are deliberately deferred until an AI-generated corpus tier exists; do not build them on judgment.
- **Ops fix worth knowing:** `.claude/` agent worktrees broke local `pnpm verify` (ESLint walked them) — ignored in eslint+vitest (#411). Local verify is trustworthy again during parallel-agent sessions.
- **Supervised drift owed to the operator:** `docs/quality-extras.txt` lines 29–34 ("MECHANICAL SUBSET … " listing 5 classes) are stale — 13 classes now; recommended wording is in PR #414's body. Human edit required.

## ⚠️ (2026-07-15) — engagement-path audit — ALL FOUR ITEMS CLOSED by the 2026-07-16 sweep (kept for provenance)

**RESOLVED:** #349, #350, #351, #352 all closed on 2026-07-16 (see the sweep section at the top). The historical findings below are preserved for the reasoning trail; the code has since changed — verify against `main`, don't act on this section as current. An execution-based audit of `run-audit.ts` → `audit-coverage.ts` → `report-template/` found:

1. **#349 (client-facing, worst).** The coverage ledger has **NO path into the report**. `grep` for any coverage symbol across `report-template/` returns nothing. The only disclosure is `meta.outOfScope` — **a hand-typed string**, i.e. the hand-kept ledger #284 abolished, reintroduced at the last mile. **A module that never ran reaches the client as silence, and silence reads as clean.** Until this lands, fixing the probes just makes an accurate ledger nobody reads.
2. **#350.** Nine of ten probes equate `exit 0` with `ran`, and the tools deliberately exit 0 when they scan nothing. **Proven:** M5 records `ran` while its own tool prints *"M5 dead-code scan (knip) did not run"* (and per #223 that is the COMMON case); M8 records `ran` while its runner returns `status: partial, "mutation scan could not run"`; M9 records `ran` against an empty dir having loaded 0 files. **In two, the tool hands the probe a correct verdict and the probe discards it.**
3. **#351.** M6's never-run alarm — documented as *"deliberately unsatisfiable by reason-writing"* — is cleared by `--llm` printing source **no reviewer ever read**. Banked evidence = the command line. M6 has no measurement of any kind (#267).
4. **#352.** `assertComplete` (M2 target coverage) is **unwired** — only tests call it, while CLAUDE.md and `audit-coverage.ts` both describe it as an active gate.

**The orchestrator's architecture HELD under attack** (8 attempts failed: no forgeable ledger, missing runner throws pre-run, crashed probe can't launder into `requires-live-run`). #229 was built right. **The disease is in the probes' definition of evidence, and at the last mile.**

## The through-line of this whole session — one defect class, ~10 instances

**A recorded claim about our own capability, drifting from reality, failing silently, in the direction of a confident-looking number.** #321 is the systemic version and is now the most-referenced issue in the backlog.

Instances found in one day: boxyhq's M10 not-run reason (fixed by #299) · #300's issue body asserting a Playwright blocker that never existed · two stale b16 entries (#264) · the scorecard's stale mappings (#332) · stale AGAIN minutes after #337 (#340) · 4 planted bugs invisible to the scorecard (#345) · GROUND-TRUTH line 57 vs its own contents (#348) · `assertComplete` described as active but unwired (#352) · M5/M8/M9's `ran` (#350) · "needs an LLM" labels nobody re-checked (#354).

**And I reproduced it five times while documenting it** — see "Supervisor errors" below. The rule now in memory: **run the thing that measures it; never let a stored number become an argument's premise.**

## Calibration — the real numbers (⚠️ 2026-07-15 snapshot, SUPERSEDED — re-measured 153/157 on 2026-07-16; never quote either from memory, run the tool)

- **`pnpm exec tsx src/cli/validate-calibration.ts` → (2026-07-16) 153/157 positives, 137/137 negatives, GATE PASS + per-module parity check (#427).** (2026-07-15 was 147/153.) The uncaught remainder are `expectedTier: "review"`/`"none"` — deliberate LLM-tier or no-mechanical-rule-by-design splits.
- **⚠️ That number is ~85% M1 and covers EIGHT modules, not ten (#341).** M1 ~130 · M10 6 · M4-M5 4 · M7 3 · M3 2 · **M8 1** · **M9-authz 1** · **M2 0** · **M6 0**. M2 (needs a live stack) and M6 (paid LLM packet) have **no fixtures and are structurally ungateable** — defensible individually, but **"147/153 GATE PASS" is a security-gate number wearing a ten-module label.**
- **`dry-run/scorecard.json` → 12 bugs: 5 caught / 3 missed / 4 requires-live-run.** Internal only — **it never touches an external app** (verified: `GROUND_TRUTH_BUGS` is hardcoded to our fixtures; `corpus-drift.ts` uses `scoreExternalBaseline`; `run-audit.ts` never references it).
- **THREE measurement surfaces, not one** (#339): the gated 153-corpus (rule fires on shape) · the dry-run (pipeline catches bug, with exploitability) · the external corpus of 6 real repos (holds on code we didn't write). They cannot collapse — self-authored fixtures **structurally cannot** measure real-world precision (#326's lesson).

## Issue-sweep #4 (2026-07-15) — the coverage gap closes, and measurement corrects three assumptions

Operator grant: **#290 + #300** (i.e. `targets/calibration/**`, `docs/design/m6-simplification-eval.md`, `.github/workflows/**`) — pulled in at the gate, verbatim _"include 290 and 300"_. Mid-sweep the operator also asked for the GitGuardian fix and chose the exclusion **+** the redaction issue.

### THE headline: #229 is done (PR #310)
`src/cli/run-audit.ts` + `src/audit-runner.ts` run all ten modules and **derive** the ledger from execution. Three properties, verified by reading the code, not the executor's summary: no parameter accepts a caller-supplied `ModuleCoverage[]`; a module with no registered runner **throws before anything runs** (`assertRegistryComplete`), so a short registry can't emit a partial ledger that reads as whole; a **crashed probe goes to `failures`, never laundered into `requires-live-run`** (that would be the silent pass the gate exists to prevent). #284 came with it — `MODULES_NEVER_EXECUTED` is now the complement of `audit-execution-log.json`, defaulting unknown → never-run.
**→ CLAUDE.md's known-gap paragraph now tells operators to hand-do what the tool does. #313 (human-owned, needs your edit).**

### Measurement beat assumption three times — the theme of this sweep
1. **boxyhq's M10 was recorded not-run for a reason that had stopped being true.** #299 fixed the quoted-identifier parser → not-run became a **measured 8/8** (95 columns/15 tables), confirmed by the corpus scorer against the real clone.
2. **#300's own issue body was wrong.** It claimed boxyhq was blocked by Playwright needing a built app + browser; boxyhq's jest config already excludes them. Trusting the recorded reason would have left a scoreable target unscored behind a fabricated blocker.
3. **The corpus's "best-tested" target scores worst.** boxyhq: 8 test files (7 E2E) → **20%** mutation. proposit: 1 spec → **100%**. Test-file count was never test quality — #263's lesson, resurfacing one level up (→ **#319**).
**Systemic root**: not-run reasons are never re-tested; the guard fails loud on *silence* but is trusting of *stated reasons* → **#321**.

### Landed
- **#302/#304 → #305** — gitleaks findings sorted before positional id assignment; three dry-run runs now byte-identical. Stale semgrep path fixed.
- **#299 → #306**; **#301 SKIPPED, no code change** — the limitation is already disclosed in the finding text (#297) and widening `SCOPE_COLUMN` would flood ordinary schemas; left open per its own revisit criteria, reasoning on the issue.
- **#251/#300 → #315** — M5-knip per-target install + M8 mutation baselines + `corpus-m8.yml` (monthly, 45m cap, read-only). Two of four suite-carrying targets scored; the other two carry **measured reasons** (Docker-per-mutant, E2E-only) — #252's ambiguity left undecided, not guessed.
- **#229/#284 → #310** · **#221 → #318** · **#290 → #316** · **#303 → #317**.
- **#264 → #330** — **the issue's premise was wrong in BOTH directions.** Of its nine "uncaught semantic" positives: **two were already caught** (#220/#256 landed after filing — the b16 note even said "no longer a static miss" while the issue still listed it uncaught; the live gate reported **seven**, not nine). **One was misfiled as semantic** — `definer-review.ts:5` on main literally names `promote_to_admin(target_user_id)` as its *"Canonical miss"*: **the rule already existed and only ran off the live DB pull, so the static gate scored a miss the reviewer could already adjudicate.** Wired the existing reviewer to parsed migration SQL (one rule set, two feeds — same pattern as the policy semantics). **The remaining six are genuinely semantic and were deliberately left alone.** Gate **146→147/153**, negatives held **131/131**. Notably the executor **raised the answer key's difficulty rather than loosening it**: it fixed the finding's `location` to include the parameter signature instead of weakening the corpus `match` key (Postgres allows overloads where one variant is gated and another isn't) — weakening the key to make its own code pass would have been the wrong direction. Corrected the b16/`review-tier.ts` notes that called this a *permanent* static miss, so the six read as a deliberate tier split rather than an unknown gap.
- **GitGuardian → #309** (operator-requested): `dry-run/**` excluded. All 5 alerts were pre-existing calibration fakes echoed in scanner **evidence output** — the exclusion treats the symptom; **#308** is the real question.

### #221 shipped narrow on purpose
Only the mechanical third (client-supplied owner id in a Server Action), `review` tier, never free-count. **Its precision is UNMEASURED against real code and no number is claimed**: ATC/AoP have **zero `'use server'` files**, so the detector's silence across 1,398 files is *no input*, not precision. Only real read available is proposit's 3 known instances → **#326**.

### #290: rebuild, not relabel (PR #316)
The old fixture's benign status rested entirely on a comment #282 stripped — it was pinning nothing. Rebuilt around a **code-evident** contract (`implements SupportedStorage` + instance handed to `createClient({auth:{storage}})`), no comments. Run 2's 1/2 deliberately **not** re-scored (the reviewer was right about the file it saw; re-scoring = the rationalized pass §3.1 warns about) → **M6 now has NO trustworthy negative datum until run 3** (**#324**).

### A fourth instance of the theme, from #264 — and the lesson generalizes
Two of #264's nine were **stale**: fixed by #220/#256 after filing, with the b16 note *already saying so* while the issue still listed them uncaught. Nobody re-checked. This is **#321's class again** (a recorded reason outliving its truth) — but in the *answer key*, not the manifest, which is worse: a stale "documented static miss" note is indistinguishable from a real tier boundary, and it hides a rule that already works. **A recorded gap is a claim about the world, and this repo has now been wrong about one four times in one sweep** (boxyhq M10, #300's Playwright blocker, the two b16 storage entries).

### Supervisor errors worth recording — five, all caught by the operator
1. **#264 was approved at the gate and I never dispatched it.** I tracked batch state in prose instead of updating the ledger after each change. Caught only at wrap-up reconciliation. **Rule: update the ledger on every state change, before writing the prose update.**
2. **I based this file's first sweep-#4 edit on the operator's uncommitted working copy** — the *exact* trap recorded in sweep #3's notes above. No work lost (the branch was cut from `origin/main`). **Note: the operator's local SESSION.md carries uncommitted sweep #2/#3 sections that have never landed on `main`.**
3. **"Mechanical is 0/8."** Quoted from a 2026-07-08 memory predating the entire rule corpus; I built #311's whole argument on it. Real: 4/8 on that fixture (5 now), **147/153 on the actual gate**. #311's premise corrected twice.
4. **"Two answer keys."** There are **three** measurement surfaces (#339).
5. **"The corpus spans all ten modules."** It covers **eight** — no M2/M6 fixtures exist. I inferred "ten" from seeing six module entry files without checking for the two absent ones (#341).
6. **Filed #344 without checking the backlog** — #267 already covered it, better. Closed as duplicate.

Every one was inference dressed as measurement, each checkable in under a minute. Memory `never-quote-capability-numbers` records the commands. **A supervisor who guesses its own numbers has no standing to sell a product that tells clients what is true about their code.**

### Follow-up filing — a wrap-up check that isn't reliable
34 issues filed (#307–#357). Reconciling against every executor's `follow_ups` + the audit's findings **and** its `unverified` list found **three unfiled**: #355 (`dry-run.ts`'s non-recursive `readMigrations` — reported by the scan-299 executor and **missed at that sweep's wrap-up**), #356 (M2's half of the flags-as-facts defect; #311 only covered M1), #357 (the audit's unverified list). **This was a reconciliation, not a proof** — anything an executor noticed but didn't report was never visible. #355 existing shows the wrap-up check misses things; it surfaced only because the operator asked.

### Operator decisions this sweep surfaced (all NEW, all yours)
- **#311** — M1 reads `ran` off the mechanical layer alone while only *claiming* the semantic/live layers are in scope. Mechanical is **0/8** on planted bugs; the LLM pipeline is **7/8**. The lead module of the wedge carrying the runner's weakest claim. Permanently `partial`, or make the semantic pass leave a checkable artifact?
- **#308** — findings quote matched secrets **verbatim** in evidence. Fixtures today; **real client credentials** on a real engagement, and `report-template/` renders them into a client-facing doc.
- **#319** — what can M8's score honestly claim? A 100% on one file of an untested repo is true and misleading.
- **#322** — per-target scan roots would make M5 measure a different tree than M4 on the same target.
- **#327** — no detector sets `precisionTier`, so detector findings silently mis-score (positives → misses; untiered FPs indistinguishable from free-count). Fixed narrowly for #221 only.

## Issue-sweep #3 (2026-07-15, later) — the module-scope cleanup

**Operator ruling at the gate, verbatim: _"M10 is included, it never should have been excluded from anything."_** That settled #289 and unblocked #288/#275, which had been excluded pending a decision on the module set. Grant this sweep: `docs/**` + `package.json` (CLAUDE.md and `findings.*.json` stayed excluded).

### The root cause of a whole class of confusion: CLAUDE.md was never committed
`CLAUDE.md` was last committed **2026-07-08**. The ten-module scope, the module→runner table, and the fail-loud coverage doctrine were written **2026-07-12** and sat **uncommitted for three days**. Sessions read the working copy (ten-module); every dispatched agent read the committed file (**9-module**, none of the table). They disagreed for three days.

That is why **#275** was filed asserting "CLAUDE.md sells ten modules but the guard sees nine" — a contradiction between a file one machine could see and the code everyone else reads. **Now committed in PR #293**, with three rows refreshed against what actually shipped while it sat: M6's `/simplify` (a skill that does not exist) → `pnpm simplify-scan`; M10's `node tools/…` → `pnpm pii-classify --schema`; and #229's "known gap" now distinguishes the gate (landed, takes its ledger from the caller) from the orchestrator (did not).

**Rule going forward: read CLAUDE.md from `origin/main`, never a working copy.** A dirty marker on the file that defines how the repo works is a question, not noise.

### Landed
- **#289/#288/#275/#254 → #294** — `docs/audit-modules.md` now says TEN consistently (was 7 on line 8, ten in the table, M1–M9 in Packaging — three counts in one file). **The dead second guard is DELETED**: `src/audit/module-coverage.ts` had zero callers and nine modules while `src/audit-coverage.ts` had ten; that duplication is how #275 was possible. New enumeration test **reads** the doc's module table rather than restating it — supervisor mutation-verified: removing M10 from the doc DOES fail it. Two more M10-exclusion instances found beyond #289's three (a composition flow, `docs/runbooks/engagement-access.md`).
- **#286/#285 → #295** — **#286 verdict: NOT a regression.** `UPDATE-UNSCOPED` scores `missed` because **no rule for that class has ever existed** (`git log -S` over `src/scan/rules/` empty across all history — supervisor-verified); fixture intact and still vulnerable at `update.js:12`; the row scored `missed` in every scorecard back to the #34 baseline. Tally stayed at the honest **2/3/3** — no expectation lowered. #285: dry-run locations relativized, two runs now byte-identical, diff 4.4k → 706 lines.
- **#277/#278/#279/#262 → #298** — M8/M5-slop/M10 corpus scoring gaps recorded with real reasons; **#262's wall-clock calibration finally RUN** (#15's original acceptance criterion, never done): concurrency 1 → 3.24s, 4 → 1.86s, 8 → 1.96s, mutation score constant at 76% (19/25). The doc explicitly refuses to extrapolate from a 25-mutant fixture to a real engagement.
- **#280/#281 → #297** — `--tenant-key`/`--tenant-mode` now on quick-scan, reusing detect-deeper's declaration (was connected-tier only, so free tier could *see* a wrong tenancy inference but not fix it). #281 resolved by disclosure rather than widening the regex — the issue's own sanctioned fallback; widening would flood ordinary schemas with noise and there is no corpus to validate against (#301).
- **#292 → #296** — axios/ws ranges widened, **all OSV-verified**, kept **disjoint** (supervisor-verified `ws@5.2.3` and `ws@6.2.2` stay silent — flattening would have flagged patched versions). Kept ws's real `introduced: "5.0.0"` floor rather than assuming `"0"`. `osv-staleness` now **32/32** claims.

### Corrections made to my own earlier work
- **#275's premise was wrong** and I filed it — cited the uncommitted CLAUDE.md as committed state. Corrected + reopened, then closed properly via #294 once the real defects (#288/#289) were split out.
- **#282 was already done** before the wrap-up agent filed it (PR #287 had de-labelled the fixtures) — a race in my own orchestration. Closed with that explanation.

## Issue-sweep 2026-07-15 — the theme: things that reported success without checking

Operator granted `.github/workflows/**` + `package.json` + `docs/**` for this sweep (CLAUDE.md and `report-template/findings.*.json` stayed excluded). 16 issues, 9 PRs, all merged. **Three independent instances of the same defect class — a mechanism reporting success without checking what it claims to check:**

1. **#212 (2026-07-14)** — a fabricated Critical CVE.
2. **#246/PR #273** — the dry-run scorecard's `matches` took `location` OR `taxonomy` as separate strings, so it structurally could not require both. It scored 4/8 planted bugs "caught" off false matches — the standout: **`COUNTER-RACE` matched `/race/i` against the dependency `braces@2.3.2`**. Honest tally was 2. Matcher fixed rather than committing the number.
3. **#275/#288** — **two** coverage guards exist. `src/audit-coverage.ts` (#229) is live with all ten modules; `src/audit/module-coverage.ts` has **zero callers** and had nine. One guard drifted while the other didn't, and nothing reconciled them.

**Supervisor error worth recording:** I filed #275 claiming "CLAUDE.md sells ten modules but the guard sees nine". Committed `CLAUDE.md` says **9-module** — the ten-module text is an *uncommitted local edit* in the operator's checkout. I cited a dirty working copy as the repo's state. The executor caught it; #275 corrected + reopened. Verify against `origin/main`, never the local checkout.

### Landed
- **#246/#253/#247 → #273** — dry-run artifacts regenerated (the fabricated CVE is gone); corpus `location` matching anchored (a bare `next` substring-matched every fixture, which is *how* #212's bad entry "passed"); **OSV staleness check** (`.github/workflows/osv-staleness.yml`, weekly, 29/29 green) — it would have caught #212 mechanically. `pnpm verify` stays offline.
- **#256/#258 → #270** — `WITH CHECK (true)` rule in the shared reviewer (both tiers). **Half of #256 correctly declined**: PG *rejects* `USING` on INSERT policies and *defaults* `WITH CHECK` to `USING` on UPDATE — verified on real Postgres 16 by the executor AND independently by me. A rule there would be a pure FP factory. #220's text corrected.
- **#249/#250 → #269** — React Compiler flag now resolves `on`/`off`/**`unresolvable`** (was silently assuming false); M10 got its `--schema` entry point (`pnpm pii-classify`).
- **#259/#260 → #272** — `total` semantics documented for consumers; `exploitabilityVerified` per-finding escape hatch (inert today, so grading is unchanged).
- **#263/#261 → #276** — **Layer-2 corpus CI ships and runs** (clones 6 pinned commits, scores baselines, 2m10s, 28/28). **The baselines were themselves wrong and had never been through the scorer**: M4 recorded jscpd *cluster* counts vs the scorer's *findings* (203 vs 68); M8 recorded test-*file* counts; two M5 modules marked "can't run" ran fine. Every M4/M8 baseline would have failed day one. One real drift caught + rebaselined (saas-lite M7 22→23, from #269's new class).
- **#265/#266 → #274, #275/#282 → #287** — M6 now has a runner (`pnpm simplify-scan`) and is `never-executed` so the gate throws until it runs for real.
- **#271 → #291** — 5 CVE ranges widened, **all OSV-verified**. Two of #271's own claims were WRONG: `undici` CVE-2022-35949 has no 6.x range (asserting it = a false High on every `undici@6.x`, the #212 defect), and `minimist@0.2.4` is *patched* — its ranges are disjoint, so a naive widen preserves an FP. Also fixed a latent comparator bug: prerelease versions collapsed (`5.0.0-beta.x` → `5.0.0`), so the next-auth beta range would have been **unmatchable while the table looked correct**.

### The M6 eval finally ran honestly — and beat its own answer key
Run 1 scored **4/4 + 2/2 and was VOIDED as contaminated**: every fixture's line 1 announced its own verdict (`// — PLANTED (M6-P-DEBOUNCE)`, `// The rubric must NOT flag this one`). A reviewer reading only first lines scores 6/6. Labels stripped (#282/PR #287), discriminators kept.

**Run 2 (fresh-context reviewer): 4/4 positives, 1/2 negatives.** It flagged `framework-adapter.ts` — a labeled *benign* — arguing Next.js dispatches `getServerSideProps` as a module-level export and never calls a class method, so `InvoicePageAdapter` is unreachable by the framework it claims to serve. **Verified: the reviewer is right and the fixture is mislabeled** (#290). Its benign status rested entirely on the header comment asserting a contract the code never demonstrates. `depdrop.ts` was spared on its `// WHY:` comment alone — a real negative working as designed.

## ⛔ BLOCKER — do not send any disclosure until #245 clears (2026-07-14)

**#212 found that the scanner asserted a Critical CVSS-10 pre-auth RCE against `next@14.2.x` that does not exist.** Verified against OSV: the Next.js RSC advisory `GHSA-9qr9-h5gf-34mp` opens at `14.3.0-canary.77`, so no released 14.2.x is in range; it is absent from all 26 advisories OSV returns for `next@14.2.5`. The corpus also cited `CVE-2025-66478` (MITRE-REJECTED, 404s at OSV) and a non-existent GHSA. Every fixed-version in that table was wrong. **This fired on 4 real targets in the 2026-07-12 sweep.**

- Corpus corrected in PR #243; each entry now carries its OSV advisory URL.
- **#245 blocks #214–#219 + #168** — re-check every open disclosure thread against the corrected corpus before sending. Several (e.g. Vercel #215) own the advisory and would spot a fabricated CVE instantly.
- **#246** — `dry-run/findings.json` still contains the FP; needs regenerating (not hand-editing: it is the record of a real historical run).
- **#247** — no staleness check against OSV; a periodic re-query would have caught all four defects mechanically.

## Issue-sweep 2026-07-14 (8 issues, 4 PRs, all merged)

- **#222/#228 → PR #241** external-repo regression corpus + quality-module precision validation. Corpus built as pinned-commit clones, **not** vendored extracts: `Wallens11/supabase-multi-tenant-starter` ships **no LICENSE** (all-rights-reserved), so its migration cannot lawfully be copied in; the #230/#232 FP shapes are whole-repo properties an extract can't reproduce anyway. Confirmed #230–#233 hold on real code (mvp-boilerplate dup 13.3%→1.35%; boxyhq Pages Router → clean 0).
  - **Thesis-validating result:** M5 found multi-tenant-starter exports `requireTenantAccess`/`requireTenantAdmin` that **nothing calls** — on the same repo whose Critical is a missing-authz self-join. The dead guard is the vulnerability's fingerprint: a quality module corroborating a security Critical. Strongest GTM artifact the sweep produced.
- **#212 → PR #243** CVE corpus provenance (see blocker above).
- **#229 → PR #243, PARTIAL, still open.** Coverage *gate* landed (`src/audit-coverage.ts`: every M1–M10 accounted for, `assertAuditComplete` throws naming gaps). The `run-audit` **orchestrator did not** — needs prereq detection (target `npm install`, `supabase start`, vitals, DB creds) across 10 heterogeneous CLIs / 3 tiers. **The seam:** the gate takes the ledger *from its caller*, so it cannot detect that you skipped M5. Bookkeeping discipline, not ground truth — CLAUDE.md's "known gap" wording still holds.
- **#227/#213/#220 → PR #244** free-tier grade scope + risk disclosure + non-grading indicators; static RLS-policy review now feeds the source tier by reusing the existing `rls-policy-review.ts` (shared with the connected tier, not a second copy).
- **#240 → PR #242** doc-completeness (operator-approved supervised `docs/**` edit).

### Open decisions the sweep surfaced (operator-owned)
- **#248** M7 micro-render FPs are only demoted when React Compiler is on, and no corpus repo enables it. Either those shapes are real work without the compiler (→ #230's ~10% precision figure is wrong) or they're noise regardless (→ demotion shouldn't be compiler-gated). Baselines move either way.
- **#255** curated severities diverging from the advisory (jsonwebtoken High vs OSV MODERATE) — defensible, but post-#212 an audit that silently re-rates a CVE invites the same credibility question.
- **#252** M8 "harness present but suite absent" (proposit: `vitest run` + exactly 1 test file → counted:1, when #224's zero-coverage finding is arguably more honest).
- **#257** static RLS residual FP (own-row policy on a table that also carries `tenant_id`) — may not be decidable from static SQL alone; the #206 boundary.

### Next-up queue (revised 2026-07-15, END of session — the audit reordered this)
1. **#349 — the only defect a paying client sees.** The coverage ledger never reaches the report; `meta.outOfScope` is hand-typed. **Nothing else in the engagement path matters until this lands** — fixing probes only produces an accurate ledger nobody reads. **Do not run a paid engagement before deciding this.**
2. **#350 / #351 / #356** — probes accept `exit 0` as evidence; M6's alarm is defeated by a flag; M1/M2 read flags as facts. #350 and #351 are the ones that bank a false `ran` **permanently** via `--record`.
3. **#245** — still the only thing blocking all 7 disclosure threads. Unstarted across **four** sweeps; judgment about what to tell third parties, not a code task.
4. **#313** — CLAUDE.md's known-gap paragraph is now **wrong** (the #229 runner shipped) and #352 adds a second stale claim (`assertComplete` described as an active gate). It is the file every dispatched agent reads; stale text there caused a whole class of confusion in sweep #3. Human-owned → yours.
5. **The honesty decisions** — **#311** (what M1's `ran` means) · **#308** (findings carry live client secrets into a rendered report) · **#319** (what a mutation score asserts) · **#341** (a blended `147/153` implying uniform ten-module coverage) · **#342** (`caught` flattening review-tier surfacing).
6. **#353 / #354 — operator-directed: can we catch these mechanically without FPs?** #353: the 3 never-covered planted bugs (**UPDATE-UNSCOPED looks most tractable** — a raw UPDATE with no WHERE is a textual fact). #354: the 6 review-tier gaps — **at least 2 look mechanical, not semantic** (`P-MW-MATCHER-EXCLUDES-API` is a string literal; `P-DRAFTMODE-NO-SECRET`'s own note looks wrong). Most of #354's negatives **already exist**; #353's must be built. Precedent for both: **#333** — the discriminator wasn't in the code shape at all.
7. **#339 / #321** — the structural fixes. One gated key per question; make stale reasons impossible rather than guarded after the fact.
8. **#283/#324** (M6's PAID tier still has no trustworthy datum: never run against a real target, eval run 3 not done — the mechanical indicator tier, by contrast, is now 13 fixture-gated classes with measured corpus behavior, see the 2026-07-16 section) · **#413** (AI-generated corpus tier — blocks the 17 measured-zero YES entries) · **#326** (#221's detector precision unmeasured) · **#320** · **#307/#322/#327**.

### Open decisions (operator-owned — agents were explicitly told not to guess these)
**Pre-existing:** #248 M7 compiler-gating · #252 M8 harness-vs-suite (hit again in #300 — saas-lite's E2E-only suite is exactly this ambiguity; recorded with a reason rather than decided) · #255 curated severity vs advisory · #257 static RLS own-row/tenant_id boundary · #267 the top-100 AI-hand-rolled corpus (HELD for a later sweep).
**New from sweep #4:** **#311** M1's `ran` claim · **#308** secrets verbatim in evidence · **#319** what M8's score can claim · **#322** per-module vs per-target scan roots · **#327** default `precisionTier` for detector findings.

_Still open + human-owned: disclosures #214–#219/#168 (blocked on #245), GTM #10–#13, live pen-tests #159/#161, Tier-2 port #4._



## Public-repo dry-run sweep #2 (2026-07-12)

Ran the free-tier static scan (`quick-scan` + `detect-static`) across the remaining `docs/test-targets.md` candidates, plus a live dynamic RLS probe on the best target. ShenSeanChen/launch-mvp was already done (→ #168). Clones + scan outputs are in the session scratchpad (throwaway).

- **6 targets scanned:** mvp-boilerplate, nextjs-saas-starter-kit-lite, nextjs-subscription-payments (vercel), proposit, boxyhq/saas-starter-kit, Wallens11/supabase-multi-tenant-starter. **Two doc-listed repos are dead:** `AppBrewers/supabase-multi-tenant-starter` (404), `mrdave001/supabase-multi-tenant` (empty, no worktree).
- **Headline result — `Wallens11/supabase-multi-tenant-starter` (0★):** static RLS-policy review predicted two tenant-isolation breaks; **both CONFIRMED dynamically** on a local self-hosted Supabase stack:
  1. `user_tenants_insert WITH CHECK (user_id = auth.uid() OR ...)` — any authenticated user self-joins **any** tenant (one INSERT) → then reads that tenant's data. Proved: userA (Acme owner) inserted membership into Beta, then read Beta + enumerated Beta members.
  2. `invitations_update_used USING (used_at IS NULL)` — unscoped; any authed user tampers/consumes **any** unused invitation (proved userA hijacked Beta's invite).
  - Dynamic method: psql, `SET LOCAL ROLE authenticated` + `request.jwt.claims` sub inside a **single transaction** (local GUC evaporates otherwise → auth.uid() NULL, the trap that voided my first probe run).
- **Triage collapsed the raw "Criticals":** raw mechanical flagged ~12 Criticals across the 6 repos; the secret-exposure ones are all **false positives** — the local Supabase demo key (`iss:"supabase-demo"`, ships with every `supabase start`) in seed/.env files, and a SAML **test** private key in boxyhq CI. The Next.js CVE Criticals are version-matches (not exploitability-confirmed; some CVE IDs unverified). proposit's 9 Server-Action Highs are review-tier heuristics (no-visible-auth / no-input-validation) needing the triage pass, not free-tier verdicts.
- **Scanner-precision follow-ups filed:** **#210** local-demo-key FP (highest priority — fires on ~every Supabase repo; a wrong Critical is credibility-fatal), **#211** CI/test private-key FP + mismatched risk copy, **#212** verify Next.js CVE corpus provenance.
- **Not done:** dynamic local testing of the other 5 targets (each needs its own stack stood up; the multi-tenant-starter was the high-value pick). Responsible disclosure for the 0★ repo left to operator discretion (low marketing value per the doc; disclosure is human-owned like #168).

### LLM deep-scan suite run across all 6 (2026-07-12, later)
Ran `/threat-model → /vuln-scan → /triage` (one parallel review agent per target). Full per-target write-up in the session scratchpad `llm-suite-results.md`. **Result validates the thesis:** the deep pass caught the real bugs the free/mechanical tier can't see and cleared every false Critical the free tier raised.
- **Real findings surfaced:** `supabase-multi-tenant-starter` **Critical** self-join owner takeover + **High** invite tampering (matches our dynamic ground truth; the agent was blind to it → independent detection); `proposit` **Critical** anon-readable invite tokens + **High** cross-tenant join + **High** member→admin privesc (3 go-live blockers); `nextjs-subscription-payments` (Vercel) **Medium** client-controlled trial → free subscription; `boxyhq` **Medium** UI-only billing authz. `mvp-boilerplate` and `saas-starter-kit-lite` correctly certified **sound** (one Low each).
- **Free-vs-deep gap (headline for GTM):** every graded free-tier "Critical" across all 6 was an unverified CVE version-match or a demo/test-key FP — none was real; the genuinely dangerous repos got the same "F" as the well-built ones. Reinforces #210/#212 and the open question below.
- **OPEN product question (unanswered by operator):** stop dependency-CVE version-matches from counting as "Critical"/setting the grade in the free tier (pair with #210/#212).
- **Responsible-disclosure candidates (operator-owned, human):** proposit (3 blockers), vercel subscription-payments (trial abuse), boxyhq (billing authz) — alongside launch-mvp #168.

### Disclosure issues + codebase-health module sweep (2026-07-12, later)
- **Disclosure tracking issues filed (drafts in scratchpad `disclosure-reports.md`):** **#214** proposit (contact: security@propositapp.com from their SECURITY.md), **#215** vercel/nextjs-subscription-payments (GH private advisory; Vercel security page), **#216** boxyhq/saas-starter-kit (GH advisory; verify boxyhq.com security contact), **#217** Wallens11 multi-tenant-starter (GH advisory; low priority, 0★). Each issue carries the findings, maintainer-contact instructions, and the per-target module results. Actual send is operator-owned (not done).
- **Module runnability learned (source-only, no target deps):** **M4 duplication (jscpd)** runs clean on any source tree — results: mvp-boilerplate 13.3%, proposit 9.8%/199 clones, subscription-payments 6.1%, boxyhq 6.0%, saas-lite 3.7%, multi-tenant-starter 3.0%. **M5 dead-code (knip)** FAILS without the target's `node_modules` (can't resolve config imports like `vitest/config`) → needs `npm install` in the target first, a per-engagement step; it drags M4 down when co-run in `quality-scan`, so run jscpd standalone for a deps-free M4. **M8 mutation (Stryker)** is not source-only — needs the target's test suite + a `stryker.conf` per repo. **M6** = paid review dimension (slop detector already runs via `detect-static`). **M10 PII** needs a DB or schema; ran indicatively off migration SQL (payment/PCI columns in the Stripe repos; invite `token` in proposit/multi-tenant-starter). boxyhq uses Prisma (no SQL migrations) → M10 needs `prisma/schema.prisma` or a live DB.
- **Not filed:** the 2 clean repos' Low courtesy notes (mvp-boilerplate latent xmr_invoices grants; saas-lite auth-callback open redirect) — kept optional in the report file, not a formal disclosure. **Now filed as #218/#219** (operator asked to file both), and real M5/M8 run on multi-tenant-starter (M5: dead `lib/security/guards.ts`; M8: repo has zero tests → coverage nil, that absence IS the finding) commented on #217.

### Product improvements learned from the sweep (2026-07-12, filed)
Beyond the precision FPs (#210–#213), the sweep surfaced coverage/positioning gains, all filed:
- **#220** static RLS-policy review over committed migrations — the highest-value class (self-join, unscoped policies) is in committed `.sql` and was found deps-free by the LLM; move it from connected-only into a source-tier indicator. **Biggest opportunity.**
- **#221** new "server trusts client input for authz" finding class (client-supplied userId, trusted price/trial, UI-only permission — recurred 4×).
- **#222** external-repo regression corpus from the 6 labeled targets (gate scanner changes against real code, not just the synthetic target).
- **#223** quality-scan decouple M4/M5 (knip failure currently drops jscpd too). **#224** mutation-scan emit a no-tests finding instead of being un-runnable. **#225** generalize the public/test-credential recognizer (supersedes #210/#211). **#226** cross-link dead security-code (M5 on auth/guard files).

### Free-grade calibration DECIDED (2026-07-12, tracker #227; locked in [[product-shape-decisions]])
Operator chose: (1) free headline = **hygiene grade + risk-disclosure line**, not one security grade; (2) **only high-precision mechanical classes move the grade** (CVE version-matches + public/test-cred shapes → non-grading Info); (3) **source-tier RLS/authz indicators (#220) shown as a non-grading "verify in deep scan" section**; (4) **grade annotated with its scope**. Invariant: free output must never contradict the deep verdict, validated on the #222 corpus. #227 is the parent spec; #213/#210/#225/#220/#222 implement it.

### COMPLETE-SUITE correction + coverage guard + quality triage (2026-07-12, latest)
Operator flagged (2×) that the whole session skewed security-only when Harvey is a **complete 10-module quality suite**; security is the wedge, not the deliverable. Corrections made:
- **CLAUDE.md updated** (operator-named the file → authorized): new section "The audit — full scope, how to run it, and the coverage guard" — the M1–M10 module→command table with per-module prereqs, the free/connected/dynamic/paid tiering, and the **coverage guard** (never silently skip; `assertComplete` + `coverage-scorecard.moduleRan`; a module that can't run is `partial`/`requires-live-run` with a reason). Corrected stale "9-module" → "ten-module (M1–M10)".
- **#229** — the real gap behind the skip: there is **no single orchestrator** that runs all M1–M10 and asserts each executed (assertComplete is M2-targets-only, coverage-scorecard is calibration-only). Filed to build a `run-audit` + fail-loud module-coverage gate.
- **Quality-module triage on the 6-repo corpus (#228 + memory [[harvey-full-quality-suite-not-security-only]]):** raw quality counts have the same precision problem as raw security. **M7 ~10%** (154→16; `exhaustive-deps` + micro-render dominate FPs), **M9 ~12%** (26→3, and those 3 are security IDOR, not App-Router rendering — server-only misfires incl. on a Pages Router repo, cache-config on auth routes), **M4 dup% overstated in 4/6** (generated types + vendored `monero/patches` fork + demo data), **M10 over+under-matching** (real headline: proposit stores plaintext per-tenant AI key + SMTP pass readable by any org member via RLS). Per-module fixes: **#230 M7, #231 M9, #232 M4, #233 M10.**
- **Corrected scorecard:** real quality signal concentrates in **proposit** (genuine per-entity dup, latent-scalability perf, the M10 secret exposure — bad on every axis); **boxyhq** is the best-engineered (only repo with a real test suite); **mvp-boilerplate's raw "13.3% dup / F" was a fork+codegen artifact**, not real. Security rank ≠ quality rank.
- **#214 updated** with proposit's M10 finding (plaintext per-tenant Anthropic key + SMTP password readable by any org member via RLS) — a real High data-exposure vuln surfaced by the data-classification pass, added to the disclosure. Other repos had no non-security disclosure-worthy items.

### Issue-sweep executed (2026-07-12, latest) — 10 issues merged, 3 PRs
`/issue-sweep` over 33 open issues → 3 sonnet batches, all merged green (required `verify`), branches deleted:
- **PR #235** (P1, `scanner-secrets`): #210 demo-key FP, #211 SAML/test-key FP + risk-copy, #225 generalized public/test-credential recognizer — one gitleaks correlation-marker recognizer; `validate:calibration` gate PASS.
- **PR #234** (`m4-m5-quality`): #223 decouple M4/M5 (knip failure → M5-00 partial, jscpd still runs), #232 M4 exclude generated/vendored/demo + fragment-size gate, #226 M5 elevate/cross-link security-file dead code.
- **PR #236** (`module-detectors`): #224 mutation-scan no-tests finding, #230 M7 FP-suppression, #231 M9 server-only/Pages-Router/cache-config gating, #233 M10 dictionary precision.
- **Deferred (opus, design-heavy, operator's call):** #213, #220, #221, #222, #227, #229 — net-new detectors/orchestrator + the grade-calibration parent spec; better as scoped standalone work than a sweep PR.
- **Excluded (not agent-executable):** #212 (needs external CVE feeds), #159/#161 (need a deployed target), #2/#4/#10–13 (business/epic), #168/#214–219 (human disclosure), #228 (analysis done, children shipped).
- **Follow-up #237:** the 3 supervised `docs/*.md` runbooks (M4/M7/M9) are stale after the precision changes — human doc update owed.



## Connected-tier review passes — live dry-run + hardening (2026-07-11, late)

Ran the #199/#200 review passes live against real targets. **NB on connection method:** the in-session dry-run used the Supabase MCP `execute_sql` as a stand-in only — the production path is `detect-deeper` with a direct read-only `SUPABASE_DB_URL`, **not** MCP (MCP is dogfood/agent-only; see `docs/runbooks/connected-access-hardening.md`).

- **ATC RAG backend (`jjznkprbotkqqnuvcost`): clean.** All 6 SECURITY DEFINER fns ruled out by the classifier (service_role-only / vault); the one multi-tenant policy (`rag_media_assets`, tenant_id-scoped) correctly cleared.
- **AoP (`udsuxdoavlvosvbjwmud`, Age of Piracy client): 2 RLS items, both false positives** — `profiles` policies keyed on `id = auth.uid()`. Motivated #206.
- **#205** (merged) — review-tier findings now embed the raw USING/WITH CHECK clauses (#199) and function body (#200) in `evidence`, so a supervised session can adjudicate offline for **any** target (not just MCP-connected ones).
- **#206 → PR #207** (merged, closes #206) — added a **per-user tenancy mode** to `rls-policy-review.ts` (`detect-deeper --tenant-mode per-user`): a row bound to `auth.uid()` counts as valid ownership; only indirect/unscoped caller refs or writes that drop the binding flag. Default stays per-tenant → multi-tenant behavior unchanged. Closes the AoP FP class. **Follow-up:** add per-user calibration-corpus fixtures under `src/scan/calibration/`; optional per-table ownership map (#206 option 2).
- **AoP is now operator-approved for read-only scanning** (was flagged off-limits) — topology memory updated. Read-only discipline still applies.
- **Tier docs (PR #208):** `docs/free-tier-scope.md` (source-only free scan — no credentials, ~8/9 modules deliver from source incl. the M1 wedge, indicators-not-verdicts framing) + `docs/runbooks/connected-access-hardening.md` (least-privilege customer-DB access ladder). The access doc is a draft to **fold into `docs/runbooks/engagement-access.md` + the intake questionnaire**.

### OPEN DECISION — real inline LLM adjudication pass
The #199/#200/#201 passes are review-tier **heuristic** surfacing, not real model calls (there is no LLM API in the repo). A real inline adjudicator needs: the Anthropic SDK (`@anthropic-ai/sdk` — touches `package.json`, supervised → needs operator sign-off), an API key at scan time, a model choice (rec: Opus 4.8 + structured output + injection-safe prompt), and calibration before any precision claim. **Short-term bridge (works today, no build):** run the review-tier findings through a supervised Claude Code session on the operator's plan — it adjudicates from the exported evidence (raw bodies via #205) and the verdicts double as calibration data for the eventual automated pass.

## Issue sweep 2026-07-11 (evening) — 2 batches merged, 5 issues closed

The connected-tier DB-check gap review (#197–#201) is now delivered. All source-level, no supervised paths touched, no new deps.

- **#197 + #198** (PR #202, sonnet) — two mechanical read-only SQL checks in `src/scan/supabase-config.ts`, wired into both scan paths in `supabase.ts`, following the `checkRealtimePublicationRls` (#196) pattern:
  - `checkDefaultPrivilegesToClientRoles` + `checkColumnGrantsToClientRoles` — default-privilege / column-level grants to anon/authenticated. **Used `pg_attribute.attacl` instead of the issue-suggested `information_schema.role_column_grants`** (that view synthesizes a row per column for ordinary table-wide grants → would flood every Supabase project with FPs).
  - `checkCronJobs` — pg_cron inventory, guarded N/A when the `cron` schema is absent. Flags superuser-run jobs, commands naming a SECURITY DEFINER function (name-match, not full body analysis), and secret-shaped literals.
- **#199 + #200 + #201** (PR #203, opus) — three review-tier passes on a shared `src/review-tier.ts` harness. **KEY FINDING: there is no runtime LLM API in this repo** — "review tier" is the existing `precisionTier: "review"` where heuristic findings are surfaced for downstream adjudication (vuln-scan LLM pass / human triage). So these were built as review-tier heuristic surfacing (clear the provably-safe, surface the rest), matching the `definer-classifier`/`grant-classifier` pattern — **no `package.json` dependency added.** Reframes the issues' literal "LLM pass" ask; operator should confirm this satisfies intent, else a real inline LLM harness is a separate (supervised, needs-dep) decision.
  - `src/rls-policy-review.ts` — #199 live `pg_policies` semantic review vs a tenancy model; `detect-deeper --tenant-key`.
  - `src/definer-review.ts` — #200 caller-authorization body-read over non-ok definer verdicts.
  - `src/pii-protection-review.ts` — #201 PII adequacy over M10 classification + exposure facts.

Each pass has positive-fires / negative-clears fixtures. `pnpm verify` green on both PRs.

### Still-open audit backlog (sweep-excluded — need live env, human, or design)
- **Live-env:** #161 (seam probes live), #159 (NO-RATE-LIMIT vs deployed test app) — need a deployed target.
- **Human/GTM/business:** #168 (responsible disclosure — outward comms), #10/#11/#12/#13 (free audits, LLC, posts, partnerships).
- **Epic/deferred-design:** #2 (epic tracker), #4 (Tier 2 vuln-pipeline port — deferred until Tier 1 ships).

## #162 checkExposedSchemas — validated live, CLOSED (2026-07-11)

Ran the connected-tier check against both ATC live projects. **Enumeration method that works:** a
PostgREST request with a bogus `Accept-Profile` returns `PGRST106` whose hint lists the exact
exposed schemas — do it with the **service_role** key against `GET /rest/v1/` (the anon key is
correctly gated off that root; good hardening). So the runner can use service_role OR the Management
API — no special token wiring needed after all.

Results: **both RAG and main are clean** on both checks. Each exposes only `public, graphql_public`
(Supabase default → `checkExposedSchemas` clean), and `pg_graphql` is **not enabled** on either
(the `/graphql/v1` introspection query returns `pg_graphql extension is not enabled` for anon AND
service_role), so `graphql_public` is inert → `checkGraphqlIntrospection` clean too. Detectors
validated live with an honest all-clean result; no ATC finding. (Note: an interim SB-GRAPHQL-
INTROSPECTION "finding" on main was MY false positive — I misread a GraphQL HTTP 200 error body as
the extension serving; verified-before-file caught it. Lesson: for GraphQL, check the body, not the
status code.) Full detail in the #162 comments.



## Issue sweep 2026-07-11 — 4 batches merged, 6 issues closed

All source-level/repo-local. Detail:
- **#163/#164/#171** (PR #184) — scanner false-positive precision: `harvey-edgefn-secret-fallback`
  now requires a secret-shaped fallback literal (URLs/env clear); `harvey-auth-admin-in-client`
  requires an admin/service-role-shaped client id (anon clears); `harvey-route-noauth` guard
  regex gained the `with*Audit` + `constantTimeEqual`/`timingSafeEqual` buckets. Calibration
  gate PASS.
- **#181** (PR #185) — M9 cache-config check tightened: suppress when the file reads a dynamic
  API (`cookies`/`headers`/`noStore`/`searchParams`), scope to page/layout only (drop `route.ts`).
  **ATC: 230 → 3 for that taxonomy, 450 → 223 total** via `pnpm detect-static`. Left
  `docs/m9-app-router.md` stale (supervised) → tracked in **#186**.
- **#179** (PR #182) — `parseBundleAnalyzerStats(statsPath)` adds M7B-04/05/06 (duplicate
  modules, dep attribution, Turbopack per-route) via a `--stats` flag; synthetic stats fixture,
  no `@next/bundle-analyzer` dep installed (package.json supervised). Stats-JSON shape is
  **unverified against a live analyzer run** — confirm on first real use.
- **#160** (PR #183) — `src/pentest/client-surface.ts`: `surveyClientSurface(app)` scans a
  client-only app (browser extension) source for manifest permissions, backend URLs, embedded
  secrets; `clientSurfaceTestedId` closes the `assertComplete` gap. CLI `--mode=surface`.

**Follow-ups opened this sweep:** #186 (M9 doc refresh, human/docs), #181 was itself opened
first then swept. Still-open audit backlog below.

### Sweep-excluded (still open — need live env or human)
- **Live-env:** #162 (checkExposedSchemas vs live project), #161 (seam probes live), #159
  (NO-RATE-LIMIT vs deployed test app) — all need a running/deployed target.
- **Human/GTM/business:** #168 (responsible disclosure — outward comms), #10/#11/#12/#13
  (free audits, LLC, posts, partnerships).
- **Epic/deferred-design:** #2 (epic tracker), #4 (Tier 2 vuln-pipeline port — deferred until
  Tier 1 ships).
- **Docs:** #186 (M9 runbook stale after #181).

## M7 code-level performance (#170) — DELIVERED, issue closed

M7 is now three layers (was: DB advisor only). Runbook: `docs/m7-performance.md` §2a/§2b/§6.

- **[M] mechanical, 17 classes**, each fixture-gated via `pnpm verify`: 14 AST classes in
  `src/detectors/perf-code.ts` (`M7C-*`, incl. React Compiler downgrade gate + version-gated
  barrel check), the `react-hooks/exhaustive-deps` adapter (`src/detectors/hook-deps.ts`,
  `M7H-*`, new devDep `eslint-plugin-react-hooks`), and the oversized-asset walk
  (`src/detectors/asset-weight.ts`, `M7A-*`, runtime-generated test fixtures).
- **[B] build tier** (`src/detectors/bundle-stats.ts`, `M7B-*`): measured gzipped first-load
  JS per route (webpack builds) + shared baseline; **Turbopack builds (Next 16 default) emit
  no per-route manifest** — baseline still measured, gap disclosed as Info (`M7B-03`).
  Remaining depth (duplicate chunks, dep attribution, Turbopack per-route via
  `@next/bundle-analyzer` stats) → **#179**.
- **[L] review checklist**: `docs/m7-performance.md` §6 — seven judgment-call classes as
  auditor questions, worked in the paid review pass.
- **Engagement entry point:** `pnpm detect-static <target> [--build <.next>]` — first CLI
  that runs the M9 + M7 detector sets over a real target (auto-detects `apps/*/.next`).
- **ATC calibration:** raw 204 → 139 after fixing 4 dogfood-exposed FP shapes (render-once
  email/PDF templates, eslint-adjudicated `<img>`, `head:true` count-only selects,
  chunked-batch loops); N+1 tiered request-path (Likely) vs background (Review). Full ATC
  static-detect run: 450 findings / 13 classes (M9's 230 cache-config best-effort rows
  dominate — that check's noisiness is pre-existing M9 territory, not touched here).
- **Coverage gate:** M7 `needs: "source"`, `freeTier: true`; no-DB engagement → M7
  **partial** (code ran, advisor n/a), never silently skipped.

## Pen-test kit (M2 / #5) — target-adaptive, monorepo-aware
The dynamic tier evolved from hardcoded calibration paths to discovering the system under test:
- **Route discovery** (`src/pentest/discovery.ts`, PR #156): walks a target's Next.js tree →
  `TargetProfile` (versioned / high-value / public-cache routes, privileged RPCs, seams). The four
  dynamic probes (#145–#148) iterate discovered candidates; a class with no candidate self-reports
  **not-applicable** (the honest result), not a hardcoded-path miss.
- **Monorepo enumeration + completeness gate** (`src/pentest/targets.ts`, PR #157):
  `discoverTargets(repoRoot, envVarNames)` → manifest of **apps** (workspace globs, classified),
  **backends** (distinct Supabase projects by env-var convention; `TEST` = write-safe instance),
  **seams** (service URLs, cross-service webhooks, service JWTs). `assertComplete` FAILS LOUD on any
  enumerated-but-untested target — coverage is now mechanical, not a judgment call (this is what the
  RAG-backend omission exposed).
- **Seam probes** (`src/pentest/verify.ts`, PR #157): DIRECT-SERVICE-CALL, SERVICE-JWT-UNVERIFIED
  (forged `alg:none` token), CROSS-SERVICE-WEBHOOK — the trust boundaries between per-app checks.
- **Intake updated to match** (PR #157): `docs/templates/auth-questionnaire.md` §0 (app/backend
  topology, per-backend connection info, write-safe-env designation, seams),
  `docs/runbooks/engagement-access.md` (manifest step, per-backend creds, seam details),
  `intake-site/index.html` (per-backend DB card + monorepo/apps/backends/seams fields). The three
  stay in sync; the questionnaire is source of truth.

**ATC live-test results (2026-07-10, read/write against TEST, read-only against prod):** tenant
isolation HOLDS on read AND write — attacker (tenant `f5665f08` owner) sees 129 own messages / 0
victim; cross-tenant reassign → `new row violates RLS`, delete → 0 (all rollback). ATC RLS keys on
`users.auth_user_id = auth.uid()` via `auth_user_can_access_conversation` (SECURITY DEFINER). Anon
denied on every sensitive table (401/42501) on both **main** and **rag**. Route discovery over ATC:
289 routes → 0 versioned, 0 public-cache, 10 high-value → SHADOW-API/CACHE-CROSS-USER correctly N/A.
See [[atc-supabase-topology]] for the MCP→project map (main = prod, rag = single prod-serving DB,
aop = off-limits client).

**Open dynamic-tier gap:** NO-RATE-LIMIT loop never run end-to-end — needs the ATC **test app
deployed** (not just the test DB) and careful scoping (its 10 candidate flows include payout/
checkout/Stripe-test paths). The apps/extension surface and the live seam probes against ATC are
also not yet exercised (enumerated, not tested — the completeness gate would flag them).

## Corpus expansion (#71 security, #72 cross-module)
Answer key + rules are per-batch modular (`src/scan/calibration/<batch>.entries.ts` +
`src/scan/rules/semgrep/<batch>.yml` / scanner extensions). Each batch is one PR, self-contained,
gated by `pnpm validate:calibration` (a class ships only if its positive is caught AND its benign
negative cleared; only `high` classes feed the free count).

**Gate after the 2026-07-10 sweep (secrets/git-history #129–#130 + review-tier authz/policy
#131–#139 merged): 142/151 static positives (62 high/free-count), 118/118 negatives cleared, the
review-tier authz/policy positives are documented offline-gate misses (LLM/paid-tier by design) —
PASS.** Connected-tier #140–#144 add live detectors (N/A in the offline static gate).

- **#71 round 1 (built earlier):** B1 secrets, B2 CVE/supply-chain, B3 injection, B4 XSS,
  B5 headers/CORS, B6 crypto, B7 auth, B8 Supabase-connected.
- **#71 round 2 (merged 2026-07-10, PRs #116–#121):** the 5-lens research (OWASP, Next.js surface,
  framework CVEs, Semgrep registry, Supabase) was deduped/ranked into
  `docs/design/corpus-roadmap-to-100.md` (PR #114), then built out in six serial batches:
  - **B9** secrets & config-secret breadth (12) · **B10** dependency-CVE & framework-version (10) ·
    **B11** crypto-API misuse & JWT-verify options (9) · **B12** next-config & client-surface
    misconfig (11) · **B13** Supabase static-config/edge + injection sinks (12) · **B14** app-logic
    heuristics (5, review-tier).
  - **Two new scanners:** `checkPublicDirSensitive` (walks `public/` for committed sensitive files,
    B12) and `supabase-static.ts::checkMigrationRlsStatic` (parses committed migrations for
    `CREATE TABLE` with no `ENABLE RLS` — moves `P-RLS-DISABLED` onto the static free tier, B13).
  - Everything else extended existing scanners/rules. ~59 new mechanical classes total (~36 high,
    ~23 review). One class dropped as a genuine B2 dup (minimist CVE).
- **#71 now has essentially no mechanical backlog.** The 18 excluded-tier candidates (semantic /
  connected / dynamic) in the roadmap §4 are correctly routed to the paid M-series, the connected
  tier, and the #5 pen-test — NOT new mechanical batches. #71 can be closed or narrowed to "connected
  P-REALTIME-NO-AUTHZ + the semantic/dynamic backlog" if you want a clean tracker.
- **#72 cross-module:** M10 PII, M4+M5 dup/dead-code, M8 mutation, M7 perf-advisors (precision-gated);
  M3 hotspots (design+fixture, live `vitals` capture deferred → **#94**); M6 simplification (paid-only).

## Excluded-tier backlog (#123–#125) — DONE, all three trackers CLOSED
The three trackers were split into 18 per-class child issues (#131–#148) and fully delivered:
- **#123 semantic (review-tier)** → children **#131–#139**, all MERGED as corpus fixture pairs
  (B15 Next.js/app-logic authz #131–#136; **B16** storage-RLS/upload/SECURITY-DEFINER policy
  #137–#139). Detection is the paid LLM `/vuln-scan`+`/triage` pass (option (b)); fixtures seeded +
  benign negatives gate-cleared offline.
- **#124 connected (live Supabase)** → children **#140–#144**, all MERGED (PR #150). Five detectors
  in `src/scan/supabase-config.ts`: `checkRealtimeAuthorization`, `checkExposedSchemas`,
  `checkGraphqlIntrospection`, `checkGotrueVersion` (×2 CVE ranges). Live-validated read-only vs ATC.
- **#125 dynamic (running-app probes)** → children **#145–#148**, all MERGED (PR #154). Four
  verify-mode replays in the #5 pen-test kit (`src/pentest/verify.ts`): SHADOW-API-VERSION,
  NO-RATE-LIMIT, CACHE-CROSS-USER, ANON-PRIVILEGED-RPC — each with a seeded positive route/RPC on
  the calibration target (GROUND-TRUTH rows 9–12) + a benign sibling the probe clears. Write probes
  gated behind `allowDestructive`. A live ATC run is the optional supervised outcome-confirmation.
- **Skills vendoring decision** (from #53, closed): reference-harness skills live user-global at
  `~/.claude/skills/`. Open call: vendor into the Harvey repo (#14) vs. keep user-global.

## ATC as live target — project topology (verified 2026-07-10)
The connected/dynamic tiers can validate against ATC. MCP → project mapping:
- **`supabase-main` = `mfaknjyqiwcjojukcnea` = atc-main, ATC PRODUCTION.** MCP applies ARE prod
  applies — **read-only introspection only** (structured tools: `list_tables`/`list_extensions`/
  `get_advisors`; no `execute_sql` exposed, a good fence). Connected-tier #140–#144 were validated
  read-only here: pg_graphql not installed + realtime.messages RLS on (clean negatives), GoTrue
  v2.192.0 w/ Azure enabled (patched — exercises #143's provider branch, no finding).
- **`supabase-rag` = `jjznkprbotkqqnuvcost`** = ATC RAG project (has `execute_sql`).
- **`supabase-aop` = `udsuxdoavlvosvbjwmud`** = the **AoP client** (Age of Piracy) — OFF-LIMITS, not ATC.

## ATC dogfood re-scan (2026-07-10) — expanded corpus validated end-to-end
Ran the full scan → LLM-triage → report pipeline against a git clone of jharvieux/ATC with the
expanded corpus. **286 raw mechanical findings triaged to 4 real (all LOW/hardening); 0 Critical/
High/Medium survived** — tenant isolation and per-route auth hold, matching the June self-audit.
- Real items: `select('*')` PII over-selection (6 routes, the one useful new-detector signal, B13),
  mutable CI action tags, a transitive `@opentelemetry/core` CVE, absent pnpm hardening opts.
- The raw scan's 3 "Criticals" + 91 "Highs" were ALL false positives (fake test-token, trusted-CI
  context, auth-via-unrecognized-guards). Strong proof of the thesis: value is in the triage gate.
- **Fix shipped: #126/PR #127** — broadened `harvey-route-noauth` to recognize custom guard helpers
  (`assertPlatformAdmin`/`assertPermission`/etc.). ATC route-noauth FPs **122 → 0**; locked into the
  #61 gate with a fixture pair. Corpus now 141/141 positives, 109/109 negatives.
- Report renderer takes raw `Finding[]` directly (same schema); render curated findings to a NEW
  `findings.<name>.json` — never overwrite `report-template/findings.atc.json` (protected).
- NOT run this pass: connected-tier live Supabase advisor (#124-adjacent, needs a live stack) and
  the dynamic pen-test (#5).

DONE (merged this session): **#53 CLOSED via PR #111** (pipeline verified end-to-end, 7/8 planted
bugs caught; runbook install path corrected). #71 round-2 corpus via PRs #112, #114–#121. Earlier:
#101/#102/#103, #54/#94/#86/#73/#76.

## Operator / manual action items (not agent-executable)
- **#70 GitGuardian — CLOSED 2026-07-10.** The `targets/calibration/` dashboard ignore works.
  Residual noted at close: FAKE secret-shaped test vectors in `src/scan/calibration.test.ts`
  (`npm_FAKE…`, `AIzaSyD0FAKE…`) sit OUTSIDE the ignored path and can trip GitGuardian on future
  batch PRs (benign; `verify` is the only required check). If it becomes annoying, add that one file
  to the dashboard ignore.
- **Vercel 404 / preview-deploy fail:** still the `harvey` project Root Directory (set to
  `intake-site`) + `RESEND_API_KEY`. PR #121's Vercel preview deploy failed for this same
  project-level reason (not a code regression — `verify` was green); merged on the required check.
- **Cross-repo GitGuardian (2026-07-09):** no other repo needs a path exclusion; ATC's only
  realistic committed secret is a fake Svix doc-example `whsec_` in two resend webhook tests.

## Deferred / not agent-executable
#4 Tier-2 (gated on demand). #10–13 business/legal/GTM. #2 epic. #14 ATC folder removal (atc repo).

## Locked product decisions (memory: `product-shape-decisions.md`)
Free count/grade = high-precision findings only + M3 descriptive map. Review/connected tier scanned
but asserted only in the paid report after verification. M6 paid-only. Gate discipline (#61): no rule
ships/counts unless it catches its positive AND clears its benign negative. **Credibility cap
(`mechanical-toolchain.md` §7): a single wrong "Critical" is credibility-fatal — the 61 high classes
were each gated exact/unambiguous; version-match ≠ exploitable, so the paid report still triages.**

## Resuming live validation (Docker down — colima stopped)
`colima start` → `supabase start -x vector,analytics` + `supabase db reset` in `targets/calibration`.
Seeded logins fail (gotrue) → mint JWTs from `JWT_SECRET`. To run the real advisor against the target:
`psql "$DB_URL" -f splinter.sql` (github.com/supabase/splinter). Scanner binaries all installed.
