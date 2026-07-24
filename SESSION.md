# SESSION — where we left off (going-forward items)

Running state log (see `CLAUDE.md` → Session log). Forward-looking; overwrite stale items.

_Last updated: 2026-07-24 (day) — LARGE issue-sweep (two waves): **17 PRs merged, 51 issues closed (0 stale), 26 net-new open → net −25**. corpus-drift now FULLY GREEN for the first time this session. See the block immediately below. Earlier blocks remain historical._

## 2026-07-24 (day, post-sweep) — benchmark research thread → BenchProctor evaluated, deterministic-triage spike filed

After the sweep, operator-driven research on external benchmarks and the LLM-triage dependency:
- **BenchProctor evaluated (#973 → PR #974 merged, `docs/design/benchproctor-evaluation.md`): DON'T-ADOPT as a general gate.** Its access-control cases are generic function-level authz (idor/authz-failure/priv-esc), NOT Harvey's ownership/tenant-scope core — 0 tenant/owner_id/org_id across 6203 JS files, Harvey 0.0% TPR there. Measured whole-suite Youden +4.0%/+3.9% (JS/TS); low score is corpus-fit (only ~12 harvey-* rules tag a CWE → CWE-strict scoring under-credits; filename ceiling +10.1%) + adversarial safe-twins penalizing the mechanical review tier, NOT capability (our #945 gate = 97.4%).
- **Confirmed for #882:** OWASP Benchmark is Java + Python-v0.1 only — **no JS/TS suite anywhere**, so the multi-tenant-isolation category genuinely has no yardstick. Reframe recorded on #882: contribute the JS/TS suite to OWASP rather than self-publish (neutralizes own-both-benchmark-and-entrant). BenchProctor is prior-art to differentiate against, not a competitor that closes the gap.
- **Filed (all via REST — `gh issue create`/GraphQL was 504ing; REST `gh api POST` worked):**
  - **#975** (sonnet) CWE-enrich the harvey-* rules + AST detectors — stands alone, serves #455 (SARIF ingestion); prerequisite for a meaningful BenchProctor score.
  - **#976** (opus) Re-score BenchProctor injection/XSS/SSRF slice as an external #945 cross-check — **blocked on #975**. Generic classes only; NOT the multi-tenant core, NOT #960's real-code aim.
  - **#977** (opus) Spike: deterministic (non-LLM) sanitizer-aware taint triage — measure the (a) guard-decidable vs (b) intent-requiring split of LLM-triage FP-suppression; benchmark the (a) half against BenchProctor's vuln/safe TWIN pairs (their purpose-built safeguard-reasoning test). The multi-tenant core is (b) and is NOT benchmarkable by BenchProctor. Complements #976 (recall) with the precision/safeguard metric; coordinate the slice.
- **None of #975/#976/#977 executed** — filed only. Natural next step: execute #975 first (unblocks #976), then #977.
- **CLAUDE.md relay from the sweep was APPLIED this session** (operator said "Update Claude.md") — 8 items + the M2 live-standup sentence. See the sweep block below.

## 2026-07-24 (day) — issue-sweep, two waves → 17 PRs merged, 51 closed, net −25

Ran `/issue-sweep` over 54 open issues. Wave 1 (operator approved 5 batches + the corpus batch): the #864–#897 adversarial-review backlog. Wave 2 (operator: "add all remainders/follow-ups to the batch", +#912/#936): the remainders/follow-ups those generated. Concurrency held at 2 (operator-set).

**Merged (17):** #903 (coverage rows for unassessable stacks: raw-SQL/other-ORM/non-JS-TS/frameworks/IaC), #909 (M2 scope-reconstruction disclosure + pg_graphql/session probes), #910 (SARIF+CycloneDX export, CVE reachability), #913 (semantic recall gate + per-module precision/recall/F1/Youden), #915 (free-tier-scope corrections + taint-ceiling disclosure), #930 (#885 fix-exec transport under the inert-diff verifier), #939 (Prisma+Supabase-native+large-schema corpus targets), #942 (SecBench recall gate + VAmPI M2 portability), #943 (ungraded breadth sweep, 15 wild repos), #947 (5 scanner/coverage bugs), #949 (framework-agnostic M9 boundary model + Remix/RR7/TanStack ports), #953 (static RLS drop-policy tracking + M1 negative), #955 (M2 invitation-BOLA/data-residue/Realtime-disclosure/PUT-discovery), #958 (Drizzle detector + framework-aware env), #959 (#928 rail-check inside verifySuggestedFix + §8 gate partial), #961 (app-layer source-recall gate), #963 (3 semantic-corpus targets scored + precision gate), #969 (M10 camelCase tokenization — was silently classifying camelCase PII as NONE), #962/#971 (corpus-drift rebaseline + M9 FP fix + carbon/inbox-zero/documenso M10 rebaseline + M4-99 sentinel).

**Highest-value finds (sweep caught, not shipped):** M10 silently classified camelCase PII columns as NONE (#936 — hit most Prisma/Drizzle apps); the M9 RR7 ports false-fired corpus-wide (#964, sweep-introduced, caught by corpus-drift, fixed same sweep); SARIF leaked operator temp paths into client deliverables (#910); quick-scan crashed on missing binaries vs disclosing (#950); mutation-scan crashed on dangling symlinks (#944). The **source-detector recall** question (#868) is now answered by measurement: **97.4% on app-layer request→sink fixtures (#945) vs 0/600 on SecBench's library-internal CVEs (#879)** — two honest, un-blended numbers, plus 72.9% SCA.

**corpus-drift reconciliation took 4 tail passes** (carbon M9 regression → M8 scorer bug → corpus-wide M10 camelCase → M4-99 sentinel) because 3 corpus-wide scanner improvements landed against a shared baseline ledger in one sweep. **Lesson for next time: rebaseline the ENTIRE corpus in one dedicated end-of-sweep pass, not per-batch.**

**✅ CLAUDE.md relays APPLIED (operator explicitly requested "Update Claude.md" at end of sweep — the named-file authorization the sensitive-paths rule requires; 8 items + the companion M2 live-standup sentence):** (1) Prisma paragraph — `detectOrm` now also resolves Drizzle/Kysely/TypeORM/etc. + raw-SQL, M1-ARCH-<LAYER> rows (#903/#901); (2) M9 row — no longer Next-only, Remix/RR7/TanStack adapters (#949); (3) coverage-guard section silent on IaC/non-JS-TS scope, now INFRA-SCOPE-00/M1-LANG-00 (#903); (4) M2 row + live-standup sentence — add pg_graphql/session/invitation-BOLA/data-residue/Realtime-disclosure/PUT probes (#909/#955); (5) run-modes section — add `--sarif-out`/`--sbom-out` (#910); (6) "M1 is the only module with a scored recall gate" — M1-semantic now has one too, M1-tenant-scope/M7/M8 precision gates (#913); (7) the "198/201, 190/190" measured-figures note is stale — re-run validate-calibration, don't quote (#913/#958); (8) app-layer source-recall gate now exists (#945). Full recommended wording is in each PR body.

**Still OPEN, genuinely operator-blocked (not sweep misses):** product rulings **#904** (M2 premium prod-probe tier), **#934** (score placeholder creds in docs/example paths — carbon "F"), **#935** (8k-finding deliverable shape); **#868** positioning edit (now armed with the real numbers, supervised doc); the fix-execution BUILD **#922–926/#929** (recommended a focused session — modifies user code); **#914** (widen free-tier M1 row, positioning); `deferred`-labeled **#920/#921** (M9 Tier B, needs SFC parse layer #920), **#946** (source-recall Lever 2). Sweep-found bugs still open: **#948** (jscpd empty-file-list root cause), **#950** (quick-scan crash-vs-disclose), **#965/#966/#967** (M2 external-target productization), **#956** (M2 storage probes), **#957** (fix §8 full run), **#960** (source-recall real-code corpus), **#899/#900** (ungraded-sweep triage/disclosure half).

## 2026-07-24 (early) — issue-sweep: M6/M7/M10 + site → 4 PRs merged (#884/#889/#891/#892), net −2

## 2026-07-24 (early) — issue-sweep: M6/M7/M10 + site → 4 PRs merged (#884/#889/#891/#892), net −2

Ran `/issue-sweep` over 28 open issues (most are operator-only: 6 responsible-disclosures #774–779, ~13 GTM/business/legal/domain, 3 epics #2/#4/#632). Operator approved **#862, #855, #830** up front, then chose **option (b)** on #749 (take the lead-capture half + #721; defer the write-probe) and told me to label the deferred remainder `deferred` + `needs-human-fix`.

- **⚠ STALE-BASE TRAP (root cause, worth remembering):** local `main` was **16 commits behind `origin/main`** at sweep start — the night session's merges (incl. PR #831 = #813/#811) had landed remotely but not locally. Triage and the first two executors (#862/#855) ran off the stale tree. Caught it when #830's packet regenerated only **7 of 12** corpus files: #813's toolchain (`m6-agreement.ts`, the 5 new fixtures, `m6-eval-runs/`) was on merged-but-locally-absent commits. Fast-forwarded local main to `d623b3b`, re-synced the executor PRs at merge. **Lesson: `git fetch origin main` and diff before triaging — don't triage against a stale checkout.**
- **Merged:**
  - **#884 (#862)** — refreshed the two stale M7 "unverified" in-code comments (`perf-scan.ts` #815, `bundle-stats.ts` #840). The third item — the **supervised** `docs/m7-performance.md` line-57 caveat — was carved out to remainder **#890** (`deferred`; agents can't edit `docs/*.md`).
  - **#889 (#855)** — wired the opt-in semantic/LLM classifier in `tools/pii-classify.mjs`: double-gated (`--semantic` flag AND `ANTHROPIC_API_KEY`), zero network when off, **no new dependency** (built-in `fetch`, injectable), default model `claude-sonnet-5`. Sends only column **name/type/table/sibling context — never cell values**; value-sampling deferred to **#893** (needs a privacy/consent ruling). Executor self-rebased off the stale base.
  - **#891 (#830)** — M6 twelve-file two-reviewer eval. Executors can't nest-spawn subagents, so the **supervisor** orchestrated it: regenerated the packet, dispatched TWO genuinely-independent fresh fable reviewers (run5/run6), then a finalizer committed. **12/12 agreement, no splits; both passes 7/7 positives + 5/5 negatives vs the §4 key** — this pair replaces the seven-file transcription as the baseline.
  - **#892 (#721 + #749 lead-capture)** — #721's intake form + Resend wiring was **already present** (night-session commits 2b939da/73e075b/81c8a13); executor didn't duplicate, added the remaining gap (per-IP rate limit + email validation on `/api/scan`). #749 lead-capture: opt-in, count-only summary, never sends project URL/anon key/table names. Write-probe deferred → **#888** (`deferred` + `needs-human-fix`; destructive-write risk, needs empirical PostgREST eval-order verification + human go/no-go).
- **Filed (3, all deferrals with named blockers):** #888 (write-probe, human), #890 (supervised M7 doc line), #893 (M10 value-sampling, privacy ruling).
- **NOT selected (left open):** **#861** (M9 raw-SQL/`pg` data-layer silent no-assessment) — a clean P2, offered as an add-on but operator didn't pull it in; still open for a follow-up sweep.
- **No CLAUDE.md sentence falsified by this sweep** (both #830 finalizer and #855 executor concurred; #855 truthed up an in-file comment only). Pre-existing relays from earlier blocks below remain owed.
- **Housekeeping:** pruned this sweep's 4 worktrees + branches. (The ~287 stale `worktree-agent-*` local branches noted in the night block still await an operator green-light.)

## 2026-07-23 (night) — M1/M2 adversarial review + competitive analysis → 23 issues filed (#864–#887)

## 2026-07-23 (night) — M1/M2 adversarial review + competitive analysis → 23 issues filed (#864–#887)

Adversarial read of M1 (multi-tenant security) + M2 (local pen-test), grounded in re-measured runs, plus a competitive analysis (per-PR reviewers CodeRabbit/Greptile/Cursor-BugBot/Graphite-Diamond; SAST/ASPM Semgrep/Snyk/SonarQube/Checkmarx-One; DAST/BOLA Escape/StackHawk/Akto/42Crunch). **No code changed, no `docs/` touched, nothing committed** — issues only.

**Measured this session (re-run, not recalled):** `detector-census` M1=161, M2=21, total 320. `validate-calibration` GATE PASS — 198/201 static positives, 190/190 negatives. 92 `harvey-*` semgrep rules, 27 taint-mode, **all 92 declare JS/TS only**.

- **The finding that matters most (#868):** across five *independent* answer-keyed targets the **FREE mechanical tier lands ~12–75%** (nocode-rescue 1/8, SuperRedHat 6/12, vandyand 6/8, SupatestVibeDemo ~0 outright, cipherx 7/20 outright) — **every 100% headline is carried by the paid semantic tier**, which itself has NO recall gate (#870). Precision is *not* the issue: the vibe-dummy `notExpectedFindings` oracle recorded 0 FPs. Since `free-tier-scope.md` makes the free scan the acquisition funnel, this is a top-of-funnel risk, not a delivery one.
- **Docs — operator edits OWED, deliberately NOT auto-applied:** **#864** `free-tier-scope.md:22` stale (free M6 indicators shipped in #267; census shows 5 live — the doc *understates* the free scan); **#865** `free-tier-scope.md:18` labels M1 "(lead)" — contradicts CLAUDE.md's equal-weight doctrine and re-seeds the #510→#504 failure mode.
- **Advertised-but-absent:** **#866** `quick-scan.ts:85` upsells SARIF + PR checks + monitoring that do not exist (PDF and re-scan DO); **#867** build SARIF (ASPM/code-scanning ingestion).
- **M1:** **#869** Drizzle/Kysely/TypeORM tenant-scope silent no-op — the M1 sibling of closed #844, never filed until now; **#871** JS/TS-only rules (a second-language service bypasses RLS invisibly); **#872** framework detect is `next|vite|other`; **#873** cross-file authz dataflow ceiling (65/92 rules syntactic); **#874** CVE reachability (confirmed absent in `dependencies.ts`).
- **M2:** **#875** we pen-test our *reconstruction*, not the deployed system — prod drift structurally invisible; **largest representation liability** ("92/92 tables, 0 leaks" is true of the reconstruction, and a client will read it as prod); **#876** four fixed personas — invite/share-link/service-account/guest paths unmodeled; **#877** no *runtime* Realtime or pg_graphql probe (#140/#142 were connected-tier *static* checks); **#878** no session-lifecycle probes (token replay after logout, refresh rotation, invalidation on role downgrade).
- **Benchmarks:** **#879** SecBench.js (real npm CVEs w/ executable oracles — fixes the "5 of 6 targets are teaching labs" distribution gap); **#880** crAPI/VAmPI as an external M2 BOLA gate; **#881** Youden/F1 in `validate-calibration`; **#882** [gtm] publish the TS/Supabase isolation benchmark — **no public benchmark exists for our niche**; operator-gated, sequence against #740.
- **Product:** **#883** fix-verification gate — **records the DECISION NOT to build a general-purpose scanning Action** (it would run our weakest tier continuously against CodeRabbit/Semgrep) and builds the narrow loop instead: findings → tickets (exists) → fix verification → re-audit credit honored with zero operator time; **#885** `src/fix/` is half-built (all safety rails, no execution path) and was **untracked**; **#886** IaC/container fail-loud row (explicitly NOT a build request); **#887** SBOM (low, procurement-driven).
- **Verified and NOT filed — false alarms, do not re-raise:** license compliance EXISTS (`supply-chain.ts:231`, #456); tracker export EXISTS (5 adapters + `findings-to-tickets.ts`); the re-audit credit EXISTS (live site + `audit-diff --baseline`); prod-DAST folded into #875 ask 2; monitoring into #883.
- **No CLAUDE.md sentence falsified by this review.** Near-miss worth recording: a mis-quoted grep suggested `assertComplete` was gone. It is real (`targets.ts:227`), called from `assertRunCoverage` (`pentest.ts:432`), and throws → exit 1. **The coverage-guard paragraph is accurate.**
- **Operator decisions needed:** #883 packaging (bundled vs paid add-on); #882 scope ruling before any build (we would own both the benchmark and an entrant); #885 shelve-or-build call on the fix execution path.

## 2026-07-23 (late evening) — M9/M10 adversarial review → issue-sweep: 4 PRs merged (#857–#860), 19 issues closed (net −17)

Adversarial read of M9 (App Router boundary/rendering) + M10 (data classification), grounded in the code, plus a competitive analysis (per-PR reviewers CodeRabbit/Greptile/Qodo/Graphite-Diamond/Cursor-BugBot/Vercel-Agent; SAST Snyk/SonarQube/Semgrep/CodeQL; DAST/BOLA Escape/StackHawk; DSPM BigID/Cyera/Nightfall; health SonarQube/CodeScene/DeepSource). Filed #843–856 + #849, then ran `/issue-sweep` over 45 open issues and executed the code-fixable set at concurrency 3. **Operator authorized:** the #849 doc edit, #815 = use ATC main via `supabase-main` (READ-ONLY), #840 = run live in the networked env.

- **Merged:**
  - **#857** — M9 (#843–849): unbounded/self-calling-route detector + fail-loud; Prisma/Drizzle data-layer "not assessed" rows; AST (not text-range) auth/validation matching; route-segment-config + missing-Suspense checks; server→client leak one-hop aliasing; 9 M9 checks seeded into calibration; `docs/m9-app-router.md` alias claim corrected.
  - **#858** — M10 (#850–856): free-text `FREE_TEXT_REVIEW` flag; fail-loud on unrecognized column types; `ALTER TABLE ADD COLUMN` parsed; scope disclosed (live=public-only, static=no-views); Prisma enum/composite classified by name; `blood_type` carve-out + salary/age/maiden-name/security-Q&A/orientation + word-bounded regexes.
  - **#860** — CLI test reliability (#838,839,841): jscpd `--no-gitignore` (worktree-nested-`.git` ENOENT root cause); 5s→30s child-process timeouts; Lighthouse soft-NO_FCP fallthrough + hermetic candidate tests.
  - **#859** — chore (#842): untrack non-deterministic `dry-run/timing.json`.
- **Live-verified & closed (no PR):**
  - **#815** — M7 `/advisors/performance` verified live vs ATC main (real 220-lint payload parsed clean by `parseAdvisorFindings()`; path confirmed via OpenAPI spec). Clears the last of the #816/#815 credibility pair.
  - **#840** — #817 Turbopack per-route bundle AND #818 Lighthouse reorder BOTH verified live against a real `next build` + served target (Chrome launched fine HERE, unlike the sandbox that filed it).
- **Filed (2):** **#861** (M9 raw-SQL/`pg` data layer still silently unassessed — #844 remainder; real blocker: needs a `detectOrm` raw-SQL signal), **#862** (refresh stale M7 "unverified" comments in `perf-scan.ts` + `bundle-stats.ts` + `docs/m7-performance.md`).
- **Still OPEN — #830** (M6 paired two-reviewer eval): still deferred — needs two genuinely independent contexts; NOT a doc edit, so intentionally excluded from "include the doc edits".
- **No CLAUDE.md sentence falsified by this sweep** (grep-verified; all executors concurred).
- **⚠ Supervised-doc correction OWED to operator:** `docs/m7-performance.md`'s "not yet independently verified" caveat is now stale (#815/#840 verified live) — tracked in #862, needs an operator-approved edit.
- **Housekeeping:** pruned this sweep's 5 worktrees + 6 branches. NOTE: **287 pre-existing `worktree-agent-*` local branches** from older sessions litter the repo — a separate cleanup for the operator to green-light.

## 2026-07-23 (evening) — issue-sweep executed the M3–M8 engineering set: 11 PRs merged (#826–#837), 20 issues closed (net −15)

Ran `/issue-sweep` over 45 open issues (most are GTM/business/epic/external-disclosure — not code-executable). Operator approved the engineering set, authorized supervised-path + CLAUDE.md/`docs/audit-modules.md` edits with report-back, ruled #824's paid signal = the existing `run-audit --connected` tier flag (no new mechanism), and **capped concurrency at 2** after a mid-sweep memory scare (freed ~15 GB by killing two crashed agents' orphaned `next-server`/`vitest` processes — no Docker was involved).

- **Merged:** #807/#808 (M3 cold-target fallback + vitals version assert), #809 (M4 whole-repo diverged-clone), #810 (M5 knip no-install → M5-98 reduced tier), #811 (M5 docs) + #813 (M6 two-reviewer protocol; **#812 closed-stale** — already done in #396/9ea4575), #814 (M6 retry/backoff+pagination indicators graduated to mechanical), #816/#817/#818 (M7 code precision **84.6%→100% measured**, Turbopack per-route bundle fallback, Lighthouse bundled-Chromium preference), #819/#820 (M8 auto-pull coverage + auto-discover Stryker path), #821/#823 (M8 assert-intent detector + M7/M8 labeled-corpus precision gates, `validate-precision.ts`), #822 (report per-module confidence/limitations block), #824/#825/#747 (paid-tier ticket gating via `--connected` + `Finding.fix`→applicable diff + tracker rate-limit/scoped-token intake), #732 (GTM "AI-review-is-weak" evidence re-verified — all 3 CONFIRMED, ~55% figure qualified as enhanced-prompt best case).
- **STILL OPEN — #815** (verify M7 `/advisors/performance` endpoint live): EXCLUDED from the sweep — needs a live Supabase project (operator resource). It is one of the two credibility-critical items from the review below; **#816 (the other) is now closed at 100% precision, so #815 is the last of that pair.**
- **Remainder #830** (OPEN): the M6 paired two-reviewer eval over the expanded 12-file corpus — needs two genuinely independent contexts a single agent can't honestly produce.
- **5 follow-ups filed:** #838 (M4 jscpd ENOENT local-sandbox flake — passes CI), #839 (spawn-heavy CLI tests time out under full-suite load), #840 (live-verify #817/#818 in a networked env), #841 (Lighthouse `launchChrome` soft-NO_FCP no-fallthrough), #842 (untrack non-deterministic `dry-run/timing.json`).

**⚠ CLAUDE.md / supervised-doc corrections OWED to operator (this session's merges falsified them):**
- **CLAUDE.md — NOT yet edited:** "only M1 has a scored recall gate" is now FALSE — #823 added an M7/M8 labeled-corpus precision gate (`validate-precision.ts`); recommend appending to the detector-census bullet. The M3 row is also understated after #807/#808 (cold-target fallback + vitals version assertion).
- **Already edited under authorization (informational):** CLAUDE.md M5 row + `docs/audit-modules.md` §M6 (both M5 engines named, M5-98 tier, #283 first-real-target status) — landed in #831.
- **Stale, NOT edited — need operator update:** `docs/m7-performance.md` §2a (missing #816 guards); `docs/m8-test-quality.md` §1/§2/§4 (Stryker report-path / manual-coverage / categories-3-4-manual now mechanized by #820/#819/#821); `docs/design/m7-chrome-provisioning.md` (browser resolution order); `docs/quality-extras.txt` ~L34-36 + `docs/design/m6-handrolled-catalogue.md` (entries 45,73) + `docs/design/m6-corpus-frequency.md` (73) (retry/backoff + pagination now graduated by #814); `docs/gtm/02-positioning-messaging.md` (fold in the re-confirmed evidence from #732).

## 2026-07-23 (later) — antagonistic M3–M8 review + competitive analysis → 19 issues filed (#807–#825)

Analysis-only session (no code changes). Ran an adversarial read of M3–M8 grounded in the code, plus a competitive analysis vs per-PR reviewers (CodeRabbit/Greptile/Qodo/Graphite-Diamond/Claude Code Review) and whole-codebase platforms (SonarQube/Codacy/DeepSource/CodeClimate/CodeScene).

**The adversarial read (what's thin):** M3 wraps the external `vitals` plugin and can't run cold (needs a pre-run `.vitals` store + git history); M4 is 90% jscpd, 10% the original `diverged-clones.ts`; M5's dead-code half is knip and breaks the "source-only" promise (needs target `npm install`); **M6 is weakest** — the paid verdict has no detector and never will, its only eval is n=6 with measured reviewer disagreement, and `simplify-scan` literally prints source without judging; M7's DB advisor rests on an endpoint path **never verified live** and its code tier measured **~10% raw precision**; M8's source tiers (test-intent + stub-check) are the strongest original work but the mutation tier is a fragile Stryker wrapper and the headline coverage-vs-mutation gap is **hand-filled**. CodeScene is the most dangerous single competitor (it IS M3+M6, productized, with ACE auto-refactor).

**Competitive throughline:** the field moved from *flag it* to *fix it* (DeepSource autofix, CodeScene ACE, Qodo test-gen). Harvey already ships a **prose** `Finding.fix` into tickets (`findings-to-tickets.ts:98`) — the gap is an *applicable diff*.

**Product decisions (operator, this session) — now in the [[product-shape-decisions]] memory:**
- Withholding *fixes* for paid tier is fine; adding *free-tier precision* is always good.
- **Ticket-filing add-on = PAID ONLY** (free-tier Info/Review indicators are too noisy to file into a client repo) → **#824**. Not yet enforced in code (`file-findings.ts` files any findings.json).
- Fixes-as-diffs = paid; free tier stays indicators-only.

**19 issues filed, all `audit-service` + tier label** (deduped clean — no open duplicates; referenced #314/#556/#793/#796/#504 are closed historical):
- M3: **#807** cold-start/vitals dependency (opus), **#808** pin vitals version (sonnet)
- M4: **#809** whole-repo diverged-clone pass — amended to REQUIRE #61 fixture pairs + volume cap (sonnet)
- M5: **#810** knip without npm install (opus), **#811** doc reconcile: slop AST runs under `detect-static` (haiku)
- M6: **#812** manifest in packet (sonnet), **#813** two-reviewer protocol (**fable**), **#814** graduate deferred hand-rolled classes (sonnet)
- M7: **#815** verify advisor endpoint live (sonnet), **#816** raise ~10% code-tier precision (opus), **#817** Turbopack bundle gap (sonnet), **#818** provision Chrome for CWV (sonnet)
- M8: **#819** auto-pull line coverage (sonnet, amended: disclose partial when no coverage), **#820** auto-discover Stryker report path (haiku), **#821** mechanize "asserts WHAT not WHY" (**fable**)
- Cross: **#822** per-module limitations block in report (sonnet), **#823** precision gates for M7/M8 detectors (opus)
- Add-on: **#824** gate ticket-filing to paid (opus), **#825** upgrade `Finding.fix` prose → applicable diff, paid-only (opus)

**Sequencing to honor:** #823 (build the M7/M8 precision instrument) BEFORE #816 (improve against a recorded baseline) — "measure, don't recall." The two credibility-critical ones for paid delivery: **#815** (unverified endpoint) + **#816** (10% precision). Cheapest competitive wins: **#819** + **#821** + **#825**.

**No CLAUDE.md relay owed** — this session filed issues, didn't falsify any CLAUDE.md claim. (Note #811, when worked, edits the CLAUDE.md M5 row — operator has authorized doc edits.)

## 2026-07-23 — corpus rescan (14 full audits), disclosures, Harvey dogfood, tool-gap fixes, Prisma support

**Flagship corpus: 14 apps FULL-audited** (mechanical + LLM semantic + `dynamic-validate --execute` live stand-up + mutation), findings.json per app in scratch (`scratchpad/corpus/`). Split: 7 real-world apps, 5 deliberately-vulnerable samples, 2 ours (Harvey, AoP). Preliminary signal (hedged, NOT published — gated on #740): of 7 real-world apps, **2 shipped a Critical** (proposit systemic cross-tenant BOLA; launch-mvp unauth account-delete/subscription-cancel); the thesis-confirming standout is supatest's **RLS tautologies that pass Supabase's own advisor but gate nothing**; makerkit/boxyhq are genuinely hardened (honest contrast). **Stack-artifact caveat:** the M2 "no login rate-limit / account enumeration" findings reflect local GoTrue defaults, not the app — stripped from the stat (and fixed in #769).

**Disclosures filed (operator action — I can't send outreach):** #774 launch-mvp (2 Crit/4 High), #775 proposit (5 High/1 Med), #776 devtodollars (1 Med), #777 boxyhq (1 High/2 Med), #778 wallens11 (1 Med; prior Crit REMEDIATED), #779 cipherx (**live service_role key committed in .env → rotate**). subpay (archived) + makerkit (hardened) → no disclosure. 4 samples only-known → no disclosure. Old stale disclosure issues (#168/#214–#219) closed.

**Harvey dogfood → 2 real bugs fixed:** #765 (**High command-injection self-RCE** — M8 stub-check shell-interpolated untrusted target test-paths; now argv-array, regression-tested), #766 (deduped the security-detector walk into `common.ts` + hardened `job-tenant-scope` tests).

**Tool-gap follow-ups (all merged):** #769 (M2 GoTrue-default auth findings → Info+caveat on local standup), #770 (M10 discovers root/nested schema.sql), #771 (M8 no-node_modules still emits M8-00), #772 (M2 seeder infers org/tenant FK-parent for org-model schemas), #773 (M8 mutation handles TypeScript-7 targets).

**Prisma/Postgres support — EPIC #756, core landed:** #757 `detectOrm` + RLS-detector gating; #758 M10 from `schema.prisma`; #759 M2 plain-Postgres + `prisma migrate` + app-route probing (**proven live: boxyhq M2 requires-live-run → real verdict, a Critical on /api/hello**); #760 M1 Prisma tenant-scope/BOLA detector (gate 198/201, 190/190). Verified: `detectOrm(boxyhq)=prisma`, M10 classifies its schema, full re-audit COVERAGE PASS. **Still open:** #761 M7 Prisma perf (deferrable), #787 authenticated cross-tenant app-route probing, #762–#764 docs/website/SEO (GTM — file-only until operator go).

**Gate figure (measured 2026-07-23): 198/201 static positives, 190/190 negatives, GATE PASS.** Never quote — run `validate-calibration`.

## 2026-07-22 issue-sweep — prior work committed, 8 issues merged + a live-M2 first (net −6)

Ran `/issue-sweep` over 31 open issues (mostly GTM/business/external-disclosure — not code-executable). Operator approved a code set and, separately, "commit and merge all prior work"; then pulled in a round 2.

- **Prior work committed + merged (PR #734):** the marketing `site/`, `docs/gtm/`, ATC/AoP engagement reports + `report-template/findings.aop.json`, and config. **Caught before committing:** `git add -A` would have staged ~37 transient `.claude/worktrees/agent-*` checkouts — added `.claude/worktrees/` to `.gitignore` instead (that dir must never be committed).
- **Round 1 merged:** **#712** (M2 loadSeeds scan-scope path fix, verified against a repro test); **#733** (Linear+GitLab tracker adapters → remainder **#736**); **#718** (the deliberately-vulnerable `targets/vuln-seam-app/` fixture, 8/8 offline-verified → remainder #738); **#726** (flagship-research methodology + `corpus-aggregate` harness → remainder **#740**); **#723/#724/#725/#727** (site audit/pricing/sample-report/trust/OG/SEO pages; `next build` green → remainders **#742/#743/#744/#745**).
- **Round 2 merged (operator pulled in):** **#736** (findings→tickets orchestration: mapping+dedup+dry-run → remainder **#747**; CI knip-failed on 4 unused exports, opus fix agent unexported them); **#745** (deeper client-side RLS-checker probes, SSRF guardrail preserved → remainder **#749**); **the live-M2 run #738+#717+#159** — `dynamic-validate --execute` stood `vuln-seam-app` up on the local Docker/Supabase stack and reached **4/4 seams proven, 0 controls flagged, clean teardown**, guarded by `src/pentest/vuln-seam-app.test.ts` and recorded in `docs/design/vuln-seam-app-live-validation.md`. (PR #751 initially re-carried the already-merged fixture → conflict; opus fix agent rebased it to a proof-only diff.)
- **Filed #752** — GTM pricing draft (`docs/gtm/content/service-page-supabase-security-audit.md`) still shows old flat $2k/$5k vs the shipped size-banded $500/$1k; operator edit (human-owned IP).

### ⚠️ CLAUDE.md RELAY (operator edit — agents can't touch CLAUDE.md)
The coverage-guard "Still open" paragraph is now stale: it says the seam probes' *proven* branches + the NO-RATE-LIMIT loop (#159) still need a target shipping insecure surfaces, "tracked as residual #717 with a … fixture to build in #718." **Those are now done live.** Recommended replacement (from PR #751): "…the seam probes' and the NO-RATE-LIMIT loop's *proven* (finding-producing) branches have now been exercised live (#717/#159 satisfied; the #718 fixture is built): a `pnpm dynamic-validate targets/vuln-seam-app --execute` run reached 4/4 proven with zero controls flagged, guarded by the offline `src/pentest/vuln-seam-app.test.ts` and recorded in `docs/design/vuln-seam-app-live-validation.md`." Keep the paragraph's final clause about out-of-orchestrator passes emitting artifacts end-to-end (still true).

### Note to self (memory written)
The local **Docker + Supabase stack is standing Harvey infrastructure**, not an environment gate — I repeatedly triaged live-M2 issues as "blocked on a live target" when the stack is right here. Operator corrected it. See the [[local-stack-is-standing-capability]] memory.

### Still open — gated on operators/external parties, NOT the stack
- **Remainders from this sweep:** #740 (research execution: corpus approval + disclosure + publish), #742 (sample-report real client data), #743 (trust-page legal review + #11), #744 (Search Console/Bing domain tokens), #747 (tracker rate-limit + scoped-token auth + full CLI), #749 (RLS-checker write-probe + lead capture), #752 (GTM pricing draft edit).
- **Non-agent-workable (unchanged):** #2/#632 epics, #4 (Tier-2, blocked on Tier-1), #10–#13 GTM/business, #168/#214–#219 external responsible-disclosures, #728–#731 GTM/brand/partnerships/social.

## GTM / marketing workstream (2026-07-21/22) — NEW, separate from the M1–M10 scanner work

A full go-to-market strategy and a marketing website were built this session. This is a
distinct workstream from the audit-tool engineering below; the GTM/business issues
(#2/#4/#10–#13) remain the tracker home for business items. Nothing here touches the
scanner code or the calibration gate.

- **Strategy lives in `docs/gtm/` — 12 docs, start at `00-overview.md`.** Built fresh
  from a verified deep-research market pass; prior GTM docs (`docs/go-no-go.md`,
  `outreach-template.md`, `free-tier-scope.md`) were deliberately NOT used as input
  (operator direction), then cross-checked after in `10-old-docs-crosscheck.md` (four
  real items folded back in: the enterprise-questionnaire trigger, the SOC 2 referral
  angle, cold-email-collapse tactic, and an AI-review-is-weak evidence set pending
  re-verification).
- **Brand DECIDED: "Harvey" = "QA leader in a box".** Whole-codebase readiness verdict
  across ten EQUAL modules; **security is one module + an acquisition hook only, never
  the product's frame** (recurring operator correction — see the
  [[harvey-full-quality-suite-not-security-only]] memory; I defaulted to security twice).
  Positioning/pillars/ICP in `02-positioning-messaging.md`.
- **Domain DECIDED: `harvey-qa.com`** (operator, 2026-07-22 — switched from the earlier
  `harvey.review` after it was taken at purchase; puts "Harvey QA" in the domain, a `.com`,
  no-hyphen `harveyqa.com` worth grabbing defensively). "Harvey" bare is unwinnable in
  search (harvey.ai legal-AI) — ranking comes from content, never the brand token.
- **Pricing DECIDED: size-banded (lines of code), three tiers**, in `03-pricing-packaging.md`:
  Free $0 / **Connected** (full source review + live-DB read, from $500) / **Full**
  (everything incl. local stand-up + live pen-test + mutation testing, from $1,000).
  Connected is the cheaper paid tier, Full the premium — the pen-test/stand-up is the
  expensive work, so it's the top tier and "Full" now genuinely means everything. Scales
  small→large, enterprise/regulated = custom. Auto-quoted from LOC measured during the
  free scan.
- **Acquisition hooks in `11-acquisition-hooks.md`:** security (verified-demand door),
  scalability/load-readiness (moment hook) + "app feels slow" (felt-pain lane), "AI slop"
  (framed at the AI, not the founder), the "re-fixing the same modules" umbrella, launch-
  readiness, diligence, compliance/PII. Each is a separate content/landing lane funneling
  to the one free scan. Demand only VERIFIED for the security cluster — validate the
  others before investing.
- **Marketing site BUILT: `site/` (in THIS repo).** Real Next.js 15 app (App Router,
  hand-authored theme-aware CSS), homepage ported 1:1 from
  `docs/gtm/content/homepage-prototype.html`. **`npm run build` is green** (verified).
  SEO/AEO wired: Organization/Service/FAQ JSON-LD, `llms.txt`, sitemap, robots, metadata,
  favicon. It has its own package.json/tsconfig/build and is **excluded from the root
  `pnpm verify` toolchain** (eslint + vitest ignore `site`, like `epic-builder-web`; knip
  and tsconfig are already `src`-scoped). (Originally built as a sibling `../harvey-review/`;
  moved into the repo per operator, 2026-07-22.)
- **LIVE IN PRODUCTION at https://harvey-qa.com** (deployed 2026-07-22, #722 done). Hosted
  by the Vercel project **`harvey`** (`prj_53NH7eOFAxXwoSKAMYO8Ye93qEer`, team
  `jharvieux-1491s-projects`). The git link to `jharvieux/Harvey` is **`sourceless`** (no
  push-to-deploy), so deploys are **CLI-driven**: `cd site && vercel --prod --yes`. Project
  config: rootDirectory cleared to null + framework `nextjs` (was a stale `intake-site`);
  `site/.vercel/` holds the link. NOTE: because deploys are CLI, pushing `site/` to `main`
  does NOT auto-deploy — redeploy via the CLI after changes.
- **Remaining before the form works:** set `RESEND_API_KEY`, `SCAN_NOTIFY_TO`, `RESEND_FROM`
  in the Vercel `harvey` project env (#721). Until then `/api/scan` returns a 503
  "not set up yet" (verified live) — graceful, no lost leads silently.
- **Positioning BROADENED (2026-07-22, operator):** homepage brand/title is now
  **"Codebase QA for AI-Generated Apps"** (was Supabase-specific) — "code" kept
  discoverable via meta/keywords/body/`llms.txt`. Site changes live: per-stack "what we
  check" section (Supabase/Next.js/Vite), the "1 in 10" stat now cites CVE-2025-48757,
  the tools-comparison expanded to two tables (each tool's job → Harvey does all + more,
  naming Snyk/Dependabot/ESLint/SonarQube/CodeRabbit), module 1 renamed **"Access control
  & data security"** (so single-tenant teams see value), the mutation-testing line
  reworded, and a **"Findings to tickets"** paid add-on (auto-file findings into
  GitHub/Jira/Linear/GitLab/Azure — automation tracked in **#733**). Strategy docs
  realigned: `00-overview`, `02-positioning`, `06-seo-aeo`.
- **All outstanding GTM/site work is tracked in #721–#733** (label `audit-service`): site
  form/deploy/pages (#721–#725), content + research (#726/#727/#732), hooks (#728),
  partnerships/brand/social (#729/#730/#731), findings-to-tickets automation (#733).
  Existing #10 (demand validation) and #11 (LLC/terms) remain valid; the #2 epic body is
  stale (commented with the refresh).
- **CLAUDE.md relay (operator, agents don't edit CLAUDE.md):** two optional additions
  proposed — (1) note that the marketing site now lives at `site/` (excluded from root
  verify like `epic-builder-web`; deploy via `cd site && vercel --prod --yes`); (2) a
  "Bash cwd resets between calls — always `cd <dir> && …` in one command" doctrine bullet
  (I ran deploys from the repo root 3× this session; also saved as the
  [[cd-into-target-dir-same-command]] memory). Wording given to the operator; not yet in
  CLAUDE.md.
- **Delivery note:** the homepage prototype is a self-contained HTML file in-repo
  (`docs/gtm/content/homepage-prototype.html`, openable in any browser); the real site is
  the Next.js app. Do NOT rely on claude.ai Artifact preview links — the operator can't
  open them; deliver files in-repo or to the side panel.

## This session (2026-07-21) — issue sweep, 10 issues merged

Ran `/issue-sweep` over 26 open issues; 10 executable, 16 excluded (EPICs, GTM/business, external-project responsible-disclosure, and M2 items that need a deployed target: #159/#161/#4). Six batches, all merged into `main` with `verify` green:

- **#698 (M8 #655)** — true root-scoped mutation run for monorepos: invoke the root runner, scope mutate globs to the app under audit; was previously only the #623 detection gap.
- **#699 (M2 #610/#617/#658)** — monorepo per-project stand-up (every Supabase project's migrations, isolated stack each), FK-to-auth owner-column seeding (`author_id` etc.), and auth-attack probe wired into the live-standup factory.
- **#700 (M1 #663/#664)** — Express+pg IDOR / mass-assign / CORS detectors + hardened service-role-literal (JWT decode, demo-key correlation, cross-file const). **res.json exposure sub-class deferred → remainder #701 (OPEN).**
- **#704 (M2 #669/#670)** — stored/second-order XSS confirmation logic + M1-finding→exploit-seed derivation, source-side + fixtures. **Live booted-target exercise deferred → remainders #702/#703 (OPEN).**
- **#705 (M2 #675)** — `--bizlogic` seed generator from route + schema introspection, new `pentest --mode=bizlogic-gen`.
- **#706 (M6 #638)** — RESOLVED: retired the false-firing `detectRouteGuard` indicator (its own positive fixture was idiomatic react-router code) and recorded EXCLUDED in `docs/design/m6-handrolled-catalogue.md`. M6 detector count 32→31; M1 calibration gate unaffected (190/193, 178/178); dry-run byte-identical.

### Follow-up arc after the sweep (all merged + LIVE-VALIDATED this session)
- **#707 (M1 #701)** — res.json excessive-data-exposure detector shipped (narrow name-gated; zero new corpus FPs). #701 CLOSED.
- **#709** — CLAUDE.md relay MERGED (operator-authorized): enriched the #545 autonomous-M2 sentence (per-DB monorepo stand-up #610 / FK-owner seeding #617 / auth-attack wiring #658) and refreshed the gate figure to **197/200 static positives, 189/189 negatives** (re-measured, not recalled).
- **Live exercise vs a stood-up `cipherx-vulnerability-lab`** (docker + supabase CLI local; target cloned in scratch):
  - **#702 (stored XSS confirm) — PROVEN live**, CLOSED. Wrote `<script>` into `support_tickets.description`, read it back unescaped from `/api/tickets/search?format=html`.
  - **#703 (finding→seed derivation) — bug found, FIXED (#710), then PROVEN live**, CLOSED. `extractParam` anchored to the sink line not the input read → 0 sinks on real scan output; #710 scans the enclosing handler body → real `m1-findings.json` now derives the SSRF sink (0→1) and the live canary out-of-band callback fires.
  - **#708 (probeInjection false-negative on ILIKE-context SQLi) — found live, FIXED (#711), then PROVEN live**, CLOSED. Widened `DB_ERROR` fingerprint + ILIKE-context boolean/timing payloads; all three signals fire on `search_tickets_unsafe`.
- **#161 seam probes — WIRED + reachability-proven live, CLOSED.** Diagnosed the structural blocker (`TargetProfile.seams` was populated only in `calibration-fixture.ts`; `buildTargetProfile` never set it). Fixed across three PRs: **#714** route-based seam-discovery (classifies inbound webhook receivers — excludes outbound `fetch(url)` SSRF — plus service-JWT and `/internal` routes; `buildTargetProfile(baseUrl)` populates `profile.seams`); **#716** precision fix (a verify-then-200-empty receiver like boxyhq dsync no longer false-positives — gate the proven verdict on `hasNonTrivialBody`; found in the #718 investigation); **#719** monorepo behind-the-gateway service detection (service-auth-wrapped routes / sibling internal service-URL env / service-app name → `serviceEndpoints`, grounded against ATC). **Live-proven** against `nextjs-subscription-payments`: `profile.seams.webhookEndpoints` populated live, `CROSS-SERVICE-WEBHOOK` ran end-to-end → not-vulnerable (400). #161 CLOSED.
- **#713 filed + FIXED (#716) + CLOSED** — the bare-2xx webhook FP the investigation caught.
- **Corpus seam-target investigation (per operator ask):** no corpus repo ships an *unverified* seam (every receiver verifies). Best public self-provisioning exerciser = `nextjs-subscription-payments` (webhook, not-vulnerable). ATC = only full-3-probe surface (all hardened). boxyhq richest but not Supabase-standable. Others: no seam.
- **#712 filed** — minor: `active-exploit --findings` `loadSeeds` doesn't normalize the scan-scope temp-copy path prefix (raw scan output fails route match; normal pipeline unaffected). Source-only.
- **#717 filed** — residual: the seam probes' *proven* branches + NO-RATE-LIMIT loop (#159) need a target shipping insecure surfaces (no corpus target does).
- **#718 filed** — build a Harvey-owned deliberately-vulnerable Supabase/Next fixture (insecure webhook / unfronted internal route / alg:none service-JWT / un-rate-limited high-value flow + negative controls + answer key) that stands up under `dynamic-validate --execute`. **This one fixture unblocks the entire live-testing backlog: #717 (seam proven branches) + #159 (rate-limit loop) + #715's live monorepo validation.**

**Still open after all this — LIVE-TESTING backlog all funnels through #718:** #159 (rate-limit proven branch), #717 (seam proven branches), #718 (the vulnerable fixture that unblocks both), #712 (minor, source-only). Non-agent-workable: #2/#632 epics, #10–#13 GTM, #168/#214–#219 external disclosures, #4 Tier-2 blocked on Tier-1.

## Where things stand (2026-07-18/19) — pipeline functional, six apps recall-tested, ATC engagement delivered

**The pipeline is functional and hardened.** The abort-fallout chain plus a large coverage campaign landed:
- **M2 is autonomous + isolated:** `dynamic-validate --execute` provisions its own local Supabase (unique project-id/ports, scoped teardown that never touches foreign volumes — #604/#609), applies the target's migrations incl. a root `schema.sql` (#574), seeds two tenants with a `handle_new_user`-trigger-safe / CHECK-constraint-aware seed (#598/#622), mints custom (non-Supabase) JWT sessions (#571), and runs live cross-tenant + IDOR-object + CSRF + member-vs-admin BFLA probes (#567/#587/#591). Stub-check is checkout-safe (#600).
- **App-Router taint sources** (`await req.json()`, `{params}`, `new URL(req.url).searchParams`) added to the M1 taint rules (#570) — the primary-stack gap that was silently missing IDOR/SSRF/mass-assign/SSTI on Next.js App Router.
- **Vite/no-code coverage:** framework detection (#573), monorepo-aware M9 gate (#597, no SSR false-fire on Vite workspaces), Vite M1 secrets/RLS/client-authz/CORS/headers (#565/#576/#578/#586), M7 Vite perf tier + dist bundle reader (#577), M5 knip-uncertainty disclosure (#580).
- **The semantic (LLM) tier is now run on every recall target** — it is the difference between a scanner and an auditor (see the scores).

**Six real apps recall-tested (full three-tier: mechanical + semantic + dynamic), reports in `docs/design/*-recall-measurement.md`:**
- SuperRedHat/secure-code-review-demo **12/12** (was 6/12 pre-campaign)
- thecipherxpro/cipherx-vulnerability-lab **20/21** (semantic carried 20/20)
- yagaMI-Reverse/nocode-rescue **8/8** (was 1/8; validated the Vite campaign)
- yoanbernabeu/SupatestVibeDemo **9/9** (semantic-ONLY; target is deliberately linter-proof)
- Bum-Boo/vibe-dummy-test-kit — recall 47/49 and **0 FALSE POSITIVES** (the precision oracle held)
- **aop** (jharvieux/AoP, operator-owned Vite monorepo) — strong posture, no High/Critical; 16 hardening findings filed in jharvieux/AoP #541–#556

**ATC full engagement DELIVERED — the valid retry (2026-07-18/19):** all ten modules × both apps (main, rag) + extension + packages × both Supabase DBs; connected tier read-only via supabase-main + supabase-rag MCP. Report: `docs/design/atc-engagement-2026-07-18.md`. **13 findings filed in jharvieux/ATC #2000–#2012** (5 Medium, rest Low/Info); ATC's app-code + DB isolation is exceptionally hardened, **no cross-tenant path found**, 0 verified secrets in 49MB git history. Coverage ledger fully fail-loud.

## This session (2026-07-19) — M2 isolation proof, monorepo harness fixes, detector wave, pen-test parity kickoff

**THE ATC RUNTIME ISOLATION PROOF IS COMPLETE — 92/92 tables = 100% coverage, 0 cross-tenant leaks.** M2 stood up its own isolated stack, applied ATC's 185 migrations, seeded two tenants, and ran the live cross-tenant PostgREST matrix over the FULL scoped surface. The seed evolved through four stages this session: introspection (#650) → SAVEPOINT skip+disclose (#649, 78/92) → constraint-shape-aware values (#656, 91/92) → reuse of migration-seeded lookup rows (#665, **92/92**). Fully autonomous, general (helps every future engagement), 0 leaks across all 92 tables. Recorded in `docs/design/atc-engagement-2026-07-18.md` (Addendum 5 + M2 ledger row updated to full proof). (App-route probe tier degraded to PostgREST-only on ATC's `workspace:*` npm-install — disclosed.)

**ATC finding correction (operator-confirmed):** the leaked-password-protection Medium (ATC#2007) was reframed to not-applicable — ATC is OAuth/social-only, no password auth surface. ATC#2007 closed as conditional; engagement doc row 9 downgraded (12 active findings + 1 conditional); underlying Harvey detector gap = **#671** (gate password-only auth advisors on whether password auth is enabled).

**M2 seed was redesigned twice to get there:** (1) it now **introspects the live post-migration schema** (`information_schema`/`pg_catalog`) instead of parsing migration text — killed the whole daterange/dropped-column/array/type-evolution failure class (#650, closed #646); (2) **per-table SAVEPOINT skip+disclose** (#652, closed #649) — one unsatisfiable table no longer aborts the entire seed; it skips+discloses and the rest seed. This makes the seed robust against ANY real app, not just ATC.

**The monorepo harness bugs the ATC run surfaced are ALL FIXED + merged:** #619 (isGitRepoRoot case-insensitive-FS silent secret-scan skip — now device+inode identity), #620 (per-app finding-ID collisions blocked `--findings-out`), #621 (M6 packet ignored hotspot scope → 105MB), #624 (M3 vitals CWD), #623 (M8 root-workspace dark), #607 (M8 stub-check workspace-symlink stale-code).

**Mechanical-detector wave (precision-gated per the operator directive "don't limit ourselves to only what we've verified"):** M6 react-router route-guard + vite-env (#628), M9 SPA error-boundary (#627, PR #654), M8 vitest detectors — unrestored spyOn / in-source coverage / vi.hoisted (#629). **M1 plain-Express taint sources + service-role Gap A (#614/#611) IN FLIGHT** (operator approved "build both, precision-gated").

**Pen-test parity (epic #632) kicked off:** the **auth-attack probe suite (#633) SHIPPED** — enumeration, JWT tampering (alg=none/strip/expiry/tenant-swap), password-reset abuse, auth rate-limit — as `pentest --mode=auth-attack`, fixture-tested.

### IN FLIGHT: none — all dispatched work merged. Awaiting operator steer.
**DONE this session (all merged):** ATC 92/92 100% isolation proof (#649/#656/#665); full pen-test-parity epic #632 (#633/#634/#635/#636/#637); M1 Express+service-role (#614/#611); AoP Vite-detector validation (#627/#628 correct, #638 open); M6/M9 detectors (#628/#627); M8 vitest (#629, vi.mock #660 EXCLUDED); monorepo harness bugs (#619/#620/#621/#623/#624/#607); auth-advisor gating (#671, from the ATC leaked-password FP → ATC#2007 reframed). Engagement doc = 12 active + 1 conditional finding.

### Steering options — RESOLVED by the 2026-07-21 sweep
(a) #663/#664 → DONE in PR #700 (res.json sub-class → remainder #701); (b) #675 bizlogic generator → DONE in PR #705; (c) live parity suites still need a DEPLOYED vulnerable target → #702/#703/#159/#161 remain OPEN; (d) #638 route-guard → RESOLVED as EXCLUDED in PR #706 (decidable from react-router's API surface, no external SPA needed); (e) operator's own direction — open.

**✅ PEN-TEST PARITY EPIC #632 — COMPLETE (all 5 suites built + merged):** #633 auth-attack, #634 active-exploitation (SSRF canary/XSS/injection), #635 file-upload, #636 race/TOCTOU, #637 business-logic (threat-model-driven). Merge-train reconciled the shared `pentest.ts` (additive union + closed the shared-trailing-brace collapse). **Remaining = LIVE exercise only:** run each `--mode` against a booted vulnerable target to convert requires-live-run rows into proven verdicts — #670 (active-exploit/upload), #159/#161 (rate-limit/seams), #675 (bizlogic `--bizlogic` seed generator). No such target ships these surfaces yet.

**DONE this batch:** #656/#666 (constraint-shape seed → **ATC 91/92**, #656 CLOSED). #634/#668 active-exploit. #614/#611 (M1 Express taint + service-role JWT-literal, gate PASS 189/192 pos / 177/177 neg, PR #662) → #614/#611/#644 CLOSED; FP-risky remainders #663/#664. #660 vi.mock → **EXCLUDED** (live repro; premise stale; PR #667, closed). AoP validation (PR #661) → #627/#628 validated correct on real Vite; #638 OPEN (route-guard shipped-but-unvalidated).

### ⚠️ CLAUDE.md RELAY (operator edit — agents can't touch CLAUDE.md)
The "Measure, don't recall" bullet's gate figure is now stale after #614/#662. It reads "186/189 static positives, negatives 170/170 … batch (#595/#601/#602/#611/#613/#616/#625)". Freshly measured: **189/192 static positives, 177/177 negatives**; append **#614** to the batch list. Recommended: update numbers to `189/192 static positives, negatives 177/177` + add `#614`. (Relayed to operator 2026-07-19.)

### AoP Vite-detector validation — DONE (PR #661, doc-only), with a caveat
Ran the batch-4 Vite detectors against real AoP (`~/ClaudeCodeProjects/AoP`, operator-owned Vite SPA), source-only. **Framework detection correct** (apps/web=vite, root=other since configs live under apps/*, per-workspace M9 gating → zero SSR false-fires). **#627 SPA error-boundary detector validated CORRECT** (silent — AoP genuinely mounts `<ErrorBoundary>` at root in main.tsx; the M6 hand-rolled-ErrorBoundary indicator correctly fired TP on ErrorBoundary.tsx:21). **#628 vite-env validated CORRECT** (silent — bare `import.meta.env` reads). **Route-guard (#638) INCONCLUSIVE, NOT resolved:** the detector `detectRouteGuard` IS shipped (#654, `handrolled.ts:1545`, dep-gated on react-router) — but AoP has NO react-router (uses a `useState<Screen>` state machine), so the dep-gate stayed closed and the detector never ran. **#638 stays OPEN** — its real question (does it false-fire on idiomatic `<Navigate>` guards?) needs a real react-router SPA target. (Caught the AoP agent's initial write-up marking the shape "not shipped/EXCLUDED" — verified against `origin/main` that it ships; correction in flight.)

Lane discipline this session: 3 disjoint lanes (semgrep / pentest / detectors) + dry-run regen only on the semgrep lane. Cap raised to 4-in-flight per operator.

## NEXT / QUEUED
- **Pen-test parity remainder (epic #632):** #634 active-exploitation (live SSRF canary + reflected-XSS + injection verification), #635 file-upload attacks, #636 race/TOCTOU, #637 business-logic (fable). All pentest-lane — serialize behind #656.
- **Fold #656 result into the ATC report.** (#658 auth-attack wiring, #610 multi-DB M2 stand-up, #617 FK-to-auth seed, #655 root-scoped mutation, #638 route-guard — all DONE in the 2026-07-21 sweep.)
- **Live-target-gated (need a deployed vulnerable target that ships the surfaces):** #702 (stored-XSS live confirm), #703 (M1-finding seed live exercise), #159/#161 (rate-limit / inter-service seams).
- **#701** — M1 res.json excessive-data-exposure detector (Express+pg): needs paired pos/neg fixtures + a `validate-calibration` gate pass with zero new corpus FPs. **The one source-only follow-up open.** (#660 vi.mock and #644 umbrella are both CLOSED.)
- **#671 (queued, next free slot) — finding-framing precision:** gate leaked-password-protection (+ other password-only auth advisors) on whether password auth is actually enabled. Origin: ATC is OAuth-only, so the Medium was a not-applicable FP (ATC#2007 reframed→closed). Detection: connected = `/auth/v1/settings` `external.email`; source = which auth methods the code calls (`signInWithPassword` vs OAuth-only) + `config.toml [auth.email]`. When unconfirmable → conditional, never asserted Medium.
- **OWED (after #665 lands):** reframe the leaked-password finding in `docs/design/atc-engagement-2026-07-18.md` from Medium to conditional/not-applicable (ATC OAuth-only) — deferred now because #665 owns that doc.
- **Not agent-workable:** disclosure sends #168/#214–#219 (operator action), business/GTM #2/#4/#10–#13.

**Gate figure:** run `validate-calibration` — never quote; #648 refreshed the CLAUDE.md figure this session. Per-module detector counts: run `pnpm detector-census` (M8 now +3 from #659).

**M6-corpus / #413:** provenance classified 2026-07-18 (comment on #413) — only devtodollars + ATC are unambiguously AI-generated; genuinely-vibe-coded-on-this-exact-stack is scarce. #267/#406 DONE; #283 cleared by the ATC + Cravab real-target M6 runs.

## 2026-07-17 (later) — first real-target ATC full-audit ATTEMPT — ABORTED as not valid  ⟶ SUPERSEDED 2026-07-19 (the retry succeeded; see the top section — the failures below were all fixed and the engagement was delivered)

Ran the "works" against the local ATC checkout (both apps, both live Supabase DBs, real creds). It produced real signal but was **aborted by the operator as not a valid audit** because of a chain of process/harness failures — the value of the run is the failure list, now all filed. **Do not treat the `reports/atc/` artifacts as a delivered audit.**

**What failed (→ issues):** reported "audit done" over a partial ledger (#509); ran M1 LLM semantic passes BEFORE vitals/M3 so hotspots fed nothing (#502); **scoped the M8 mutation run to the security surface, invalidating whole-suite M8** (#504) — root cause was treating security as "flagship" (#510) + a wrong "Stryker is multi-hour" assumption (it's fast — ~20k mutants/15min; memory `stryker-is-fast` written); M4/M5 hung on the whole monorepo, only did apps/main first (#505), and per-app/per-DB tiers (M7 advisors, M10 live) only hit one app/DB until prompted (#506); wrongly declared vitals unavailable when it's a plugin install (#507); M2 never actually ran (fixtures skipped) (#508). Third-party portability gaps ATC masked (it already had Stryker/test-DB/fixtures): #512/#513/#514 (fable). Cross-module hotspot prioritization, esp. M6 maintainability: #515. Deliverable completeness must derive from the ledger: #509. Full-engagement runbook: #511.

**Real findings the run DID surface (worth keeping as leads for the real retry):** M1 core-isolation is strong (416 RLS policies all gate on `auth_user_in_tenant`, JWT fail-closed, webhook replay guard correct); the one notable security item = `tenantClient` UPDATE path doesn't sanitize `tenant_id` in the SET payload (latent cross-tenant write, no confirmed call site); M10 data-classification is the real high-severity signal (gmail_oauth_tokens, contacts, booking_passengers passport/DOB); M8 tenant-isolation tests mock the DB client (53 sites) so they can't catch RLS regressions; live SECURITY DEFINER `tenant_is_active` is an existence oracle. ATC#1999 (TZ-brittle test) also found.

**Process notes:** ATC prod is reachable read-only via `supabase-main` MCP (ref `mfaknjyqiwcjojukcnea`); RAG DB is `supabase-rag` (`jjznkprbotkqqnuvcost`). Connected-tier creds: the Supabase access token is on the MCP server config (NOT in ATC `.env.local` despite expectation); `SUPABASE_DB_URL`/`SUPABASE_RAG_DB_URL` are in ATC `.env.local`. Full Stryker needs `TZ=Pacific/Honolulu` (ATC#1999). All background scans were killed and `.stryker-tmp` cleaned; ATC repo left clean (scan output only in gitignored paths).

## 2026-07-17 issue-sweep #3 — drain (5 PRs merged, 6 issues closed — net −4)

Operator-approved. Ran the two feature builds + the corpus follow-up; then the operator pulled the findings-enrichment batch (#455/#456) back in and had the CLAUDE.md relay items applied. All builds came back clean.

- **#492 (#456 + #455) — M1 findings enrichment** (excluded at the gate, then operator pulled it back in). #456: `checkLicenseCompliance` does a live npm-registry SPDX lookup per dependency (same trust boundary as the existing slopsquat check), classifies permissive/copyleft/unknown, flags GPL/AGPL/LGPL/SSPL-family conflicts (high precision) and unknown/UNLICENSED as review disclosures — never defaulted to permissive. #455: added `cwe`/`owasp` fields to the Finding schema, threaded from real semgrep rule metadata (verified the `p/owasp-top-ten` shape live) + hand-mapped 18 harvey-* rules. **Caveat → #493:** those 18 OWASP-2021 category assignments are standard but recalled, not cross-checked against OWASP's official CWE→Top-10 table — hardening pass filed before client use.
- **#491 — CLAUDE.md relay applied** (operator authorized): M7 table row now lists `pnpm lighthouse-scan`; run-modes note added for `run-audit --baseline`.

### The three feature/corpus builds (all merged):

- **#489 (#457) — engagement baseline diff.** New `src/audit-diff.ts` classifies each finding `resolved` / `persistent` / `new` across two audits of one client. Identity model (operator chose "executor decides"): `normalize(taxonomy||category) :: normalizeLocation(location)` — deliberately excludes raw line/snippet/severity so a finding that only moved stays `persistent`; a rename breaks the key and surfaces as `new` with a **low-confidence-match pointer** to the plausible prior (both sides flagged for human confirmation, never silently merged — fail loud). Consumed via `pnpm run-audit <t> --findings-out cur.json --baseline prior.json`; report leads with a progress banner + NEW/CARRIED-OVER badges + resolved-since-last-audit section. 12 intent tests.
- **#487 (#387) — M7 Core Web Vitals / Lighthouse.** Was 0% implemented (doc paragraph only). New `pnpm lighthouse-scan` (`src/lighthouse.ts` pure parse + `src/cli/lighthouse-scan.ts`): **runs locally** — builds+serves the target (`next build && next start`) and drives Chrome via **`chrome-launcher` + `lighthouse`** (both deps added, operator-approved; can reuse the Playwright chromium). Emits M7L-* findings for LCP/TBT(as INP lab proxy)/CLS/perf-score vs Google "Good" thresholds; degrades to an M7L-00 disclosure finding (exit 0, never silent) when the target can't build/serve. Opt-in CLI (heavy live pass, not folded into run-audit's M7 probe). `docs/m7-performance.md` §3 updated (approved). Live end-to-end validation split to **#488**.
- **#486 (#483) — M6-indicator corpus-drift baseline.** Measured per-target M6-indicator counts from fresh clones (proposit 10, boxyhq 2, saas-lite 2, others 0) and wired M6-indicator into the drift scorer. **Caught a real trap:** M6 indicators are `Info`-only by design (#267), and the scorer's `countedFor` excludes Info for every other module — so an un-special-cased baseline would score a permanent 0, making the drift check structurally unable to fail (the exact blind spot #483 exists to close). Special-cased M6-indicator to count Info, matched by the explicit `M6 — Indicator:` taxonomy. **#402 closed stale** — #479 had already re-baselined all M5-slop counts post-#391.

### CLAUDE.md relay — DONE (#491)
Both applied: the M7 module-table row now lists `pnpm lighthouse-scan` (#387), and the run-modes section notes `run-audit --baseline <prior findings.json>` (#457). No open CLAUDE.md relay items from this sweep.

### New backlog opened
- **#488** — validate the Lighthouse build→serve→Chrome→Lighthouse pipeline end-to-end against a real target (live-only; joins #159/#161 as operator/live work).
- **#493** — cross-check the 18 harvey-* rules' OWASP-2021 category mappings against OWASP's official CWE→Top-10 table before client use (#455 caveat).

### Still open (nothing agent-executable without operator input)
- Disclosure sends #168/#214–#219 · live M2 #159/#161/#488 · real-target #283 · **design-heavy M6-corpus trio #267/#406/#413** (need an AI-generated-code corpus sourced + free/paid ruling + supervised brief edits — a dedicated session, not a sweep) · #301 (deferred-by-design per #281) · business/GTM #2/#4/#10–#13.

## 2026-07-17 issue-sweep #2 — the backlog + earlier-deferred rulings (7 PRs merged, 12 issues closed — net −11)

Swept the six issues the first sweep opened, and — at the operator's request — put the product rulings deferred at the earlier plan gate as explicit questions, which unblocked five more. Fable on the two judgment-heavy batches (corpus/calibration honesty + the M9 owner-id detector); both came back exemplary. Everything below is MERGED on `main`.

- **#478 (M9 owner-id, Fable) — #465 + #433.** Widened `detectClientSuppliedOwnerId` to the bare-id / INSERT-value / no-in-body-auth shapes, **measured 0/3 → 3/3 recall with 0 FP** on proposit, gated on the RLS-bypassing service client (the precision boundary), and **deduped against the M1 no-auth finding** (one code defect → one finding). Wired the BOLA class into the mechanical gate via new `src/scan/bola-owner.ts` (#433) — fires exactly once across the calibration corpus; `P-BOLA-BODY-OWNER` graduated. Live gate **PASS 156/159** (was 155). Operator chose the higher-risk widen-and-wire path; the honesty gate held (real measurement, not a forced number).
- **#479 (corpus/calibration, Fable) — #470 + #322 + #252 + #248.** **#470:** corpus-drift now runs `mutation-scan --detect-only` so the `stryker binary not found` crash is gone *by construction*; M8 mutation scoring stays in corpus-m8.yml. **The drift gate is green again — first passing corpus-drift run since 2026-07-15, confirmed on the PR's own CI.** **#322:** per-module scan roots with a recorded `[scanned scope: …]` stamp so two modules can't silently describe different trees (mvp-boilerplate M5-knip not-run→22). **#252:** ≤1 placeholder/smoke spec counts as suite-absent → M8-00 zero-coverage finding. **#248:** micro-render M7 findings emit only when React Compiler is confirmed ON. All six targets' baselines re-measured from fresh clones (table in the PR); also fixed an M8/M8-intent taxonomy split that had been faking a stale-reason alarm every CI run.
- **#476 (#397)** — M6 free indicator layer now records `partial` coverage (derived from detect-static's output, not exit code), never silently `requires-live-run`; `ran` still gated on a reviewed verdict. (Decision 2 — an M6-indicator drift baseline — was scoped out → **#483**.)
- **#477 (#255)** — CVE severity may diverge from OSV but the finding must state it. Live-audited all 12 curated CVE entries against api.osv.dev: kept jsonwebtoken High with a disclosed reason, found **4 more undisclosed divergences** (next-auth/undici×2/ws) with no recorded rationale and aligned them to OSV rather than invent post-hoc justifications.
- **#481 (M10) — #459 + #460.** Dedicated report-template section for the JSONB "review for nested PII" flags (excluded from asserted tallies); planted the new PCI/HIPAA/national-ID/JSONB columns in the fixture migration — end-to-end 13/13 positives detected, 9/9 negatives clean.
- **#480 (#474)** — replaced the NUL delimiter in `diverged-clones.ts` with the `\x1f` unit separator (git treats it as text again; a first attempt used `|` which was collision-unsafe — caught in review and fixed).
- **#482 (#472)** — `pnpm run-audit` alias for the orchestrator + doc references.

### ⚠ OPERATOR-RELAY (agents can't edit these — supervised/human-owned)
1. **CLAUDE.md** now has THREE stale spots: (a) the earlier sweep's "Known gaps → Still open" sentence (#434/#435/#436 all landed); (b) the "Measure, don't recall" bullet says "155/159 static" — now **156/159** after #433 graduated P-BOLA-BODY-OWNER (recommended wording in PR #478); (c) the module table + coverage-guard spell the long `pnpm exec tsx src/cli/run-audit.ts` form — could mention the new `pnpm run-audit` alias (optional; PR #482). Best handled in one pass.
2. **docs/m7-performance.md** — the micro-render class table + "React Compiler gate" paragraph need to say those three classes now emit ONLY when the compiler is confirmed on, suppressed otherwise (recommended wording in PR #479).
3. **docs/m8-test-quality.md** — the "No test suite at all (#224)" section needs the widened M8-00 trigger (harness present but ≤1 placeholder spec) per #252 (wording in PR #479).
4. **#168 disclosure** (still from sweep #1) — don't send until its finding text is corrected to only CVE-2026-44578.

### New backlog opened this sweep
- **#483** — M6 corpus-drift indicator baseline (decision 2 of #397; now unblocked since the drift gate is green).

### Still deferred (need operator / live / design)
- **#402** — re-measure M5 baselines: now that #322 (scan roots) and #470 (drift gate) landed, this is a good candidate for the next sweep. · Disclosure sends #168/#214–#219 · live M2 #159/#161 · real-target #283 · design-heavy M6/M7 #267/#387/#406/#413 · business/GTM #2/#4/#10–#13 · #301.

## 2026-07-17 issue-sweep #1 (11 PRs merged, 25 issues closed — net −20)

Operator-approved `/issue-sweep`, 4-in-flight, Fable on the two judgment-heavy P1 batches (M10 dictionary + CVE re-check). Everything below is MERGED on `main`.

- **#461 (M10)** — parser now admits `inet/cidr/citext/bytea/geography/geometry` (#375); PCI PIN/track-data (#376), HIPAA MAC/plate/photo (#378), generic national-ID (#379) dictionary rules; **#377** JSONB "review for nested PII" low-confidence flag (report-template presentation split → **#459**); **#436** `dataMapToFindings` emits report-schema `Finding[]` from pii-classify. Calibration entries not yet planted in fixture SQL (supervised) → **#460**.
- **#462 (M4)** — test-file clones no longer elevated to security severity (#400); diverged-clone scope widened to tenant-key/supabase-query heuristics (#399). Baselines re-measured (boxyhq M4 48→47, proposit M4-diverged 1→12).
- **#464 (runners)** — M8 free-tier wiring reports `partial` not `requires-live-run` (#401); surviving-mutants → `Finding[]` (#435); M7 advisor project-ref threaded (#434). #390 (M3 artifact path) closed stale — already landed via #349/#420.
- **#466 (M9)** — path-aliased `@/…` imports now resolved in the leak/server-only checks (#380); new SSR browser-API misuse detector (#381). #326 validated: `detectClientSuppliedOwnerId` recall 0/3 on proposit — a shape mismatch (those are the no-auth class M1 already catches), not a bug; stale header comment corrected; widening design → **#465**.
- **#467 (M6)** — simplify-scan packet now carries the target dependency manifest, so the "already-in-the-dependency-tree" rubric class is appliable (#396).
- **#468 (calibration)** — #398 core was already fixed by #341/#427; added the missing regression test (module-tagged entries never silently dropped).
- **#469 (M8)** — boxyhq's 7-vs-8/35 drift is a genuine unseeded-`Math.random()` Stryker flake in boxyhq's own suite; fixed with a per-baseline tolerance band, not a point rebaseline (#432).
- **#463** — proposit's 85 M5-knip findings measured (fresh clone+install): 0 are config artifacts, ~41 real dead code vs 44 low-value; 2 auth-adjacent dead-code items flagged, neither a live vuln (#320).
- **#471 (#450)** — dynamic-validation harness: #453 delivered the core; added the two missing tests (fixture-repo layouts + emitted-artifact round-trip). Live run stays operator-side (#159/#161).
- **#473 (docs)** — planted-bug count truthed-up (#348), #221 briefs/taxonomy/ground-truth filled (#328), stale boxyhq "upper reference" framing corrected (#323), coverage-runner docs de-staled (#313). `package.json run-audit` alias was a product ruling not made → split to **#472**.
- **#245** — CVE re-check before disclosure: 7 open threads verified against the corrected corpus; only #168 needs a prose fix (drop CVE-2025-55182 + fabricated CVE-2025-66478, keep CVE-2026-44578) before sending — corrected on-thread. No corpus bug. Comment-only, closed.

### ⚠ OPERATOR-RELAY (agents can't do these)
1. **CLAUDE.md is now stale** — the coverage-guard "Known gaps → Still open" sentence lists M7 advisors (#434), M8 surviving-mutants (#435), and M10 data-map→`Finding[]` (#436) as open finding-capture gaps. **All three landed this sweep (#464, #461).** Recommended replacement: drop #434/#435/#436 from "Still open" and note "M7 advisors (#434), M8 surviving-mutants (#435), and M10 data-map→`Finding[]` (#436) landed 2026-07-17; live tiers derive `ran` when captured, schema/source tiers stay `partial` for the rows-not-sampled reason." Also `docs/m9-app-router.md` (~lines 44-45, 73-75) has aliased-import "false negative" claims now false after #466, and needs a "Checks" entry for the new SSR detector — recommended wording is in PR #466's comments. `docs/design/m6-simplification-eval.md` §3.4 wants a note that eval packets now include the target manifest (PR #467 body).
2. **#168 disclosure** — do not send until its DEP-NEXT finding text is corrected per the #168 comment (only CVE-2026-44578 is real).

### New backlog opened
- **#459** M10 JSONB nested-PII report-template presentation · **#460** M10 calibration fixture parity (plant entries in migration SQL) · **#465** M9 client-owner detector widening design · **#470** corpus-drift CI job crashes on `stryker binary not found` (the Layer-2 drift gate is blind since ~2026-07-16 — non-required check, real fail-loud gap) · **#472** `pnpm run-audit` package.json alias (product ruling) · **#474** `diverged-clones.ts` NUL bytes make git treat it as binary.

### Still open, not swept (need operator / live / design)
- Disclosure sends #168/#214–#219 (operator action) · live M2 #159/#161 (deployed app + local stack) · #283 (needs a real engagement target) · design-heavy M6/M7 #267/#387/#406/#413 (blocked on supervised briefs + rulings) · #4/#10–#13/#2 (business/GTM/epic) · #301 (deferred by design) · product rulings #248/#252/#255/#322/#397/#433 and #402 (corpus re-measure) — all deferred at this sweep's plan gate.

## 2026-07-17 — detector census, hotspot→LLM, orchestrator artifact path, dynamic-validation harness (9 PRs merged)

Started from an operator question — "detection coverage per module?" — which had no clean answer (detectors live in two engines and M1/M2/M3/M4 don't tag findings with a module). Fixed the measurement, then worked outward through the orchestrator's artifact path and the free/validation/paid run model. **Everything below is MERGED on `main`.**

- **#443** — `pnpm detector-census`: per-module detector count derived from source by owning-file map (**M1 129 · M2 3 · M3 3 · M4 1 · M5 16 · M6 13 · M7 25 · M8 7 · M9 6 · M10 32 = 235** at merge; counts DETECTORS, not recall — run it, never quote it). Plus `simplify-scan --hotspots` (M3→M6 ordering). CLAUDE.md now names detector-census as the canonical count source.
- **#444** — `harvey-route-noauth` widened to all App Router mutation verbs. Gate **155/159** static, 139/139 negatives. (Needed a dry-run regen at merge — the calibration-PR tax.)
- **#445** — three M2 probes: IDOR/BOLA dynamic-id sweep, missing/forged-auth sweep (deny-by-default allowlist), mass-assignment. Fixture-tested; live is #159/#161.
- **#446 (#416) + #451 (#448)** — the orchestrator's **derive-`ran`-from-artifact** path, read + write. `run-audit --artifacts-dir <dir>` derives `ran` for the out-of-orchestrator passes (M1 semantic/live, M2 dynamic, M3 vitals, M6 verdict) from a fresh, target-matching `<module>.pass.json`; `pnpm record-pass` emits one from any pass. Schema: `docs/design/audit-pass-artifacts.md`.
- **#447** — `pnpm scan-focus <m3-hotspots>` → hotspot-priority brief for the `/vuln-scan --extra` semantic pass (the M1 half of the M3→LLM wiring).
- **#453 (#450)** — dynamic-validation harness core: `pnpm dynamic-validate <repo>` assesses stand-up-ability (GO/NO-GO + coverage + disclosed limitations); `--execute` runs the live pipeline and emits `M2.pass.json`. Decision logic + emission tested; the live Docker/supabase pipeline is operator-run (#159/#161).
- **#454** — CLAUDE.md: fixed the stale "#416 is open" claim and added the **Run modes** note (free / validation / paid = one orchestrator gated by env flags; validation = source + LLM-over-source + local-stack dynamic, no client DB, via the pass-artifact flow).

### Backlog this session opened (all yours to prioritize)
- **#448 emit side is DONE (#451)**; what remains is each pass emitting its artifact routinely end-to-end.
- **#450 harness**: the live pipeline (Docker + Supabase CLI) has never run end-to-end against a real public repo — the remaining live work, alongside #159/#161.
- **#455** — label findings with CWE/OWASP IDs (schema field + populate from semgrep metadata; Harvey runs `p/owasp-top-ten` but findings carry no CWE). `sonnet`.
- **#456** — dependency LICENSE compliance (SPDX + GPL/AGPL); the supply-chain scan is CVE-only today. `sonnet`.
- **#457** — engagement baseline diff (resolved-vs-new across re-audits); crux is a stable finding-identity model. `opus`.
- **Idea, unfiled:** a `--validation` preset (`--llm --dynamic --artifacts-dir`, asserting the pass artifacts are present) so validation is one flag, not a combination to remember.
- **Still operator/live:** #159/#161 (deployed app / seams), the #446 target-commit-binding tightening.

**Merge mechanics learned (in the [[harvey-sweep-merge-mechanics]] memory):** branch protection requires up-to-date branches → sequential merges each need `update-branch` + a CI cycle; a stacked PR auto-closes when its base merges and must be reopened as a fresh PR to `main`; adjacent CLAUDE.md bullet edits across PRs conflict despite "different lines."

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
