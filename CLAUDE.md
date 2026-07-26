# CLAUDE.md — Harvey (external code-audit service)

Working instructions for Claude Code sessions in this repo.

## What this repo is

The productized audit service extracted from `jharvieux/atc` (ATC issue 1527, now epic #2 here): a complete **ten-module (M1–M10) security & codebase-health audit** for multi-tenant Supabase/Next.js apps. It holds the scanner code (`src/`), the venture docs (`docs/`), the functional audit briefs (`briefs/`), the report renderer (`report-template/`), and standalone audit tools (`tools/`).

- Epic: issue #2. Module and GTM work items: issues #3–#18 (label `audit-service`).
- Full spec: `briefs/audit-modules.md`, `docs/go-no-go.md`. Briefs: `briefs/scan-extras.txt`, `briefs/quality-extras.txt`, `briefs/fp-rules.txt`.
- **Prisma/Postgres apps are supported (not just Supabase), detection-gated — epic #756 complete 2026-07-23:** `detectOrm` (#757) routes a Prisma app to the app-layer M1 tier (Supabase RLS detectors gate off as N/A-by-architecture) plus a Prisma tenant-scope/BOLA detector (#760); M10 classifies `schema.prisma` (#758); M7 flags unindexed FKs from `schema.prisma` (#761); M2 stands up plain Postgres + `prisma migrate` + app-route probing with the PostgREST/RLS matrix recorded not-applicable, INCLUDING an **authenticated cross-tenant BOLA probe** (two-tenant Team/membership seed + minted sessions — next-auth cookies AND HS256/custom-JWT bearers, #759/#787/#802) — proven live against boxyhq (routed as Prisma, sessions authenticated, 14 team-scoped routes probed, correctly isolated). The missing-auth sweep gates on the response exposing data so a public `/api/hello` isn't flagged (#791), regression-gated offline in the vuln-seam-app standing check (#792); the cross-tenant probe has its own offline in-process fixture control (`targets/prisma-xtenant-app`, #796). M7 also flags Prisma N+1 + filter-column-without-index in app code (#793). Docs/site/SEO landed (#762–#764). No open Prisma residuals. **Since #869/#901, `detectOrm` also resolves Drizzle/Kysely/TypeORM/Sequelize/Knex/Mongoose and bare raw-SQL drivers (`pg`/postgres.js/@vercel/postgres/Neon/mysql2) to their own values — they route the same way as Prisma (Supabase RLS detectors N/A-by-architecture) and emit an `M1-ARCH-<LAYER>` not-assessed row naming the layer; Drizzle additionally has a real tenant-scope/BOLA detector (#901, mirroring #760).**

## The audit — full scope, how to run it, and the coverage guard

**This is a COMPLETE codebase-health audit, not a security scan.** All ten modules (M1–M10) carry **equal weight** in the deliverable — none is the "lead," none is secondary, and none may be prioritized over the others when executing. Running a security-only (or any ad-hoc) subset — or scoping any single module's run to only its security-relevant portion — is a defect; it has happened, don't repeat it. Every engagement accounts for all ten modules against every enumerated target. Authoritative scope: `briefs/audit-modules.md`.

### The ten modules and how to run each

The per-module run table (exact command, tier/prereq), the free/connected/dynamic/paid-LLM tier
split, and the `run-audit` orchestrator's run modes live in the **`run-audit` skill**
(`.claude/skills/run-audit/SKILL.md`) — invoke it before executing an engagement. Scope authority
remains `briefs/audit-modules.md`. Whichever mode runs, all ten modules are accounted for: a tier
not in scope records `requires-live-run`/`partial` with a reason, never a skip.

### The coverage guard — never silently skip a module

Completeness is a core product principle: **a module that cannot run is recorded as `partial` / `requires-live-run` WITH THE REASON — never silently omitted. Fail loud.**

**Silent omission is worse than a wrong status.** A `missed` shows up in the tally; an absent row does not. If a thing cannot be assessed, say so IN THE OUTPUT — an unstated limitation reads as a clean bill of health. (`requires-live-run: 0` once asserted nothing awaited a live run while four planted bugs were simply not listed — #345.)

**Scope decisions that are DISCLOSED, not silent (#903):** infrastructure code (Dockerfiles, Compose, Terraform, K8s/Helm) is out of scope BY DECISION — rationale in `docs/design/infrastructure-out-of-scope.md` — and a target containing it gets an `INFRA-SCOPE-00` not-assessed row naming what was found and its file counts, never silence. The same posture covers non-JS/TS source (M1's rules are JS/TS-only): `M1-LANG-00` names each language M1 cannot analyse (#871). SFC files (`.svelte`/`.vue`/`.astro`) the source loader can't read get a counted not-assessed row too (#919), pending the parse layer (#920). `M1-EXT-00` completes the family (#1065): it reports source files LOADED vs. source-like files PRESENT — measured against a yardstick deliberately independent of the loader's own extension filter — so a narrowing of what gets read fires a row instead of silently shrinking the scan.

- **The full-audit runner** (`pnpm exec tsx src/cli/run-audit.ts <target>`, #229/#310) runs all ten modules and **derives** the ledger from what each probe reported — there is no parameter through which a caller can assert that a module ran. A module with no registered runner throws before anything runs; a crashed probe fails loud rather than being excused as an environment gap.
- `src/audit-coverage.ts` (`pnpm audit-coverage`) remains the caller-supplied path, for engagements whose modules run outside the orchestrator: every M1–M10 accounted for, an unmentioned module is a gap, `assertAuditComplete` throws naming gaps. **On this path the ledger comes from the CALLER** — it enforces bookkeeping discipline, not ground truth. Prefer `run-audit`.
- `coverage-scorecard.ts` scores any bug whose detecting tier did not run (`detection: null`, supplied by the caller) as `requires-live-run`, never `missed` — it never guesses that something executed.
- `assertComplete` (`src/pentest/targets.ts`) throws, naming any enumerated-but-untested M2 target. It is wired into `pnpm exec tsx src/cli/pentest.ts --mode=coverage` (#352, closed 2026-07-16), which discovers the target manifest and fails loud on any enumerated app/backend/seam that `--tested` did not list; its firing is proven at the discovery-and-assert level and by a child-process CLI test. It has not yet been exercised against a live two-tenant stack (that limitation is now recorded in-probe, #357).
- **Known gaps in what the guard actually proves** — the running record of what has been closed and what is still open (last updated 2026-07-16) lives in `docs/design/coverage-guard-status.md`. **Still open:** each out-of-orchestrator pass emitting its artifact routinely end-to-end.

An ad-hoc security-only subset is a coverage failure, not a scan.

## Git and PRs

- **Base branch: `main`.** It is protected — every change lands via a PR into `main` with the required `verify` check green, then squash-merge and delete the branch.
- Branch names: `feature/<short-name>` or `docs/<short-name>`.
- Commit messages: imperative mood, ≤72-char summary, reference the issue (`#5: seed probe kit`).
- Never force-push `main`, never bypass branch protection, never disable CI checks.

## Verify command

```bash
pnpm verify   # typecheck + lint + tests + knip (unused code)
```

Run it before every push. If it fails, fix and re-verify before pushing. If a failure is pre-existing on `main` (not caused by your branch), call it out and don't block on it.

Other checks, run on demand: `pnpm check:duplication` (jscpd), `pnpm validate:findings <file>`.

**Regenerate the committed dry-run artifacts after any change to a detector, semgrep rule, finding schema, or calibration fixture.** Run `pnpm exec tsx src/cli/dry-run.ts --target targets/calibration --out dry-run` and commit BOTH `dry-run/findings.json` AND `dry-run/pii-data-map.json`. The `dry-run-drift` CI gate diffs both, but it is non-required (it will not block a merge), so regenerate proactively rather than relying on it. Regenerate on a machine with the mechanical-tier binaries installed (semgrep/trufflehog/osv-scanner/gitleaks) — a run missing semgrep/trufflehog/gitleaks fails, and a run missing osv-scanner produces a DEP-OSV-00 disclosure finding that does not belong in the committed artifact. The dry-run harness deliberately skips the two live npm-registry checks (`checkLicenseCompliance`/`checkSlopsquat`, via `skipNetworkChecks`) so `findings.json` stays network-independent and deterministic; real engagement scans still run both.

## Session log

`SESSION.md` (repo root) is the running "where we left off" log, refreshed toward the end of a
working session. It complements the issue-tracking rule above: GitHub issues track individual
deferrals; `SESSION.md` holds the current cross-cutting state — what's in flight, what's queued
next and in what order, open decisions, operator/manual action items, and any notes needed to
resume live work (e.g. how to bring the local stack up). Keep it forward-looking and current:
overwrite stale items rather than appending a full history. It is not sensitive — update it freely.

## Sensitive paths — never auto-change

Automated agents (issue-sweep or any batch pipeline) must never modify these without an explicit human request naming the file:

- `docs/*.md` and `docs/**/*.md` — the venture's positioning, specs, and GTM strategy. Human-owned IP. (`briefs/` is functional tool input the scanners read at runtime, NOT prose — it is deliberately not protected here, operator ruling 2026-07-24.)
- `report-template/findings.*.json` — engagement findings (client data).
- `.github/workflows/` — CI definitions.
- `CLAUDE.md` — this file.

## Model-tier labels

Issues carry one of `haiku` / `sonnet` / `opus` / `fable` to tell automated sweeps which model tier the task needs: `haiku` = mechanical/small, `sonnet` = standard implementation, `opus` = design-heavy or security-sensitive, `fable` = hardest architecture / product-shape / top-tier reasoning (above opus). Unlabeled issues default to `sonnet`.

## Working doctrine (ported from ATC)

- **Simplicity first.** Minimum code that solves the problem. No features beyond what was asked, no abstractions for single-use code.
- **Surgical changes.** Don't refactor what isn't broken; match existing style.
- **Slop sweep before commit.** Re-read your own diff and delete: comments that say WHAT instead of WHY, single-call helper functions, try/catch that re-throws or swallows, JSDoc paragraphs on simple functions, TODOs without an owner or issue ref, defensive validation of inputs that can't be invalid.
- **Tests verify intent, not just behavior.** A test that can't fail when business logic changes is wrong.
- **Never leave a known bug or deferral untracked.** Trivial: fix inline. Non-trivial: open a GitHub issue before the session ends, specific enough that someone returning cold can pick it up.
- **Fail loud.** "Done" is wrong if anything was skipped silently. Silent omission is worse than a wrong status — an absent row never appears in a tally, so it cannot be argued with. If something could not be assessed, say so in the output.
- **Never present a guess as fact.** Flag uncertainty before the claim, especially for library/API behavior and version-specific syntax.
- **Verify the defect before you fix it — this is a step with an output, not a posture.** Before writing code against an issue, a recorded blocker, or a `not-run` reason: read the current code, run the failing case or reproduce the symptom, and check `git log` on the touched paths for work that landed after the claim was written. State in the PR body what you verified and how. Already fixed → do NOT re-implement: close it with a comment naming the fixing commit/PR. Misdiagnosed but a real adjacent defect exists → fix that and correct the record. Trackers go stale: a single 2026-07-24 sweep found **four** recorded blockers false (#977's "needs `semgrep --pro`", #997's "token identity unreachable", #1009's "unplanted fixtures", #1011's "both detectors outside the gate" — the last one written in the issue *and* its design doc). The general gate for this landed in #1033: `pnpm exec tsx src/cli/validate-reasons.ts --revalidate`.
- **Measure, don't recall.** Never state a capability number — recall, coverage, precision, "we catch X", "module Y is unrunnable" — from memory, a doc, a comment, or a prior session. **Run the thing that measures it**: `pnpm exec tsx src/cli/validate-calibration.ts` for corpus recall; the dry-run scorecard only after regenerating it via the tool; `ls src/scan/calibration/*.entries.ts` for what the gate actually covers. A recorded number is a claim about the past, not the present. If you cannot verify it, write "recorded as N, unverified" — never let a stored number become an argument's premise. Beware blended numbers: they hide skew — the gate's headline positive count is nearly all M1 by design (it scores only the M1 mechanical corpus; the per-module census #341 and the parity minimum #427 make the split legible). **No recall figure is recorded in this file on purpose**: it moves every time a detector or fixture lands, and a number written here becomes an argument's premise months after it stopped being true. `pnpm exec tsx src/cli/validate-calibration.ts` prints the current TP/FN/FP/TN, the per-module census and the verdict in one run — quote that run, dated, or write "unverified".
- **Per-module detector counts come from `pnpm detector-census`, never from memory or this file.** "How many things can each module detect?" is the most-asked question in this repo and there is NO single stored number — detectors live in two engines (semgrep `harvey-*` rules in `src/scan/rules/semgrep/*.yml`, plus TS/AST detectors tagged by `taxonomy:` strings) and the repo does not tag every detector with its module, so the count is **derived by file ownership** in `src/cli/detector-census.ts`. Run `pnpm detector-census` to get the current per-module breakdown; it counts DETECTORS (capable of firing), which is distinct from RECALL. M1 mechanical has a scored recall gate and M1 SEMANTIC now has one too (`pnpm exec tsx src/cli/validate-semantic.ts --artifacts-dir <dir>`, #870/#912 — scores recorded semantic pass artifacts against an answer-keyed corpus, fails loud when nothing scored); there is also an app-layer request→sink SOURCE-detector recall gate (`pnpm exec tsx src/cli/validate-source-recall.ts`, #945) and the SecBench SCA recall gate (`validate-secbench`, #879). M1 tenant-scope, M7 and M8 have a scored PRECISION gate over a labeled corpus (`pnpm exec tsx src/cli/validate-precision.ts`, #823/#896). When you add a detector file, add it to that tool's `OWNERS` map — that is the single maintenance point. Do not quote a detector count without re-running it.
- **A recorded reason is a claim about the world, and claims decay.** When you read a comment, note, `not-run` reason, or status explaining why something cannot run or is not caught — treat it as **unverified until you re-test it**, however confidently it is written. This is the repo's signature defect: ~10 instances found on 2026-07-15 alone, every one failing silently toward a confident-looking number (#321, closed 2026-07-16, added a re-validation pass that re-tests the external-corpus not-run reasons on every drift run; #1033 generalized it repo-wide — see the next bullet). Rules that "never existed" existed; targets that "can't be scored" scored; gates described as active were unwired. **Check before you repeat it, and especially before you build an argument on it.**
- **When you RECORD a reason, tag its provenance and write the falsifier — and since #1033 there is a machine-readable form and a gate.** These claims are born at the moment work stops — a blocker is a justification for deferring, so nobody stress-tests it and, by construction, nobody exercises the path it describes. Negative claims are self-sealing: "X works" fails loudly when wrong, "X can't be done" fails silently forever. So mark every reason you write as **MEASURED** (name the command and date), **TRIED** (what you actually attempted, and what it did), or **ASSUMED** (inferred, never tested) — the four blockers falsified on 2026-07-24 were all ASSUMED written in MEASURED's confident register. **Split the reason by kind and record it as a block** (`REASON:` / `KIND:` / `PROVENANCE:` / `FALSIFIER:` or `OWNER:`+`DECISION:` / optional `TOUCHES:`; convention and rationale in `docs/design/recorded-reasons.md`): an **empirical** reason is re-testable against the world and MUST carry the command that would falsify it — **written so the command EXITS 0 WHEN THE BLOCKER IS GONE** — while a **decisional** reason awaits a human ruling and must NOT carry one (re-testing a product ruling is a category error; the gate refuses it). A reason with no falsifier is unfalsifiable and therefore permanent. `pnpm exec tsx src/cli/validate-reasons.ts` checks the structure (also enforced under `pnpm verify` by `src/recorded-reasons.test.ts`); `--revalidate` re-runs every empirical falsifier and fails loud on any that now succeeds. Prefer phrasing an untested blocker as a question ("does the token store expose non-owner reads?") over an assertion ("token identity is unreachable") — a question invites the next person to test it, an assertion closes the file. And never let a claim launder itself by being copied: two documents citing one guess is not corroboration — the #1033 sweep found that exact shape twice more (§8 classes 1/2/5 "no detector" in `fix-implementation.md` + `fix-calibration-acceptance.md`, and F-11 "no static detector at all" in `superredhat-recall-measurement.md` + `src/scan/semantic-corpus.ts`), both false, both corrected.
- **If your change falsifies a claim in this file, say so — you cannot fix it yourself.** This file is supervised: agents must not edit it. So the moment your work makes a sentence here untrue — a "known gap" you closed, a prereq you removed, a command you renamed, a guard you wired or unwired — **name the exact sentence and recommend the replacement wording**, in your PR body AND your report to the supervisor. **The supervisor must relay it to the operator with that recommendation before the session ends — it may not be silently absorbed.** Every dispatched agent reads this file: a false sentence here misinforms every future session, and in sweep #3 an uncommitted-vs-committed drift in this one file caused a class of phantom bugs. #310 falsified its own known-gap paragraph the moment it merged; its executor reported it and it still took an operator question hours later to surface. **A stale CLAUDE.md is not a documentation chore — it is a defect with a blast radius.**

Reference material in `docs/runbooks/`: `slop-detection.md`, `pr-self-review.md`, `flaky-test-policy.md`. The D-091 catalog (also the M1 taxonomy source) is `briefs/anti-patterns.md`.

## The user

Technically fluent (IT/network/systems, vendor management, leading dev/QA) but **does not write or review code**. Ask about product behavior, scope, sequencing, and trade-offs in plain-English outcomes — never ask them to read a diff.

## File conventions

- `briefs/` is functional tool input the scanners read at runtime, not prose — distinct from `docs/`.
- `report-template/` needs `pnpm exec playwright install chromium` once before it can render.
