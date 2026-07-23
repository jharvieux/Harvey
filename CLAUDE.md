# CLAUDE.md — Harvey (external code-audit service)

Working instructions for Claude Code sessions in this repo.

## What this repo is

The productized audit service extracted from `jharvieux/atc` (ATC issue 1527, now epic #2 here): a complete **ten-module (M1–M10) security & codebase-health audit** for multi-tenant Supabase/Next.js apps. It holds the scanner code (`src/`), the audit briefs and venture docs (`docs/`), the report renderer (`report-template/`), and standalone audit tools (`tools/`).

- Epic: issue #2. Module and GTM work items: issues #3–#18 (label `audit-service`).
- Full spec: `docs/audit-modules.md`, `docs/go-no-go.md`. Briefs: `docs/scan-extras.txt`, `docs/quality-extras.txt`, `docs/fp-rules.txt`.
- **Prisma/Postgres apps are supported (not just Supabase), detection-gated — epic #756 complete 2026-07-23:** `detectOrm` (#757) routes a Prisma app to the app-layer M1 tier (Supabase RLS detectors gate off as N/A-by-architecture) plus a Prisma tenant-scope/BOLA detector (#760); M10 classifies `schema.prisma` (#758); M7 flags unindexed FKs from `schema.prisma` (#761); M2 stands up plain Postgres + `prisma migrate` + app-route probing with the PostgREST/RLS matrix recorded not-applicable, INCLUDING an **authenticated cross-tenant BOLA probe** (two-tenant Team/membership seed + minted sessions — next-auth cookies AND HS256/custom-JWT bearers, #759/#787/#802) — proven live against boxyhq (routed as Prisma, sessions authenticated, 14 team-scoped routes probed, correctly isolated). The missing-auth sweep gates on the response exposing data so a public `/api/hello` isn't flagged (#791), regression-gated offline in the vuln-seam-app standing check (#792); the cross-tenant probe has its own offline in-process fixture control (`targets/prisma-xtenant-app`, #796). M7 also flags Prisma N+1 + filter-column-without-index in app code (#793). Docs/site/SEO landed (#762–#764). No open Prisma residuals.

## The audit — full scope, how to run it, and the coverage guard

**This is a COMPLETE codebase-health audit, not a security scan.** All ten modules (M1–M10) carry **equal weight** in the deliverable — none is the "lead," none is secondary, and none may be prioritized over the others when executing. Running a security-only (or any ad-hoc) subset — or scoping any single module's run to only its security-relevant portion — is a defect; it has happened, don't repeat it. Every engagement accounts for all ten modules against every enumerated target. Authoritative scope: `docs/audit-modules.md`.

### The ten modules and how to run each

| # | Module | Run it with | Tier / prereq |
|---|--------|-------------|---------------|
| M1 | Multi-tenant security | `pnpm quick-scan --dir <t>` (mechanical) + `pnpm exec tsx src/cli/scan.ts --supabase <ref\|local>` (config) + LLM `/vuln-scan --extra docs/scan-extras.txt --extra <pnpm scan-focus M3-hotspots.txt>` → `/triage --fp-rules docs/fp-rules.txt` (semantic; the M3 hotspot focus prioritizes review on the hottest files, #442) + `pnpm detect-deeper` (live RLS/policy review) | free → connected → paid-LLM |
| M2 | Local pen-test (dynamic) | `pnpm exec tsx src/cli/pentest.ts` against a local `supabase start` stack seeded with two tenants | needs live stack; `assertComplete` gates target coverage |
| M3 | Hotspot analysis | `pnpm exec tsx src/cli/hotspot-scan.ts <t>` — wraps `vitals_cli.py report --json` (pass `--report <capture>` when vitals is off PATH, #314; `--hotspots-out` feeds M8's `--hotspots` and M6 `simplify-scan --hotspots`, #442) | external plugin; run, don't build |
| M4 | Duplication | `pnpm check:duplication` or `pnpm quality-scan <t>` (jscpd + diverged-clone near-miss pass, #360) | source-only |
| M5 | Slop / dead code | `pnpm quality-scan <t>` (knip) | **NEEDS target `npm install`** — knip can't resolve config imports without the target's deps |
| M6 | Simplification / maintainability | `pnpm quick-scan --dir <t>` (free report: non-grading "looks hand-rolled" indicators, rolled up per class per file, #267) + `pnpm detect-static <t>` (same indicators as raw findings) + `pnpm simplify-scan <t>` (assembles the `docs/quality-extras.txt` brief + source into a review packet) | free = non-grading "looks hand-rolled" indicators; paid = triage + name the replacement (#267). **`simplify-scan` produces a review PACKET, not a verdict — printing source is not running M6; the verdict is a human/LLM pass over the packet (#351).** **First run against a real target** (stoimera/Cravab, 2026-07-18) — the paid verdict is recorded via the M6 pass artifact + `run-audit --record`, so M6 is no longer in `MODULES_NEVER_EXECUTED` (#283, see `docs/design/m6-first-real-target-verdict.md`) |
| M7 | Performance | `pnpm detect-static <t>` (code tier) + `pnpm quick-scan --dir <t>` (static RLS initplan, #374) + `pnpm perf-scan` (DB advisors) + `pnpm lighthouse-scan` (Core Web Vitals / Lighthouse, local build+serve+browser, #387) | source (code) + connected (advisors) + local-run (Lighthouse) |
| M8 | Test quality | `pnpm detect-static <t>` (test-intent detectors, #372) + `pnpm mutation-scan <t> --stub-check` (pre-Stryker deletion survival, #373) + `pnpm mutation-scan <t>` (StrykerJS) | source (test-intent; stub-check needs the target's tests runnable but no Stryker install); full mutation run needs the target test suite; a missing Stryker config is scaffolded per detected runner (vitest/jest/mocha), and missing Stryker packages install `--no-save` only with `--install` (#513); a scoped run records `partial` with its scope (#504); a failed dry run surfaces as a distinct env-fragile-suite verdict (#503); **no tests → emit a zero-coverage finding, don't skip** (#224) |
| M9 | App Router boundary/rendering | `pnpm detect-static <t>` (M9 AST) | source-only |
| M10 | Data classification (PII/PHI/PCI) | `pnpm pii-classify` — `SUPABASE_DB_URL=…` (live) or `--schema <path…>` over a migrations dir, a `.sql` file, discovered root/nested schema DDL, or a `schema.prisma` (#250/#529/#770/#758) | connected or schema |

Source/free tier = M1(mechanical), M4, M5, M6(indicators, #267), M7(code), M8(test-intent, #372), M9, M10(schema); connected adds M1(live), M7(advisors), M10(live); dynamic = M2; paid-LLM = M1(semantic), M6(triage), M3-depth. Per-module free/paid split: `docs/free-tier-scope.md` + the `product-shape-decisions` memory.

**Run modes are ONE orchestrator (`pnpm exec tsx src/cli/run-audit.ts <t>`, aliased as `pnpm run-audit <t>`) gated by env flags, not three tools.** Every mode runs all ten modules; a tier not in scope records `requires-live-run`/`partial` with a reason, never a skip (the flags declare which environments the engagement HAS, not which modules to run).
- **Free** = `run-audit <t>` — source, mechanical only.
- **Validation** = `run-audit <t> --llm --dynamic --artifacts-dir <dir>` — source + the LLM passes over source + a local-stack pen-test, but NO client DB. "Validation" is running everything against a public repo we were given nothing on; dynamic (M2) still applies because we stand up our OWN local Supabase (`pnpm dynamic-validate <repo>` assesses stand-up-ability, `--execute` runs it). The orchestrator does not itself run the LLM or the pen-test — those are operator/skill passes that leave a `<module>.pass.json` (`pnpm record-pass …` / `pnpm dynamic-validate`), which `--artifacts-dir` reads to derive `ran`.
- **Paid** = add `--connected` (a live read-only client DB) for the connected tiers (M1 live, M7 advisors, M10 live).
- **Re-audit diff:** `run-audit <t> --findings-out cur.json --baseline <prior findings.json>` classifies each finding resolved / persistent / new against a prior engagement of the same client (stable taxonomy+location identity), for repeat customers (#457).

### The coverage guard — never silently skip a module

Completeness is a core product principle: **a module that cannot run is recorded as `partial` / `requires-live-run` WITH THE REASON — never silently omitted. Fail loud.**

**Silent omission is worse than a wrong status.** A `missed` shows up in the tally; an absent row does not. If a thing cannot be assessed, say so IN THE OUTPUT — an unstated limitation reads as a clean bill of health. (`requires-live-run: 0` once asserted nothing awaited a live run while four planted bugs were simply not listed — #345.)

- **The full-audit runner** (`pnpm exec tsx src/cli/run-audit.ts <target>`, #229/#310) runs all ten modules and **derives** the ledger from what each probe reported — there is no parameter through which a caller can assert that a module ran. A module with no registered runner throws before anything runs; a crashed probe fails loud rather than being excused as an environment gap.
- `src/audit-coverage.ts` (`pnpm audit-coverage`) remains the caller-supplied path, for engagements whose modules run outside the orchestrator: every M1–M10 accounted for, an unmentioned module is a gap, `assertAuditComplete` throws naming gaps. **On this path the ledger comes from the CALLER** — it enforces bookkeeping discipline, not ground truth. Prefer `run-audit`.
- `coverage-scorecard.ts` scores any bug whose detecting tier did not run (`detection: null`, supplied by the caller) as `requires-live-run`, never `missed` — it never guesses that something executed.
- `assertComplete` (`src/pentest/targets.ts`) throws, naming any enumerated-but-untested M2 target. It is wired into `pnpm exec tsx src/cli/pentest.ts --mode=coverage` (#352, closed 2026-07-16), which discovers the target manifest and fails loud on any enumerated app/backend/seam that `--tested` did not list; its firing is proven at the discovery-and-assert level and by a child-process CLI test. It has not yet been exercised against a live two-tenant stack (that limitation is now recorded in-probe, #357).
- **Known gaps in what the guard actually proves (updated 2026-07-16 — the 2026-07-15 gaps below all CLOSED this sweep):** the exit-0-as-evidence blindness is closed (#350) — M4/M5/M8/M9 now derive status from the tool's machine-readable output, and a scan of zero files (or an incomplete per-workspace scan, #505) records `partial`/`requires-live-run`, never `ran`. M6's never-run alarm can no longer be cleared by an unread review packet (#351) — it reports `partial` until a reviewed verdict is recorded. The coverage ledger now HAS a path into the client report (#349): `run-audit --findings-out` assembles the derived ledger into the engagement findings.json and `report-template` renders per-module coverage, so a module that never ran shows as a "Not run" row with its reason rather than silence. The orchestrator's **derive-`ran`-from-artifact path LANDED** (#416 read side + #448 emit side): `run-audit --artifacts-dir <dir>` derives `ran` for the out-of-orchestrator passes (M1 semantic/live, M2 dynamic, M3 vitals, M6 verdict) from a fresh, target-matching `<module>.pass.json` and folds its findings into the deliverable — a stale/wrong-target artifact is rejected, never a silent `ran`. `pnpm record-pass` emits one from any operator/LLM pass; `pnpm dynamic-validate` is the M2 producer. Schema/flow: `docs/design/audit-pass-artifacts.md`. M7 advisors (#434), M8 surviving-mutants (#435), and M10's data-map → `Finding[]` (#436) landed 2026-07-17; M3/M8 capture + explicit non-collection landed in #420. The **M2 live stand-up is now AUTONOMOUS** (#545): `pnpm dynamic-validate <t> --execute` provisions its own local Supabase, applies every Supabase project's migrations (per-DB across a monorepo's projects, #610), seeds two tenants + two auth users (per-user owner columns inferred from FK-to-auth graph, e.g. `author_id`, #617), and runs the live PostgREST cross-tenant matrix plus the wired-in auth-attack probe (#658) with no operator step (`src/pentest/live-standup.ts`); the app-route probe tier is built and proven live (#552 — a real Critical on a booted target). The inter-service seam probes are WIRED and reachability-proven live (#161 CLOSED — route-based seam-discovery populates `profile.seams` #714, precision-hardened #716, monorepo behind-the-gateway service detection #719, and ran live against a real Stripe webhook receiver reaching a correct verdict). The seam probes' and the NO-RATE-LIMIT loop's *proven* (finding-producing) branches have now ALSO been exercised live (#717/#159 CLOSED; the #718 fixture is built at `targets/vuln-seam-app/`): a `pnpm dynamic-validate targets/vuln-seam-app --execute` run reached 4/4 seams proven with zero controls flagged, guarded against regression by the offline `src/pentest/vuln-seam-app.test.ts` and recorded in `docs/design/vuln-seam-app-live-validation.md`. **Still open:** each out-of-orchestrator pass emitting its artifact routinely end-to-end.

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

- `docs/*.txt` and `docs/*.md` — the venture's briefs, positioning, and GTM strategy. Human-owned IP.
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
- **Measure, don't recall.** Never state a capability number — recall, coverage, precision, "we catch X", "module Y is unrunnable" — from memory, a doc, a comment, or a prior session. **Run the thing that measures it**: `pnpm exec tsx src/cli/validate-calibration.ts` for corpus recall; the dry-run scorecard only after regenerating it via the tool; `ls src/scan/calibration/*.entries.ts` for what the gate actually covers. A recorded number is a claim about the past, not the present. If you cannot verify it, write "recorded as N, unverified" — never let a stored number become an argument's premise. Beware blended numbers: they hide skew — the gate's headline positive count is nearly all M1 by design (it scores only the M1 mechanical corpus; the per-module census #341 and the parity minimum #427 make the split legible; run the tool, don't quote this — it measured 198/201 static positives, negatives 190/190, after the 2026-07-19 mechanizable-coverage batch (#595/#601/#602/#611/#613/#616/#625) + the M6 precision-gate graduation (#639) + the 2026-07-19 audit-tooling batch that added the env-schema (#679), secret-rotation (#680), and background-job tenant-scope (#681/#684) M1 detectors + the 2026-07-21 sweep that added the Express+pg IDOR/mass-assign/CORS and hardened service-role detectors (#663/#664) and the res.json excessive-data-exposure detector (#701) + the 2026-07-23 Prisma tenant-scope/BOLA detector (#760, part of the Prisma-support epic #756), still ~85% M1).
- **Per-module detector counts come from `pnpm detector-census`, never from memory or this file.** "How many things can each module detect?" is the most-asked question in this repo and there is NO single stored number — detectors live in two engines (semgrep `harvey-*` rules in `src/scan/rules/semgrep/*.yml`, plus TS/AST detectors tagged by `taxonomy:` strings) and the repo does not tag every detector with its module, so the count is **derived by file ownership** in `src/cli/detector-census.ts`. Run `pnpm detector-census` to get the current per-module breakdown; it counts DETECTORS (capable of firing), which is distinct from RECALL (only M1 has a scored recall gate). When you add a detector file, add it to that tool's `OWNERS` map — that is the single maintenance point. Do not quote a detector count without re-running it.
- **A recorded reason is a claim about the world, and claims decay.** When you read a comment, note, `not-run` reason, or status explaining why something cannot run or is not caught — treat it as **unverified until you re-test it**, however confidently it is written. This is the repo's signature defect: ~10 instances found on 2026-07-15 alone, every one failing silently toward a confident-looking number (#321, closed 2026-07-16, added a re-validation pass that re-tests the external-corpus not-run reasons on every drift run — but the general, repo-wide version of this discipline is still unsolved). Rules that "never existed" existed; targets that "can't be scored" scored; gates described as active were unwired. **Check before you repeat it, and especially before you build an argument on it.**
- **If your change falsifies a claim in this file, say so — you cannot fix it yourself.** This file is supervised: agents must not edit it. So the moment your work makes a sentence here untrue — a "known gap" you closed, a prereq you removed, a command you renamed, a guard you wired or unwired — **name the exact sentence and recommend the replacement wording**, in your PR body AND your report to the supervisor. **The supervisor must relay it to the operator with that recommendation before the session ends — it may not be silently absorbed.** Every dispatched agent reads this file: a false sentence here misinforms every future session, and in sweep #3 an uncommitted-vs-committed drift in this one file caused a class of phantom bugs. #310 falsified its own known-gap paragraph the moment it merged; its executor reported it and it still took an operator question hours later to surface. **A stale CLAUDE.md is not a documentation chore — it is a defect with a blast radius.**

Reference material in `docs/runbooks/`: `anti-patterns.md` (the D-091 catalog — also the M1 taxonomy source), `slop-detection.md`, `pr-self-review.md`, `flaky-test-policy.md`.

## The user

Technically fluent (IT/network/systems, vendor management, leading dev/QA) but **does not write or review code**. Ask about product behavior, scope, sequencing, and trade-offs in plain-English outcomes — never ask them to read a diff.

## File conventions

- `src/` — scanner/toolkit code (TypeScript, strict). Tests co-located as `*.test.ts`.
- `docs/` — briefs, specs, venture docs. `docs/runbooks/` — operational references.
- `report-template/` — findings JSON → HTML/PDF renderer (needs `pnpm exec playwright install chromium` once).
- `tools/` — standalone audit tools (e.g. `pii-classify.mjs`).
