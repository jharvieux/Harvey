# CLAUDE.md — Harvey (external code-audit service)

Working instructions for Claude Code sessions in this repo.

## What this repo is

The productized audit service extracted from `jharvieux/atc` (ATC issue 1527, now epic #2 here): a complete **ten-module (M1–M10) security & codebase-health audit** for multi-tenant Supabase/Next.js apps. It holds the scanner code (`src/`), the audit briefs and venture docs (`docs/`), the report renderer (`report-template/`), and standalone audit tools (`tools/`).

- Epic: issue #2. Module and GTM work items: issues #3–#18 (label `audit-service`).
- Full spec: `docs/audit-modules.md`, `docs/go-no-go.md`. Briefs: `docs/scan-extras.txt`, `docs/quality-extras.txt`, `docs/fp-rules.txt`.

## The audit — full scope, how to run it, and the coverage guard

**This is a COMPLETE codebase-health audit, not a security scan.** Security (M1/M2) is the marketing wedge and leads the report, but the *deliverable is all ten modules*. Running a security-only (or any ad-hoc) subset is a defect — it has happened; don't repeat it. Every engagement accounts for all ten modules against every enumerated target. Authoritative scope: `docs/audit-modules.md`.

### The ten modules and how to run each

| # | Module | Run it with | Tier / prereq |
|---|--------|-------------|---------------|
| M1 | Multi-tenant security (lead) | `pnpm quick-scan --dir <t>` (mechanical) + `pnpm exec tsx src/cli/scan.ts --supabase <ref\|local>` (config) + LLM `/vuln-scan --extra docs/scan-extras.txt` → `/triage --fp-rules docs/fp-rules.txt` (semantic) + `pnpm detect-deeper` (live RLS/policy review) | free → connected → paid-LLM |
| M2 | Local pen-test (dynamic) | `pnpm exec tsx src/cli/pentest.ts` against a local `supabase start` stack seeded with two tenants | needs live stack; `assertComplete` gates target coverage |
| M3 | Hotspot analysis | `vitals` plugin — `/vitals:scan` or `vitals_cli.py report --json <path>` | external plugin; run, don't build |
| M4 | Duplication | `pnpm check:duplication` or `pnpm quality-scan <t>` (jscpd) | source-only |
| M5 | Slop / dead code | `pnpm quality-scan <t>` (knip) | **NEEDS target `npm install`** — knip can't resolve config imports without the target's deps |
| M6 | Simplification / maintainability | `pnpm simplify-scan <t>` (assembles the `docs/quality-extras.txt` brief + source into a review packet) | free = non-grading "looks hand-rolled" indicators; paid = triage + name the replacement (#267). **`simplify-scan` produces a review PACKET, not a verdict — printing source is not running M6; the verdict is a human/LLM pass over the packet (#351).** **Never yet run against a real target** (#283) |
| M7 | Performance | `pnpm detect-static <t>` (code tier) + `pnpm perf-scan` (DB advisors) | source (code) + connected (advisors) |
| M8 | Test quality | `pnpm mutation-scan <t>` (StrykerJS) | needs target test suite + stryker config; **no tests → emit a zero-coverage finding, don't skip** (#224) |
| M9 | App Router boundary/rendering | `pnpm detect-static <t>` (M9 AST) | source-only |
| M10 | Data classification (PII/PHI/PCI) | `pnpm pii-classify` — `SUPABASE_DB_URL=…` (live) or `--schema <dir\|.sql>` over `supabase/migrations/` (#250) | connected or schema |

Source/free tier = M1(mechanical), M4, M5, M7(code), M9, M10(schema); connected adds M1(live), M7(advisors), M10(live); dynamic = M2; paid-LLM = M1(semantic), M6, M3-depth. Per-module free/paid split: `docs/free-tier-scope.md` + the `product-shape-decisions` memory.

### The coverage guard — never silently skip a module

Completeness is a core product principle: **a module that cannot run is recorded as `partial` / `requires-live-run` WITH THE REASON — never silently omitted. Fail loud.**

**Silent omission is worse than a wrong status.** A `missed` shows up in the tally; an absent row does not. If a thing cannot be assessed, say so IN THE OUTPUT — an unstated limitation reads as a clean bill of health. (`requires-live-run: 0` once asserted nothing awaited a live run while four planted bugs were simply not listed — #345.)

- **The full-audit runner** (`pnpm exec tsx src/cli/run-audit.ts <target>`, #229/#310) runs all ten modules and **derives** the ledger from what each probe reported — there is no parameter through which a caller can assert that a module ran. A module with no registered runner throws before anything runs; a crashed probe fails loud rather than being excused as an environment gap.
- `src/audit-coverage.ts` (`pnpm audit-coverage`) remains the caller-supplied path, for engagements whose modules run outside the orchestrator: every M1–M10 accounted for, an unmentioned module is a gap, `assertAuditComplete` throws naming gaps. **On this path the ledger comes from the CALLER** — it enforces bookkeeping discipline, not ground truth. Prefer `run-audit`.
- `coverage-scorecard.ts` (`moduleRan`) scores any non-run module `requires-live-run`, never `missed` — it never guesses that something executed.
- `assertComplete` (`src/pentest/targets.ts`) throws, naming any enumerated-but-untested M2 target. **⚠️ It is currently unwired — only tests call it, so it cannot fire on a real pen-test run (#352).** Do not rely on it as an active gate until that closes.
- **Known gaps in what the guard actually proves (2026-07-15, all measured):** most probes accept a tool's `exit 0` as evidence it ran, so M5/M8/M9 can record `ran` while their own tools report they did not (#350); M6's never-run alarm is cleared by a review packet no reviewer read (#351); and **the ledger has no path into the client report** — a module that never ran reaches the customer as silence (#349). **The guard is real but its inputs are not yet trustworthy. Read #349 before any paid engagement.**

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

Issues carry one of `haiku` / `sonnet` / `opus` to tell automated sweeps which model tier the task needs: `haiku` = mechanical/small, `sonnet` = standard implementation, `opus` = design-heavy or security-sensitive. Unlabeled issues default to `sonnet`.

## Working doctrine (ported from ATC)

- **Simplicity first.** Minimum code that solves the problem. No features beyond what was asked, no abstractions for single-use code.
- **Surgical changes.** Don't refactor what isn't broken; match existing style.
- **Slop sweep before commit.** Re-read your own diff and delete: comments that say WHAT instead of WHY, single-call helper functions, try/catch that re-throws or swallows, JSDoc paragraphs on simple functions, TODOs without an owner or issue ref, defensive validation of inputs that can't be invalid.
- **Tests verify intent, not just behavior.** A test that can't fail when business logic changes is wrong.
- **Never leave a known bug or deferral untracked.** Trivial: fix inline. Non-trivial: open a GitHub issue before the session ends, specific enough that someone returning cold can pick it up.
- **Fail loud.** "Done" is wrong if anything was skipped silently. Silent omission is worse than a wrong status — an absent row never appears in a tally, so it cannot be argued with. If something could not be assessed, say so in the output.
- **Never present a guess as fact.** Flag uncertainty before the claim, especially for library/API behavior and version-specific syntax.
- **Measure, don't recall.** Never state a capability number — recall, coverage, precision, "we catch X", "module Y is unrunnable" — from memory, a doc, a comment, or a prior session. **Run the thing that measures it**: `pnpm exec tsx src/cli/validate-calibration.ts` for corpus recall; the dry-run scorecard only after regenerating it via the tool; `ls src/scan/calibration/*.entries.ts` for what the gate actually covers. A recorded number is a claim about the past, not the present. If you cannot verify it, write "recorded as N, unverified" — never let a stored number become an argument's premise. Beware blended numbers: they hide skew (`147/153` is ~85% M1 and covers 8 of 10 modules — #341).
- **A recorded reason is a claim about the world, and claims decay.** When you read a comment, note, `not-run` reason, or status explaining why something cannot run or is not caught — treat it as **unverified until you re-test it**, however confidently it is written. This is the repo's signature defect: ~10 instances found on 2026-07-15 alone, every one failing silently toward a confident-looking number (#321 tracks the systemic fix). Rules that "never existed" existed; targets that "can't be scored" scored; gates described as active were unwired. **Check before you repeat it, and especially before you build an argument on it.**
- **If your change falsifies a claim in this file, say so — you cannot fix it yourself.** This file is supervised: agents must not edit it. So the moment your work makes a sentence here untrue — a "known gap" you closed, a prereq you removed, a command you renamed, a guard you wired or unwired — **name the exact sentence and recommend the replacement wording**, in your PR body AND your report to the supervisor. **The supervisor must relay it to the operator with that recommendation before the session ends — it may not be silently absorbed.** Every dispatched agent reads this file: a false sentence here misinforms every future session, and in sweep #3 an uncommitted-vs-committed drift in this one file caused a class of phantom bugs. #310 falsified its own known-gap paragraph the moment it merged; its executor reported it and it still took an operator question hours later to surface. **A stale CLAUDE.md is not a documentation chore — it is a defect with a blast radius.**

Reference material in `docs/runbooks/`: `anti-patterns.md` (the D-091 catalog — also the M1 taxonomy source), `slop-detection.md`, `pr-self-review.md`, `flaky-test-policy.md`.

## The user

Technically fluent (IT/network/systems, vendor management, leading dev/QA) but **does not write or review code**. Ask about product behavior, scope, sequencing, and trade-offs in plain-English outcomes — never ask them to read a diff.

## File conventions

- `src/` — scanner/toolkit code (TypeScript, strict). Tests co-located as `*.test.ts`.
- `docs/` — briefs, specs, venture docs. `docs/runbooks/` — operational references.
- `report-template/` — findings JSON → HTML/PDF renderer (needs `pnpm exec playwright install chromium` once).
- `tools/` — standalone audit tools (e.g. `pii-classify.mjs`).
