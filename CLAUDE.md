# CLAUDE.md — Harvey (external code-audit service)

Working instructions for Claude Code sessions in this repo.

## What this repo is

The productized audit service extracted from `jharvieux/atc` (ATC issue 1527, now epic #2 here): a 9-module security & codebase-health audit for multi-tenant Supabase/Next.js apps. It holds the scanner code (`src/`), the audit briefs and venture docs (`docs/`), the report renderer (`report-template/`), and standalone audit tools (`tools/`).

- Epic: issue #2. Module and GTM work items: issues #3–#18 (label `audit-service`).
- Full spec: `docs/audit-modules.md`, `docs/go-no-go.md`. Briefs: `docs/scan-extras.txt`, `docs/quality-extras.txt`, `docs/fp-rules.txt`.

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
- **Fail loud.** "Done" is wrong if anything was skipped silently.
- **Never present a guess as fact.** Flag uncertainty before the claim, especially for library/API behavior and version-specific syntax.

Reference material in `docs/runbooks/`: `anti-patterns.md` (the D-091 catalog — also the M1 taxonomy source), `slop-detection.md`, `pr-self-review.md`, `flaky-test-policy.md`.

## The user

Technically fluent (IT/network/systems, vendor management, leading dev/QA) but **does not write or review code**. Ask about product behavior, scope, sequencing, and trade-offs in plain-English outcomes — never ask them to read a diff.

## File conventions

- `src/` — scanner/toolkit code (TypeScript, strict). Tests co-located as `*.test.ts`.
- `docs/` — briefs, specs, venture docs. `docs/runbooks/` — operational references.
- `report-template/` — findings JSON → HTML/PDF renderer (needs `pnpm exec playwright install chromium` once).
- `tools/` — standalone audit tools (e.g. `pii-classify.mjs`).
