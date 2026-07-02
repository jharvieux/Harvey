# AI-slop detection (D-091)

How this repo detects and discourages low-quality AI-generated code patterns.

## Three layers

### 1. CLAUDE.md doctrine (the strongest filter)

`CLAUDE.md` instructs the AI to default to no comments, surgical changes, no speculative abstractions, etc. Re-read on every session start. Effective because it shapes what gets written in the first place, not just what gets caught after.

The **End-of-session protocol** includes a "slop sweep" step — Claude re-reads its own diff with an explicit anti-slop lens before commit.

### 2. ESLint rules (line-level catch)

Two rules in `packages/config/eslint-rules/`:

| Rule | Default | What it catches |
|---|---|---|
| `atc/no-orphan-todo` | `error` | `TODO`, `FIXME`, `XXX`, `HACK` markers without an owner or issue ref. Accepts `TODO(@owner)`, `TODO(#123)`, `TODO(bp23-foo)`. Rejects `TODO:`, `(TODO)`, `// TODO ...`. |
| `atc/no-narrating-comments` | `off` | Short single-line comments (`<=6 words`) starting with a narrating verb (`fetch`, `loop`, `iterate`, `validate`, etc.). Opt-in because heuristic. |

To enable `no-narrating-comments` after auditing existing code, flip to `warn` or `error` in `apps/main/.eslintrc.json`.

### 3. `slop-check` diff scanner (local)

`pnpm slop-check` scans **lines added in the current branch vs `origin/dev`** for:

1. Orphan TODOs (same rule as ESLint, but applied to the diff)
2. Narrating comments (same)
3. `try/catch` blocks that just re-throw the caught error
4. `export function foo(...) { return bar(...); }` single-expression wrappers

Output: markdown, advisory only. Runs **locally** as part of `pnpm verify` (and on demand via `pnpm slop-check`); the `pre-pr-reviewer` audit subagent also reads its output before a PR is opened. It is deliberately **not** a CI check — see the 2026-05-29 calibration-log entry for why the GitHub Action was removed.

Run locally:

```
pnpm slop-check
# or against a specific base:
SLOP_CHECK_BASE_REF=origin/release/2026.05 pnpm slop-check
```

## Adding a new pattern

1. Add a regex + finding kind in `scripts/slop-check.ts`.
2. If the same pattern can be a line-local lint rule, add it to `packages/config/eslint-rules/` and register in both `packages/config/eslint-plugin.js` AND `packages/eslint-plugin-atc/index.js` (the legacy `.eslintrc` resolver re-exports from there).
3. Enable in `apps/main/.eslintrc.json` (and optionally `apps/rag/.eslintrc.json`) at `warn` first; bump to `error` after a one-pass cleanup.

## Calibration log

- 2026-05-26: `no-orphan-todo` shipped at `error`. Cleaned up 5 pre-existing violations in the same PR.
- 2026-05-26: `no-narrating-comments` shipped at `off` — codebase has not been audited for prior narration. Flip on after a sweep.
- 2026-05-29: removed the `slop-check` GitHub Action (`.github/workflows/slop-check.yml`); the scanner is now local-only (`pnpm verify` / `pnpm slop-check`). Reasons: (1) the only hard rule it carries — orphan TODOs — is already enforced at CI by the required `Lint` check (`atc/no-orphan-todo` at `error`); (2) the soft heuristics false-positive on intentional extractions (e.g. a 2-caller wrapper extracted precisely so prod + test import one symbol) and aren't worth a PR comment or status line; (3) the workflow's `$GITHUB_OUTPUT` heredoc step crashed on any non-empty report, so the non-required check showed RED on every findings-producing PR. See D-117.

## What we deliberately do NOT do

- **No AI-detection tools** that classify code as "AI-likeness." Punishes style, not slop. High false-positive rate.
- **No banning of AI-generated code.** The CLAUDE.md doctrine is a more useful guardrail than a ban.
- **No blocking merge on slop findings.** Slop is a tradeoff (sometimes a TODO without an owner is genuinely temporary); blocking merge produces escape hatches that defeat the purpose. Local `pnpm verify` output + the `pre-pr-reviewer` audit is the right pressure.
