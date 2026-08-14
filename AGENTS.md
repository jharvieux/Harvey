# AGENTS.md — Harvey

Always-on instructions for Codex in this repository. Keep this file concise: Codex loads project instructions once per run and may truncate oversized files. Put task-specific procedure in skills and volatile measurements in status documents.

## Shell commands

Prefix every shell command with `rtk`. In a command chain, prefix every segment. Use raw commands only when debugging an `rtk`-filtered result; use `rtk proxy <command>` when exact output is required.

Examples: `rtk git status`, `rtk read <file>`, `rtk grep <pattern>`, `rtk pnpm verify`, `rtk gh pr view <n>`.

## What this repository is

Harvey is an external code-audit service for multi-tenant web applications. It contains scanner code (`src/`), functional audit briefs (`briefs/`), venture and design documents (`docs/`), a report renderer (`report-template/`), standalone tools (`tools/`), and calibration targets (`targets/`).

The product is a complete ten-module codebase-health audit, not a security-only scanner. M1–M10 have equal weight. Do not prioritize, narrate, or rank non-security modules as secondary. An M4 duplicate or M8 untested branch is part of the deliverable, not garnish.

## Read the relevant source of truth

Do not duplicate these files into prompts or rely on remembered counts.

| Need | Read or invoke |
|---|---|
| Execute an audit or determine tier/prerequisites | `.agents/skills/run-audit/SKILL.md` |
| Authoritative M1–M10 scope | `briefs/audit-modules.md` |
| Concise module capability map | `MODULES.md` |
| Sweep open issues | `source-command-issue-sweep` skill and `.codex/agents/` |
| Recorded-reason policy | `docs/design/recorded-reasons.md` |
| Coverage-guard state | `docs/design/coverage-guard-status.md` |
| Engagement operations | `docs/runbooks/` |
| Current handoff and volatile state | `SESSION.md` |
| Historical agent doctrine and rationale | `docs/runbooks/agent-doctrine.md` |

When a task matches an available skill, read its complete `SKILL.md` before acting. Follow referenced files only as needed. Prefer skills over re-embedding their procedure here.

## Audit invariants

- Account for every module M1–M10 against every enumerated target. A tier that cannot run is `partial` or `requires-live-run` with a concrete reason, provenance, and falsifier; it is never silently skipped.
- Prefer `pnpm exec tsx src/cli/run-audit.ts <target>`. It derives coverage from probe results. Use `pnpm audit-coverage` only when modules ran outside the orchestrator; its ledger proves bookkeeping, not ground truth.
- A disclosure row is incomplete unless its reason reaches the rendered client deliverable. An internal finding or green ledger is not sufficient.
- Preserve the conservation equation: `produced == delivered + deduped + suppressed + capped + not-applicable`. Every non-delivered finding needs a reason. A requested export that produced no file is a failure.
- A probe reports what it examined, not only what it found. Use `Examined { findings, unitsExamined, scope }` or `NotAssessed { reason, provenance, falsifier }`. Zero examined units is invalid.
- New mechanical finding producers must be owned by their live phase registry, declare implementation, taxonomy, applicability, examined-unit, fallback, and evidence metadata, consume the shared `MechanicalScanContext`, and pass the discovery, registry, evidence-link, and readonly-context tests.
- Infrastructure and unsupported-language/source shapes are disclosed as not assessed rather than omitted. The disclosure family is extensible; no existing row is the final one.
- M1 semantic remains an interactive `vuln-scan` then `triage` skill pair. Do not describe it as a slash command or pretend it has an orchestrated self-emit path.
- Measure claims against the current tree. Dates, finding counts, test counts, required contexts, runner timings, and open-gap lists become stale; rerun the owning command or read the current status document.

## Roles and delegation

Use these terms consistently:

- **Primary supervisor:** owns scope, sequencing, integration, verification, and final delivery.
- **Delegated executor:** implements one bounded work package in an isolated worktree and reports evidence; it does not merge.
- **Acceptance verifier:** independently checks an executor's work against the issue and acceptance criteria; it does not repair the implementation it verifies.

Parallelize independent work when useful. Give each delegated executor exclusive file ownership or a clearly separable change. The primary supervisor resolves overlaps and performs final integration.

For Codex custom agents, use `.codex/agents/*.toml`. Provider labels from older instructions map by responsibility, not by brand name:

- inexpensive issue classification → a fast, low-cost model with moderate reasoning;
- implementation → the default coding model with high reasoning;
- independent acceptance verification → a separate context using the strongest available reasoning.

Never assume a model alias such as Haiku, Sonnet, Opus, or Fable exists in Codex. Configure supported Codex model identifiers in the agent profile when an explicit override is needed; otherwise inherit the session model.

## Working doctrine

- Start from the real acceptance criteria and verify the production seam. A unit test of a helper does not prove the CLI, report, workflow, or exported artifact works.
- A passing test must have a failing direction. Revert or disable the production behavior and confirm the relevant test fails; do not weaken production code merely to manufacture that result.
- Close the whole defect class when the broader fix is supported by evidence. Prefer discovery-backed registries and ratchets over manually maintained allowlists.
- When execution forks, every path must preserve policy or disclose why it cannot. Audit sibling entry points, output modes, and workflow branches.
- Preserve provenance. A conclusion should identify where its evidence came from and what would falsify it.
- Do not use output-shape plausibility as proof. Independently inspect the actual producer, consumer, and final artifact.
- If a task stalls because of a broken tool, prerequisite, or harness, investigate and repair that in-scope blocker when safe. Do not bypass a quality gate.
- Treat environmental limits as hypotheses. Run the relevant command before declaring a stack or dependency unavailable.
- Never silently raise a baseline. A baseline update must explain each added row and disclose the changed count for review.
- Keep comments and docs focused on rationale and non-obvious constraints. Do not narrate obvious syntax.

## Code review rules

When reviewing code, report concrete defects with file and line references. Prioritize correctness, silent omission, security, data loss, broken production seams, and missing regression protection.

Specifically verify:

- a green coverage ledger is not being treated as proof that findings reached the client artifact;
- acceptance criteria were checked independently rather than copied from the implementation report;
- regression tests fail when the production fix is reverted;
- new scan paths, extensions, languages, and conditional branches cannot silently reduce scope;
- suppressions, deduplication, caps, and not-applicable classifications carry client-legible reasons;
- baseline changes are explained row by row;
- inherited measurements and historical claims were reproduced before being used as current facts.

Do not dismiss non-M1 findings as “low-stakes,” “maintainability-only,” “cosmetic,” “just a nit,” or “noise.” If volume is the problem, use a threshold or disclosed rollup without demoting the module.

## Git and pull requests

- Base branch: `main`. It is protected; all changes land through a pull request with every currently required check green. Measure required contexts from GitHub rather than quoting a stored count.
- Primary Codex branches: `codex/<short-name>`. Issue-sweep executors retain `feature/sweep-<issue>-<slug>` because the sweep tooling and branch guards depend on that shape. Docs-only work may use `docs/<short-name>`.
- Commit messages use imperative mood, a summary of at most 72 characters, and an issue reference when one exists.
- Never force-push `main`, bypass branch protection, or disable checks.
- Preserve unrelated user changes in dirty worktrees. Use an isolated worktree for parallel or unrelated work.
- Delegated executors open PRs but do not merge. The primary supervisor measures checks, completes acceptance review, and merges only when authorized by the active workflow.

## Verification

Run before every push:

```bash
pnpm verify
```

This is the light suite: typecheck, lint, tests, knip, test-only-export ratchet, and precision validation. Heavy child-process tests are intentionally separate:

```bash
HARVEY_HEAVY_CLI_TESTS=1 pnpm exec vitest run
pnpm exec tsx src/cli/heavy-shard.ts --shard N --of 3
```

Do not quote the number of heavy files or binary-gated files; run the shard command. Keep any single blocking test window comfortably below the process-ack timeout. Timing tests anchor to the child's first byte, not process spawn.

Every `src/cli` entry point that may exit non-zero imports `./sync-stdio.js` as its first import. Add the import for new CLIs; do not edit the discovery ratchet to avoid it.

After changing a detector, Semgrep rule, finding schema, or calibration fixture, regenerate and commit both artifacts:

```bash
pnpm exec tsx src/cli/dry-run.ts --target targets/calibration --out dry-run
```

The machine must have the mechanical binaries installed. A missing required binary or nondeterministic external input must be fixed or explicitly pinned; do not commit a degraded artifact.

Other checks are run when relevant:

```bash
pnpm check:duplication
pnpm validate:findings <file>
pnpm exec tsx src/cli/validate-conservation.ts
pnpm exec tsx src/cli/validate-calibration.ts
```

If a failure is proven to pre-exist on `main`, report the evidence and do not hide it. Otherwise fix and re-run before pushing.

## Sensitive paths

Require explicit user authorization before changing:

- `.github/workflows/**`
- `supabase/migrations/**`
- `package.json`, lockfiles, dependency manifests, or version constraints
- `docs/**/*.md`, `README.md`, and `CLAUDE.md`
- baseline files such as `test-only-exports.baseline.json`

The user's current request may provide that authorization by naming the file or approving a clearly described set of edits. Never infer authorization for a materially broader change.

Generated artifacts are not hand-edited. Regenerate them through their owning command.

## User preferences

Lead with plain-language outcomes and explain why they matter. The user does not review code, so handoffs must state what changed, what was verified, and any remaining decision or risk without requiring a diff review.

The user welcomes durable improvements over tactical patches. Suggest a broader fix when evidence supports it, but do not expand scope into unrelated external changes without authorization.
