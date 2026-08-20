# SESSION — 2026-08-20 issue-sweep checkpoint

_Last updated: 2026-08-20. The operator asked to wrap this session at a safe
stopping point. This file preserves evidence and next actions; it does not itself
authorize a future task to resume the sweep._

## Completed in this sweep

- PR #1951 merged as `588125a23b7c7749fad12631654b7a7649f7eb32`,
  closing #1910 only. Issue #1800 remains open; its unpublished 765-row census is
  retained at `/private/tmp/path-scope-census-1800-final.{json,md}`.
- PR #1952 merged, closing #1893.
- PR #1953 merged as the prior session checkpoint.
- PR #1955 merged as `255df9498f0157890268847c6366a372876360ad`,
  closing exactly #1896 and #1907. Both issues were re-read as CLOSED.
- Local `main` and `origin/main` are both `255df9498f0157890268847c6366a372876360ad`.

## Active PR #1954 — source graph and Carbon determinism

- PR: https://github.com/jharvieux/Harvey/pull/1954
- Branch/worktree: `feature/sweep-source-graph-1640` at
  `/private/tmp/harvey-sweep-source-graph-1640`.
- Remote/local branch head: `21ba0ae7d9f7c5b3f90bb5d33cce756e6c741782`,
  tree `6ff94e439503cdded4c6af4a98f9252fdf99f627`; worktree clean.
- Close-set remains exactly #1640 and #1812. Issue #1795 remains OPEN and must
  not close: its sensitive external-corpus note still says 23/36 while the
  measured result is 24/35.
- The #1640/#1812 implementation and independent acceptance criteria are met.
  The PR must not merge yet because the hosted producer/replay aggregate still
  detects raw Semgrep nondeterminism on Carbon.

### Exact hosted failure

- Workflow run `32412748690`, aggregate job `96575138337`.
- Carbon producer: 2,109 findings; replay: 2,107.
- Removing sequential IDs leaves exactly two producer-only rows:
  `harvey-log-injection` at
  `packages/database/supabase/functions/post-shipment/index.ts:1114` and
  `:1691`. Replay has no unique rows.
- The first divergence is raw Semgrep 1.164.0 JSON from subpartition
  `local-injection/isolated-log-injection/file-016`: producer emitted lines
  `[40,1114,1691]`, replay emitted `[40]`.
- Target pin/tree/prepared digest, rule bytes, runtime, runner image/region,
  execution plan, diagnostics, examined-unit digest, and every other partition
  match. The producer was a real cache miss. The strict comparator, cache,
  canonical merge, and normalization are behaving correctly and must not be
  relaxed.
- Retained artifact census: `/private/tmp/pr1954-run32412748690.26TSwS`.

### Falsifiers already completed

- Scratch-root naming is not causal: exact shipping argv returned all three rows
  in 4/4 fixed-root and 6/6 renamed-root runs. Evidence:
  `/private/tmp/pr1954-semgrep-root-falsifier`.
- Removing deprecated `--x-parmap` while retaining `-j 1 --timeout 0` also
  returned all three rows in 10/10 local file runs; one complete sequential
  22-subscan hybrid conserved 87 findings, 4,152 scanned files, and 30 rules.
  This is a candidate only, not hosted proof. Evidence:
  `/private/tmp/pr1954-semgrep-no-parmap-{root-falsifier,hybrid}`.
- Prior two cold hybrid references remain byte-identical at SHA-256
  `02d98136a14807d7f4905b5e27994301e482e4f558b8447033bbebb0f7288802`.

### Upstream evidence and next action

- Semgrep 1.171.0 is the smallest release with an explicit upstream fix for
  rare nondeterministic crashes and incorrect results.
- Semgrep 1.173.0 additionally fixes silent parallel target-filter omission.
- Neither release specifically claims to fix this OSS JS/TS taint case; open
  upstream nondeterministic-taint reports remain. Treat both as candidates to
  prove, not assumed fixes.
- Next execution step: run a hosted-equivalent discriminating version/topology
  ladder, beginning with 1.171.0 and then 1.173.0 if necessary, using the exact
  Carbon file-016 oracle `[40,1114,1691]` and full producer/replay equality.
  Do not ship local-only evidence, retries, unions/intersections, suppression,
  comparator relaxation, or a fixed-root-only change.
- Before any next PR #1954 push, integrate exact current main `255df949...`,
  obtain fresh independent acceptance on the resulting head, run one (not
  duplicated) pre-push `pnpm verify`, push, and require green hosted checks.

## Durable sweep state

- `.git/issue-sweep-ledger.json` records the PR #1955 merge, PR #1954 hosted
  failure, completed artifact census, and active fixer routing. Normal and
  `--turn-exit` validators were both `PARALLEL PLAN VALID` at the stopping point.
- Primary checkout has only the known untracked `.pnpm-store/`; do not delete or
  commit it without separate instruction.
- #1410/#1758 remain parked behind sensitive docs/baseline authority. #1795
  remains partial as described above. #1800 remains unpublished pending informed
  operator approval.

## Resume rule

The operator ended this active session at the checkpoint above and explicitly
cancelled the old 10:15 PM continuation automation. Resume only from a new,
explicit operator request. On resume, load the issue-sweep skill and ledger; do
not re-triage unchanged issues or repeat completed local gates.
