# SESSION — 2026-08-20 active issue sweep

_Last updated: 2026-08-20. The operator explicitly resumed the issue sweep in the
current task. This checkpoint records active ownership and exact next actions; it does
not authorize a later task to resume automatically._

## Completed in the active sweep

- PR #1951 merged as `588125a23b7c7749fad12631654b7a7649f7eb32`.
  It closed #1910 only. Issue #1800 remains open because its complete 765-row
  external-corpus census has not been published for review.
- The #1951 repair preserved the strict producer/replay comparator and stabilized the
  known Semgrep `harvey-log-injection` omission class with paired cold exact
  verification before return or cache write. The verified repair head was
  `4f6db20df6243cd3ea8b49d209d2b8aaad0d50f3`; all protected checks passed.
- The unpublished #1800 census is retained locally at
  `/private/tmp/path-scope-census-1800-final.json` and
  `/private/tmp/path-scope-census-1800-final.md`. It covers 17 pins × 45 classes =
  765 rows: 505 applicable/populated, 148 applicable/zero, and 112 explicitly
  inapplicable. Publishing that full evidence requires informed operator approval.

## Active pull request

- PR #1952, `Define bounded M7 capacity contract (#1893)`, is open at exact head
  `38443256c46f04bdc3f3cf1201efadfe27f1ac77` on base `588125a`.
- Its close-set is exactly #1893. Independent acceptance verification passed all five
  live criteria. The base update preserved the exact five-file diff and stable patch
  identity.
- The PR-body acceptance evidence was corrected after a metadata-only gate rejected
  two lines that lacked a concrete backticked source/command reference. Only that
  failed acceptance run was restarted; the full CI/corpus jobs already in progress
  were not restarted for the metadata edit.
- Next action: wait for protected checks, perform two exact-head/close-set readbacks,
  then squash-merge with `Closes #1893` if every required check is green.

## Active source-graph batch

All lanes start from merged main `588125a23b7c7749fad12631654b7a7649f7eb32`.

- Integration owner: #1640 on `feature/sweep-source-graph-1640` in
  `/private/tmp/harvey-sweep-source-graph-1640`. It owns the canonical emitted-family
  registry/parity validator and final integration; documentation remains parked.
- Auxiliary writer: #1795 on `feature/sweep-source-graph-1795` in
  `/private/tmp/harvey-sweep-source-graph-1795`. It owns nested Nest module-import
  reachability in `src/detectors/perf-code.ts` and must measure all 17 pins before any
  baseline proposal.
- Pending lane: #1812, baseUrl-only bare-specifier resolution in
  `src/detectors/app-router.ts`. Dispatch it when a worker slot is free. It is
  measurement-first and must preserve resolution precedence and the declared-package
  near miss.
- No lane may silently edit a corpus baseline. The integration owner must receive a
  row-by-row census, integrate local commits, run the owning generated-artifact and
  conservation gates, and obtain independent exact-head acceptance verification
  before push.

## Durable workflow rule

The active task continues because the operator explicitly said to continue the issue
sweep. A future task must not resume from this file, an agent completion, a CI result,
or a scheduled wakeup unless the operator explicitly asks to resume.
