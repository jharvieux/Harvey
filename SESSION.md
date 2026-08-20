# SESSION — 2026-08-20 issue-sweep merge-train wrap-up

_Last updated: 2026-08-20. The approved merge train and its missed instruction-file
wrap-up are complete. No workflow resumes automatically from this checkpoint._

## Outcome

The final four pull requests in this merge train were independently verified, passed
the protected checks, and merged in dependency order:

| PR | Outcome |
| --- | --- |
| #1949 | Refreshed external-input provenance and stabilized current-mechanical execution. |
| #1944 | Delivered scoped idempotency-key validation and closed #1925. |
| #1948 | Delivered the M5/M6 polyglot and M8 detector work and closed #1926, #1927, #1928, #1929, and #1931. |
| #1945 | Canonicalized finding identity and workspace containment without closing the broader partial issue #1899. |

The merge-train base before this instruction-only checkpoint was
`7e8f3d3700612820630c4896ac4f14f7a2773127`.

## Issue reconciliation

- Verified closed: #1925, #1926, #1927, #1928, #1929, and #1931.
- Intentionally open: #1787, #1899, and #1930. Their full acceptance criteria were
  not represented by the merged close-sets.
- The PR carrying this checkpoint has an empty issue close-set.

## Instruction updates

- `AGENTS.md` now requires native commands for verification, tests, diffs, GitHub
  queries, and machine-readable evidence. RTK is display-only unless its result is
  independently verified.
- `.codex/agents/acceptance-verifier.toml` no longer hard-codes one reasoning effort.
  The sweep supervisor selects verifier effort from the actual close-set complexity,
  including scoped lower-cost reruns where the contract permits them.
- `pnpm verify:changed` is now the local pre-push gate. It uses a focused validation
  path only for operating Markdown, Markdown under `docs/`, and Codex agent TOML;
  every executable, generated, manifest, workflow, mixed, empty, or unknown change set
  fails safe to the full `pnpm verify` suite.

The first two changes were produced during the prior sweep session and should have been
landed as its consolidated instruction-only wrap-up instead of being left in the
primary checkout. The path-sensitive local gate was added during finalization at the
operator's direction.

## Local and durable state

- `.pnpm-store/` is generated package-manager storage and is intentionally excluded
  from source control.
- `.git/issue-sweep-ledger.json` is retained durable state from the broader sweep. Its
  projections predate this completed merge train; a future explicit resume must run
  delta reconciliation before dispatching any remaining batch.
- No agent completion, CI result, reconnect, or scheduled wakeup resumes the sweep.

## Exact next action

Do nothing automatically. When the operator explicitly resumes the broader issue sweep,
reconcile the retained ledger against current `main` and GitHub issue/PR state, reuse only
still-valid readiness receipts, and continue the next approved non-terminal batch.
