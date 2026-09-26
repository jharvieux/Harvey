# Corpus advisory snapshot refresh

The primary supervisor for the corpus sweep owns snapshot freshness until an explicitly
named engagement operator takes over. The existing daily `corpus-drift` schedule is the
early-warning channel: its shared-input job checks every `EXTERNAL_CORPUS` pin before
cloning or scanning, retains a per-target receipt with capture time, expiry and digest,
and fails the scheduled run when any snapshot is within 72 hours of expiry. That failure
reaches the existing corpus alert issue. A relevant PR, merge-group or push run fails
before hosted work when a snapshot is already expired, invalid, or could expire within
the six-hour run budget. Runtime consumers still check freshness when they read each
payload; a start-of-run receipt cannot certify a later read.

When the warning fires, the owner prepares a reviewed refresh before the earliest
expiry. Confirm that each target's pinned commit is unchanged, obtain authorization for
the live OSV submission, and run `pnpm exec tsx src/cli/corpus-advisory-snapshot.ts`
from a fresh worktree. The scanner is the only writer of compressed payloads and manifest
epochs. Regenerate `src/environment-dependency-inventory.json` with its owning census
command after committing changed source or inputs. Do not edit `capturedAt`, `expiresAt`,
payloads or hashes by hand, or move an expiry without an actual recapture.

Review every target in the generated manifest, including targets with no findings.
For each pin compare the prior and new package/input population and the added, removed
and changed advisory findings. A changed finding requires a human decision and a reason
in the PR; a failed or partial refresh remains red and is retried from measured inputs,
not silently omitted. Run `pnpm verify:changed`, the complete freshness preflight, and
the full hosted corpus producer plus independent replay on the protected PR. Record the
exact head, all target receipts and required checks before merging. Keep the issue open
until a real refresh crosses this boundary with all checks green.
