<!--
If this PR carries a closing keyword (`Closes #N`), the `acceptance` check requires every
acceptance bullet of #N to be mapped below. Delete this block if the PR closes nothing.

  ACCEPTANCE #<issue>.<n> met: <the command run and its output, the test name, or file:line>
  ACCEPTANCE #<issue>.<n> split: #<remainder>     ← must exist, be OPEN, and be cross-linked from #<issue>
  ACCEPTANCE #<issue>.<n> relayed: <the question — which must ALSO be a comment on #<issue>>
  ACCEPTANCE #<issue> no-stated-criteria: <what the bar was>   ← only if #<issue> states none

Bullets are numbered in the order they appear in the issue's `## Acceptance` section (or its
checklist), starting at 1. A bare "done" is not evidence and fails the gate.

ONE VENUE PER CRITERION. The gate reads this body AND every comment on #<issue>, cumulatively, and
a criterion may be dispositioned exactly once across all of them. So if you have already commented
these lines on the issue, do not repeat them here (or neutralise the comment) — the same lines in
two places is a double mapping, and it fails. The one exception (#1753): a single `met`/`split`
over a single earlier `relayed` is a COMPLETED RELAY — it supersedes the `relayed` line
automatically, so record the completion and leave the old line alone.

Check it before you push:
  pnpm validate-acceptance --body-file <a file holding this body> --repo <owner/repo>
It reads the issues and their comments over `gh`, exactly as the PR check does.
Closing keywords go on their own line at the bottom; GitHub's parser is negation-blind, so
"does not close #N" closes #N. Linking the issue in the Development sidebar closes it too, with no
keyword at all — the gate reads that link, so those criteria are checked as well.
-->

## What changed

## Verification
