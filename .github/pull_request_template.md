<!--
If this PR carries a closing keyword (`Closes #N`), the `acceptance` check requires every
acceptance bullet of #N to be mapped below. Delete this block if the PR closes nothing.

  ACCEPTANCE #<issue>.<n> met: <the command run and its output, the test name, or file:line>
  ACCEPTANCE #<issue>.<n> split: #<remainder>     ← must exist, be OPEN, and be cross-linked from #<issue>
  ACCEPTANCE #<issue>.<n> relayed: <the question — which must ALSO be a comment on #<issue>>
  ACCEPTANCE #<issue> no-stated-criteria: <what the bar was>   ← only if #<issue> states none

Bullets are numbered in the order they appear in the issue's `## Acceptance` section (or its
checklist), starting at 1. A bare "done" is not evidence and fails the gate.

Check it before you push:  pnpm validate-acceptance --body-file <a file holding this body>
Closing keywords go on their own line at the bottom; GitHub's parser is negation-blind, so
"does not close #N" closes #N.
-->

## What changed

## Verification
