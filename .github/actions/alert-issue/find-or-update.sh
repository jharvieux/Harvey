# shellcheck shell=bash
# Shared find-or-update + duplicate-reconciliation logic for the alert-issue action.
#
# Extracted out of action.yml (untracked race, fixed alongside jharvieux/Harvey#1511/#1512) for two
# reasons: (1) it is the one piece of this action a real concurrency test can exercise — a test can
# spawn genuine background bash processes against a mocked `gh` and race them, which is not possible
# against inline `run:` YAML — and (2) it keeps the race fix in one place shared by every caller.
#
# Sourced by action.yml's run step, which has already exported MARKER, GH_TOKEN/GH_REPO (for `gh`)
# and defines SUFFIX before sourcing this file in production; a test sources this file directly with
# its own MARKER/SUFFIX and a mocked `gh` function on PATH (see src/alert-issue-race.test.ts).
#
# THE RACE THIS FIXES: ci.yml's heavy-cli job runs 3 matrix shards, and each one independently calls
# `uses: ./.github/actions/alert-issue` when it fails on a schedule/dispatch run. All three run this
# script concurrently. `find_open` → `gh issue create` is a classic check-then-act: if two shards
# both list zero open issues before either one's create lands, both create — one issue where there
# should be one. This is exactly what happened for `ci-heavy-cli-alert` (run 30436646111, shards 1
# and 2 each opened/updated a separate issue: #1511 and #1512).
#
# THE FIX IS SELF-HEALING CONVERGENCE, NOT A LOCK. A true mutex needs a place to hold it; the only
# atomic primitive available to a composite action with no infra beyond `gh` is a git ref create,
# which has no usable timestamp for detecting an abandoned lock (the target sha's commit date is
# whenever that commit was authored, not when the ref was created) — building a safe steal-on-timeout
# lock on top of that is real machinery for a path that fires rarely and races at most 3-wide.
# Instead, every racer that creates-or-comments finishes by calling `reconcile_duplicates`, which
# lists every OPEN issue in its namespace, keeps the LOWEST-numbered one canonical, and closes the
# rest with a comment pointing at the canonical one. Whichever racer runs its reconcile LAST sees the
# true final set (every sibling racer's create has already landed, because reconcile runs after each
# racer's own create/comment step, and this whole step is synchronous within one job), so the run
# converges to exactly one open issue by the time all racers finish. `gh issue close`/`gh issue
# comment` on an issue another racer already closed/commented is idempotent enough to just re-run
# harmlessly (GitHub allows commenting on a closed issue and closing an already-closed one).

# $1 = drill|real. Partitions open issues on the marker by title so a drill and a live alarm can
# never be confused for one another.
find_open() {
  gh issue list --state open --label "$MARKER" --json number,title \
    | jq -r --arg s "$SUFFIX" --arg want "$1" \
        '[.[] | select((.title | endswith($s)) == ($want == "drill"))] | .[0].number // empty'
}

# Collapse every OPEN issue in this namespace down to one: the lowest-numbered survives, every other
# one is closed with a comment redirecting to it. Returns the surviving (canonical) issue number, or
# empty if none are open. Idempotent and safe to call after every create/comment, including when
# there was never a duplicate — it then finds exactly one open issue and returns it unchanged.
reconcile_duplicates() {
  local namespace="$1" nums canonical="" n
  nums=$(gh issue list --state open --label "$MARKER" --json number,title \
    | jq -r --arg s "$SUFFIX" --arg want "$namespace" \
        '[.[] | select((.title | endswith($s)) == ($want == "drill"))] | sort_by(.number) | .[].number') || return $?
  for n in $nums; do
    if [ -z "$canonical" ]; then
      canonical="$n"
    else
      gh issue comment "$n" --body "Duplicate alarm for the same underlying failure — consolidated into #${canonical} by the alert-issue duplicate-reconciliation guard (jharvieux/Harvey#1511/#1512)." > /dev/null || return $?
      gh issue close "$n" > /dev/null || return $?
    fi
  done
  echo "$canonical"
}

# THE find-or-update logic (#1348, reconciled #1511/#1512) — the ONE code path both the production
# branch and the drill run. $1 = namespace (drill|real), $2 = title, $3 = body. Prints
# "created\t<number>\t<url>" or "commented\t<number>\t" (tab-separated, one line) so a caller can
# tell which half ran without re-deriving it — and, when a sibling racer's reconcile closed the issue
# this call just created/commented on, the number is already the surviving canonical one, not a
# closed duplicate.
# `|| return $?` on every gh/find_open call below is load-bearing, not defensive filler: a bare
# `existing=$(find_open ...)` or `gh issue comment ...` followed unconditionally by more commands
# means the function's own exit status (its LAST command) is whatever THAT command returns, not the
# one that actually failed — and dry-running this against a `gh` shim rigged to fail (#1348) proved
# it two different ways: the caller reported "Commented on existing tracking issue" even though the
# comment call itself had failed, and separately a failing `find_open` was swallowed the same way.
# `set -e` does not save either case: a function invoked inside a command substitution (`result=$(
# find_or_update ...)`) does not abort on an interior failure the way a true-top-level command does —
# proven empirically, not assumed. Explicitly forwarding the failing command's exit code makes the
# function's return status meaningful again, which the call sites below rely on.
find_or_update() {
  local namespace="$1" title="$2" body="$3" existing url status num canonical
  existing=$(find_open "$namespace") || return $?
  if [ -n "$existing" ]; then
    # `gh issue comment` prints the new comment's URL to stdout on success — which, inside
    # `result=$(find_or_update ...)`, would land in the SAME captured stream as the `printf` below
    # and break the caller's parse (a live drill run caught this, #1348: pass 2 reported a comment
    # URL where a "commented" status was expected). Discarded on purpose.
    gh issue comment "$existing" --body "$body" > /dev/null || return $?
    status=commented; num="$existing"; url=""
  else
    url=$(gh issue create --title "$title" --label "$MARKER" --body "$body") || return $?
    status=created; num="${url##*/}"
  fi
  canonical=$(reconcile_duplicates "$namespace") || return $?
  if [ -n "$canonical" ] && [ "$canonical" != "$num" ]; then
    status=commented
    num="$canonical"
    url=""
  fi
  printf '%s\t%s\t%s\n' "$status" "$num" "$url"
}
