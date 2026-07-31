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
# lists every OPEN issue in its namespace and collapses each RUN ID's cluster down to its
# lowest-numbered member (#1595 — see that function's header for why it is per-run-id and not one
# global canonical), closing the rest with a comment pointing at the survivor. Whichever racer runs
# its reconcile LAST sees the true final set (every sibling racer's create has already landed,
# because reconcile runs after each racer's own create/comment step, and this whole step is
# synchronous within one job), so racers of ONE run converge to exactly one open issue by the time
# all of them finish. `gh issue close`/`gh issue comment` on an issue another racer already
# closed/commented is idempotent enough to just re-run harmlessly (GitHub allows commenting on a
# closed issue and closing an already-closed one).

# $1 = drill|real. Partitions open issues on the marker by title so a drill and a live alarm can
# never be confused for one another.
find_open() {
  gh issue list --state open --label "$MARKER" --json number,title \
    | jq -r --arg s "$SUFFIX" --arg want "$1" \
        '[.[] | select((.title | endswith($s)) == ($want == "drill"))] | .[0].number // empty'
}

# Extracts the run identifier a body embeds ("actions/runs/<id>" — every alert body in
# .github/workflows/*.yml carries one; see RUN_URL in action.yml). Empty if none found. First match
# only: an alert body has exactly one self-referential run link in practice.
run_id_of() {
  grep -oE 'actions/runs/[0-9]+' <<<"$1" | head -n1 | grep -oE '[0-9]+' || true
}

# Collapse OPEN issues in this namespace down to one PER RUN ID (#1595), not down to one overall.
# Sorts by number; for each run id, the FIRST (lowest-numbered) issue citing it becomes that run's
# canonical, and every later issue citing the SAME run id is closed as a duplicate of it — that is
# the one piece of positive evidence every alert body already carries for free, and it is exact (two
# different failures never share a run id, and two shards of one failing run always do). An issue
# sharing the marker but citing NO run id, or a DIFFERENT one (a human-labelled issue, or a genuinely
# separate failure of the same workflow), matches no cluster and is left OPEN, untouched — the
# pre-#1594 behaviour for anything this function cannot positively confirm.
#
# Grouping by the single lowest-numbered issue overall (rather than per run id) is wrong the moment
# TWO distinct runs are open at once: whichever run happens to own issue #1 would "win" as the sole
# canonical and every issue from every OTHER run would be compared against a run id that never
# matches, closing nothing — see the regression this comment is next to for the reproduction.
#
# $2 = the run id (if any) of the alert THIS call is about — i.e. run_id_of on the body find_or_update
# was invoked with. Returns the surviving canonical for THAT run's cluster specifically (empty if $2
# is empty, since there is then no evidence to resolve one from). Idempotent and safe to call after
# every create/comment, including when there was never a duplicate.
reconcile_duplicates() {
  local namespace="$1" own_run="$2" rows row n body run
  local -A cluster_of=()
  rows=$(gh issue list --state open --label "$MARKER" --json number,title,body \
    | jq -c --arg s "$SUFFIX" --arg want "$namespace" \
        '[.[] | select((.title | endswith($s)) == ($want == "drill"))] | sort_by(.number) | .[]') || return $?
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    n=$(jq -r '.number' <<<"$row")
    body=$(jq -r '.body' <<<"$row")
    run=$(run_id_of "$body")
    [ -z "$run" ] && continue # no evidence at all: never a cluster member, never closed, never canonical
    if [ -n "${cluster_of[$run]:-}" ]; then
      gh issue comment "$n" --body "Duplicate alarm for the same underlying failure (both cite run ${run}) — consolidated into #${cluster_of[$run]} by the alert-issue duplicate-reconciliation guard (jharvieux/Harvey#1511/#1512, run-ID gated per #1595)." > /dev/null || return $?
      gh issue close "$n" > /dev/null || return $?
    else
      cluster_of[$run]="$n"
    fi
  done <<<"$rows"
  # Explicit `return 0`: without it, an empty $own_run (or one with no cluster entry) makes the `if`
  # itself the function's exit status — false, i.e. non-zero — which callers like find_or_update
  # would read as reconcile_duplicates HAVING FAILED (`|| return $?`) rather than "nothing to report".
  if [ -n "$own_run" ] && [ -n "${cluster_of[$own_run]:-}" ]; then
    echo "${cluster_of[$own_run]}"
  fi
  return 0
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
  local namespace="$1" title="$2" body="$3" existing url status num canonical own_run
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
  own_run=$(run_id_of "$body")
  canonical=$(reconcile_duplicates "$namespace" "$own_run") || return $?
  if [ -n "$canonical" ] && [ "$canonical" != "$num" ]; then
    status=commented
    num="$canonical"
    url=""
  fi
  printf '%s\t%s\t%s\n' "$status" "$num" "$url"
}
