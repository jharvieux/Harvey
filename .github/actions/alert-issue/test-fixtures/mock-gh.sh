#!/usr/bin/env bash
# Mock `gh` for src/alert-issue-race.test.ts. Backed by a JSON "issue store" file at
# $MOCK_GH_STORE, guarded by an mkdir-based spinlock so each individual call here is atomic (the
# way a real GitHub API request is) — the race the test exercises lives BETWEEN calls (list, then
# create), which is the real shape of #1511/#1512, not inside a single call.
#
# `gh issue list` synchronizes on a BARRIER, keyed by $MOCK_GH_BARRIER racers AND by which `list`
# call this is FOR THIS RACER (1st = find_open's pre-create check, 2nd = reconcile_duplicates'
# post-create read) — tracked via $RACER_ID, which the test harness sets once per spawned racer
# process. $PPID does NOT work for this: a pipe (`gh issue list | jq ...`) and a command
# substitution (`existing=$(find_open ...)`) each fork their own subshell, so `gh`'s immediate
# parent pid is a different, freshly-forked subshell on every single call — even two calls from the
# SAME racer never share a $PPID (MEASURED: 10 distinct callcount files for 5 racers making 2 calls
# each). Every racer's Nth `list`
# call blocks until all $MOCK_GH_BARRIER racers have reached their own Nth call, at which point
# whichever racer arrives last freezes a snapshot of the live store for everyone at that call-index
# to read. This guarantees every racer's 1st call observes "nothing open yet" whenever that is
# genuinely true (no racer can have created yet — none of them have passed their own 1st call), and
# every racer's 2nd call (reconcile) observes the FULL set of what every racer created (no racer can
# have reached its 2nd call before finishing its own create).
#
# THREE WEAKER DESIGNS WERE TRIED AND MEASURED UNRELIABLE FIRST (kept here so nobody re-tries them):
#   1. A fixed sleep before every `list` read: one racer's whole check-then-act round trip routinely
#      completes in under the ~10ms spinlock retry interval, so whichever racer's sleep happens to
#      elapse first can slip through before its siblings even retry acquiring the lock — reproducing
#      the race by luck (MEASURED: 5 racers, fixed 1.2s delay, only 1-2 of 5 actually created).
#   2. A single barrier only on the 1st `list` call: reads still take turns on the same file lock
#      once released, and a fast racer can finish read-decide-create before a slower sibling gets its
#      own read turn (MEASURED: only 1-2 of 5 created).
#   3. Freezing a snapshot on the 1st call only, with reconcile reading the SAME barrier/snapshot
#      pair: reconcile's own `list` call then either reused the frozen pre-create snapshot (seeing
#      nobody's create) or read live and ran before its siblings had all created, so it never saw the
#      full set and closed nothing (MEASURED: fixed produced 5 of 5 still open — reconcile ran, but
#      too early, every time). The per-call-index barrier below is what actually fixes it.
set -euo pipefail
STORE="$MOCK_GH_STORE"
LOCKDIR="$STORE.lock"
BARRIER_N="${MOCK_GH_BARRIER:-1}"
CALL_COUNT_FILE="$STORE.callcount-${RACER_ID:-$$}"

acquire() { until mkdir "$LOCKDIR" 2>/dev/null; do sleep 0.01; done; }
release() { rmdir "$LOCKDIR"; }

cmd="$1"; shift
sub="$1"; shift

case "$cmd $sub" in
  "issue list")
    call_index=$(( $(cat "$CALL_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$call_index" > "$CALL_COUNT_FILE"
    if [ "$BARRIER_N" -gt 1 ]; then
      bfile="$STORE.barrier.$call_index"
      sfile="$STORE.snapshot.$call_index"
      acquire
      count=$(( $(cat "$bfile" 2>/dev/null || echo 0) + 1 ))
      echo "$count" > "$bfile"
      if [ "$count" -eq "$BARRIER_N" ]; then
        cat "$STORE" > "$sfile"
      fi
      release
      while [ ! -f "$sfile" ]; do sleep 0.01; done
      data=$(cat "$sfile")
    else
      acquire
      data=$(cat "$STORE")
      release
    fi
    echo "$data" | jq '[.[] | select(.state=="open")] | map({number, title})'
    ;;
  "issue create")
    title=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --title) title="$2"; shift 2 ;;
        --body|--label) shift 2 ;;
        *) shift ;;
      esac
    done
    acquire
    data=$(cat "$STORE")
    num=$(echo "$data" | jq '([.[].number] + [0]) | max + 1')
    data=$(echo "$data" | jq --arg t "$title" --argjson n "$num" '. + [{number: $n, title: $t, state: "open", comments: 0}]')
    echo "$data" > "$STORE"
    release
    echo "https://example.invalid/issues/$num"
    ;;
  "issue comment")
    num="$1"; shift
    while [ $# -gt 0 ]; do
      case "$1" in
        --body) shift 2 ;;
        *) shift ;;
      esac
    done
    acquire
    data=$(cat "$STORE")
    data=$(echo "$data" | jq --argjson n "$num" 'map(if .number == $n then .comments += 1 else . end)')
    echo "$data" > "$STORE"
    release
    echo "https://example.invalid/issues/$num#issuecomment-1"
    ;;
  "issue close")
    num="$1"; shift
    while [ $# -gt 0 ]; do
      case "$1" in
        --comment) shift 2 ;;
        *) shift ;;
      esac
    done
    acquire
    data=$(cat "$STORE")
    data=$(echo "$data" | jq --argjson n "$num" 'map(if .number == $n then .state = "closed" else . end)')
    echo "$data" > "$STORE"
    release
    ;;
  *)
    echo "mock-gh: unhandled command: $cmd $sub $*" >&2
    exit 1
    ;;
esac
