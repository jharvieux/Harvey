# shellcheck shell=bash
# A frozen, literal copy of find_open/find_or_update as they shipped BEFORE #1511/#1512 — i.e. with
# no reconcile_duplicates step. Sourced by nothing except src/alert-issue-race.test.ts, whose job is
# to prove the race this file is vulnerable to actually reproduces under real concurrency, so the
# fixed find-or-update.sh (which DOES converge) is proof of something rather than an assertion.
# Do not "fix" this file — that would defeat the regression test it exists for.

find_open() {
  gh issue list --state open --label "$MARKER" --json number,title \
    | jq -r --arg s "$SUFFIX" --arg want "$1" \
        '[.[] | select((.title | endswith($s)) == ($want == "drill"))] | .[0].number // empty'
}

find_or_update() {
  local namespace="$1" title="$2" body="$3" existing url
  existing=$(find_open "$namespace") || return $?
  if [ -n "$existing" ]; then
    gh issue comment "$existing" --body "$body" > /dev/null || return $?
    printf 'commented\t%s\t\n' "$existing"
  else
    url=$(gh issue create --title "$title" --label "$MARKER" --body "$body") || return $?
    printf 'created\t%s\t%s\n' "${url##*/}" "$url"
  fi
}
