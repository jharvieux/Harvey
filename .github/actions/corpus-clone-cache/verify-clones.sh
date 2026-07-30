#!/usr/bin/env bash
# The ONE definition of "this tree holds every pinned clone", read from the pin file the manifest
# itself generates (src/cli/corpus-pins.ts) and shared by BOTH sides of the corpus clone cache
# (#1571). Deliberately one script rather than two copies of this loop: the restore side and the
# save side disagreeing about what "complete" means is the whole failure this closes.
#
#   restore  A HIT that does not reproduce every pin is poison. Fail the job BY NAME before
#            anything is scored — never a quietly smaller corpus.
#   save     A run that does not HOLD every pin must never WRITE the pin-set key. Report
#            complete=false and let the caller skip actions/cache/save. This mode never fails the
#            job: an incomplete clone set is the NORMAL state of corpus-m8.yml (4 of the pinned
#            targets) and of corpus-drift.yml's #1498 narrowed PR path (only the slugs the diff
#            touched), not an error.
#
# Usage: verify-clones.sh <cache-dir> <pin-file> restore|save
set -euo pipefail

cache_dir="$1"
pin_file="$2"
mode="$3"

bad=()
count=0
while read -r slug repoAt; do
  [ -n "$slug" ] || continue
  count=$((count + 1))
  repo="${repoAt%@*}"
  commit="${repoAt#*@}"
  dir="$cache_dir/${repo//\//__}"
  if [ ! -d "$dir/.git" ]; then
    bad+=("$slug ($repo): no clone at $dir")
    continue
  fi
  head=$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo "")
  if [ "$head" != "$commit" ]; then
    bad+=("$slug ($repo): HEAD=$head, pin expects $commit")
    continue
  fi
  if [ -n "$(git -C "$dir" status --porcelain 2>&1)" ]; then
    bad+=("$slug ($repo): working tree is dirty — a partial or corrupted checkout")
  fi
done < "$pin_file"

if [ "$mode" = save ]; then
  if [ "${#bad[@]}" -gt 0 ]; then
    echo "corpus-clone-cache: NOT saving — this run holds ${#bad[@]} of $count pinned clone(s) short of the full set:"
    for b in "${bad[@]}"; do echo "  - $b"; done
    echo "The key hashes the WHOLE pin set, so only a run holding the whole set may write it."
    echo "complete=false" >> "$GITHUB_OUTPUT"
  else
    echo "corpus-clone-cache: all $count pinned clones present — this run may write the pin-set key."
    echo "complete=true" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

if [ "${#bad[@]}" -gt 0 ]; then
  echo "::error::corpus-clone-cache: restored cache is poisoned or incomplete for ${#bad[@]} of $count pinned target(s):"
  for b in "${bad[@]}"; do echo "::error::  - $b"; done
  # NOT "re-run to let it rebuild": a cache key is IMMUTABLE once written, so a re-run restores the
  # same bad entry and dies here again. Only deleting the entry or moving the key escapes it.
  echo "::error::A restored cache must reproduce every pinned clone exactly — never a quietly smaller scan. A GitHub Actions cache key is IMMUTABLE: re-running CANNOT rebuild this entry, it restores the same one and fails here again. Recover by deleting it (gh cache delete <key> --repo <owner/repo>) or by bumping the key suffix in .github/actions/corpus-clone-cache/action.yml. Since #1571 only a run holding EVERY pinned clone may write this key, so a freshly written entry cannot be partial."
  exit 1
fi
echo "corpus-clone-cache: verified $count/$count cached clones match their pins."
