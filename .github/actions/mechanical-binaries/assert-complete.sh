#!/usr/bin/env bash
# The completeness assertion for the mechanical-binaries cache (#1516, remainder of #1509).
#
# WHY IT RESOLVES AN EXACT PATH AND NOT `command -v`: the check this replaces was
#
#     command -v "$b" >/dev/null || { echo "::error::$b missing after install/restore"; exit 1; }
#
# which searches the WHOLE PATH. The runner ships preinstalled tooling in /opt/pipx_bin and
# /usr/local/bin, so a binary that exists only there satisfied the check while the CACHED TREE was
# missing it — the cache was then saved incomplete, and the failure landed on the NEXT PR, on someone
# else's branch. That is the 2026-07-29 outage in #1509 exactly: semgrep installed to /opt/pipx_bin,
# a cache saved without it, and every later run taking a cache HIT with no semgrep at all. #1509
# fixed the CAUSE (PIPX_HOME/PIPX_BIN_DIR now steer semgrep into the cached tree); this asserts the
# PROPERTY, so the next tool that resolves from somewhere else fails on the PR that caused it.
#
# WHY IT IS A FILE AND NOT INLINE YAML: a guard nobody has watched fail is indistinguishable from one
# that cannot fail, and a workflow step cannot be run by a test. src/mechanical-binaries-cache.test.ts
# executes THIS file against a scratch HOME in both directions. Same reasoning as find-or-update.sh
# (#1511) and gate-liveness.sh (#1509).
#
# Env in: BIN_DIR (defaults to $HOME/.local/bin).
set -uo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
TOOLS="semgrep trufflehog osv-scanner gitleaks"

missing=""
for b in $TOOLS; do
  # -x, not -e: a dangling pipx shim is a real failure mode here. Caching ~/.local/bin without
  # ~/.local/pipx yields a semgrep shim that resolves and then dies at exec, which is why the
  # action caches both paths or neither.
  if [ ! -x "$BIN_DIR/$b" ]; then
    missing="$missing $b"
  fi
done

if [ -n "$missing" ]; then
  echo "::error::mechanical-binaries cache INCOMPLETE —${missing} not executable in $BIN_DIR. Not saving the cache: an incomplete entry is saved under a key that promises all four, so the next job takes a HIT, skips the install and runs without them — failing on a PR that did not cause it (#1509/#1516). If a tool resolves elsewhere on PATH (/opt/pipx_bin, /usr/local/bin), it is NOT in the cached tree and does not count."
  echo "PATH resolution for comparison, so the cause is visible rather than inferred:"
  for b in $TOOLS; do
    echo "  $b -> $(command -v "$b" 2>/dev/null || echo '(nowhere on PATH)')"
  done
  exit 1
fi

echo "mechanical-binaries cache COMPLETE — all four executable in $BIN_DIR:"
for b in $TOOLS; do
  echo "  $b -> $BIN_DIR/$b"
done
