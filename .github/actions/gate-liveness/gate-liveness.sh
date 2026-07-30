#!/usr/bin/env bash
# The body of .github/actions/gate-liveness. Kept as a file rather than inline YAML so it can be
# executed directly by src/ci-liveness.test.ts — a guard nobody has watched fail is indistinguishable
# from one that cannot, and a copy of this logic in TypeScript would only prove the copy.
#
# DELIBERATELY DEPENDENCY-FREE: bash and coreutils only. The failure this exists to catch is a job
# dying in SETUP (#1509 — a poisoned pipx cache), which is exactly the state in which node, pnpm and
# tsx are not available. A liveness check that needs the toolchain cannot report on the toolchain.
#
# Env in:  MODE, GATE, UNITS, STATUS, SCOPE, EXPECT, HARVEY_LIVENESS_RECEIPT, JOB
set -uo pipefail

RECEIPT="${HARVEY_LIVENESS_RECEIPT:-${RUNNER_TEMP:-/tmp}/harvey-gate-liveness.receipt}"

fail() {
  echo "::error::$*"
  exit 1
}

# `summary` goes to stdout AND, when running in Actions, to the job summary — the whole point is
# that a reader can tell "scored and found nothing" from "died before scoring" WITHOUT opening logs.
summary() {
  printf '%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"; fi
}

valid_gate_id() {
  case "$1" in
    "" | *[!a-z0-9-]*) return 1 ;;
    *) return 0 ;;
  esac
}

case "${MODE:-}" in
  record)
    status="${STATUS:-measured}"
    scope=$(printf '%s' "${SCOPE:-}" | tr '\n\r\t' '   ')
    [ -n "${GATE:-}" ] || fail "gate-liveness record: no gate id given."
    [ -n "${scope// /}" ] || fail "gate-liveness record: gate=${GATE} carries no scope. A record with no scope says a phase ran without saying what it measured, which is the shape this action exists to reject."
    case "$status" in
      measured)
        case "${UNITS:-}" in
          '' | *[!0-9]*) fail "gate-liveness record: gate=${GATE} status=measured needs an integer unit count, got \"${UNITS:-}\"." ;;
        esac
        [ "${UNITS}" -gt 0 ] || fail "gate-liveness record: gate=${GATE} measured 0 units. Examining nothing is not a clean run — it is a job that died before its measuring phase, or a no-op nobody declared. Mirrors src/audit-runner.ts's Examined rule: unitsExamined=0 is a NotAssessed with a reason, never a pass."
        units="${UNITS}"
        ;;
      declared-no-op)
        units=0
        ;;
      *) fail "gate-liveness record: unknown status \"$status\" (expected 'measured' or 'declared-no-op')." ;;
    esac
    mkdir -p "$(dirname "$RECEIPT")"
    for gate in ${GATE//,/ }; do
      valid_gate_id "$gate" || fail "gate-liveness record: gate id \"$gate\" must be lowercase [a-z0-9-]."
      printf 'harvey-liveness gate=%s status=%s units=%s scope=%s\n' "$gate" "$status" "$units" "$scope" >> "$RECEIPT"
      echo "gate-liveness: recorded $gate ($status, $units units) -> $RECEIPT"
    done
    ;;

  assert)
    expect="${EXPECT:-}"
    expect="${expect//,/ }"
    [ -n "${expect// /}" ] || fail "gate-liveness assert: no gate ids to expect. An assert that expects nothing passes vacuously, which is the defect."

    rows=""
    dead=""
    live=0
    noop=0
    for gate in $expect; do
      valid_gate_id "$gate" || fail "gate-liveness assert: gate id \"$gate\" must be lowercase [a-z0-9-]."
      measured_units=0
      measured_records=0
      detail=""
      noop_reason=""
      if [ -f "$RECEIPT" ]; then
        while IFS= read -r line; do
          case "$line" in
            "harvey-liveness gate=$gate status="*) ;;
            *) continue ;;
          esac
          rest="${line#harvey-liveness gate="$gate" status=}"
          st="${rest%% *}"
          rest="${rest#* }"
          u="${rest#units=}"
          u="${u%% *}"
          sc="${line#*scope=}"
          if [ "$st" = "declared-no-op" ]; then
            noop_reason="$sc"
          else
            measured_records=$((measured_records + 1))
            measured_units=$((measured_units + u))
            detail="$sc"
          fi
        done < "$RECEIPT"
      fi

      if [ "$measured_units" -gt 0 ]; then
        live=$((live + 1))
        rows="${rows}| \`$gate\` | ✅ MEASURED | $measured_units | $detail |"$'\n'
      elif [ -n "$noop_reason" ]; then
        noop=$((noop + 1))
        rows="${rows}| \`$gate\` | ⏭️ DECLARED NO-OP | 0 | $noop_reason |"$'\n'
      elif [ "$measured_records" -gt 0 ]; then
        dead="${dead} $gate"
        rows="${rows}| \`$gate\` | ❌ ZERO UNITS | 0 | $detail |"$'\n'
      else
        dead="${dead} $gate"
        rows="${rows}| \`$gate\` | ❌ NEVER REACHED | — | no record on the receipt — this phase did not run |"$'\n'
      fi
    done

    if [ -n "${dead// /}" ]; then
      headline="**GATE LIVENESS: FAILED** — this job did NOT reach its measuring phase for:${dead}. It measured nothing, so it proves nothing; do not read it as \"scored and found no problems\"."
    elif [ "$live" -eq 0 ]; then
      headline="**GATE LIVENESS: DECLARED NO-OP** — nothing was measured, and the job said why (below). This is NOT a scoring run and carries no evidence about the code."
    elif [ "$noop" -gt 0 ]; then
      headline="**GATE LIVENESS: MEASURED (partial)** — $live gate(s) scored, $noop declared a no-op with a reason."
    else
      headline="**GATE LIVENESS: MEASURED** — all $live gate(s) reached their measuring phase and scored real units."
    fi

    summary "### Gate liveness — ${JOB:-this job}"
    summary ""
    summary "$headline"
    summary ""
    summary "| gate | verdict | units | scope / reason |"
    summary "| --- | --- | --- | --- |"
    summary "${rows%$'\n'}"

    if [ -n "${dead// /}" ]; then
      for gate in $dead; do
        echo "::error::gate \"$gate\" never reached its measuring phase (receipt: $RECEIPT). A job that dies before scoring must not be mistaken for one that scored and found nothing (#1509)."
      done
      exit 1
    fi
    ;;

  *) fail "gate-liveness: mode must be 'record' or 'assert', got \"${MODE:-}\"." ;;
esac
