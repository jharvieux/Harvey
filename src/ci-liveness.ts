// The producer side of the CI gate-liveness receipt (.github/actions/gate-liveness).
//
// A gate CLI calls recordMeasured() AFTER it has scored, with the count it actually scored. The
// workflow's assert step then refuses to let the job be green unless that record is on the receipt.
// Rationale and the incident behind it: .github/actions/gate-liveness/action.yml.
//
// The zero-units rule is NOT a new idea — it is src/audit-runner.ts's `Examined` contract applied to
// CI: "a probe that examined nothing did not run, and must say so as NotAssessed". A gate that
// scored 0 units is a gate that died before its measuring phase, and it throws here rather than
// printing a reassuring summary.

import { appendFileSync } from "node:fs";

const RECEIPT_ENV = "HARVEY_LIVENESS_RECEIPT";

// Off CI (no receipt path in the environment) this writes nothing and prints nothing, so a local
// `pnpm corpus-drift` reads exactly as it did before — but the invariant still runs, so the same code
// path refuses to claim a zero-unit run measured anything wherever it is called from.
function assertGateId(gate: string): void {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(gate)) {
    throw new Error(`gate-liveness: gate id "${gate}" must be lowercase [a-z0-9-] — it is matched literally by .github/actions/gate-liveness/gate-liveness.sh.`);
  }
}

export function recordMeasured(gate: string, units: number, scope: string): void {
  assertGateId(gate);
  if (!scope.trim()) {
    throw new Error(`gate-liveness: gate "${gate}" recorded no scope. A unit count with no statement of what the units are says a phase ran without saying what it measured.`);
  }
  if (!Number.isInteger(units) || units <= 0) {
    throw new Error(
      `gate-liveness: gate "${gate}" reported units=${units} (${scope}) — scoring nothing is not a clean run, it is a run that never reached its measuring phase (#1509). Same rule as src/audit-runner.ts's Examined: unitsExamined=0 is a NotAssessed with a reason, never a pass.`,
    );
  }
  write(`harvey-liveness gate=${gate} status=measured units=${units} scope=${clean(scope)}`);
}

/**
 * The other legitimate outcome: the gate ran and DELIBERATELY scored nothing — a PR that closes no
 * issue, a bot-opened tracking issue, a filter that found nothing relevant. The workflow's `mode:
 * record status: declared-no-op` says this for a shell-level phase; this is the same statement from
 * a gate CLI, which is the only place that knows it short-circuited.
 *
 * It is NOT a quieter pass: the asserter prints DECLARED NO-OP as its own headline, so a reader
 * never reads it as a scoring run. Omitting it instead would be the silent omission — a run
 * that scored nothing on purpose and a run that died before scoring would both leave an empty
 * receipt.
 */
export function recordDeclaredNoOp(gate: string, reason: string): void {
  assertGateId(gate);
  if (!reason.trim()) {
    throw new Error(`gate-liveness: gate "${gate}" declared a no-op with no reason. "Nothing was scored" with no statement of why is the absence this whole mechanism exists to refuse.`);
  }
  write(`harvey-liveness gate=${gate} status=declared-no-op scope=${clean(reason)}`);
}

const clean = (s: string): string => s.replace(/[\r\n\t]+/g, " ").trim();

function write(line: string): void {
  const receipt = process.env[RECEIPT_ENV];
  if (!receipt) return;
  appendFileSync(receipt, `${line}\n`);
  console.error(line);
}
