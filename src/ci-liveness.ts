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

/**
 * Record that `gate` reached its measuring phase and scored `units` of `scope`.
 *
 * Off CI (no receipt path in the environment) this is silent apart from the invariant check — the
 * point is that a local `pnpm corpus-drift` reads exactly as it did before, while the same code path
 * still refuses to claim a zero-unit run measured anything.
 */
export function recordMeasured(gate: string, units: number, scope: string): void {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(gate)) {
    throw new Error(`gate-liveness: gate id "${gate}" must be lowercase [a-z0-9-] — it is matched literally by .github/actions/gate-liveness/gate-liveness.sh.`);
  }
  if (!scope.trim()) {
    throw new Error(`gate-liveness: gate "${gate}" recorded no scope. A unit count with no statement of what the units are says a phase ran without saying what it measured.`);
  }
  if (!Number.isInteger(units) || units <= 0) {
    throw new Error(
      `gate-liveness: gate "${gate}" reported units=${units} (${scope}) — scoring nothing is not a clean run, it is a run that never reached its measuring phase (#1509). Same rule as src/audit-runner.ts's Examined: unitsExamined=0 is a NotAssessed with a reason, never a pass.`,
    );
  }
  const receipt = process.env[RECEIPT_ENV];
  if (!receipt) return;
  const line = `harvey-liveness gate=${gate} status=measured units=${units} scope=${scope.replace(/[\r\n\t]+/g, " ").trim()}`;
  appendFileSync(receipt, `${line}\n`);
  console.error(line);
}
