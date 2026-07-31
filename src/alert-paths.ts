// Gate 5 of epic #1320 (#1287). A CI alert path that has never fired is indistinguishable from one
// that cannot fire, and this repo shipped four of them: `ci-conservation-alert`, `ci-reasons-alert`
// and `ci-owasp-watch-alert` did not exist as LABELS, and every alert step carries a self-healing
// `gh label create` — so the missing label was machine-checkable proof the step had never executed.
// `ci-corpus-drift-alert` and `ci-heavy-cli-alert` existed but had opened zero issues.
//
// What this module derives, from the workflow files themselves rather than from a list someone
// maintains:
//
//   • every alert path is DISPATCH-PROVABLE — its `if:` admits workflow_dispatch, and its workflow
//     exposes an `alert_drill` input with a step that fails on it. A cron-only alert is one nobody
//     can prove, which is how all four got shipped unfired.
//   • every alert path has a RECORDED PROOF in .github/alert-paths.json — the run that fired it.
//   • the registry and the workflows agree in BOTH directions, so neither a new unregistered path
//     nor a stale registry entry passes.
//   • every SCHEDULED workflow either has an alert path or is disclosed as not having one. A
//     scheduled job that goes red with no alarm is the same defect one file over, and an absent row
//     never appears in a tally.
//
// The label-existence check is the standing invariant #1287 asks for and it needs the network, so
// it lives in the CLI (`--labels`), not here.

import { parse } from "yaml";

const ALERT_ACTION = "./.github/actions/alert-issue";
const DRILL_INPUT = "alert_drill";

export interface AlertStep {
  marker: string;
  /** The step's `if:` expression, verbatim. "" when the step has none. */
  condition: string;
}

export interface WorkflowFacts {
  workflow: string;
  scheduled: boolean;
  /** Declared under `on.workflow_dispatch.inputs`. */
  hasDrillInput: boolean;
  /** A step gated on the drill input — without one, dispatching the drill does nothing. */
  hasDrillStep: boolean;
  alertSteps: AlertStep[];
}

export interface ProvenBy {
  run: string;
  issue: number;
  at?: string;
  /**
   * Git blob sha (`git rev-parse HEAD:.github/actions/alert-issue/find-or-update.sh`) of the
   * shared `find_or_update` implementation at the moment this path was drilled (#1604). Every
   * converted path's alert step runs through that one script, so a change to it — #1594 and
   * #1602 both landed one without re-drilling the other six markers — makes every OTHER entry's
   * `provenBy` a claim about code that no longer exists, with nothing to notice it. Optional
   * because `unconverted` entries are inlined, not routed through the shared script, and older
   * entries predate the field.
   */
  sourceSha?: string;
}

// REASON: a brand-new alerting workflow's drill is not dispatchable until the workflow file is on the DEFAULT branch, so its alert path has no way to be proven before it merges — which is why `pendingProof` exists at all rather than every new path simply being drilled first
// KIND: empirical
// PROVENANCE: TRIED 2026-07-28 — `gh workflow run secbench.yml --ref feature/secbench-cadence -f alert_drill=true` against the pushed-but-unmerged branch, three ways (by file, by name, and raw `POST .../workflows/secbench.yml/dispatches`). GitHub answers verbatim: `HTTP 404: workflow secbench.yml not found on the default branch`. Operator ruling the same day: land the path unproven, drill immediately after merge, record the run id and delete the hatch.
// FALSIFIER: command -v gh >/dev/null 2>&1 || exit 127; gh api repos/jharvieux/Harvey >/dev/null 2>&1 || exit 127; gh api "repos/jharvieux/Harvey/contents/.github/workflows/secbench.yml?ref=main" >/dev/null 2>&1 && exit 0 || exit 1
// TOUCHES: .github/alert-paths.json .github/workflows/secbench.yml
//
// The falsifier above is deliberately self-retiring: the day secbench.yml lands on main it exits 0,
// reasons-drift reports this row STALE, and the remedy is the drill run this hatch was opened for.
//
/**
 * The one disclosed way an alert path may sit on `main` unproven (#1288, operator ruling
 * 2026-07-28) — see the reason block above for the circularity it exists to answer.
 *
 * It is a hatch, so it is built to fail loud rather than to fail open:
 *   • `tracking` must name an OPEN issue, re-read by `--labels` (checkDisclosureTracking). The day
 *     that issue closes with no proof recorded, the gate goes red — the same posture as
 *     scheduledWithoutAlertPath, whose disclosure used to fail open (#1287).
 *   • the marker label is EXCLUDED from expectedLabels while pending. A pending path's label does
 *     not exist yet, and that absence is the evidence; creating it by hand to keep the gate quiet
 *     would be manufacturing the proof this whole module exists to demand.
 *   • pendingProof and provenBy are mutually exclusive, so a recorded proof REPLACES the hatch
 *     instead of sitting beside it, where it would re-authorise skipping the next one.
 */
export interface PendingProof {
  /** Why the proof is still outstanding, in the words someone re-reading this will need. */
  why: string;
  /** Open issue carrying the outstanding proof run. */
  tracking: number;
  /** When the path landed unproven, so an old hatch is visible as old. */
  since: string;
}

export interface AlertPathRegistry {
  paths: { workflow: string; marker: string; provenBy?: ProvenBy; pendingProof?: PendingProof }[];
  unconverted: { workflow: string; marker: string; why: string; provenBy: ProvenBy }[];
  scheduledWithoutAlertPath: { workflow: string; tracking: number }[];
}

function steps(doc: unknown): Record<string, unknown>[] {
  const jobs = (doc as { jobs?: Record<string, { steps?: unknown }> } | null)?.jobs ?? {};
  return Object.values(jobs).flatMap((job) => (Array.isArray(job?.steps) ? (job.steps as Record<string, unknown>[]) : []));
}

/**
 * `on:` is the reason this parses YAML rather than grepping: under YAML 1.1 the bare key `on`
 * resolves to the boolean `true`, so a hand-rolled reader silently finds no triggers at all and
 * every workflow reads as "not scheduled" — a false pass in a gate built to prevent false passes.
 * The `yaml` package defaults to the 1.2 core schema, where it stays the string "on".
 */
export function workflowFacts(workflow: string, text: string): WorkflowFacts {
  const doc = parse(text) as { on?: Record<string, unknown> } | null;
  const on = doc?.on ?? {};
  const dispatch = on["workflow_dispatch"] as { inputs?: Record<string, unknown> } | null | undefined;
  const all = steps(doc);

  return {
    workflow,
    scheduled: "schedule" in on,
    hasDrillInput: DRILL_INPUT in (dispatch?.inputs ?? {}),
    hasDrillStep: all.some((s) => String(s["if"] ?? "").includes(`inputs.${DRILL_INPUT}`)),
    alertSteps: all
      .filter((s) => s["uses"] === ALERT_ACTION)
      .map((s) => ({
        marker: String((s["with"] as Record<string, unknown> | undefined)?.["marker"] ?? ""),
        condition: String(s["if"] ?? ""),
      })),
  };
}

interface Violation {
  workflow: string;
  detail: string;
}

export function checkAlertPaths(facts: WorkflowFacts[], registry: AlertPathRegistry): Violation[] {
  const out: Violation[] = [];
  const registered = new Map(registry.paths.map((p) => [p.marker, p]));
  const disclosed = new Set(registry.scheduledWithoutAlertPath.map((w) => w.workflow));
  const unconverted = new Set(registry.unconverted.map((u) => u.marker));
  const seen = new Set<string>();

  for (const f of facts) {
    for (const step of f.alertSteps) {
      seen.add(step.marker);

      if (!step.condition.includes("workflow_dispatch")) {
        out.push({
          workflow: f.workflow,
          detail: `alert path '${step.marker}' cannot be reached by workflow_dispatch (if: ${step.condition || "none"}). A cron-only alert path cannot be proven to work, which is how #1287's four unfired paths shipped.`,
        });
      }

      const entry = registered.get(step.marker);
      if (!entry) {
        out.push({
          workflow: f.workflow,
          detail: `alert path '${step.marker}' is not in .github/alert-paths.json. Prove it with \`gh workflow run <name> -f ${DRILL_INPUT}=true\`, then record the run.`,
        });
      } else if (entry.workflow !== f.workflow) {
        out.push({ workflow: f.workflow, detail: `alert path '${step.marker}' is registered against ${entry.workflow}.` });
      } else if (entry.pendingProof && entry.provenBy) {
        out.push({
          workflow: f.workflow,
          detail: `alert path '${step.marker}' carries BOTH a recorded proof run and a pendingProof hatch. Drop the hatch — a proven path with an open exemption re-opens the door the proof just closed.`,
        });
      } else if (entry.pendingProof) {
        if (!entry.pendingProof.why?.trim() || !(entry.pendingProof.tracking > 0) || !entry.pendingProof.since?.trim()) {
          out.push({
            workflow: f.workflow,
            detail: `alert path '${step.marker}' declares pendingProof but not all of why/tracking/since. An exemption with no reason, no tracker and no date is indistinguishable from a forgotten one.`,
          });
        }
      } else if (!entry.provenBy?.run || entry.provenBy.run === "PENDING" || !entry.provenBy.issue) {
        out.push({
          workflow: f.workflow,
          detail: `alert path '${step.marker}' has no recorded proof run. Unfired is indistinguishable from unfireable — dispatch the drill and record the run URL and issue number.`,
        });
      }
    }

    if (f.alertSteps.length > 0 && !f.hasDrillInput) {
      out.push({ workflow: f.workflow, detail: `has an alert path but no \`${DRILL_INPUT}\` workflow_dispatch input, so its alert path is not re-provable.` });
    }
    if (f.alertSteps.length > 0 && !f.hasDrillStep) {
      out.push({ workflow: f.workflow, detail: `declares \`${DRILL_INPUT}\` but no step is gated on it, so dispatching the drill would pass and prove nothing.` });
    }
    if (f.scheduled && f.alertSteps.length === 0 && !disclosed.has(f.workflow)) {
      out.push({
        workflow: f.workflow,
        detail: `runs on a schedule but raises no alert on failure. A scheduled job goes red on a branch nobody watches. Add an alert path, or disclose it in scheduledWithoutAlertPath with a tracking issue.`,
      });
    }
  }

  for (const marker of registered.keys()) {
    if (!seen.has(marker)) {
      out.push({ workflow: registered.get(marker)?.workflow ?? "(registry)", detail: `registry lists '${marker}' but no workflow uses it. A retired marker whose proof stays on the books is a claim about a path that no longer exists.` });
    }
  }
  for (const marker of unconverted) {
    if (seen.has(marker)) out.push({ workflow: "(registry)", detail: `'${marker}' is listed as unconverted but a workflow now routes it through the shared action — move it into paths.` });
  }

  return out;
}

/**
 * Every marker the gate expects to exist as a label: converted paths plus the inlined ones.
 *
 * A path with a pendingProof hatch is EXCLUDED, and that exclusion is the point rather than a
 * concession: its label has not been created because its alert step has never run, which is exactly
 * the machine-checkable evidence #1287 was built on. Demanding the label before the drill would
 * leave one remedy — creating it by hand — and a hand-made label is a forged proof of liveness.
 */
export function expectedLabels(registry: AlertPathRegistry): string[] {
  return [...registry.paths.filter((p) => !p.pendingProof).map((p) => p.marker), ...registry.unconverted.map((u) => u.marker)].sort();
}

/**
 * `scheduledWithoutAlertPath` is the hatch that lets a scheduled workflow ship with no alarm, on the
 * promise that a tracking issue carries it. Nothing validated that promise: the moment #1333 closes,
 * four undisclosed-alarm workflows go back to passing silently — a disclosure that fails OPEN, which
 * is the shape this whole gate exists against. So the tracking issue must exist AND be open.
 *
 * `state` returns undefined when the issue could not be read at all; that is UNVERIFIABLE and the
 * caller must not fold it in with "the issue is closed" (#1246).
 */
export function checkDisclosureTracking(registry: AlertPathRegistry, state: (issue: number) => string | undefined): Violation[] {
  const rows = [
    ...registry.scheduledWithoutAlertPath.map((w) => ({ workflow: w.workflow, tracking: w.tracking, what: "is disclosed as having no alert path" })),
    // Same hatch, same failure mode: a pendingProof whose tracker closes has quietly become a
    // permanent exemption from the proof requirement (#1288).
    ...registry.paths.filter((p) => p.pendingProof).map((p) => ({ workflow: p.workflow, tracking: p.pendingProof!.tracking, what: `has an UNPROVEN alert path '${p.marker}'` })),
  ];
  return rows.flatMap((row) => {
    const s = state(row.tracking);
    if (s === "OPEN") return [];
    return [{
      workflow: row.workflow,
      detail: s === undefined
        ? `${row.what}, tracked by #${row.tracking} — which could not be read. An unreadable tracker is no measurement, not a clean one.`
        : `${row.what}, tracked by #${row.tracking} — which is ${s}. The disclosure now points at nothing, so a scheduled failure here raises no alarm and appears in no tally. Give it an alert path or re-point the disclosure.`,
    }];
  });
}

/**
 * #1604's fifth acceptance line: make the staleness it found DETECTABLE rather than something a
 * reviewer has to notice by reading `find-or-update.sh`'s own git log. Reported INFORMATIONALLY,
 * not folded into `checkAlertPaths`'s violations — the operator decision recorded in #1604's PR
 * body was to surface drift rather than block every future PR on a full re-drill of every
 * marker (that would need `workflow_dispatch` on all six-plus paths before an unrelated
 * find-or-update.sh change could merge). A path with no recorded `sourceSha` predates the field
 * and is silently skipped, not reported stale.
 */
export function staleProofs(registry: AlertPathRegistry, currentSourceSha: string): { marker: string; recordedSha: string }[] {
  return registry.paths
    .filter((p): p is typeof p & { provenBy: ProvenBy & { sourceSha: string } } => !!p.provenBy?.sourceSha && p.provenBy.sourceSha !== currentSourceSha)
    .map((p) => ({ marker: p.marker, recordedSha: p.provenBy.sourceSha }));
}

/**
 * A REQUIRED status check that shells out to `gh` couples every merge in the repo to GitHub API
 * availability — no other required context here does that. Retry the transient case before a blip
 * becomes merge-blocking. Exit 127 on the last failure is still the rule (#1246): "I could not
 * check" must not share a channel with "I checked and it is gone".
 */
export function retrying<T extends { status: number | null }>(run: () => T, attempts: number, pause: (ms: number) => void): T {
  let last = run();
  for (let attempt = 1; attempt < attempts && last.status !== 0; attempt++) {
    pause(1000 * 2 ** (attempt - 1));
    last = run();
  }
  return last;
}
