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
}

export interface AlertPathRegistry {
  paths: { workflow: string; marker: string; provenBy: ProvenBy }[];
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

/** Every marker the gate expects to exist as a label: converted paths plus the inlined ones. */
export function expectedLabels(registry: AlertPathRegistry): string[] {
  return [...registry.paths.map((p) => p.marker), ...registry.unconverted.map((u) => u.marker)].sort();
}
