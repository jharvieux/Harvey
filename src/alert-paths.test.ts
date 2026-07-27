import { describe, expect, it } from "vitest";
import { checkAlertPaths, expectedLabels, workflowFacts, type AlertPathRegistry, type WorkflowFacts } from "./alert-paths.js";
import { loadFacts, loadRegistry } from "./cli/validate-alert-paths.js";

const PROVEN = { run: "https://github.com/o/r/actions/runs/1", issue: 7, at: "2026-07-27" };

function registry(over: Partial<AlertPathRegistry> = {}): AlertPathRegistry {
  return { paths: [{ workflow: "wf.yml", marker: "m-alert", provenBy: PROVEN }], unconverted: [], scheduledWithoutAlertPath: [], ...over };
}

function facts(over: Partial<WorkflowFacts> = {}): WorkflowFacts {
  return {
    workflow: "wf.yml",
    scheduled: true,
    hasDrillInput: true,
    hasDrillStep: true,
    alertSteps: [{ marker: "m-alert", condition: "failure() && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')" }],
    ...over,
  };
}

describe("workflowFacts — parses YAML because `on:` is the trap (#1287)", () => {
  // Under YAML 1.1 the bare key `on` is the boolean true. A reader that gets this wrong finds no
  // triggers at all, so every workflow reads as "not scheduled" and the scheduled-without-alert
  // check silently covers nothing — a false pass inside a gate built against false passes.
  it("resolves the `on:` key as a mapping, not as boolean true", () => {
    const f = workflowFacts("wf.yml", "name: x\non:\n  schedule:\n    - cron: '0 7 * * *'\njobs: {}\n");
    expect(f.scheduled).toBe(true);
  });

  it("reads the drill input, the drill step and each alert step's marker and condition", () => {
    const f = workflowFacts(
      "wf.yml",
      [
        "on:",
        "  workflow_dispatch:",
        "    inputs:",
        "      alert_drill:",
        "        type: boolean",
        "jobs:",
        "  j:",
        "    steps:",
        "      - if: inputs.alert_drill",
        "        run: exit 1",
        "      - if: failure() && github.event_name == 'workflow_dispatch'",
        "        uses: ./.github/actions/alert-issue",
        "        with:",
        "          marker: m-alert",
        "",
      ].join("\n"),
    );
    expect(f.hasDrillInput).toBe(true);
    expect(f.hasDrillStep).toBe(true);
    expect(f.alertSteps).toEqual([{ marker: "m-alert", condition: "failure() && github.event_name == 'workflow_dispatch'" }]);
  });
});

describe("checkAlertPaths — the seeded states main was actually in before #1287", () => {
  it("passes a dispatch-provable path with a recorded proof run", () => {
    expect(checkAlertPaths([facts()], registry())).toEqual([]);
  });

  // This is verbatim what all five alert steps said before #1287, and all five were unfired.
  it("rejects a schedule-only alert condition — an alert nobody can fire cannot be shown to work", () => {
    const v = checkAlertPaths([facts({ alertSteps: [{ marker: "m-alert", condition: "failure() && github.event_name == 'schedule'" }] })], registry());
    expect(v).toHaveLength(1);
    expect(v[0]?.detail).toContain("cannot be reached by workflow_dispatch");
  });

  it("rejects a path whose proof run is still PENDING", () => {
    const v = checkAlertPaths([facts()], registry({ paths: [{ workflow: "wf.yml", marker: "m-alert", provenBy: { run: "PENDING", issue: 0 } }] }));
    expect(v[0]?.detail).toContain("no recorded proof run");
  });

  it("rejects an alert path missing from the registry, and a registry entry missing from the workflows", () => {
    expect(checkAlertPaths([facts()], registry({ paths: [] }))[0]?.detail).toContain("not in .github/alert-paths.json");
    expect(checkAlertPaths([facts({ alertSteps: [] })], registry())[0]?.detail).toContain("no workflow uses it");
  });

  // Without this the drill input is decorative: dispatching it runs a green job and "proves" a path
  // that never executed.
  it("rejects an alert path whose workflow has no drill input or no step gated on it", () => {
    expect(checkAlertPaths([facts({ hasDrillInput: false })], registry())[0]?.detail).toContain("not re-provable");
    expect(checkAlertPaths([facts({ hasDrillStep: false })], registry())[0]?.detail).toContain("prove nothing");
  });

  it("rejects a scheduled workflow that raises nothing, unless it is disclosed with a tracking issue", () => {
    const silent = facts({ workflow: "quiet.yml", alertSteps: [] });
    expect(checkAlertPaths([facts(), silent], registry())[0]?.detail).toContain("raises no alert on failure");
    expect(checkAlertPaths([facts(), silent], registry({ scheduledWithoutAlertPath: [{ workflow: "quiet.yml", tracking: 1333 }] }))).toEqual([]);
  });

  it("does not demand an alert path from a workflow that never runs on a schedule", () => {
    expect(checkAlertPaths([facts({ workflow: "pr-only.yml", scheduled: false, alertSteps: [] })], registry({ paths: [] }))).toEqual([]);
  });
});

describe("this repo's own alert paths (the gate `pnpm verify` enforces)", () => {
  const facts_ = loadFacts();
  const reg = loadRegistry();

  it("has every alert path dispatch-provable, registered, and carrying a proof run", () => {
    expect(checkAlertPaths(facts_, reg)).toEqual([]);
  });

  // The count is derived, never written down: a sixth alert path added without a registry entry
  // fails the assertion above rather than quietly joining an unchecked population.
  it("still finds the five converted alert paths in the workflows themselves", () => {
    expect(facts_.flatMap((f) => f.alertSteps.map((s) => s.marker)).sort()).toEqual(reg.paths.map((p) => p.marker).sort());
  });

  it("expects a marker label for the inlined owasp-ack path too, not only the drilled ones", () => {
    expect(expectedLabels(reg)).toContain("owasp-ack-alert");
  });
});
