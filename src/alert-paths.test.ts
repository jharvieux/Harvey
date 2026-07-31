import { describe, expect, it } from "vitest";
import { checkAlertPaths, checkDisclosureTracking, expectedLabels, retrying, seedClosedTrackingPopulation, staleProofs, SYNTHETIC_HATCH, workflowFacts, type AlertPathRegistry, type WorkflowFacts } from "./alert-paths.js";
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
    expect(checkAlertPaths([facts({ scheduled: false, alertSteps: [] })], registry())[0]?.detail).toContain("no workflow uses it");
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

// #1288's hatch. A drill only dispatches against a workflow already on the default branch, so a new
// alerting workflow is unprovable until it merges — the requirement above would otherwise forbid
// adding one at all. The tests that matter here are the ones proving the hatch closes rather than
// parking a path unproven forever.
describe("pendingProof — the one disclosed way an alert path lands unproven (#1288)", () => {
  const pending = { why: "cannot dispatch a drill until the workflow is on main", tracking: 1288, since: "2026-07-28" };
  const withPending = (over: Record<string, unknown> = {}) =>
    registry({ paths: [{ workflow: "wf.yml", marker: "m-alert", pendingProof: { ...pending, ...over } }] });

  it("accepts a path with a complete pendingProof and no recorded run", () => {
    expect(checkAlertPaths([facts()], withPending())).toEqual([]);
  });

  it("rejects a pendingProof missing its reason, its tracker or its date", () => {
    expect(checkAlertPaths([facts()], withPending({ why: "  " }))[0]?.detail).toContain("not all of why/tracking/since");
    expect(checkAlertPaths([facts()], withPending({ tracking: 0 }))[0]?.detail).toContain("not all of why/tracking/since");
    expect(checkAlertPaths([facts()], withPending({ since: "" }))[0]?.detail).toContain("not all of why/tracking/since");
  });

  // The hatch is for a path that has not been drilled. Once it has, leaving the hatch open would
  // re-authorise skipping the proof on any later change to the same path.
  it("rejects a path carrying both a proof run and the hatch", () => {
    const both = registry({ paths: [{ workflow: "wf.yml", marker: "m-alert", provenBy: PROVEN, pendingProof: pending }] });
    expect(checkAlertPaths([facts()], both)[0]?.detail).toContain("BOTH a recorded proof run and a pendingProof");
  });

  // The load-bearing one. A pending marker's label does NOT exist — its step has never run — and
  // the only way to satisfy a label check on it is to create the label by hand, which forges the
  // exact evidence #1287 rests on.
  it("does not demand a marker label for a path that has never fired", () => {
    expect(expectedLabels(withPending())).not.toContain("m-alert");
  });

  // How the hatch closes rather than fails open: same treatment as scheduledWithoutAlertPath.
  it("fails once the tracking issue closes with the proof still unrecorded", () => {
    expect(checkDisclosureTracking(withPending(), () => "OPEN")).toEqual([]);
    expect(checkDisclosureTracking(withPending(), () => "CLOSED")[0]?.detail).toContain("UNPROVEN alert path 'm-alert'");
  });
});

describe("checkDisclosureTracking — the no-alarm hatch must not fail open", () => {
  const disclosed = registry({ paths: [], scheduledWithoutAlertPath: [{ workflow: "quiet.yml", tracking: 1333 }] });

  it("accepts a disclosure whose tracking issue is open", () => {
    expect(checkDisclosureTracking(disclosed, () => "OPEN")).toEqual([]);
  });

  // The negative control, and the only way this hatch fails: #1333 closes, and four workflows with
  // no alarm at all go back to passing silently on a disclosure that now points at nothing.
  it("fails when the tracking issue has been closed", () => {
    expect(checkDisclosureTracking(disclosed, () => "CLOSED").map((v) => v.workflow)).toEqual(["quiet.yml"]);
  });

  // Unreadable is not clean. Reported separately so the caller can exit 127 rather than 1 (#1246).
  it("fails distinctly when the tracking issue could not be read at all", () => {
    expect(checkDisclosureTracking(disclosed, () => undefined)[0]?.detail).toContain("could not be read");
  });
});

// #1333. The control above is only a control while it has something to check, and the registry it
// reads is designed to empty out. MEASURED 2026-07-31 against the pre-fix CLI with the hatch
// population driven to zero: `--seed-closed-tracking` contributed 0 violations, so the gate exited 0
// and alert-paths.yml's step would have reported "the control failed to fail" — about a control with
// nothing to fail on.
describe("seedClosedTrackingPopulation — a negative control with no population is not a control", () => {
  it("leaves a registry that already has a hatch alone, so the control tests the REAL row", () => {
    const live = registry({ scheduledWithoutAlertPath: [{ workflow: "quiet.yml", tracking: 1333 }] });
    expect(seedClosedTrackingPopulation(live)).toBe(live);
    expect(seedClosedTrackingPopulation(live).scheduledWithoutAlertPath.map((w) => w.workflow)).toEqual(["quiet.yml"]);
  });

  it("counts a pendingProof as population too — it is the same hatch under a different key", () => {
    const pending = registry({ paths: [{ workflow: "wf.yml", marker: "m-alert", pendingProof: { why: "w", tracking: 9, since: "2026-07-31" } }] });
    expect(seedClosedTrackingPopulation(pending)).toBe(pending);
  });

  it("supplies a labelled synthetic row when nothing is left to seed, so the control still fails", () => {
    const empty = registry();
    const seeded = seedClosedTrackingPopulation(empty);
    expect(seeded).not.toBe(empty);
    expect(seeded.scheduledWithoutAlertPath.map((w) => w.workflow)).toEqual([SYNTHETIC_HATCH]);
    // The point of the whole exercise: CLOSED must still produce a violation at zero population.
    expect(checkDisclosureTracking(seeded, () => "CLOSED")).toHaveLength(1);
    expect(checkDisclosureTracking(seeded, () => "OPEN")).toEqual([]);
  });

  it("does not touch the real registry's own hatch count", () => {
    expect(seedClosedTrackingPopulation(registry()).paths).toEqual(registry().paths);
  });
});

describe("retrying — a required check must not fail on one API blip", () => {
  const attempt = (statuses: (number | null)[]) => {
    let i = 0;
    return () => ({ status: statuses[i++] ?? null });
  };

  it("returns the first success and stops calling", () => {
    const paused: number[] = [];
    expect(retrying(attempt([1, 0, 0]), 3, (ms) => paused.push(ms)).status).toBe(0);
    expect(paused).toEqual([1000]);
  });

  // The control: retrying must not turn a real "the label is gone" into a pass. It hands back the
  // last failure and the caller still exits 127.
  it("gives up and returns the failure when every attempt fails", () => {
    const paused: number[] = [];
    expect(retrying(attempt([1, 1, 1]), 3, (ms) => paused.push(ms)).status).toBe(1);
    expect(paused).toEqual([1000, 2000]);
  });
});

// #1604: six provenBy entries cited shas that predated two later changes to the ONE shared
// find-or-update.sh every alert step invokes — an argument that the old and new logic were
// equivalent in the drills' single-open-issue namespace, not a re-measurement. sourceSha makes
// that class of drift detectable rather than something a reviewer has to notice by hand.
describe("staleProofs — a shared-script change invalidates every OTHER marker's provenBy, not just the one that touched it (#1604)", () => {
  const withShas = (a: string | undefined, b: string | undefined) =>
    registry({
      paths: [
        { workflow: "a.yml", marker: "m-a", provenBy: { ...PROVEN, sourceSha: a } },
        { workflow: "b.yml", marker: "m-b", provenBy: { ...PROVEN, sourceSha: b } },
      ],
    });

  it("reports nothing when every recorded sourceSha matches the current one", () => {
    expect(staleProofs(withShas("abc123", "abc123"), "abc123")).toEqual([]);
  });

  it("flags a marker whose recorded sourceSha no longer matches the current file", () => {
    expect(staleProofs(withShas("abc123", "def456"), "abc123")).toEqual([{ marker: "m-b", recordedSha: "def456" }]);
  });

  // An entry with no sourceSha predates the field (or is inlined, not routed through the shared
  // script) — reporting it stale would be a false positive, not a stricter check.
  it("silently skips a path with no recorded sourceSha at all", () => {
    expect(staleProofs(withShas("abc123", undefined), "zzz999")).toEqual([{ marker: "m-a", recordedSha: "abc123" }]);
  });
});

describe("this repo's own alert paths (the gate `pnpm verify` enforces)", () => {
  const facts_ = loadFacts();
  const reg = loadRegistry();

  it("has every alert path dispatch-provable, registered, and carrying a proof run or a disclosed hatch", () => {
    expect(checkAlertPaths(facts_, reg)).toEqual([]);
  });

  // The count is derived, never written down: a new alert path added without a registry entry
  // fails the assertion above rather than quietly joining an unchecked population.
  it("finds exactly the registered alert paths in the workflows themselves", () => {
    expect(facts_.flatMap((f) => f.alertSteps.map((s) => s.marker)).sort()).toEqual(reg.paths.map((p) => p.marker).sort());
  });

  // The hatch is a named list, not a category that grows: any unproven path has to edit this line,
  // which is where it gets noticed. secbench occupied it under #1288's operator ruling and was
  // retired the same day once its drill ran (run 30376371298, issue #1430). site-smoke-alert
  // (#1509/#1543) occupied it the same way and was retired 2026-07-31 once site-smoke.yml landed on
  // main and its drill ran (run 30595915001, issue #1598).
  //
  // #1333 (2026-07-31) retired two more, and the reason matters more than the count. Both
  // ci-free-recall-alert (#1185/#1536) and ci-semantic-freshness-alert (#1270/#1611) cited the same
  // circularity — "a drill only dispatches against a workflow already on the DEFAULT branch" — which
  // was true the day each was written and had since expired unread: both files had long since
  // merged, so nothing was blocking either drill except nobody re-reading the reason. They drilled
  // first try (runs 30605913478 / 30605914742). The comment that stood here also asserted the
  // circularity was "about what the default branch can RUN, not about which file exists"; that was
  // MEASURED FALSE the same day — a workflow_dispatch run executes the copy on the ref you name, so
  // a job or input present only on a branch is dispatchable from it (see .github/alert-paths.json's
  // `_why`). ONE occupant today, ci-main-red-alert (#1507/#1612), and its hatch now records an
  // operational reason — a full red ci.yml run during a live merge train — not a structural one.
  // Retire it the same way: drill it, record provenBy, drop pendingProof, and this list goes back to
  // empty, which is the state it should normally be in. `pendingProof`'s own behaviour stays covered
  // by the fixture tests above, so naming the current occupant here does not un-test the mechanism.
  it("names the current unproven alert path(s) explicitly — the hatch is a named exception, not a silent default", () => {
    // `ci-supervised-declines-alert` joined on 2026-07-31 (#1545): its workflow file is not yet on
    // the default branch, and GitHub refuses workflow_dispatch for one that is not — MEASURED, a
    // 404 from the dispatch API, tracked by #1688. This list is meant to SHRINK; each addition has
    // to be a named exception a reader can go and check, never a silent default.
    expect(reg.paths.filter((p) => p.pendingProof).map((p) => p.marker).sort()).toEqual(["ci-main-red-alert", "ci-supervised-declines-alert"]);
    expect(reg.paths.filter((p) => !p.pendingProof).every((p) => p.provenBy?.run)).toBe(true);
  });

  it("expects a marker label for the inlined owasp-ack path too, not only the drilled ones", () => {
    expect(expectedLabels(reg)).toContain("owasp-ack-alert");
  });
});
