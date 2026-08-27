// Both directions of the CI gate-liveness guard, plus the registry that stops a new gate job from
// quietly joining without one. A guard nobody has watched fail is indistinguishable from a guard with
// no failing direction — so every verdict below is exercised, not asserted about.
//
// The assert half is BASH (.github/actions/gate-liveness/gate-liveness.sh), deliberately: the failure
// it exists to catch is a job dying in setup, which is exactly when node/pnpm/tsx are unavailable.
// These tests execute that script rather than a TypeScript copy of it — a copy would only prove the
// copy.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { readNamesSafe } from "./fs-walk.js";
import { recordMeasured } from "./ci-liveness.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, ".github", "actions", "gate-liveness", "gate-liveness.sh");
const WORKFLOWS = join(REPO_ROOT, ".github", "workflows");

interface Registry {
  gates: {
    workflow: string;
    expect: string[];
    note: string;
    provenBy?: { run: string; at: string };
    pendingProof?: { why: string; tracking: number; since: string };
  }[];
  exempt: { workflow: string; measures: string; whyDistinguishable: string }[];
}
const registry = JSON.parse(readFileSync(join(REPO_ROOT, ".github", "gate-liveness.json"), "utf8")) as Registry;

function run(env: Record<string, string>): { status: number; out: string } {
  const r = spawnSync("bash", [SCRIPT], { env: { PATH: process.env.PATH ?? "", ...env }, encoding: "utf8" });
  return { status: r.status ?? -1, out: `${r.stdout}${r.stderr}` };
}

function receipt(): string {
  return join(mkdtempSync(join(tmpdir(), "harvey-liveness-")), "receipt");
}

describe("recordMeasured — the producer side", () => {
  it("refuses to claim a zero-unit run measured anything, the way Examined refuses unitsExamined: 0", () => {
    const path = receipt();
    process.env.HARVEY_LIVENESS_RECEIPT = path;
    try {
      expect(() => recordMeasured("corpus-drift", 0, "baseline checks")).toThrow(/never reached its measuring phase/);
      expect(() => recordMeasured("corpus-drift", -1, "baseline checks")).toThrow(/never reached its measuring phase/);
    } finally {
      delete process.env.HARVEY_LIVENESS_RECEIPT;
    }
    // nothing reached the receipt, so the workflow's assert still FAILS rather than passing on a lie
    expect(run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path }).status).toBe(1);
  });

  it("refuses a unit count with no statement of what the units are", () => {
    expect(() => recordMeasured("corpus-drift", 12, "  ")).toThrow(/no scope/);
  });

  it("writes a line the bash asserter can read back", () => {
    const path = receipt();
    process.env.HARVEY_LIVENESS_RECEIPT = path;
    try {
      recordMeasured("corpus-drift", 42, "baseline checks over 6 pinned target(s)");
    } finally {
      delete process.env.HARVEY_LIVENESS_RECEIPT;
    }
    expect(readFileSync(path, "utf8")).toBe("harvey-liveness gate=corpus-drift status=measured units=42 scope=baseline checks over 6 pinned target(s)\n");
    expect(run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path }).status).toBe(0);
  });

  it("stays silent off CI — a local gate run must read exactly as it did before", () => {
    delete process.env.HARVEY_LIVENESS_RECEIPT;
    expect(() => recordMeasured("corpus-drift", 42, "baseline checks")).not.toThrow();
  });
});

describe("gate-liveness.sh — the three verdicts a reader has to tell apart", () => {
  it("a scored run passes and says MEASURED with the count", () => {
    const path = receipt();
    expect(run({ MODE: "record", GATE: "corpus-drift", UNITS: "97", SCOPE: "baseline checks", HARVEY_LIVENESS_RECEIPT: path }).status).toBe(0);
    const r = run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(0);
    expect(r.out).toContain("GATE LIVENESS: MEASURED");
    expect(r.out).toContain("97");
  });

  it("a job that died before scoring FAILS, naming the phase that never ran", () => {
    const path = receipt();
    const r = run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(1);
    expect(r.out).toContain("GATE LIVENESS: FAILED");
    expect(r.out).toContain("NEVER REACHED");
    expect(r.out).toContain('::error::gate "corpus-drift" never reached its measuring phase');
  });

  it("a declared no-op passes but cannot be read as a scoring run", () => {
    const path = receipt();
    run({ MODE: "record", GATE: "dry-run-regen, dry-run-diff", STATUS: "declared-no-op", SCOPE: "in-job filter found nothing relevant", HARVEY_LIVENESS_RECEIPT: path });
    const r = run({ MODE: "assert", EXPECT: "dry-run-regen, dry-run-diff", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(0);
    expect(r.out).toContain("GATE LIVENESS: DECLARED NO-OP");
    expect(r.out).toContain("carries no evidence about the code");
    expect(r.out).not.toContain("GATE LIVENESS: MEASURED");
  });

  it("the three verdicts are visibly different headlines, not three shades of green", () => {
    const headline = (setup: (p: string) => void): string => {
      const path = receipt();
      setup(path);
      return run({ MODE: "assert", EXPECT: "g", HARVEY_LIVENESS_RECEIPT: path }).out.split("\n").find((l) => l.includes("GATE LIVENESS")) ?? "";
    };
    const measured = headline((p) => void run({ MODE: "record", GATE: "g", UNITS: "3", SCOPE: "things", HARVEY_LIVENESS_RECEIPT: p }));
    const noop = headline((p) => void run({ MODE: "record", GATE: "g", STATUS: "declared-no-op", SCOPE: "why", HARVEY_LIVENESS_RECEIPT: p }));
    const dead = headline(() => {});
    expect(new Set([measured, noop, dead]).size).toBe(3);
  });

  it("recording zero units is itself refused — the count cannot be laundered through the action", () => {
    const path = receipt();
    const r = run({ MODE: "record", GATE: "corpus-drift", UNITS: "0", SCOPE: "baseline checks", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(1);
    expect(r.out).toContain("Examining nothing is not a clean run");
  });

  it("a hand-forged zero-unit record still FAILS the assert", () => {
    const path = receipt();
    writeFileSync(path, "harvey-liveness gate=corpus-drift status=measured units=0 scope=forged\n");
    const r = run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(1);
    expect(r.out).toContain("ZERO UNITS");
  });

  it("one gate's record cannot satisfy another's — a shard-conditional step that stops matching is caught", () => {
    const path = receipt();
    run({ MODE: "record", GATE: "heavy-cli-tests", UNITS: "12", SCOPE: "tests", HARVEY_LIVENESS_RECEIPT: path });
    const r = run({ MODE: "assert", EXPECT: "heavy-cli-tests calibration-gate", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(1);
    expect(r.out).toContain("GATE LIVENESS: FAILED");
    expect(r.out).toContain("| `calibration-gate` | ❌ NEVER REACHED");
  });

  it("a mix of scored and declared-no-op reads as partial, not as a full scoring run", () => {
    const path = receipt();
    run({ MODE: "record", GATE: "dry-run-regen", UNITS: "9", SCOPE: "findings", HARVEY_LIVENESS_RECEIPT: path });
    run({ MODE: "record", GATE: "dry-run-diff", STATUS: "declared-no-op", SCOPE: "nothing to compare", HARVEY_LIVENESS_RECEIPT: path });
    const r = run({ MODE: "assert", EXPECT: "dry-run-regen, dry-run-diff", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(0);
    expect(r.out).toContain("GATE LIVENESS: MEASURED (partial)");
  });

  it("sums repeated records, so the #1498 narrowed corpus-drift path is still a scoring run", () => {
    const path = receipt();
    run({ MODE: "record", GATE: "corpus-drift", UNITS: "5", SCOPE: "target a", HARVEY_LIVENESS_RECEIPT: path });
    run({ MODE: "record", GATE: "corpus-drift", UNITS: "7", SCOPE: "target b", HARVEY_LIVENESS_RECEIPT: path });
    const r = run({ MODE: "assert", EXPECT: "corpus-drift", HARVEY_LIVENESS_RECEIPT: path });
    expect(r.status).toBe(0);
    // and the summing is SAID, not left to be inferred: conservation invokes its gate three times
    // over ten module plants, and a bare "30" reads as thirty plants.
    expect(r.out).toContain("| 12 (sum of 2 runs) |");
  });

  it("an assert that expects nothing is refused rather than passing vacuously", () => {
    expect(run({ MODE: "assert", EXPECT: "", HARVEY_LIVENESS_RECEIPT: receipt() }).status).toBe(1);
  });
});

describe("the registry — a new gate job cannot join without a liveness assert", () => {
  // #1568 replaced a PROXY with the population. The rule used to be "workflows that install the
  // mechanical binaries", chosen because that is what #1509 broke — and it left nine workflows
  // outside the registry BY CONSTRUCTION, including two (semantic-freshness, site-ci) that #1568's
  // own list of nine did not think to name. A proxy does not become exhaustive by being widened; it has
  // to be replaced by it. Every workflow file is now a row, so a new one can only be CLASSIFIED,
  // never omitted.
  const allWorkflows = readNamesSafe(WORKFLOWS)
    .filter((f) => f.endsWith(".yml"))
    .map((f) => `.github/workflows/${f}`);
  const text = (workflow: string): string => readFileSync(join(REPO_ROOT, workflow), "utf8");

  it("every workflow is either a registered gate or exempt with a reason", () => {
    const known = new Set([...registry.gates.map((g) => g.workflow), ...registry.exempt.map((e) => e.workflow)]);
    expect(allWorkflows.length).toBeGreaterThan(0);
    expect(allWorkflows.filter((w) => !known.has(w)), "unregistered workflow(s)").toEqual([]);
    // And in the other direction: a registry row for a workflow that has been deleted or renamed is
    // a claim about a job that no longer exists.
    const onDisk = new Set(allWorkflows);
    expect([...known].filter((w) => !onDisk.has(w)), "registry row(s) with no workflow").toEqual([]);
  });

  // An exemption is a CLAIM — "a dead run here is distinguishable without a receipt" — and this is
  // the half of it a test can settle. A step gated on an in-job filter output or a matrix
  // conditional is exactly the shape (#1107's filter-moved-in-job) that turns a dead scoring phase
  // GREEN, so an exempt row over one of those is refused rather than believed.
  it("refuses an exemption for a workflow whose scoring can be short-circuited to a green no-op", () => {
    const conditional = registry.exempt.filter((e) =>
      text(e.workflow).split("\n").some((l) => /^\s*if:/.test(l) && /steps\.[A-Za-z0-9_-]+\.outputs|matrix\./.test(l)),
    );
    expect(conditional.map((e) => e.workflow), "exempt but carries a conditional step").toEqual([]);
  });

  it("an exempt row states BOTH what the job measures and why its death is visible without a receipt", () => {
    expect(registry.exempt.length).toBeGreaterThan(0);
    for (const e of registry.exempt) {
      expect(e.measures?.trim().length, `${e.workflow} measures`).toBeGreaterThan(40);
      expect(e.whyDistinguishable?.trim().length, `${e.workflow} whyDistinguishable`).toBeGreaterThan(40);
    }
  });

  // The commonest `whyDistinguishable` is "it goes red and its alert path raises a tracking issue".
  // That is checkable, and an exemption resting on an alarm that does not exist is worse than no
  // exemption at all — it is a reason that reads settled.
  it("a SCHEDULED exempt workflow really does carry the alert path its exemption rests on", () => {
    for (const e of registry.exempt) {
      const yml = text(e.workflow);
      if (!/^\s*schedule:/m.test(yml)) continue;
      expect(yml, `${e.workflow} is scheduled and exempt, so it must alert on failure`).toContain("./.github/actions/alert-issue");
    }
  });

  // #1716. A gate id is matched as a WHOLE TOKEN, not as a substring. MEASURED 2026-07-31 on the
  // substring form this replaces: renaming a workflow's `expect: genai-admission-census` to
  // `…-censuss` left all 17 tests green, while renaming it to an unrelated id went red — so the
  // check could see the far miss a reviewer catches anyway and not the near miss a typo produces.
  // The boundary excludes `-` as well as word characters, because every id here is hyphenated:
  // `corpus-drift-extra` must not satisfy `corpus-drift` either.
  const declaredIds = (yml: string, key: "expect" | "gate"): Set<string> => {
    const lines = yml.match(new RegExp(String.raw`^\s*${key}:.*$`, "gm"))?.join("\n") ?? "";
    return new Set(lines.match(/[A-Za-z0-9][A-Za-z0-9-]*/g) ?? []);
  };

  it("every registered gate id is BOTH asserted by its workflow and produced by something", () => {
    const producers = readNamesSafe(join(REPO_ROOT, "src", "cli"))
      .filter((f) => f.endsWith(".ts"))
      .map((f) => readFileSync(join(REPO_ROOT, "src", "cli", f), "utf8"))
      .join("\n");
    for (const gate of registry.gates) {
      const yml = readFileSync(join(REPO_ROOT, gate.workflow), "utf8");
      const asserted = declaredIds(yml, "expect");
      const recorded = declaredIds(yml, "gate");
      for (const id of gate.expect) {
        expect(asserted.has(id), `${gate.workflow} asserts ${id}`).toBe(true);
        expect(recorded.has(id) || producers.includes(`recordMeasured("${id}"`), `${gate.workflow}: ${id} is produced by a record step or a gate CLI`).toBe(true);
      }
    }
  });

  // The failing direction, over the REAL registry rather than a fixture: extend each id by one
  // character in a copy of its own workflow and both halves must stop recognising it. Under the
  // substring form every one of these assertions passed, which is the whole defect.
  it("a one-character extension of a gate id is not accepted for it", () => {
    let checkedAsserted = 0;
    let checkedRecorded = 0;
    for (const gate of registry.gates) {
      const yml = readFileSync(join(REPO_ROOT, gate.workflow), "utf8");
      for (const id of gate.expect) {
        const typo = yml.replaceAll(id, `${id}s`);
        expect(declaredIds(typo, "expect").has(id), `${gate.workflow}: ${id}s satisfies expect ${id}`).toBe(false);
        checkedAsserted++;
        if (declaredIds(yml, "gate").has(id)) {
          expect(declaredIds(typo, "gate").has(id), `${gate.workflow}: ${id}s satisfies gate ${id}`).toBe(false);
          checkedRecorded++;
        }
      }
    }
    // A control that scored nothing proves nothing — both halves must have had a population.
    expect(checkedAsserted).toBeGreaterThan(0);
    expect(checkedRecorded).toBeGreaterThan(0);
  });

  // #1569, mirroring .github/alert-paths.json. A guard nobody has watched fail is indistinguishable
  // from a guard with no failing direction — this repo shipped five of those in its alert paths and
  // three marker labels that had never been created were the proof. The drill input is required
  // FIRST, because scoping the proof rule to "workflows that happen to have a drill" would make
  // deleting the input the way out.
  it("every gate is drillable — its workflow declares a `liveness_drill` dispatch input", () => {
    for (const gate of registry.gates) {
      const yml = text(gate.workflow);
      expect(yml, `${gate.workflow} declares liveness_drill`).toMatch(/^\s{6}liveness_drill:/m);
      expect(yml, `${gate.workflow} has a step gated on liveness_drill`).toMatch(/if:.*liveness_drill/);
    }
  });

  // The producer and the asserter have to agree about WHERE the receipt is. `recordMeasured` writes
  // nothing when `HARVEY_LIVENESS_RECEIPT` is unset (it is silent off CI by design) while the bash
  // asserter falls back to `$RUNNER_TEMP` — so a job missing the env var asserts against an empty
  // file and fails a run that scored perfectly. MEASURED 2026-07-31: five workflows landed without
  // it and all five went red on their first real CI run. A drill cannot catch this — the drill
  // expects a red job.
  // Scoped to the JOB THAT ASSERTS, not to the file. A file-wide `grep` passes when the pin sits on
  // some OTHER job — corpus-drift.yml already has plan/shard/aggregate jobs, so the shape is present
  // in this repo today — and the asserting job would still read an empty receipt while this check
  // stayed green. That is the same "green and executed are different facts" failure the whole
  // registry exists to close, so it may not sit inside the registry's own guard.
  it("the job that ASSERTS liveness is the job that pins the receipt path", () => {
    for (const gate of registry.gates) {
      const doc = parse(text(gate.workflow)) as { env?: Record<string, unknown>; jobs: Record<string, { env?: Record<string, unknown>; steps?: { uses?: string; with?: { mode?: string } }[] }> };
      const asserting = Object.entries(doc.jobs).filter(([, job]) => job.steps?.some((s) => s.uses?.includes("gate-liveness") && s.with?.mode === "assert"));
      expect(asserting.length, `${gate.workflow} has no job running gate-liveness in assert mode`).toBeGreaterThan(0);
      for (const [name, job] of asserting) {
        const pinned = job.env?.HARVEY_LIVENESS_RECEIPT ?? doc.env?.HARVEY_LIVENESS_RECEIPT;
        expect(pinned, `${gate.workflow} job \`${name}\` asserts liveness but does not pin HARVEY_LIVENESS_RECEIPT — it would assert against a file its own recorder never wrote`).toBeTruthy();
      }
    }
  });

  it("every gate carries the run that PROVED it can fail, or a pendingProof hatch with a tracker", () => {
    for (const gate of registry.gates) {
      const { provenBy, pendingProof } = gate;
      expect(!!provenBy && !!pendingProof, `${gate.workflow}: a proven gate with an open exemption re-opens the door the proof closed`).toBe(false);
      if (pendingProof) {
        expect(pendingProof.why?.trim().length, `${gate.workflow} pendingProof.why`).toBeGreaterThan(40);
        expect(pendingProof.tracking, `${gate.workflow} pendingProof.tracking`).toBeGreaterThan(0);
        expect(pendingProof.since?.trim(), `${gate.workflow} pendingProof.since`).toBeTruthy();
        continue;
      }
      // "PENDING" is refused explicitly: it is what a placeholder looks like, and a placeholder in
      // this field is a gate recorded as proven by nothing.
      expect(provenBy?.run, `${gate.workflow} has no recorded drill run — dispatch \`gh workflow run "<name>" -f liveness_drill=true\` and record it`).toMatch(/^https:\/\/github\.com\/.+\/actions\/runs\/\d+$/);
      expect(provenBy?.at, `${gate.workflow} provenBy.at`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it("binds the two newly retired hatches to their exact main liveness drills", () => {
    const accepted = {
      ".github/workflows/supervised-declines.yml": "33033969989",
      ".github/workflows/genai-census.yml": "33033974828",
    } as const;
    for (const [workflow, run] of Object.entries(accepted)) {
      expect(registry.gates.find((gate) => gate.workflow === workflow)?.provenBy).toEqual({
        run: `https://github.com/jharvieux/Harvey/actions/runs/${run}`,
        at: "2026-08-27",
      });
    }
  });

  // The liveness drill deliberately fails the job; the alert path fires on a workflow_dispatch
  // failure. Wired naively, DRILLING THE GUARD OPENS A REAL ALARM — #1586's criterion 4 sat
  // unproven for exactly that reason. Each drill must switch the other's machinery off.
  it("a liveness drill cannot open a real alert issue", () => {
    for (const gate of registry.gates) {
      const yml = text(gate.workflow);
      const alertConditions = yml
        .split("\n")
        .filter((l) => /^\s*if:.*failure\(\)/.test(l) && /workflow_dispatch/.test(l));
      for (const c of alertConditions) {
        expect(c, `${gate.workflow}: an alert step reachable on a liveness drill would raise a false alarm`).toContain("!inputs.liveness_drill");
      }
    }
  });

  it("the assert step runs on always(), or a job that died in setup would skip the thing that names it", () => {
    for (const gate of registry.gates) {
      const yml = readFileSync(join(REPO_ROOT, gate.workflow), "utf8");
      const assertBlocks = yml.split("mode: assert").slice(0, -1);
      expect(assertBlocks.length, `${gate.workflow} has a gate-liveness assert`).toBeGreaterThan(0);
      for (const before of assertBlocks) {
        const ifLine = before.split("\n").reverse().find((l) => l.trim().startsWith("if:")) ?? "";
        expect(ifLine, `${gate.workflow}: assert step gated on always()`).toContain("always()");
      }
    }
  });
});
