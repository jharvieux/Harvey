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
import { readNamesSafe } from "./fs-walk.js";
import { recordMeasured } from "./ci-liveness.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, ".github", "actions", "gate-liveness", "gate-liveness.sh");
const WORKFLOWS = join(REPO_ROOT, ".github", "workflows");

interface Registry {
  gates: { workflow: string; expect: string[]; note: string }[];
  exempt: { workflow: string; reason: string }[];
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
  // A job heavy enough to install the scanner binaries is a job that can die in setup, which is the
  // #1509 shape exactly. Comment lines are excluded: site-smoke.yml only MENTIONS the action.
  const heavyWorkflows = readNamesSafe(WORKFLOWS)
    .filter((f) => f.endsWith(".yml"))
    .filter((f) => /^\s*(- )?uses:\s*\.\/\.github\/actions\/mechanical-binaries\s*$/m.test(readFileSync(join(WORKFLOWS, f), "utf8")))
    .map((f) => `.github/workflows/${f}`);

  it("every workflow that installs the mechanical binaries is registered or exempt with a reason", () => {
    const known = new Set([...registry.gates.map((g) => g.workflow), ...registry.exempt.map((e) => e.workflow)]);
    expect(heavyWorkflows.length).toBeGreaterThan(0);
    expect(heavyWorkflows.filter((w) => !known.has(w))).toEqual([]);
    for (const e of registry.exempt) expect(e.reason.trim().length).toBeGreaterThan(40);
  });

  it("every registered gate id is BOTH asserted by its workflow and produced by something", () => {
    const producers = readNamesSafe(join(REPO_ROOT, "src", "cli"))
      .filter((f) => f.endsWith(".ts"))
      .map((f) => readFileSync(join(REPO_ROOT, "src", "cli", f), "utf8"))
      .join("\n");
    for (const gate of registry.gates) {
      const yml = readFileSync(join(REPO_ROOT, gate.workflow), "utf8");
      const asserted = yml.match(/^\s*expect:.*$/gm)?.join("\n") ?? "";
      const recorded = yml.match(/^\s*gate:.*$/gm)?.join("\n") ?? "";
      for (const id of gate.expect) {
        expect(asserted, `${gate.workflow} asserts ${id}`).toContain(id);
        expect(recorded.includes(id) || producers.includes(`recordMeasured("${id}"`), `${gate.workflow}: ${id} is produced by a record step or a gate CLI`).toBe(true);
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
