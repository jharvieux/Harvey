import { describe, expect, it } from "vitest";
import { NOT_SCORED, SCORED_GATES, checkScoredGates, discoverValidateClis, type GateInputs, type ScoredGate } from "./scored-gates.js";
import { loadGateInputs } from "./cli/validate-scored-gates.js";

const REAL = loadGateInputs();

function inputs(over: Partial<GateInputs> = {}): GateInputs {
  return {
    discovered: ["validate-x"],
    scripts: { "validate:x": "tsx src/cli/validate-x.ts", verify: "pnpm typecheck && pnpm validate:x" },
    workflows: { ".github/workflows/ci.yml": "run: pnpm exec tsx src/cli/validate-x.ts" },
    ...over,
  };
}

const gate = (over: Partial<ScoredGate> = {}): ScoredGate[] => [
  { id: "validate-x", script: "validate:x", measures: "x recall", cadence: { kind: "verify" }, ...over },
];

describe("#1288 — the scored gates still have the cadence they claim", () => {
  // This is the whole point: not that the wiring is correct today (a diff shows that), but that
  // removing it later turns this test red. #1288 found five scored gates running nowhere.
  it("passes against the real repo", () => {
    expect(checkScoredGates(REAL)).toEqual([]);
  });

  it("names a real CLI for every registered gate, and a classification for every discovered CLI", () => {
    // Guards the discovery half against the registry drifting apart from src/cli in either
    // direction — checkScoredGates reports both, so assert it sees the real filesystem.
    expect(REAL.discovered.length).toBeGreaterThan(SCORED_GATES.length);
    for (const g of SCORED_GATES) expect(REAL.discovered).toContain(g.id);
    for (const n of NOT_SCORED) expect(REAL.discovered).toContain(n.id);
  });

  it("fails when a gate has no package.json script — the state #1288 found four of", () => {
    const v = checkScoredGates(inputs({ scripts: { verify: "pnpm validate:x" } }), gate());
    expect(v.join("\n")).toContain('no package.json script "validate:x"');
  });

  it("fails when the script exists but does not invoke the gate's own CLI", () => {
    const v = checkScoredGates(inputs({ scripts: { "validate:x": "tsx src/cli/something-else.ts", verify: "pnpm validate:x" } }), gate());
    expect(v.join("\n")).toContain("does not invoke src/cli/validate-x.ts");
  });

  it("fails when a `verify` cadence is claimed but the verify chain does not run it", () => {
    const v = checkScoredGates(inputs({ scripts: { "validate:x": "tsx src/cli/validate-x.ts", verify: "pnpm typecheck" } }), gate());
    expect(v.join("\n")).toContain("does not run `pnpm validate:x`");
  });

  // `verify: "pnpm validate:x-ray"` must not satisfy a gate whose script is `validate:x` — a
  // substring match would let a renamed script keep a stale gate's cadence looking alive.
  it("does not accept a longer script name that merely starts with the gate's", () => {
    const v = checkScoredGates(inputs({ scripts: { "validate:x": "tsx src/cli/validate-x.ts", verify: "pnpm validate:x-ray" } }), gate());
    expect(v.join("\n")).toContain("does not run `pnpm validate:x`");
  });

  it("fails when the workflow that claims the cadence no longer invokes the CLI", () => {
    const v = checkScoredGates(
      inputs({ workflows: { ".github/workflows/ci.yml": "run: pnpm test" } }),
      gate({ cadence: { kind: "workflow", file: ".github/workflows/ci.yml", job: "heavy-cli shard 1" } }),
    );
    expect(v.join("\n")).toContain("never invokes src/cli/validate-x.ts");
  });

  it("fails when a new validate-* CLI is classified nowhere", () => {
    const v = checkScoredGates(inputs({ discovered: ["validate-x", "validate-brand-new-recall"] }), gate());
    expect(v.join("\n")).toContain("validate-brand-new-recall: src/cli/validate-brand-new-recall.ts is not classified");
  });

  it("fails on a stale registry row whose CLI has been deleted", () => {
    const v = checkScoredGates(inputs({ discovered: [] }), gate());
    expect(v.join("\n")).toContain("stale row");
  });

  it("requires a gate with no cadence to name the issue tracking it", () => {
    const v = checkScoredGates(inputs(), gate({ cadence: { kind: "none", issue: 0 } }));
    expect(v.join("\n")).toContain("names no tracking issue");
  });

  it("discovers validate-* CLIs and excludes their test files", () => {
    const ids = discoverValidateClis(new URL("./cli/", import.meta.url).pathname);
    expect(ids).toContain("validate-reasons");
    expect(ids.some((id) => id.endsWith(".test"))).toBe(false);
  });
});
