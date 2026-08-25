import { describe, expect, it } from "vitest";
import { NOT_SCORED, SCORED_GATES, checkScoredGates, discoverValidateClis, loadGateInputs, type GateInputs, type ScoredGate } from "./scored-gates.js";

const REAL = loadGateInputs();

function inputs(over: Partial<GateInputs> = {}): GateInputs {
  return {
    discovered: ["validate-x"],
    scripts: { "validate:x": "tsx src/cli/validate-x.ts", verify: "pnpm typecheck && pnpm validate:x" },
    workflows: { ".github/workflows/ci.yml": "run: pnpm exec tsx src/cli/validate-x.ts" },
    lightTests: ["src/detectors/m9-taxonomy-docs.test.ts"],
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
      gate({ cadence: { kind: "workflow", file: ".github/workflows/ci.yml", job: "heavy-cli planned slot", when: "every code PR + daily schedule" } }),
    );
    expect(v.join("\n")).toContain("there invokes src/cli/validate-x.ts");
  });

  it("fails when a new validate-* CLI is classified nowhere", () => {
    const v = checkScoredGates(inputs({ discovered: ["validate-x", "validate-brand-new-recall"] }), gate());
    expect(v.join("\n")).toContain("validate-brand-new-recall: src/cli/validate-brand-new-recall.ts is not classified");
  });

  it("fails on a stale registry row whose CLI has been deleted", () => {
    const v = checkScoredGates(inputs({ discovered: [] }), gate());
    expect(v.join("\n")).toContain("stale row");
  });

  it("fails when a structural gate's standing test leaves light-suite discovery", () => {
    const structural = [{ id: "validate-x", why: "structural", verificationTest: "src/x.test.ts" }];
    const v = checkScoredGates(inputs({ lightTests: [] }), [], structural, []);
    expect(v.join("\n")).toContain("src/x.test.ts as its pnpm verify cadence, but that file is absent from light-suite discovery");
  });

  it("requires a gate with no cadence to name the issue tracking it", () => {
    const v = checkScoredGates(inputs(), gate({ cadence: { kind: "none", issue: 0 } }));
    expect(v.join("\n")).toContain("names no tracking issue");
  });

  // #1270's substitute: a gate whose score has no cadence may name a workflow that watches its
  // STALENESS instead. That claim needs the same failing direction the `workflow` cadence has —
  // otherwise a deleted alarm leaves the row still printing "its staleness is alarmed by".
  it("fails when the named staleness alarm no longer exists", () => {
    const cadence = { kind: "none", issue: 1270, alarmedBy: { file: ".github/workflows/gone.yml", when: "daily" } } as const;
    expect(checkScoredGates(inputs(), gate({ cadence })).join("\n")).toContain("as its staleness alarm, and that workflow does not exist");
  });

  it("accepts a staleness alarm that does exist, so the check above is not simply always-on", () => {
    const cadence = { kind: "none", issue: 1270, alarmedBy: { file: ".github/workflows/ci.yml", when: "daily" } } as const;
    // The synthetic `inputs()` discovers only validate-x, so every NOT_SCORED row reports stale here
    // by construction; the assertion is scoped to the staleness-alarm violation this pair is about.
    expect(checkScoredGates(inputs(), gate({ cadence })).join("\n")).not.toContain("as its staleness alarm");
  });

  // #1691 — MEASURED 2026-07-31: a workflow naming the CLI ONLY in its PR-trigger `paths:` filter
  // satisfied the cadence check, so deleting the invocation left this gate green. A path filter says
  // which diffs START the job; it never says the job runs the tool.
  it("REFUSES a cadence evidenced only by a PR-trigger paths: filter", () => {
    const yml = ['on:', '  pull_request:', '    paths:', '      - "src/cli/validate-x.ts"', 'jobs:', '  x:', '    steps:', '      - run: echo hi'].join("\n");
    const v = checkScoredGates(inputs({ workflows: { ".github/workflows/x.yml": yml } }), gate({ cadence: { kind: "workflow", file: ".github/workflows/x.yml", job: "x", when: "PR" } }));
    expect(v.join("\n")).toContain("there invokes src/cli/validate-x.ts");
  });

  it("accepts an invocation by CLI path or by package script, so the check above is not always-on", () => {
    const base = ['on:', '  pull_request:', '    paths:', '      - "docs/**"', 'jobs:', '  x:', '    steps:'].join("\n");
    const cadence = { kind: "workflow", file: ".github/workflows/x.yml", job: "x", when: "PR" } as const;
    for (const step of ["      - run: pnpm exec tsx src/cli/validate-x.ts", "      - run: pnpm validate:x"]) {
      const v = checkScoredGates(inputs({ workflows: { ".github/workflows/x.yml": `${base}\n${step}` } }), gate({ cadence }));
      expect(v.join("\n"), step).not.toContain("there invokes src/cli/validate-x.ts");
    }
  });

  // #1702 — the same false pass the `paths:` control above removes, reached through a COMMENT. Every
  // gate step in this repo's workflows carries a long explanatory comment above it, so deleting the
  // `run:` line and leaving the comment was the cheapest way to retire a gate silently. A step
  // `name:` is the same shape: the workflow "mentions" the CLI in a position that never executes.
  it("REFUSES a cadence evidenced only by a YAML comment or a step name", () => {
    const cadence = { kind: "workflow", file: ".github/workflows/x.yml", job: "x", when: "PR" } as const;
    const cases = {
      comment: ["jobs:", "  x:", "    steps:", "      # was: pnpm exec tsx src/cli/validate-x.ts — removed while we chase a flake", "      - run: echo hi"],
      "step name": ["jobs:", "  x:", "    steps:", "      - name: run src/cli/validate-x.ts", "        run: echo hi"],
      "trailing comment on a live step": ["jobs:", "  x:", "    steps:", "      - run: echo hi # replaces pnpm validate:x"],
    };
    for (const [label, lines] of Object.entries(cases)) {
      const v = checkScoredGates(inputs({ workflows: { ".github/workflows/x.yml": lines.join("\n") } }), gate({ cadence }));
      expect(v.join("\n"), label).toContain("there invokes src/cli/validate-x.ts");
    }
  });

  // The other direction for the same extraction: a `uses:` value and a `with:` input are executable
  // positions too, so narrowing to `run:` alone would have made this check fail on a live cadence.
  it("accepts an invocation in a uses: value or a with: input", () => {
    const cadence = { kind: "workflow", file: ".github/workflows/x.yml", job: "x", when: "PR" } as const;
    for (const lines of [
      ["jobs:", "  x:", "    steps:", "      - uses: ./.github/actions/run-cli", "        with:", "          cmd: pnpm exec tsx src/cli/validate-x.ts"],
      ["jobs:", "  x:", "    steps:", "      - run: |", "          set -e", "          pnpm validate:x"],
    ]) {
      const v = checkScoredGates(inputs({ workflows: { ".github/workflows/x.yml": lines.join("\n") } }), gate({ cadence }));
      expect(v.join("\n"), lines.join("\n")).not.toContain("there invokes src/cli/validate-x.ts");
    }
  });

  // A venue that fails to parse is not a venue that passed. Falling back to a raw text match here
  // would reintroduce exactly the hole above on any workflow with a YAML error.
  it("refuses a workflow that does not parse rather than falling back to a text match", () => {
    const cadence = { kind: "workflow", file: ".github/workflows/x.yml", job: "x", when: "PR" } as const;
    const broken = "jobs:\n  x:\n    steps:\n      - run: pnpm exec tsx src/cli/validate-x.ts\n  : : :\n";
    const v = checkScoredGates(inputs({ workflows: { ".github/workflows/x.yml": broken } }), gate({ cadence }));
    expect(v.join("\n")).toContain("does not parse as YAML");
  });

  // #1691's disclosure row: a measured-number CLI outside the `validate-*` discovery predicate is
  // named rather than skipped, and held to the SAME cadence check — which makes it a disclosure.
  it("holds a MEASURED_OUTSIDE_DISCOVERY row to the cadence check", () => {
    const outside: ScoredGate[] = [{ id: "some-census", script: "some-census", measures: "a population", cadence: { kind: "workflow", file: ".github/workflows/gone.yml", job: "c", when: "monthly" } }];
    expect(checkScoredGates(inputs(), gate(), NOT_SCORED, outside).join("\n")).toContain("some-census: declares cadence in .github/workflows/gone.yml, which does not exist");
  });

  it("discovers validate-* CLIs and excludes their test files", () => {
    const ids = discoverValidateClis(new URL("./cli/", import.meta.url).pathname);
    expect(ids).toContain("validate-reasons");
    expect(ids.some((id) => id.endsWith(".test"))).toBe(false);
  });
});
