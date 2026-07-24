// #935 — the deliverable-at-volume rules (report-template/rollup.mjs). Measured motivation: one
// target (crbnos/carbon) produced 8,027 counted findings — 3,251 of them one M4 shape — and a
// one-card-per-finding report stops being a deliverable at that volume. These tests pin the two
// invariants the rollup must never lose:
//   1. CONSERVATION — every finding appears exactly once across singles + representatives +
//      withheld. A rollup that drops a finding is the coverage guard's failure mode wearing a UI.
//   2. DISCLOSED CAPS — whatever is not individually rendered is counted in the output
//      (group.count = shown + withheld; capActionPlan returns the withheld number).

import { describe, expect, it } from "vitest";
import {
  ACTION_PLAN_MAX_ROWS,
  capActionPlan,
  ROLLUP_REPRESENTATIVES,
  ROLLUP_THRESHOLD,
  rollupFindings,
  type RollupGroup,
  type RollupItem,
} from "../report-template/rollup.mjs";

interface F {
  id: string;
  taxonomy: string;
  severity: string;
  category: string;
}

const make = (taxonomy: string, severity: string, n: number, prefix = taxonomy): F[] =>
  Array.from({ length: n }, (_, i) => ({ id: `${prefix}-${severity}-${i + 1}`, taxonomy, severity, category: "Maintainability" }));

const flatten = (items: RollupItem<F>[]): F[] =>
  items.flatMap((x) => (x.kind === "finding" ? [x.finding] : [...x.representatives, ...x.withheld]));

describe("rollupFindings (#935)", () => {
  it("leaves shapes at or below the threshold untouched, in order", () => {
    const input = [...make("M4 — Duplication", "Medium", ROLLUP_THRESHOLD), ...make("M7 — N+1", "Low", 2)];
    const items = rollupFindings(input);
    expect(items.every((x) => x.kind === "finding")).toBe(true);
    expect(flatten(items).map((f) => f.id)).toEqual(input.map((f) => f.id));
  });

  it("rolls a shape above the threshold into ONE group whose count equals shown + withheld", () => {
    const items = rollupFindings(make("M4 — Duplication", "Low", ROLLUP_THRESHOLD + 1));
    expect(items).toHaveLength(1);
    const g = items[0] as RollupGroup<F>;
    expect(g.kind).toBe("group");
    expect(g.count).toBe(ROLLUP_THRESHOLD + 1);
    expect(g.representatives).toHaveLength(ROLLUP_REPRESENTATIVES);
    expect(g.withheld).toHaveLength(g.count - ROLLUP_REPRESENTATIVES);
  });

  it("emits the group at its first (highest-ranked) member's position and keeps its sort order", () => {
    const big = make("M5 — Single-use helper", "Low", 40);
    const input = [{ id: "lead", taxonomy: "M1 — Leaked key", severity: "Critical", category: "Secret exposure" }, big[0]!, { id: "tail", taxonomy: "M9 — Waterfall", severity: "Medium", category: "Rendering" }, ...big.slice(1)];
    const items = rollupFindings(input);
    expect(items.map((x) => (x.kind === "group" ? "group" : x.finding.id))).toEqual(["lead", "group", "tail"]);
    const g = items[1] as RollupGroup<F>;
    // Representatives are the group's first members in the caller's (already-ranked) order.
    expect(g.representatives.map((f) => f.id)).toEqual(big.slice(0, ROLLUP_REPRESENTATIVES).map((f) => f.id));
  });

  it("same taxonomy at different severities are different shapes — a Medium vein never buries a Critical one", () => {
    const input = [...make("M4 — Duplication", "Medium", 30), ...make("M4 — Duplication", "Critical", 2)];
    const items = rollupFindings(input);
    const groups = items.filter((x): x is RollupGroup<F> => x.kind === "group");
    expect(groups).toHaveLength(1);
    expect(groups[0]?.severity).toBe("Medium");
    expect(items.filter((x) => x.kind === "finding")).toHaveLength(2);
  });

  it("CONSERVATION at carbon scale — 8k findings across mixed shapes, every one present exactly once", () => {
    // The measured carbon mix, order of magnitude: one huge M4 shape, a huge M5 shape, a mid M7
    // shape, and a tail of small shapes.
    const input = [
      ...make("M4 — Duplication", "Low", 3251),
      ...make("M5 — Slop / dead code", "Low", 2773),
      ...make("M5 — Single-use helper", "Low", 1125),
      ...make("M7 — Await in loop (N+1)", "Perf", 673),
      ...make("M8 — Call-count-only test", "Medium", 3),
      ...make("M6 — Indicator: currency formatting", "Info", 5),
    ];
    const items = rollupFindings(input);
    // The deliverable shrinks to a handful of items…
    expect(items.length).toBeLessThan(30);
    // …but the data does not: exact multiset identity with the input.
    expect(flatten(items).map((f) => f.id).sort()).toEqual(input.map((f) => f.id).sort());
    // And every disclosed count is arithmetic over what is actually carried.
    for (const g of items.filter((x): x is RollupGroup<F> => x.kind === "group")) {
      expect(g.count).toBe(g.representatives.length + g.withheld.length);
    }
  });
});

describe("capActionPlan (#935)", () => {
  it("under the cap: unchanged, nothing withheld", () => {
    const actions = make("M1 — Leaked key", "Critical", 3);
    expect(capActionPlan(actions)).toEqual({ shown: actions, withheldCount: 0 });
  });

  it("over the cap: exactly the cap shown, the remainder COUNTED — a cap must state what it capped", () => {
    const actions = make("M9 — Route action missing validation", "High", ACTION_PLAN_MAX_ROWS + 26);
    const { shown, withheldCount } = capActionPlan(actions);
    expect(shown).toHaveLength(ACTION_PLAN_MAX_ROWS);
    expect(withheldCount).toBe(26);
    expect(shown).toEqual(actions.slice(0, ACTION_PLAN_MAX_ROWS));
  });
});
