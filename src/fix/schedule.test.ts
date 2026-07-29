import { describe, expect, it } from "vitest";
import type { Severity } from "../findings.js";
import {
  DEFAULT_CAPS,
  detectLateConflict,
  emitMergeOrder,
  runScheduled,
  scheduleFixes,
  type ScheduleNode,
} from "./schedule.js";

const node = (findingId: string, files: string[], severity: Severity = "Medium", bftb = 50): ScheduleNode => ({
  findingId,
  severity,
  bftb,
  files,
});

describe("scheduleFixes — the real caller of batch()", () => {
  it("serializes two fixes whose diffs touch the SAME file into one component", () => {
    const comps = scheduleFixes([node("A", ["src/a.ts"]), node("B", ["src/a.ts", "src/b.ts"])]);
    expect(comps).toHaveLength(1);
    expect(comps[0]!.findingIds.sort()).toEqual(["A", "B"]);
  });

  it("runs two fixes whose diffs do NOT overlap as independent components (parallel-eligible)", () => {
    const comps = scheduleFixes([node("A", ["src/a.ts"]), node("B", ["src/b.ts"])]);
    expect(comps).toHaveLength(2);
    expect(comps.every((c) => c.findingIds.length === 1)).toBe(true);
  });

  it("orders within a component by severity desc then BFTB desc", () => {
    const comps = scheduleFixes([
      node("low", ["src/x.ts"], "Low", 90),
      node("crit", ["src/x.ts"], "Critical", 10),
      node("med", ["src/x.ts"], "Medium", 99),
    ]);
    expect(comps[0]!.findingIds).toEqual(["crit", "med", "low"]);
  });

  it("orders components by highest contained severity first", () => {
    const comps = scheduleFixes([
      node("a", ["src/a.ts"], "Low"),
      node("b", ["src/b.ts"], "Critical"),
      node("c", ["src/c.ts"], "Medium"),
    ]);
    expect(comps.map((c) => c.topSeverity)).toEqual(["Critical", "Medium", "Low"]);
  });
});

describe("emitMergeOrder", () => {
  it("emits a merge-first note wherever two fixes in a component share a file", () => {
    const nodes = [node("crit", ["src/shared.ts"], "Critical"), node("low", ["src/shared.ts"], "Low")];
    const mo = emitMergeOrder(scheduleFixes(nodes), nodes);
    expect(mo.order).toEqual(["crit", "low"]);
    expect(mo.notes).toHaveLength(1);
    expect(mo.notes[0]).toContain("merge crit first");
    expect(mo.notes[0]).toContain("src/shared.ts");
  });

  it("emits no note for independent fixes", () => {
    const nodes = [node("a", ["src/a.ts"]), node("b", ["src/b.ts"])];
    expect(emitMergeOrder(scheduleFixes(nodes), nodes).notes).toEqual([]);
  });
});

describe("detectLateConflict — the pre-push dynamic check", () => {
  it("flags overlap with an already-pushed branch and names the shared file", () => {
    const conflicts = detectLateConflict(
      ["src/new.ts", "src/a.ts"],
      [{ findingId: "A", changedFiles: ["src/a.ts"] }, { findingId: "B", changedFiles: ["src/b.ts"] }],
    );
    expect(conflicts).toEqual([{ findingId: "A", files: ["src/a.ts"] }]);
  });

  it("returns nothing when a fix's changed files are disjoint from every pushed branch", () => {
    expect(detectLateConflict(["src/x.ts"], [{ findingId: "A", changedFiles: ["src/a.ts"] }])).toEqual([]);
  });
});

describe("runScheduled — concurrency caps are enforced, not documented", () => {
  it("never exceeds maxSlots concurrent workers", async () => {
    let live = 0;
    let peak = 0;
    const comps = scheduleFixes(Array.from({ length: 12 }, (_, i) => node(`F${i}`, [`src/${i}.ts`])));
    await runScheduled(
      comps,
      async () => {
        live++;
        peak = Math.max(peak, live);
        await new Promise((r) => setTimeout(r, 5));
        live--;
        return null;
      },
      { maxSlots: 3, maxClientChecks: 2 },
    );
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1); // it really did overlap — not accidentally serial
  });

  it("holds full client-check runs under maxClientChecks even while more workers overlap", async () => {
    let checksLive = 0;
    let checksPeak = 0;
    const comps = scheduleFixes(Array.from({ length: 8 }, (_, i) => node(`F${i}`, [`src/${i}.ts`])));
    await runScheduled(
      comps,
      async (_c, clientCheck) =>
        clientCheck(async () => {
          checksLive++;
          checksPeak = Math.max(checksPeak, checksLive);
          await new Promise((r) => setTimeout(r, 5));
          checksLive--;
        }),
      { maxSlots: 8, maxClientChecks: 2 },
    );
    expect(checksPeak).toBeLessThanOrEqual(2);
    expect(checksPeak).toBeGreaterThan(1);
  });

  it("defaults to 4 slots / 2 client-checks", () => {
    expect(DEFAULT_CAPS).toEqual({ maxSlots: 4, maxClientChecks: 2 });
  });

  // The NEGATIVE CONTROL for the two assertions above (#1272). `peak <= cap` is only evidence if it
  // can fail, and a peak measurement that never rises would satisfy it while proving nothing. Same
  // workload, same instrument, semaphore removed: the peak goes straight past the cap. So the two
  // green assertions above are held by runScheduled, not by the workload happening to be serial.
  it("the same workload WITHOUT runScheduled blows past the cap — so the cap assertions can fail", async () => {
    let live = 0;
    let peak = 0;
    const comps = scheduleFixes(Array.from({ length: 12 }, (_, i) => node(`F${i}`, [`src/${i}.ts`])));
    await Promise.all(
      comps.map(async () => {
        live++;
        peak = Math.max(peak, live);
        await new Promise((r) => setTimeout(r, 5));
        live--;
      }),
    );
    expect(peak).toBe(12);
    expect(peak).toBeGreaterThan(DEFAULT_CAPS.maxSlots);
  });
});
