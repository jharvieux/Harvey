import { describe, expect, it } from "vitest";
import { assembleHandoff, type FixOutcomeSummary } from "./handoff.js";

const outcome = (o: Partial<FixOutcomeSummary> & Pick<FixOutcomeSummary, "findingId" | "status">): FixOutcomeSummary => ({
  severity: "Medium",
  bftb: 50,
  files: [],
  ...o,
});

describe("assembleHandoff", () => {
  it("lists EVERY approved finding as a row — delivered, downgraded, or blocked", () => {
    const h = assembleHandoff({
      client: "Acme",
      baselineCommit: "abc",
      outcomes: [
        outcome({ findingId: "F-1", status: "verified-inert", files: ["src/a.ts"] }),
        outcome({ findingId: "F-2", status: "recommend-only", reason: "needs a migration" }),
        outcome({ findingId: "F-3", status: "rails-blocked", reason: "denylisted path" }),
        outcome({ findingId: "F-4", status: "manual", reason: "ease/safety below threshold" }),
      ],
    });
    expect(h.rows.map((r) => r.findingId).sort()).toEqual(["F-1", "F-2", "F-3", "F-4"]);
  });

  it("keeps a downgraded fix as a row WITH its reason — never a silent omission", () => {
    const h = assembleHandoff({
      client: "Acme",
      baselineCommit: "abc",
      outcomes: [outcome({ findingId: "F-2", status: "recommend-only", reason: "needs client DBA review" })],
    });
    const row = h.rows.find((r) => r.findingId === "F-2");
    expect(row?.reason).toBe("needs client DBA review");
  });

  it("assigns a merge rank only to deliverable fixes, in severity-then-BFTB order", () => {
    const h = assembleHandoff({
      client: "Acme",
      baselineCommit: "abc",
      outcomes: [
        outcome({ findingId: "low", status: "verified-inert", severity: "Low", files: ["src/x.ts"] }),
        outcome({ findingId: "crit", status: "verified-inert", severity: "Critical", files: ["src/y.ts"] }),
        outcome({ findingId: "rec", status: "recommend-only", reason: "downgraded" }),
      ],
    });
    expect(h.mergeOrder.order).toEqual(["crit", "low"]);
    expect(h.rows.find((r) => r.findingId === "crit")?.mergeRank).toBe(1);
    expect(h.rows.find((r) => r.findingId === "low")?.mergeRank).toBe(2);
    expect(h.rows.find((r) => r.findingId === "rec")?.mergeRank).toBeUndefined();
  });

  it("emits a merge-order note when two delivered fixes touch the same file", () => {
    const h = assembleHandoff({
      client: "Acme",
      baselineCommit: "abc",
      outcomes: [
        outcome({ findingId: "crit", status: "verified-inert", severity: "Critical", files: ["src/shared.ts"] }),
        outcome({ findingId: "low", status: "verified-inert", severity: "Low", files: ["src/shared.ts"] }),
      ],
    });
    expect(h.mergeOrder.notes).toHaveLength(1);
    expect(h.mergeOrder.notes[0]).toContain("merge crit first");
  });

  it("records not-approved findings as their own transparency rows", () => {
    const h = assembleHandoff({ client: "Acme", baselineCommit: "abc", outcomes: [], notApproved: ["F-9"] });
    expect(h.rows).toEqual([
      { findingId: "F-9", status: "not-approved", reason: "present in findings but not client-approved for this engagement" },
    ]);
  });
});
