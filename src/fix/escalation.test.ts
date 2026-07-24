import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan, ScreenOptions } from "./plan.js";
import { initialTier, MAX_ATTEMPTS_PER_TIER, planningTriggers, plansDisagree, runEscalation } from "./escalation.js";

function plan(o: Partial<FixPlan> = {}): FixPlan {
  return {
    findingId: "F-1",
    severity: "Medium",
    category: "Data integrity",
    mode: "auto",
    detectorId: "d",
    approach: "Handle the ignored error.",
    blastRadius: { files: ["src/a.ts"], createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 0 },
    verifyCommands: [],
    testPlan: "",
    tier: "cheap",
    risks: [],
    ...o,
  };
}

function finding(o: Partial<Finding> = {}): Finding {
  return {
    id: "F-1", title: "t", severity: "Medium", confidence: "Confirmed", category: "Data integrity",
    taxonomy: "d", location: "apps/main/src/x.ts", status: "Open", evidence: "e", impact: "i", fix: "f",
    value: 4, ease: 5, safety: 5, ...o,
  };
}

const opts: ScreenOptions = { enabledCategories: ["Data integrity"] };

describe("plansDisagree", () => {
  it("agrees when file set and approach match", () => {
    expect(plansDisagree(plan(), plan())).toBe(false);
  });
  it("disagrees on a different file set", () => {
    expect(plansDisagree(plan(), plan({ blastRadius: { ...plan().blastRadius, files: ["src/b.ts"] } }))).toBe(true);
  });
  it("disagrees on a materially different approach", () => {
    expect(plansDisagree(plan(), plan({ approach: "Rewrite the whole handler." }))).toBe(true);
  });
  it("ignores whitespace/case noise between the two approaches", () => {
    expect(plansDisagree(plan(), plan({ approach: "  handle the IGNORED error.  " }))).toBe(false);
  });
});

describe("planningTriggers", () => {
  it("fires on Critical/High severity", () => {
    expect(planningTriggers(finding({ severity: "High" }), opts)).toContain("critical-or-high-severity");
  });
  it("fires on a sensitive keyword", () => {
    expect(planningTriggers(finding({ evidence: "stripe webhook replay" }), opts)).toContain("sensitive-path-or-keyword");
  });
  it("fires on plan self-disagreement when threaded in", () => {
    expect(planningTriggers(finding(), opts, true)).toContain("plan-self-disagreement");
  });
  it("is empty for a plain mechanical finding", () => {
    expect(planningTriggers(finding(), opts)).toEqual([]);
  });
});

describe("initialTier", () => {
  it("stays at the screened tier with no triggers", () => {
    expect(initialTier("cheap", [])).toBe("cheap");
  });
  it("bumps to standard on a single trigger", () => {
    expect(initialTier("cheap", ["critical-or-high-severity"])).toBe("standard");
  });
  it("bumps to flagship on two or more triggers", () => {
    expect(initialTier("cheap", ["critical-or-high-severity", "sensitive-path-or-keyword"])).toBe("flagship");
  });
});

describe("runEscalation", () => {
  it("records a single tier when the cheap attempt verifies first try", () => {
    const r = runEscalation("cheap", [], () => true);
    expect(r).toEqual({ tiersUsed: ["cheap"], outcome: "implementable" });
  });

  it("records more than one tier when a verification failure escalates cheap → standard", () => {
    let calls = 0;
    // fail both cheap attempts, then pass at standard
    const r = runEscalation("cheap", [], () => ++calls > MAX_ATTEMPTS_PER_TIER);
    expect(r.tiersUsed).toEqual(["cheap", "standard"]);
    expect(r.outcome).toBe("implementable");
  });

  it("starts at standard (observable second tier) when a planning trigger fired", () => {
    const r = runEscalation("cheap", ["critical-or-high-severity"], () => true);
    expect(r.tiersUsed).toEqual(["standard"]);
  });

  it("downgrades and names the verification-failure trigger when standard is exhausted", () => {
    const r = runEscalation("cheap", [], () => false);
    expect(r.outcome).toBe("downgrade");
    expect(r.tiersUsed).toEqual(["cheap", "standard"]);
    expect(r.downgradeReason).toContain("verification-failure");
    expect(r.downgradeReason).toContain("standard");
  });

  it("does not retry below flagship in Phase 1 — a ≥2-trigger fix that fails downgrades", () => {
    const r = runEscalation("cheap", ["critical-or-high-severity", "sensitive-path-or-keyword"], () => false);
    expect(r.tiersUsed).toEqual(["flagship"]);
    expect(r.outcome).toBe("downgrade");
  });

  it("caps attempts per tier at MAX_ATTEMPTS_PER_TIER", () => {
    let calls = 0;
    runEscalation("cheap", [], () => {
      calls++;
      return false;
    });
    expect(calls).toBe(MAX_ATTEMPTS_PER_TIER * 2); // cheap ×2 then standard ×2, then downgrade
  });
});
