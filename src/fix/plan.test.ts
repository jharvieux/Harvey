import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { screenFinding, type ScreenOptions } from "./plan.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    title: "Unchecked mutation",
    severity: "Medium",
    confidence: "Confirmed",
    category: "Data integrity",
    taxonomy: "D-091 #3",
    location: "apps/main/src/actions/save.ts",
    status: "Open",
    evidence: "await supabase.from('x').update(...) with the { error } ignored",
    impact: "Silent write failures",
    fix: "Handle the returned error",
    value: 4,
    ease: 5,
    safety: 5,
    ...overrides,
  };
}

const opts: ScreenOptions = { enabledCategories: ["Data integrity", "Security"] };

describe("screenFinding", () => {
  it("routes a confirmed, high-ease, high-safety, enabled finding to the auto path at cheap tier", () => {
    expect(screenFinding(makeFinding(), opts)).toEqual({ mode: "auto", tier: "cheap" });
  });

  it("downgrades Review/N-A confidence to recommend-only — those are never auto-fixed", () => {
    const s = screenFinding(makeFinding({ confidence: "Review" }), opts);
    expect(s.mode).toBe("recommend-only");
    expect(s.reason).toContain("confidence");
  });

  it("downgrades a finding whose category the engagement did not enable", () => {
    const s = screenFinding(makeFinding({ category: "Performance" }), opts);
    expect(s.mode).toBe("recommend-only");
    expect(s.reason).toContain("category");
  });

  it("routes low ease/safety to manual — a plan is drafted but no subagent writes code", () => {
    expect(screenFinding(makeFinding({ ease: 2 }), opts).mode).toBe("manual");
    expect(screenFinding(makeFinding({ safety: 3 }), opts).mode).toBe("manual");
  });

  it("escalates Critical/High severity from cheap to standard tier", () => {
    expect(screenFinding(makeFinding({ severity: "High" }), opts).tier).toBe("standard");
    expect(screenFinding(makeFinding({ severity: "Critical" }), opts).tier).toBe("standard");
  });

  it("escalates on sensitive keywords in the finding text", () => {
    expect(screenFinding(makeFinding({ evidence: "missing replay protection in the stripe webhook" }), opts).tier).toBe(
      "standard",
    );
  });

  it("escalates when the location sits under an engagement-configured sensitive path", () => {
    const s = screenFinding(makeFinding({ location: "apps/main/src/auth/session.ts" }), {
      ...opts,
      sensitivePaths: ["apps/main/src/auth/"],
    });
    expect(s.tier).toBe("standard");
  });
});
