import { describe, expect, it } from "vitest";
import { buildExecutionPlan, formatExecutionPlan } from "./audit-plan.js";
import type { EngagementEnv } from "./audit-coverage.js";

const env = (over: Partial<EngagementEnv> = {}): EngagementEnv => ({ connected: false, dynamic: false, llm: false, ...over });

// The dependency #502 exists to protect: M3 must precede the M1 focus brief, which must precede the
// M1 semantic pass. The plan is worthless if it lets those run in the wrong order.
const orderOf = (label: string, labels: string[]) => labels.indexOf(label);

describe("buildExecutionPlan sequences M3 → scan-focus → M1 semantic (#502)", () => {
  it("puts M3 vitals before the M1 focus brief, and the brief before the semantic pass", () => {
    const labels = buildExecutionPlan(env({ llm: true })).map((s) => s.label);
    expect(orderOf("M3 vitals (hotspot ranking)", labels)).toBeLessThan(orderOf("M1 semantic focus brief", labels));
    expect(orderOf("M1 semantic focus brief", labels)).toBeLessThan(orderOf("M1 semantic (/vuln-scan → /triage)", labels));
  });

  it("marks the focus brief as depending on M3, and the semantic pass on the brief", () => {
    const steps = buildExecutionPlan(env({ llm: true }));
    expect(steps.find((s) => s.label === "M1 semantic focus brief")?.dependsOn).toBe("M3 vitals (hotspot ranking)");
    expect(steps.find((s) => s.label === "M1 semantic (/vuln-scan → /triage)")?.dependsOn).toBe("M1 semantic focus brief");
  });

  it("omits the LLM chain when the paid tier is not in scope, but always plans M3", () => {
    const labels = buildExecutionPlan(env()).map((s) => s.label);
    expect(labels).toContain("M3 vitals (hotspot ranking)");
    expect(labels).not.toContain("M1 semantic (/vuln-scan → /triage)");
  });

  it("adds the dynamic and connected passes only when their env is present", () => {
    const labels = buildExecutionPlan(env({ dynamic: true, connected: true })).map((s) => s.label);
    expect(labels).toContain("M2 dynamic pen-test");
    expect(labels).toContain("M7 advisors (per DB)");
    expect(labels).toContain("M10 live classification");
  });
});

describe("formatExecutionPlan", () => {
  it("renders the dependency of a gated step so an operator sees what blocks it", () => {
    const out = formatExecutionPlan(buildExecutionPlan(env({ llm: true })));
    expect(out).toMatch(/runs after: M3 vitals \(hotspot ranking\)/);
    expect(out).toMatch(/do NOT start before its output exists/);
  });
});
