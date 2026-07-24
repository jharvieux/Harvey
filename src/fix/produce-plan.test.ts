import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { checkPlanRails, type EngagementManifest } from "./pipeline.js";
import { screenFinding, type ScreenOptions } from "./plan.js";
import { deriveCallers, fileOfLocation, producePlan } from "./produce-plan.js";

function makeFinding(o: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    title: "Unchecked mutation",
    severity: "Medium",
    confidence: "Confirmed",
    category: "Data integrity",
    taxonomy: "harvey-unchecked-mutation",
    location: "apps/main/src/actions/save.ts:42",
    status: "Open",
    evidence: "await supabase.from('x').update(...) with the { error } ignored",
    impact: "Silent write failures",
    fix: "Handle the returned { error } and surface it to the caller.",
    value: 4,
    ease: 5,
    safety: 5,
    ...o,
  };
}

const opts: ScreenOptions = { enabledCategories: ["Data integrity"] };

describe("fileOfLocation", () => {
  it("strips a line (or line-range) suffix and passes through a bare path", () => {
    expect(fileOfLocation("apps/main/src/x.ts:42")).toBe("apps/main/src/x.ts");
    expect(fileOfLocation("apps/main/src/x.ts:42-58")).toBe("apps/main/src/x.ts");
    expect(fileOfLocation("apps/main/src/x.ts")).toBe("apps/main/src/x.ts");
  });
});

describe("deriveCallers", () => {
  const sources: SourceInput[] = [
    { path: "apps/main/src/actions/save.ts", text: "export function save() {}" },
    { path: "apps/main/src/page.tsx", text: "import { save } from '../actions/save';" },
    { path: "apps/main/src/other.ts", text: "import { load } from './load';" },
    { path: "apps/main/src/cjs.ts", text: "const { save } = require('./actions/save');" },
  ];

  it("finds importers of the changed module and never lists the changed file itself", () => {
    expect(deriveCallers("apps/main/src/actions/save.ts", sources)).toEqual([
      "apps/main/src/cjs.ts",
      "apps/main/src/page.tsx",
    ]);
  });

  it("does not match an unrelated module that merely shares a directory", () => {
    expect(deriveCallers("apps/main/src/load.ts", sources)).toEqual(["apps/main/src/other.ts"]);
  });
});

describe("producePlan", () => {
  const sources: SourceInput[] = [
    { path: "apps/main/src/actions/save.ts", text: "export function save() {}" },
    { path: "apps/main/src/page.tsx", text: "import { save } from '../actions/save';" },
  ];

  it("produces a plan that round-trips through checkPlanRails without hand-editing", () => {
    const finding = makeFinding();
    const screen = screenFinding(finding, opts);
    const plan = producePlan(finding, { screen, sources });

    const manifest = { allowlist: ["apps/main/src/**"] } as EngagementManifest;
    expect(checkPlanRails(plan, manifest).ok).toBe(true);

    expect(plan.findingId).toBe("F-1");
    expect(plan.mode).toBe("auto");
    expect(plan.detectorId).toBe("harvey-unchecked-mutation"); // taxonomy → the verify §2.3 detector
    expect(plan.blastRadius.files).toEqual(["apps/main/src/actions/save.ts"]);
    expect(plan.blastRadius.callers).toEqual(["apps/main/src/page.tsx"]); // real grep, not a guess
    expect(plan.approach).toBe("Handle the returned { error } and surface it to the caller.");
  });

  it("carries the screen's downgrade reason onto a non-auto plan and omits it on an auto plan", () => {
    const manual = producePlan(makeFinding({ ease: 2 }), { screen: screenFinding(makeFinding({ ease: 2 }), opts), sources });
    expect(manual.mode).toBe("manual");
    expect(manual.downgradeReason).toContain("ease/safety");

    const auto = producePlan(makeFinding(), { screen: screenFinding(makeFinding(), opts), sources });
    expect(auto.downgradeReason).toBeUndefined();
  });

  it("blocks a plan whose file escapes the allowlist at plan time, before any worktree", () => {
    const finding = makeFinding({ location: "infra/deploy.ts:3" });
    const plan = producePlan(finding, { screen: screenFinding(finding, opts), sources });
    const manifest = { allowlist: ["apps/main/src/**"] } as EngagementManifest;
    expect(checkPlanRails(plan, manifest).ok).toBe(false);
  });
});
