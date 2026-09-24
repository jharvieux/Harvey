import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HealthScorecard } from "../health-scorecard.js";
import { CLI, MECHANICAL_BINARIES_PRESENT, createQuickScanTestHarness } from "./quick-scan-test-support.js";

const { dirs, run, cleanup } = createQuickScanTestHarness();
afterEach(cleanup);

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("M9 workspace assessment at quick-scan output (#2074)", () => {
  it.each(["unsupported-only", "native-astro-only", "mixed-clean", "mixed-defects"].flatMap((shape) =>
    ["json", "text"].map((format) => ({ shape, format })),
  ))("preserves assessment and disclosure for $shape ($format)", async ({ shape, format }) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-m9-workspace-"));
    dirs.push(target);
    mkdirSync(join(target, "apps/site/src"), { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m9-scope-fixture", private: true, workspaces: ["apps/*"] }));
    for (const config of ["next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts", "babel.config.js", "babel.config.mjs", "babel.config.cjs"]) {
      writeFileSync(join(target, config), "export default {};");
    }
    writeFileSync(join(target, "apps/site/package.json"), JSON.stringify({ name: "site", dependencies: { astro: "5.0.0" } }));
    writeFileSync(join(target, "apps/site/src", shape === "native-astro-only" ? "page.astro" : "main.ts"), shape === "native-astro-only" ? "<h1>Site</h1>" : "export const site = 1;");
    if (shape.startsWith("mixed")) {
      mkdirSync(join(target, "apps/api/app"), { recursive: true });
      writeFileSync(join(target, "apps/api/package.json"), JSON.stringify({ name: "api", dependencies: { next: "14.0.0" } }));
      for (let i = 0; i < (shape === "mixed-defects" ? 6 : 1); i += 1) {
        mkdirSync(join(target, `apps/api/app/p${i}`), { recursive: true });
        writeFileSync(join(target, `apps/api/app/p${i}/page.tsx`), shape === "mixed-defects"
          ? "export default function Page() { return <div>{window.innerWidth}</div>; }"
          : "export default function Page() { return null; }");
      }
    }
    const output = await run([CLI, "--dir", target, ...(format === "json" ? ["--json"] : [])]);
    const scorecard = format === "json" ? (JSON.parse(output.stdout) as { scorecard: HealthScorecard }).scorecard : undefined;
    const m9 = scorecard?.dimensions.find((d) => d.module === "M9");
    const text = format === "json" ? JSON.stringify(m9) : output.stdout;
    expect(text).toContain("Astro");
    expect(text).toContain("apps/site");
    if (format === "json") {
      if (!scorecard || !m9) throw new Error("JSON report is missing its M9 scorecard dimension");
      if (shape.startsWith("mixed")) {
        expect(m9.status).toBe("graded");
        expect(m9.count).toBe(shape === "mixed-defects" ? 6 : 0);
        expect(m9.notAssessedRows).toBe(1);
        expect(m9.reason).toContain("was not analysed");
        if (shape === "mixed-clean") expect(m9.score).toBe(100);
      } else {
        expect(m9.status).toBe("not-assessed");
        expect(m9.grade).toBeUndefined();
        expect(m9.score).toBeUndefined();
        expect(scorecard.gradedModules).not.toContain("M9");
        const graded = scorecard.dimensions.filter((d) => d.status === "graded" && d.module !== "M9");
        expect(scorecard.score).toBe(Math.round(graded.reduce((sum, d) => sum + d.score!, 0) / graded.length));
      }
    } else {
      const m9Line = output.stdout.split("\n").find((line) => line.includes("M9") && line.includes("Framework-boundary correctness"))!;
      if (shape.startsWith("mixed")) {
        expect(m9Line).toMatch(/[A-F] \(\d+\/100\)/);
      } else {
        expect(m9Line).toContain("NOT ASSESSED");
        expect(m9Line).not.toMatch(/[A-F] \(\d+\/100\)/);
      }
    }
  }, 120000);
});
