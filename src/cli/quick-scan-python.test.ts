import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HealthScorecard } from "../health-scorecard.js";
import { CLI, MECHANICAL_BINARIES_PRESENT, createQuickScanTestHarness } from "./quick-scan-test-support.js";

const { dirs, run, cleanup } = createQuickScanTestHarness();
afterEach(cleanup);

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("quick-scan M5 Python evidence (#2156)", () => {
  it.each([
    { shape: "Python product and Python tests", product: true, jsTests: false },
    { shape: "Python product and JS tests", product: true, jsTests: true },
    { shape: "Python tests only", product: false, jsTests: false },
  ])("keeps the assessed population honest for $shape", async ({ product, jsTests }) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-m5-product-population-"));
    dirs.push(target);
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m5-product-population", private: true }));
    const python = "def work():\n    try:\n        run()\n    except Exception:\n        pass\n";
    if (product) writeFileSync(join(target, "worker.py"), python);
    writeFileSync(join(target, jsTests ? "index.test.ts" : "test_worker.py"), jsTests ? "export const ready = true;\n" : python);
    const jsonOut = join(target, "quick.json");
    const sarifOut = join(target, "quick.sarif");
    await run([CLI, "--dir", target, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
    const scorecard = (JSON.parse(readFileSync(jsonOut, "utf8")) as { scorecard: HealthScorecard }).scorecard;
    const m5 = scorecard.dimensions.find((row) => row.module === "M5")!;
    const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as { runs: Array<{ results: Array<{ ruleId: string; message: { text: string } }> }> };
    const m5Results = sarif.runs[0]!.results.filter((result) => result.ruleId.startsWith("M5 — "));
    expect(m5.grade).toBeUndefined();
    expect(m5.score).toBeUndefined();
    expect(scorecard.gradedModules).not.toContain("M5");
    if (product) {
      expect(m5).toMatchObject({ status: "indicator-only", count: 1 });
      expect(m5.scope).toContain("python: 1/1 examined (partial");
      expect(m5.scope).not.toContain("javascript/typescript: 1/1");
      expect(m5.evidence?.examples.map((example) => example.location)).toEqual(["worker.py:4"]);
      expect(m5Results.filter((result) => result.ruleId === "M5 — Python empty/pass exception handler")).toHaveLength(1);
      const assessmentText = m5Results.find((result) => result.ruleId === "M5 — Source coverage partial: python")?.message.text;
      expect(assessmentText).toContain("Identified=1 (");
      expect(assessmentText).toContain("examined=1 (");
    } else {
      expect(m5.status).toBe("not-assessed");
      expect(m5.reason).toContain("No authored product source files");
      expect(m5Results).toHaveLength(0);
    }
  }, 120000);

  it.each([
    { shape: "positive Python", python: "def work():\n    try:\n        run()\n    except Exception:\n        pass\n", js: false, count: 1, scorecardCount: 1 },
    { shape: "zero-finding Python", python: "def work():\n    return 42\n", js: false, count: 0, scorecardCount: 0 },
    { shape: "mixed JS/Python", python: "def work():\n    try:\n        run()\n    except Exception:\n        pass\n", js: true, count: 1, scorecardCount: 2 },
  ])("carries $shape assessment through JSON and SARIF", async ({ python, js, count, scorecardCount }) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-m5-python-scorecard-"));
    dirs.push(target);
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m5-python-evidence", private: true }));
    writeFileSync(join(target, "worker.py"), python);
    if (js) writeFileSync(join(target, "index.ts"), "// TODO fix\nexport const ready = true;\n");
    const jsonOut = join(target, "quick.json");
    const sarifOut = join(target, "quick.sarif");
    await run([CLI, "--dir", target, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
    const scorecard = (JSON.parse(readFileSync(jsonOut, "utf8")) as { scorecard: HealthScorecard }).scorecard;
    const m5 = scorecard.dimensions.find((row) => row.module === "M5")!;
    const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as {
      runs: Array<{ results: Array<{ ruleId: string; properties: { location?: string; precisionTier?: string } }> }>;
    };
    const results = sarif.runs[0]!.results;
    const pythonHits = results.filter((result) => result.ruleId === "M5 — Python empty/pass exception handler");
    expect(pythonHits).toHaveLength(count);
    expect(results.some((result) => result.ruleId === "M5 — Source coverage partial: python")).toBe(true);
    expect(m5.count).toBe(scorecardCount);
    expect(m5.evidence?.totalFindings).toBe(scorecardCount);
    expect(m5.evidence?.examples.map((example) => example.location)).toEqual(js ? ["index.ts:1", "worker.py:4"] : count ? ["worker.py:4"] : []);
    expect(m5.scope).toContain("python: 1/1 examined (partial");
    expect(m5.scope).toContain("review-tier");
    if (count) expect(pythonHits[0]!.properties).toMatchObject({ location: "worker.py:4", precisionTier: "review" });
    if (js) {
      expect(m5).toMatchObject({ status: "graded", grade: "F" });
      expect(m5.measure).toContain("(1 in");
      expect(m5.measure).toContain("1 review-tier signal(s) shown separately from the grade");
      expect(m5.scope).toContain("javascript/typescript: 1/1 examined");
    } else {
      expect(m5.status).toBe("indicator-only");
      expect(m5.grade).toBeUndefined();
      expect(m5.score).toBeUndefined();
      expect(scorecard.gradedModules).not.toContain("M5");
    }
  }, 120000);
});
