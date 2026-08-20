import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { readEntriesSafe } from "../fs-walk.js";
import type { SourceInput } from "./common.js";
import {
  classifyVacuousAssertions,
  detectM8VacuousAssertionFindings,
  M8_VACUOUS_ASSERTION_TAXONOMY,
  type VacuousAssertionClassification,
} from "./m8-vacuous-assertion.js";
import { m8VacuousPolyglotEntries } from "../scan/calibration/m8-vacuous-polyglot.entries.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/m8-vacuous-assertion/", import.meta.url));
const TARGET_ROOT = fileURLToPath(new URL("../../targets/calibration/src/m8-vacuous-assertion/", import.meta.url));

function loadFixtureDir(relativeDirectory: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relativeDirectory);
  const files: SourceInput[] = [];
  const walk = (directory: string): void => {
    for (const entry of readEntriesSafe(directory).entries) {
      if (entry.isDirectory) walk(entry.path);
      else if (entry.name.endsWith(".txt")) {
        files.push({
          path: relative(root, entry.path).replace(/\.txt$/, "").split(sep).join("/"),
          text: readFileSync(entry.path, "utf8"),
        });
      }
    }
  };
  walk(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function loadTargetFiles(): SourceInput[] {
  return readEntriesSafe(TARGET_ROOT).entries
    .filter((entry) => !entry.isDirectory)
    .map((entry) => ({
      path: `m8-vacuous-assertion/${entry.name}`,
      text: readFileSync(entry.path, "utf8"),
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

interface FixtureCase {
  name: string;
  directory: string;
  positiveCount: number;
  apis: readonly string[];
}

const CASES: FixtureCase[] = [
  { name: "Jest/Vitest", directory: "jest", positiveCount: 4, apis: ["expect(...).toBe", "expect(...).toEqual", "expect(...).toStrictEqual"] },
  { name: "Node assert", directory: "node-assert", positiveCount: 3, apis: ["assert.equal", "assert.strictEqual", "assert.ok"] },
  { name: "Chai", directory: "chai", positiveCount: 4, apis: ["expect(...).equal", "assert.equal", "Chai should.equal", "Chai expect(...).to.be.true"] },
  { name: "Python", directory: "python", positiveCount: 4, apis: ["Python assert", "unittest.assertTrue", "unittest.assertEqual"] },
  { name: "mixed-quality file", directory: "mixed", positiveCount: 1, apis: ["expect(...).toBe"] },
];

function requireDetectedPopulation(
  files: readonly SourceInput[],
  classifier: (inputs: readonly SourceInput[]) => VacuousAssertionClassification[] = classifyVacuousAssertions,
): void {
  if (classifier(files).length === 0) throw new Error("vacuous-assertion positive population was not detected");
}

describe.each(CASES)("$name fixed-assertion classifier", ({ directory, positiveCount, apis }) => {
  it("detects the exact positive population with canonical assertion identities", () => {
    const positiveFiles = loadFixtureDir(`${directory}/positive`);
    expect(positiveFiles).toHaveLength(1);
    const hits = classifyVacuousAssertions(positiveFiles);
    expect(hits).toHaveLength(positiveCount);
    expect(new Set(hits.map((hit) => hit.identity)).size).toBe(hits.length);
    for (const api of apis) expect(hits.some((hit) => hit.api === api)).toBe(true);
  });

  it("clears the exact negative population", () => {
    const negativeFiles = loadFixtureDir(`${directory}/negative`);
    expect(negativeFiles).toHaveLength(1);
    expect(classifyVacuousAssertions(negativeFiles)).toEqual([]);
  });
});

describe("scope and evidence", () => {
  it("finds exactly one fixed assertion inside a mixed-quality file", () => {
    const hits = classifyVacuousAssertions(loadFixtureDir("mixed/positive"));
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ api: "expect(...).toBe", expression: "true toBe true" });
  });

  it("keeps source assertion identity distinct from mutation-scan file evidence", () => {
    const findings = detectM8VacuousAssertionFindings(loadFixtureDir("mixed/positive"));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "M8VAC-01",
      taxonomy: M8_VACUOUS_ASSERTION_TAXONOMY,
      precisionTier: "review",
      confidence: "Review",
      mechanical: true,
      location: "mixed.test.ts:6",
    });
    expect(findings[0]?.taxonomy).not.toBe("M8 — Vacuous test (kills zero mutants)");
  });

  it("names the assertion API, expression, and production-independence in client evidence", () => {
    const findings = detectM8VacuousAssertionFindings([
      ...loadFixtureDir("jest/positive"),
      ...loadFixtureDir("node-assert/positive"),
      ...loadFixtureDir("chai/positive"),
      ...loadFixtureDir("python/positive"),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.evidence).toMatch(/(?:expect|assert|Chai|unittest)/);
      expect(finding.evidence).toMatch(/production/i);
    }
  });

  it("requires explicit test-file SourceInput paths for both language families", () => {
    const source = "expect(true).toBe(true);";
    const python = "assert True\n";
    expect(classifyVacuousAssertions([{ path: "src/example.ts", text: source }, { path: "script.py", text: python }])).toEqual([]);
    expect(classifyVacuousAssertions([{ path: "example.test.ts", text: source }, { path: "test_example.py", text: python }])).toHaveLength(2);
  });
});

describe("calibration population and failing directions", () => {
  it("locks every exact positive/negative fixture pair into the population", () => {
    expect(CASES.map((fixtureCase) => fixtureCase.directory)).toEqual(["jest", "node-assert", "chai", "python", "mixed"]);
    for (const fixtureCase of CASES) {
      expect(loadFixtureDir(`${fixtureCase.directory}/positive`)).toHaveLength(1);
      expect(loadFixtureDir(`${fixtureCase.directory}/negative`)).toHaveLength(1);
    }
  });

  it("makes a disabled classifier fail the positive-population contract", () => {
    const positives = CASES.flatMap((fixtureCase) => loadFixtureDir(`${fixtureCase.directory}/positive`));
    expect(() => requireDetectedPopulation(positives, () => [])).toThrowError("vacuous-assertion positive population was not detected");
    expect(() => requireDetectedPopulation(positives)).not.toThrow();
  });

  it("binds target calibration rows to live positive and negative files", () => {
    const targetFiles = loadTargetFiles();
    expect(targetFiles.map((file) => file.path)).toEqual([
      "m8-vacuous-assertion/controls.test.ts",
      "m8-vacuous-assertion/test_controls.py",
      "m8-vacuous-assertion/test_vacuous.py",
      "m8-vacuous-assertion/vacuous.test.ts",
    ]);
    const hits = classifyVacuousAssertions(targetFiles);
    expect(hits.map((hit) => `${hit.path}:${hit.line}`)).toEqual([
      "m8-vacuous-assertion/test_vacuous.py:2",
      "m8-vacuous-assertion/test_vacuous.py:3",
      "m8-vacuous-assertion/vacuous.test.ts:4",
    ]);
    expect(m8VacuousPolyglotEntries.map((entry) => entry.id)).toEqual([
      "M8VAC-P-JS-FIXED",
      "M8VAC-N-JS-OBSERVED",
      "M8VAC-P-PYTHON-FIXED",
      "M8VAC-N-PYTHON-OBSERVED",
    ]);
  });
});
