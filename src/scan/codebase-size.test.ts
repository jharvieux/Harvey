// #1044: the pricing page gates its price tiers on a codebase size it says is "measured
// automatically during the free scan", so the number is the quote mechanism, not decoration. These
// pin the count against a fixture whose generated/vendored/build directories are known, because the
// commercial claim being backed is "generated and vendored code doesn't count" — a claim that fails
// silently (an inflated invoice) rather than loudly if the exclusions stop matching M4's list.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { measureCodebaseSize } from "./codebase-size.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// 10 non-blank lines, plus blanks that must NOT be counted.
const body = (n: number): string => Array.from({ length: n }, (_, i) => `export const v${i} = ${i};`).join("\n\n");

function fixture(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-size-"));
  dirs.push(root);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

describe("measureCodebaseSize (#1044)", () => {
  const target = () =>
    fixture({
      "src/app.ts": body(10),
      "src/util.tsx": body(5),
      "src/app.test.ts": body(3), // tests are the client's code and M8 assesses them — counted
      "node_modules/dep/index.js": body(500),
      "dist/bundle.js": body(500),
      "src/generated/client.ts": body(400),
      "src/types_db.ts": body(300),
      "src/schema.gen.ts": body(200),
      "vendor/fork/lib.ts": body(100),
      "coverage/lcov-report/block.js": body(900),
      "README.md": "# not source\n",
    });

  it("counts non-blank application source lines only", () => {
    expect(measureCodebaseSize(target()).loc).toBe(18);
  });

  it("counts the application source files, not the excluded or non-source ones", () => {
    expect(measureCodebaseSize(target()).files).toBe(3);
  });

  // The exclusions are the commercial claim. Reporting HOW MANY files were left out is what makes
  // "you are not quoted on generated code" checkable instead of a promise. Build output (coverage/)
  // is dropped entirely rather than counted as excluded — it is not the client's code at all.
  it("reports the generated/vendored files it excluded from the quote", () => {
    expect(measureCodebaseSize(target()).excludedFiles).toBe(6);
  });

  it("bands the result in the pricing table's own words", () => {
    const small = measureCodebaseSize(target());
    expect(small.band).toBe("small");
    expect(small.bandLabel).toBe("Small · under 10k lines");
  });

  it("crosses into the next band exactly at the published threshold", () => {
    // 10,000 lines is the boundary: "under 10k" is Small, so 10k itself is Medium.
    const atBoundary = fixture({ "src/big.ts": Array.from({ length: 10_000 }, (_, i) => `const a${i}=${i};`).join("\n") });
    expect(measureCodebaseSize(atBoundary).band).toBe("medium");
  });

  it("ships the measurement definition with the number, never separately", () => {
    const { definition } = measureCodebaseSize(target());
    expect(definition).toMatch(/Non-blank lines/);
    expect(definition).toMatch(/M4 duplication module/);
    // The site routes monorepo/regulated apps to Enterprise regardless of size; that is an operator
    // judgement, and saying so is what stops a small-LOC regulated app reading as a settled quote.
    expect(definition).toMatch(/operator judgement/);
  });
});
