import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// #1252, found while shipping a detector: reverting the ONE line in mechanical.ts that calls a new
// scanner left all 1704 tests in src/scan/ green. The detector's own unit tests still passed, its
// negative controls still failed in both directions, and nothing in `pnpm verify` noticed that its
// findings had stopped reaching any deliverable. Only `validate-calibration` catches it, and that
// runs in heavy-cli, outside `pnpm verify`.
//
// That is the repo's "accounted for is not delivered" gap at the producer seam, so this is a
// ratchet rather than a one-off assertion: any `scan*` export under src/scan/ must be invoked by
// runMechanicalScan, or be named here with the runner that does invoke it. A new detector that is
// written, tested and never wired fails at `pnpm verify` instead of at a gate that does not block.

const SCAN_DIR = fileURLToPath(new URL(".", import.meta.url));

// Invoked by a DIFFERENT runner, named so the exception is a statement rather than a silence. Each
// entry carries the file that calls it; the second half of the test proves that call still exists.
const ELSEWHERE: Record<string, string> = {
  scanPrismaAppPerf: "src/cli/static-detect.ts",
  scanPrismaSchemaPerf: "src/cli/static-detect.ts",
};

function scannerExports(): { file: string; name: string }[] {
  return readdirSync(SCAN_DIR)
    .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== "mechanical.ts")
    .flatMap((file) => {
      const text = readFileSync(join(SCAN_DIR, file), "utf8");
      return [...text.matchAll(/^export function (scan[A-Za-z0-9_]*)/gm)].map((m) => ({ file, name: m[1]! }));
    });
}

describe("mechanical scan wiring (#1252 — a detector nobody calls reports nothing and stays green)", () => {
  const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
  const mechanical = readFileSync(join(SCAN_DIR, "mechanical.ts"), "utf8");

  it("every scan* export under src/scan/ is invoked by runMechanicalScan or declared elsewhere", () => {
    const exports = scannerExports();
    // Guards the guard: if this file stops finding scanners the assertion below passes vacuously.
    expect(exports.length).toBeGreaterThan(20);
    const unwired = exports.filter(({ name }) => !mechanical.includes(`${name}(`) && !(name in ELSEWHERE));
    expect(unwired, "add the call to mechanical.ts, or name its runner in ELSEWHERE").toEqual([]);
  });

  it("each declared exception is really invoked by the runner it names", () => {
    for (const [name, runner] of Object.entries(ELSEWHERE)) {
      expect(readFileSync(join(repoRoot, runner), "utf8"), `${name} claims ${runner} calls it`).toContain(`${name}(`);
    }
  });
});
