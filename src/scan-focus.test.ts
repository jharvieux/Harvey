import { describe, expect, it } from "vitest";
import { buildScanFocus, parseHotspots } from "./scan-focus.js";

describe("parseHotspots", () => {
  it("keeps rank order and drops blank lines", () => {
    expect(parseHotspots("src/a.ts\n\n  src/b.ts  \n\nsrc/c.ts\n")).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"]);
  });

  it("returns an empty list for empty input", () => {
    expect(parseHotspots("\n  \n")).toEqual([]);
  });
});

describe("buildScanFocus (#442)", () => {
  it("numbers the files in hotspot rank order", () => {
    const brief = buildScanFocus(["src/hot.ts", "src/warm.ts"]);
    expect(brief).toContain("1. `src/hot.ts`");
    expect(brief).toContain("2. `src/warm.ts`");
    // rank 1 must appear before rank 2
    expect(brief.indexOf("src/hot.ts")).toBeLessThan(brief.indexOf("src/warm.ts"));
  });

  it("frames the list as a priority ordering, not a scope limit", () => {
    const brief = buildScanFocus(["src/hot.ts"]);
    expect(brief).toMatch(/priority ordering,\s+not a scope limit/i);
    expect(brief).toMatch(/still review every file/i);
  });

  it("throws on an empty ranking rather than emitting a hollow brief (fail loud)", () => {
    expect(() => buildScanFocus([])).toThrow(/no hotspots/i);
  });
});
