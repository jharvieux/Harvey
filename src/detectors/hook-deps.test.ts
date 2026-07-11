// Calibration gate for the hook-deps adapter (#170): the upstream rule must fire on the
// planted missing-dep and stay silent on the corrected version — same fixture discipline as
// the other M7C classes.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectHookDepFindings } from "./hook-deps.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/perf/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".txt")) {
        files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

describe("missing hook dependencies (react-hooks/exhaustive-deps adapter)", () => {
  it("flags a useEffect reading a prop with an empty dependency array", () => {
    const hits = detectHookDepFindings(loadFixtureDir("hook-deps/positive"));
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ severity: "Low", confidence: "Likely", taxonomy: "M7 — Missing hook dependencies" });
    expect(hits[0]?.evidence).toContain("userId");
    expect(hits[0]?.location).toBe("components/profile.tsx:10"); // the rule anchors at the dep-array line
  });

  it("does not flag the corrected dependency list", () => {
    expect(detectHookDepFindings(loadFixtureDir("hook-deps/negative"))).toHaveLength(0);
  });

  it("emits M7H ids so it can merge with M7C findings without collision", () => {
    const hits = detectHookDepFindings(loadFixtureDir("hook-deps/positive"));
    expect(hits[0]?.id).toBe("M7H-01");
  });
});
