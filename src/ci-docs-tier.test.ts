import { globSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Guard for the CI tier router in .github/workflows/ci.yml. The router lets prose
// docs (SESSION.md, docs/**.md) skip the `build` job. Any doc the test suite reads
// from disk is NOT inert — a change to it can fail a test — so it must stay on the
// build path via an explicit `code=true` case. This fails loud if a test starts
// reading a docs/*.md the router still treats as skippable, closing the silent-decay
// gap where such a change would skip verify on the PR.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));

function docsMarkdownReadByTests(): Set<string> {
  const found = new Set<string>();
  const readCall = /(?:readFileSync|readFile)\([^)]*?["'`]?(?:\.\.\/)*(docs\/[\w./-]+\.md)/g;
  for (const rel of globSync("src/**/*.test.ts", { cwd: repoRoot })) {
    const text = readFileSync(join(repoRoot, rel), "utf8");
    for (const m of text.matchAll(readCall)) if (m[1]) found.add(m[1]);
  }
  return found;
}

function routerBuildRelevantDocs(): Set<string> {
  const yaml = readFileSync(join(repoRoot, ".github/workflows/ci.yml"), "utf8");
  const relevant = new Set<string>();
  for (const m of yaml.matchAll(/^\s*(docs\/[\w./-]+\.md)\)\s*code=true/gm)) if (m[1]) relevant.add(m[1]);
  return relevant;
}

describe("CI docs tier router", () => {
  it("keeps every test-read docs/*.md on the build path", () => {
    const buildRelevant = routerBuildRelevantDocs();
    const skippable = [...docsMarkdownReadByTests()].filter((d) => !buildRelevant.has(d));
    expect(
      skippable,
      `These docs are read by a test but would skip the build job. Add a ` +
        `\`${skippable[0] ?? "docs/x.md"}) code=true ;;\` case to .github/workflows/ci.yml.`,
    ).toEqual([]);
  });
});
