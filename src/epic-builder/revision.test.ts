import { describe, expect, it } from "vitest";
import { extractComments, hasUnresolvedComments, renderDiff } from "./revision.js";

const withComments = `## Acceptance criteria
- Export completes in under 30s

> [!comment]
> 30s is too generous — the SLA is 10s.
> Also add an empty-results criterion.

## Tests
- t1
`;

describe("comment protocol", () => {
  it("extracts each comment block's text in situ", () => {
    expect(extractComments(withComments)).toEqual([
      "30s is too generous — the SLA is 10s.\nAlso add an empty-results criterion.",
    ]);
  });

  it("detects a surviving comment as a contract violation", () => {
    expect(hasUnresolvedComments(withComments)).toBe(true);
    expect(hasUnresolvedComments("## AC\n- done\n")).toBe(false);
  });
});

describe("renderDiff", () => {
  it("marks removed and added lines and keeps context", () => {
    const diff = renderDiff("a\nb\nc\n", "a\nB\nc\n");
    expect(diff).toContain("  a");
    expect(diff).toContain("- b");
    expect(diff).toContain("+ B");
    expect(diff).toContain("  c");
  });
});
