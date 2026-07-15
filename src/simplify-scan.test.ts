import { describe, expect, it } from "vitest";
import { buildPacket, extractM6Brief, renderPacket } from "./simplify-scan.js";

const BRIEF = `# quality-extras

## SLOP / DEAD CODE (M5) — flag for deletion or inlining

- NARRATING COMMENTS — restate WHAT the next line does.

## SIMPLIFICATION / REUSE (M6) — flag for replacement

- HAND-ROLLED PRIMITIVES — a bespoke debounce/UUID → name the standard replacement.
- OVER-ABSTRACTION — an interface with a single implementation.

## SUPPORTABILITY / MAINTENANCE SIGNALS

- BUS-FACTOR RISK — a complex module with no tests.

## FALSE POSITIVES (don't flag)

- An abstraction mandated by a framework/library contract (not gratuitous).
- A re-implementation chosen deliberately to drop a heavy dependency.
`;

describe("extractM6Brief", () => {
  it("carries the M6 rubric and drops the other modules' sections", () => {
    const brief = extractM6Brief(BRIEF);
    expect(brief).toContain("HAND-ROLLED PRIMITIVES");
    expect(brief).toContain("OVER-ABSTRACTION");
    // M5/M8/supportability sections would dilute an M6-scoped pass.
    expect(brief).not.toContain("NARRATING COMMENTS");
    expect(brief).not.toContain("BUS-FACTOR RISK");
  });

  it("keeps the FALSE POSITIVES section — it is what makes the pass reason about WHY", () => {
    // The eval's two negatives (a deliberate dep-drop, a framework-mandated shape) are only
    // sparable if the reviewer has this section. A packet without it invites shape-matching.
    const brief = extractM6Brief(BRIEF);
    expect(brief).toContain("mandated by a framework/library contract");
    expect(brief).toContain("drop a heavy dependency");
  });

  it("refuses to build a brief with no M6 section rather than shipping an empty rubric", () => {
    expect(() => extractM6Brief("# quality-extras\n\n## SLOP\n\n- things\n")).toThrow(/SIMPLIFICATION/);
  });

  it("refuses when FALSE POSITIVES is missing — a rubric with no negative class is the failure mode", () => {
    const noFp = "## SIMPLIFICATION / REUSE (M6)\n\n- HAND-ROLLED PRIMITIVES\n";
    expect(() => extractM6Brief(noFp)).toThrow(/FALSE POSITIVES/);
  });
});

describe("renderPacket", () => {
  const packet = buildPacket(BRIEF, process.cwd(), [`${process.cwd()}/package.json`]);

  it("includes the target source under review", () => {
    const out = renderPacket(packet);
    expect(out).toContain("package.json");
    expect(out).toContain("simplify-scan"); // the file's actual content made it in
  });

  it("instructs the reviewer to reason about WHY, not to pattern-match on shape", () => {
    expect(renderPacket(packet)).toMatch(/reason about WHY/i);
  });

  it("tells the reviewer its verdict is an opinion needing human review, per §5", () => {
    const out = renderPacket(packet);
    expect(out).toMatch(/opinion, not a fact/i);
    expect(out).toMatch(/human review/i);
  });
});
