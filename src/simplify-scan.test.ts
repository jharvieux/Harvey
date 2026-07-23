import { describe, expect, it } from "vitest";
import { buildPacket, extractM6Brief, renderPacket, scopePacketFiles } from "./simplify-scan.js";

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

describe("renderPacket two-reviewer protocol (#813)", () => {
  const packet = buildPacket(BRIEF, process.cwd(), [`${process.cwd()}/package.json`]);
  const out = renderPacket(packet);

  it("tells the reviewer it is one of two independent passes and forbids consulting the other", () => {
    expect(out).toMatch(/ONE OF TWO independent reviewers/);
    expect(out).toMatch(/do not consult/i);
  });

  it("routes splits to a human adjudicator, never straight into a report", () => {
    expect(out).toMatch(/human adjudicator/);
    expect(out).toMatch(/never goes\s+straight into a report/);
  });

  it("carries the machine-readable verdict template, pre-filled with this packet's target", () => {
    expect(out).toContain("## Verdict format — two-reviewer protocol (#813)");
    expect(out).toContain('"verdict": "flag | spare"');
    expect(out).toContain(`"target": "${process.cwd()}"`);
    // Comparison is mechanical — the packet names the tool that computes agreement.
    expect(out).toContain("src/cli/m6-agreement.ts");
  });

  it("requires every packet file to appear in the verdict block — no silent default to spare", () => {
    expect(out).toMatch(/exactly once/);
    expect(out).toMatch(/does not default to "spare"/);
  });
});

describe("buildPacket dependency manifest (#396)", () => {
  const cwd = process.cwd();
  const sourcePaths = [`${cwd}/package.json`]; // stands in for a source file under review

  it("includes the manifest's own section, ahead of the source files", () => {
    const packet = buildPacket(BRIEF, cwd, sourcePaths, [], [`${cwd}/package.json`]);
    expect(packet.manifests).toEqual([{ path: "package.json", text: expect.any(String) }]);
    const out = renderPacket(packet);
    expect(out).toContain("## Dependency manifest");
    expect(out).toContain('"devDependencies"'); // the target's actual manifest content made it in
    // The manifest section must precede the source-under-review section.
    expect(out.indexOf("## Dependency manifest")).toBeLessThan(out.indexOf("## The source under review"));
  });

  it("names a dependency that is actually installed, so the reviewer can apply the class", () => {
    const packet = buildPacket(BRIEF, cwd, sourcePaths, [], [`${cwd}/package.json`]);
    // vitest is a real devDependency of this repo — proves the manifest's real content is present,
    // not just a placeholder section heading.
    expect(renderPacket(packet)).toContain("vitest");
  });

  it("fails loud — not silently — when the target has no package.json", () => {
    const packet = buildPacket(BRIEF, cwd, sourcePaths, [], []);
    expect(packet.manifests).toEqual([]);
    const out = renderPacket(packet);
    expect(out).toContain("## Dependency manifest");
    expect(out).toMatch(/no package\.json was found/i);
    expect(out).toMatch(/unverifiable/i);
  });
});

describe("buildPacket hotspot ordering (#442)", () => {
  const cwd = process.cwd();
  const paths = [`${cwd}/package.json`, `${cwd}/tsconfig.json`];

  it("leads with the hottest file and annotates its rank when hotspots are supplied", () => {
    // tsconfig.json is listed second but ranked hottest — it must come first, tagged #1.
    const packet = buildPacket(BRIEF, cwd, paths, ["tsconfig.json", "package.json"]);
    expect(packet.hotspotRanked).toBe(true);
    expect(packet.files[0]?.path).toBe("tsconfig.json");
    expect(packet.files[0]?.hotspotRank).toBe(1);
    const out = renderPacket(packet);
    expect(out).toContain("### [hotspot #1] tsconfig.json");
    expect(out).toMatch(/ordered by M3 hotspot rank/i);
  });

  it("leaves order untouched and adds no hotspot note when none are supplied", () => {
    const packet = buildPacket(BRIEF, cwd, paths);
    expect(packet.hotspotRanked).toBe(false);
    expect(packet.files[0]?.path).toBe("package.json");
    expect(renderPacket(packet)).not.toMatch(/hotspot/i);
  });

  it("ranks known hotspots ahead of files absent from the list", () => {
    // Only package.json is a hotspot; tsconfig.json (not listed) sorts after it.
    const packet = buildPacket(BRIEF, cwd, paths, ["package.json"]);
    expect(packet.files[0]?.path).toBe("package.json");
    expect(packet.files[0]?.hotspotRank).toBe(1);
    expect(packet.files[1]?.hotspotRank).toBeUndefined();
  });
});

describe("scopePacketFiles (#621 — --hotspots bounds the packet on a monorepo)", () => {
  const dir = "/repo";
  const all = ["/repo/apps/main/a.ts", "/repo/apps/main/b.ts", "/repo/packages/x/c.ts"];

  it("keeps only files whose target-relative path is in the hotspot list", () => {
    const scoped = scopePacketFiles(all, dir, ["apps/main/a.ts", "packages/x/c.ts"]);
    expect(scoped).toEqual(["/repo/apps/main/a.ts", "/repo/packages/x/c.ts"]);
  });

  it("returns every file when no hotspots are supplied (single-target behaviour)", () => {
    expect(scopePacketFiles(all, dir, [])).toEqual(all);
  });

  it("drops files not in the hotspot list — the whole-tree packet cannot leak back in", () => {
    const scoped = scopePacketFiles(all, dir, ["apps/main/a.ts"]);
    expect(scoped).toEqual(["/repo/apps/main/a.ts"]);
    expect(scoped).not.toContain("/repo/apps/main/b.ts");
  });
});
