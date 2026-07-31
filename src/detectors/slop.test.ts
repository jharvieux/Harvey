// M5 slop calibration gate: every AI-slop class ships only with a caught positive AND a
// cleared benign negative — the #61 fixture discipline, applied to the slop detectors.

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detectSlopFindings } from "./slop.js";
import type { SourceInput } from "./common.js";

const FIXTURES_ROOT = fileURLToPath(new URL("./__fixtures__/slop/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES_ROOT, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string) => {
    for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) walk(full);
      else if (entry.endsWith(".txt")) files.push({ path: relative(root, full).replace(/\.txt$/, "").split(sep).join("/"), text: readFileSync(full, "utf8") });
    }
  };
  walk(root);
  return files;
}

function byTaxonomy(relDir: string, taxonomy: string) {
  return detectSlopFindings(loadFixtureDir(relDir)).filter((f) => f.taxonomy === taxonomy);
}

interface Case {
  name: string;
  dir: string;
  taxonomy: string;
  posCount: number;
  severity: string;
  confidence: string;
}

const CASES: Case[] = [
  // Ported from ATC slop-check.
  { name: "orphan TODO", dir: "orphan-todo", taxonomy: "M5 — Orphan TODO", posCount: 4, severity: "Low", confidence: "Likely" },
  { name: "narrating comment", dir: "narrating-comment", taxonomy: "M5 — Narrating comment", posCount: 2, severity: "Info", confidence: "Review" },
  { name: "rethrow catch", dir: "rethrow-catch", taxonomy: "M5 — Rethrow catch", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "single-call wrapper", dir: "single-call-wrapper", taxonomy: "M5 — Single-call wrapper", posCount: 1, severity: "Low", confidence: "Review" },
  // Additional researched classes.
  { name: "placeholder stub", dir: "placeholder", taxonomy: "M5 — Placeholder stub", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "elision placeholder", dir: "elision", taxonomy: "M5 — Elision placeholder", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "AI comment phrasing", dir: "ai-phrasing", taxonomy: "M5 — AI comment phrasing", posCount: 1, severity: "Info", confidence: "Review" },
  { name: "redundant boolean", dir: "redundant-boolean", taxonomy: "M5 — Redundant boolean", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "else after return", dir: "else-after-return", taxonomy: "M5 — Else after return", posCount: 1, severity: "Low", confidence: "Likely" },
  { name: "decorative emoji", dir: "emoji", taxonomy: "M5 — Decorative emoji", posCount: 2, severity: "Info", confidence: "Review" },
  { name: "redundant JSDoc", dir: "redundant-jsdoc", taxonomy: "M5 — Redundant JSDoc", posCount: 1, severity: "Low", confidence: "Review" },
  // Coverage fan-out (#362, #364, #370, #371).
  { name: "unused parameter", dir: "unused-parameter", taxonomy: "M5 — Unused parameter", posCount: 2, severity: "Low", confidence: "Review" },
  { name: "unused import", dir: "unused-import", taxonomy: "M5 — Unused import", posCount: 2, severity: "Low", confidence: "Likely" },
  { name: "single-use helper", dir: "single-use-helper", taxonomy: "M5 — Single-use helper", posCount: 7, severity: "Low", confidence: "Review" },
  { name: "unreachable branch", dir: "unreachable-branch", taxonomy: "M5 — Unreachable branch", posCount: 2, severity: "Low", confidence: "Likely" },
];

for (const c of CASES) {
  describe(c.name, () => {
    it("catches the positive with the right count, severity, confidence, and a line-anchored location", () => {
      const hits = byTaxonomy(`${c.dir}/positive`, c.taxonomy);
      expect(hits).toHaveLength(c.posCount);
      for (const h of hits) {
        expect(h).toMatchObject({ category: "Maintainability", status: "Open", severity: c.severity, confidence: c.confidence });
        expect(h.location).toMatch(/[^:]:\d+$/); // `path:line`, not a bare file — catches a detector that loses its line
      }
    });
    it("clears the benign negative (incl. the discrimination boundaries)", () => {
      expect(byTaxonomy(`${c.dir}/negative`, c.taxonomy)).toHaveLength(0);
    });
  });
}

// The discrimination boundaries that keep these low-FP are the load-bearing logic — assert the
// exact line so a detector that fires on the wrong node (or a mutation that drops a guard) fails,
// not just one that stops firing entirely.
describe("discrimination boundaries (regression locks)", () => {
  it("rethrow keys on the SAME caught variable — a different-var rethrow is not flagged", () => {
    // negative/c.ts has `catch (caught) { throw fallbackErr }` — must stay silent, or the \1
    // backreference has been lost and every throw-in-catch would flag.
    const hits = byTaxonomy("rethrow-catch/negative", "M5 — Rethrow catch");
    expect(hits).toHaveLength(0);
  });

  it("wrapper flags a bare free-function forward but NOT a method-call predicate", () => {
    // negative/d.ts has `isAdminRole(role) { return ADMIN_ROLES.has(role) }` — the method-call
    // guard must keep it silent (this is the exact FP class tuned out during the dogfood).
    expect(byTaxonomy("single-call-wrapper/negative", "M5 — Single-call wrapper")).toHaveLength(0);
    const pos = byTaxonomy("single-call-wrapper/positive", "M5 — Single-call wrapper");
    expect(pos).toHaveLength(1);
    expect(pos[0]?.location).toBe("d.ts:2"); // anchors on the `export function getUser` declaration
    expect(pos[0]?.title).toContain("getUser");
  });

  it("orphan-todo covers all four markers and the paren form, but exempts any-paren refs", () => {
    const pos = byTaxonomy("orphan-todo/positive", "M5 — Orphan TODO");
    expect(pos.map((f) => f.location)).toEqual(["a.ts:2", "a.ts:3", "a.ts:4", "a.ts:5"]);
    expect(byTaxonomy("orphan-todo/negative", "M5 — Orphan TODO")).toHaveLength(0);
  });

  it("narrating-comment matches multiple verbs but not a verb-first long sentence", () => {
    expect(byTaxonomy("narrating-comment/positive", "M5 — Narrating comment")).toHaveLength(2);
    expect(byTaxonomy("narrating-comment/negative", "M5 — Narrating comment")).toHaveLength(0);
  });

  it("unused-parameter flags a trailing unused param but exempts a leading one before a used param, and never visits an anonymous inline callback", () => {
    // negative/handlers.ts has `errorHandler(err, req, res, next)` where only `next` (last) is
    // used — err/req/res come BEFORE the last used param, so the after-used convention must
    // keep them silent. It also has an anonymous `numbers.map((item, index, array) => ...)`
    // callback: never a named declaration, so this detector never even visits it — that's what
    // actually keeps the callback-contract shape silent (not ESLint's after-used rule, which a
    // live check showed DOES flag that shape).
    expect(byTaxonomy("unused-parameter/negative", "M5 — Unused parameter")).toHaveLength(0);
    const pos = byTaxonomy("unused-parameter/positive", "M5 — Unused parameter");
    expect(pos.map((f) => f.location)).toEqual(["keys.ts:3", "keys.ts:7"]);
    expect(pos[0]?.title).toContain("kid");
    expect(pos[1]?.title).toContain("includeEmail");
  });

  it("single-use-helper exempts an exported single-caller but still catches a non-exported one, and stays silent on a two-site helper", () => {
    const pos = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper");
    expect([...pos.map((f) => f.title)].sort()).toEqual([
      expect.stringContaining("buildFeedXml"),
      expect.stringContaining("cacheIsWarm"),
      expect.stringContaining("computeDiscount"),
      expect.stringContaining("detectIntent"),
      expect.stringContaining("loadRate"),
      expect.stringContaining("requireCliLogin"),
      expect.stringContaining("streamToText"),
    ]);
    expect(byTaxonomy("single-use-helper/negative", "M5 — Single-use helper")).toHaveLength(0);
  });

  // #1532 — the half of the seam premise `containsAwait` does not look for. MEASURED
  // 2026-07-30: a seeded 50-row sample of what the #1447 exemption spares across the ten pinned
  // corpus targets found 5 wrongly spared, and every one was the helper doing the I/O itself
  // without an `await` — `spawnSync`, `spawn`, `existsSync`, or a hand-rolled `new Promise` over
  // stream events. Both shapes now fail here, and the scope control keeps the widening honest:
  // a pure helper that merely CALLS a platform API (`crypto.getRandomValues`) stays spared.
  it("does not spare a helper that does its own I/O without awaiting — sync spawn or a hand-rolled Promise (#1532)", () => {
    const titles = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper").map((f) => f.title);
    expect(titles.some((t) => t.includes("requireCliLogin"))).toBe(true); // spawnSync + process.exit
    expect(titles.some((t) => t.includes("streamToText"))).toBe(true); // new Promise over stream events
    // Scope control: widening `doesOwnIo` must not swallow the class it exists to protect.
    expect(byTaxonomy("single-use-helper/negative", "M5 — Single-use helper")).toEqual([]);
  });

  // #1532 residual, found by RE-DRAWING (seed 20260731, 30 of the 597 then spared, read at source):
  // 1 of the 30 was still wrongly spared because `doesOwnIo` reads the helper's own body only, and
  // carbon's `depsInSync` stats two files through `isAtLeastAsNew` one call away. The same run found
  // the opposite error: matching the spawner names on a METHOD call made `RE.exec(s)` read as
  // spawning, which cost three rows including one #1532's own baseline note grades a genuine seam.
  it("follows a resolvable callee one hop for I/O, and does not read `RE.exec(s)` as spawning (#1532)", () => {
    const titles = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper").map((f) => f.title);
    expect(titles.some((t) => t.includes("cacheIsWarm"))).toBe(true); // existsSync/statSync one hop away, through a `.js` specifier
    expect(titles.some((t) => t.includes("requireCliLogin"))).toBe(true); // the bare-identifier `spawnSync` half must survive the narrowing
    expect(byTaxonomy("single-use-helper/negative", "M5 — Single-use helper")).toEqual([]); // `matchTeamRoute` stays spared
  });

  // #370 criterion 3, the FP class briefs/quality-extras.txt names and #325 fixtures for M6.
  // MEASURED 2026-07-28: before this, M5 and M6 diverged on it — M6-N-SEAM (reconcile.ts) is spared
  // by M5 only because it happens to be exported; dropping that one keyword made M5 flag the very
  // shape M6's rubric protects. The negative fixture now carries the non-exported seam, so the
  // exemption is a fixture that can fail rather than a claim in a comment.
  it("spares a pure single-use helper whose sole caller does the I/O — the seam class M6 spares too (#370/#325)", () => {
    const negatives = byTaxonomy("single-use-helper/negative", "M5 — Single-use helper");
    expect(negatives).toEqual([]);
    // ...and the exemption is not a blanket async pass: a helper doing the I/O ITSELF is still slop.
    const pos = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper");
    expect(pos.some((f) => f.title.includes("loadRate"))).toBe(true);
    const evidence = pos.find((f) => f.title.includes("loadRate"))?.evidence ?? "";
    expect(evidence).toContain("exempts a helper that does no I/O of its own whose one caller is async or awaits");
    // #1532/#1345: the bound reaches the client WITH ITS POPULATION. #1447 disclosed the bound and
    // shipped no number, which leaves a reader nothing to weigh it against. Re-measured 2026-07-31
    // over the same ten pins: 592 spared (653 before #1532/#1533), 380 on an await that has nothing
    // to do with the helper, 24 on an async caller this pass could not read.
    expect(evidence).toContain("592");
    expect(evidence).toContain("653");
    expect(evidence).toContain("380");
    expect(evidence).toContain("24");
  });

  // #1533 — the `async` caller that awaits NOTHING. MEASURED 2026-07-31 over the same ten pins:
  // 39 rows, of which 14 now fire and 25 stay spared; all 14 were read at source and none is a
  // false positive. Each assertion below has a live counterexample in the negative fixture, so
  // neither direction can pass by accident.
  it("fires when an async caller that awaits nothing provably does no async work, and only then (#1533)", () => {
    const titles = byTaxonomy("single-use-helper/positive", "M5 — Single-use helper").map((f) => f.title);
    expect(titles.some((t) => t.includes("buildFeedXml"))).toBe(true); // caller returns `new Response(...)`
    expect(titles.some((t) => t.includes("detectIntent"))).toBe(true); // needs the CROSS-FILE hop to know composeStarterResult is sync
    // All three counterexamples must stay spared: a caller that returns a local async function's
    // promise, one that hands an async callback to a constructor, and one whose callee is a
    // package outside the repo and therefore unreadable.
    expect(byTaxonomy("single-use-helper/negative", "M5 — Single-use helper")).toEqual([]);
  });
});

describe("finding shape", () => {
  it("emits sequential SLOP-* ids", () => {
    const findings = detectSlopFindings(loadFixtureDir("redundant-boolean/positive"));
    expect(findings.length).toBeGreaterThan(0);
    findings.forEach((f, i) => expect(f.id).toBe(`SLOP-${String(i + 1).padStart(2, "0")}`));
  });

  it("ignores non-source files", () => {
    expect(detectSlopFindings([{ path: "README.md", text: "// TODO: implement everything 🚀" }])).toHaveLength(0);
  });
});
