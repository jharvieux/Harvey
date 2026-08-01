import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  auditEntriesHeaders,
  checkClaims,
  commentBlocks,
  commentLines,
  entriesFiles,
  extractClaims,
  loadRows,
  residualRatchet,
} from "./entries-header-drift.js";
import type { EntryRow, FileReport } from "./entries-header-drift.js";

const B15 = "src/scan/calibration/b15-nextjs-authz.entries.ts";

function claimsIn(source: string, rows: readonly EntryRow[]) {
  const ids = rows.map((r) => r.id);
  return commentBlocks(source).flatMap((b) => extractClaims(b, ids).claims);
}

function violationsFor(source: string, rows: readonly EntryRow[]) {
  return checkClaims("fixture.entries.ts", rows, claimsIn(source, rows));
}

// The rows a synthetic header is judged against. Written here, not read from the corpus, so a test
// that is supposed to prove the checker works cannot pass by agreeing with the file it reads.
const ROWS: EntryRow[] = [
  { id: "P-ALPHA", expectedTier: "review" },
  { id: "P-BETA", expectedTier: "review" },
  { id: "P-GAMMA", expectedTier: "none", gapKind: "measured-gap" },
  { id: "N-DELTA" },
];

describe("the committed corpus", () => {
  let reports: FileReport[];

  it("has no header contradicting its own rows", async () => {
    reports = await auditEntriesHeaders();
    const violations = reports.flatMap((r) => r.violations);
    expect(
      violations.map((v) => `${v.file}:${v.line} ${v.claim}: header says ${v.stated}, rows say ${v.actual}`),
    ).toEqual([]);
  });

  it("judges a real population rather than an empty one", async () => {
    reports ??= await auditEntriesHeaders();
    // A gate that resolved zero claims would report the same clean run as one that resolved many —
    // the #1345 "a limit with a population of zero is a guess" shape. These floors are deliberately
    // below the measured 46/17 so ordinary corpus growth does not trip them, but a plumbing change
    // that silently stopped extracting anything does.
    expect(reports.length).toBeGreaterThanOrEqual(40);
    expect(reports.flatMap((r) => r.claims).length).toBeGreaterThanOrEqual(12);
  });

  it("discloses what its vocabulary could not read, and the disclosure stays true", async () => {
    reports ??= await auditEntriesHeaders();
    const { risen, stale } = residualRatchet(reports);
    expect({ risen, stale }).toEqual({ risen: [], stale: [] });
  });
});

// Criterion 4. Both directions of the b15 correction, against the REAL file and the REAL rows —
// the expected numbers below are literals, never re-derived from the prose or the array the checker
// reads, because four guards in this repo turned out to be copies of the thing they guarded.
describe("negative control: the b15 header", () => {
  it("passes as corrected, and fails when the corrected sentence is reverted", async () => {
    const rows = await loadRows(B15);
    const source = readFileSync(B15, "utf8");

    expect(violationsFor(source, rows)).toEqual([]);

    // The exact wording #1811 left behind, restored.
    const reverted = source.replace(
      "The one `none` row leaves the recall denominator",
      'The two "none" rows leave the recall denominator',
    );
    expect(reverted, "the corrected sentence was not found — this control is testing nothing").not.toBe(source);

    const violations = violationsFor(reverted, rows);
    expect(violations.map((v) => [v.claim, v.stated, v.actual])).toEqual([["at least 2 none rows", "2", "1"]]);
  });

  it("fails when the ROWS move under a correct header", async () => {
    const rows = await loadRows(B15);
    const source = readFileSync(B15, "utf8");

    // The defect as it actually arrives: a class graduates and nobody edits the prose.
    const graduated = rows.map((r) => (r.id === "P-MW-SOLE-AUTHZ" ? { ...r, expectedTier: "review", gapKind: undefined } : r));
    const violations = violationsFor(source, graduated);

    // Three distinct claims about that row survive in the header — its count, its tier and its gap
    // kind — and every one of them has to notice. The tier claim is stated in two separate clauses,
    // so it is reported twice; what matters is that no kind of claim stays silent.
    expect([...new Set(violations.map((v) => v.claim))].sort()).toEqual([
      "at least 1 none rows",
      "gap kind of P-MW-SOLE-AUTHZ",
      "tier of P-MW-SOLE-AUTHZ",
    ]);
    expect(violations.length).toBeGreaterThanOrEqual(3);
  });
});

describe("claim extraction", () => {
  it("fails a count the rows fall short of, and passes the same sentence when they do not", () => {
    const twoGaps = "// The two `none` rows leave the recall denominator.\nexport const x = 1;\n";
    expect(violationsFor(twoGaps, ROWS).map((v) => [v.stated, v.actual])).toEqual([["2", "1"]]);

    const oneGap = "// The one `none` row leaves the recall denominator.\nexport const x = 1;\n";
    expect(violationsFor(oneGap, ROWS)).toEqual([]);
  });

  it("fails a universal one row contradicts, and passes it when none does", () => {
    const src = "// Every entry here is `review` tier.\nexport const x = 1;\n";
    expect(violationsFor(src, ROWS).map((v) => v.actual)).toEqual(["P-GAMMA=none"]);
    expect(violationsFor(src, ROWS.filter((r) => r.id !== "P-GAMMA"))).toEqual([]);
  });

  it("fails a row named beside a tier it does not carry", () => {
    const src = "// P-ALPHA is `expectedTier: \"none\"` with gapKind \"measured-gap\".\nexport const x = 1;\n";
    expect(violationsFor(src, ROWS).map((v) => v.claim).sort()).toEqual(["gap kind of P-ALPHA", "tier of P-ALPHA"]);
  });

  it("accepts a from/to narration naming the current tier, and still fails one that does not", () => {
    const ok = "// #1811 graduated P-ALPHA from `none` to `review` on a real rule.\nexport const x = 1;\n";
    expect(violationsFor(ok, ROWS)).toEqual([]);

    const stale = "// P-ALPHA is `expectedTier: \"none\"`, outstanding work.\nexport const x = 1;\n";
    expect(violationsFor(stale, ROWS).map((v) => v.claim)).toContain("tier of P-ALPHA");
  });

  it("does not read a claim out of a `//` inside a row's note string", () => {
    const src = `export const x = [{ id: "P-ALPHA", note: "see // Every entry here is \`review\` tier" }];\n`;
    expect(claimsIn(src, ROWS)).toEqual([]);
    expect(commentLines(src)).toEqual([]);
  });

  it("matches a claim that wraps across a line break", () => {
    const wrapped = "// The two\n// `none` rows leave the recall denominator.\nexport const x = 1;\n";
    expect(violationsFor(wrapped, ROWS).map((v) => [v.stated, v.actual])).toEqual([["2", "1"]]);
  });
});

describe("the vocabulary's declared bounds", () => {
  const residualOf = (source: string) =>
    commentBlocks(source).flatMap((b) => extractClaims(b, ROWS.map((r) => r.id)).residual);

  it("does not judge a past-tense narration, and counts it instead", () => {
    const src = "// Every row here used to be `expectedTier: \"connected\"`.\nexport const x = 1;\n";
    expect(violationsFor(src, ROWS)).toEqual([]);
    expect(residualOf(src).map((t) => t.reason)).toEqual(["historical-narration"]);
  });

  it("does not judge a clause whose subject row lives in another file, and counts it instead", () => {
    const src = "// P-MW-SOLE-AUTHZ is the one member still `expectedTier: \"none\"`.\nexport const x = 1;\n";
    expect(violationsFor(src, ROWS)).toEqual([]);
    expect(residualOf(src).map((t) => t.reason)).toEqual(["cross-file-row-reference"]);
  });

  it("lets a subset count stand when the file holds more, but still fails a zero claim", () => {
    const subset = "// All two of those remain `review` rows.\nexport const x = 1;\n";
    expect(violationsFor(subset, ROWS)).toEqual([]);

    const zero = "// This corpus has no `none` rows left.\nexport const x = 1;\n";
    expect(violationsFor(zero, ROWS).map((v) => [v.claim, v.actual])).toEqual([["no none rows", "1"]]);
  });

  it("does not count the spaced English phrase, but still reads it beside a row id", () => {
    const english = "// The first live run recorded one measured gap.\nexport const x = 1;\n";
    expect(violationsFor(english, ROWS)).toEqual([]);

    const beside = "// P-ALPHA MEASURED GAP, outstanding work.\nexport const x = 1;\n";
    expect(violationsFor(beside, ROWS).map((v) => [v.claim, v.actual])).toEqual([
      ["gap kind of P-ALPHA", 'not a gap (tier "review")'],
    ]);
  });

  it("reads no quantifier out of an issue ref, a section or a date", () => {
    const src = "// As of #425 (§4a, 2026-07-31) it is a corpus entry at the `none` tier.\nexport const x = 1;\n";
    expect(violationsFor(src, ROWS)).toEqual([]);
    expect(residualOf(src).map((t) => t.reason)).toEqual(["no-quantifier-or-noun"]);
  });
});

describe("the residual ratchet", () => {
  const report = (file: string, residualCount: number): FileReport => ({
    file: `src/scan/calibration/${file}`,
    rows: 1,
    commentLines: 1,
    claims: [],
    residual: Array.from({ length: residualCount }, () => ({
      line: 1,
      token: "`review`",
      reason: "no-quantifier-or-noun" as const,
      text: "x",
    })),
    violations: [],
  });

  it("fails on unread prose the baseline does not cover", () => {
    const { risen } = residualRatchet([report("b10-deps.entries.ts", 99)]);
    expect(risen).toEqual([{ file: "b10-deps.entries.ts", baseline: 1, actual: 99 }]);
  });

  it("fails on a baseline row that has since become readable", () => {
    const { stale } = residualRatchet([report("b10-deps.entries.ts", 0)]);
    expect(stale).toContainEqual({ file: "b10-deps.entries.ts", baseline: 1, actual: 0 });
  });
});

describe("discovery", () => {
  it("covers every entries file in the corpus directory, so a new one cannot arrive unwatched", async () => {
    const files = entriesFiles();
    expect(files.length).toBeGreaterThanOrEqual(40);
    for (const f of files) expect((await loadRows(f)).length).toBeGreaterThan(0);
  });
});
