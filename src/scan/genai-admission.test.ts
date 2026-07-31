// Guards the classification in genai-admission.ts (#1600). The tool's whole value is the
// split between a HIGH-precision trailer admission and a LOW-precision prose one — if that split is
// wrong the census reports a real population as a different population, which is the shape the
// issue exists to stop.
//
// The first revision of this tool got exactly that wrong: it keyed the trailer off "the first line"
// of the record, read the newline that `%n` emits after the record sentinel, and scored EVERY repo
// at 0 trailer admissions across an 18-repo run while the trailer text fell through to the prose
// bucket. It exited 0 and produced a plausible-looking table. So these cases assert the counts in
// both directions, not merely that the parser runs.

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { admittedCommits, allZeroAdmissionError, ADMISSION_FORMAT, blameLineShas, CENSUS_FORMAT, censusOfLog, density } from "./genai-admission.js";

// Builds the same text `git log --format=CENSUS_FORMAT --name-only` produces, from the format
// constant itself, so a change to the format keeps the fixture and the parser in step (a fixture
// with its own hardcoded sentinels would keep passing after such a change).
const commit = (trailers: string, message: string, files: string[]): string =>
  CENSUS_FORMAT.replace("%n%(trailers:key=Co-authored-by,valueonly,separator=%x2C)%n", `\n${trailers}\n`)
    .replace("%n%B%n", `\n${message}\n`)
    .replace(/%n$/, "") + `\n${files.join("\n")}\n\n`;

const AI_TRAILER = "Claude <noreply@anthropic.com>";
const HUMAN_TRAILER = "Dana Rivera <dana@example.com>";

describe("censusOfLog", () => {
  it("counts an assistant Co-authored-by trailer as a TRAILER admission, not a prose one", () => {
    const c = censusOfLog(commit(AI_TRAILER, "feat: add invoice totals", ["src/lib/totals.ts"]));
    expect(c).toMatchObject({ commits: 1, trailerAdmitted: 1, proseOnlyAdmitted: 0, admittedProduct: 1, unadmittedProduct: 0 });
  });

  it("counts an assistant named only in the MESSAGE as a prose admission, keeping the buckets apart", () => {
    const c = censusOfLog(commit(HUMAN_TRAILER, "fix: rewrote this with ChatGPT's help", ["src/lib/totals.ts"]));
    expect(c).toMatchObject({ commits: 1, trailerAdmitted: 0, proseOnlyAdmitted: 1, admittedProduct: 1 });
  });

  it("does not double-count a commit that admits in BOTH the trailer and the message", () => {
    const c = censusOfLog(commit(AI_TRAILER, "chore: generated with Claude Code", ["src/lib/totals.ts"]));
    expect(c).toMatchObject({ trailerAdmitted: 1, proseOnlyAdmitted: 0, admittedProduct: 1 });
  });

  it("counts a commit with a human co-author and no mention as UNADMITTED", () => {
    const c = censusOfLog(commit(HUMAN_TRAILER, "fix: correct the tax rounding", ["src/lib/totals.ts"]));
    expect(c).toMatchObject({ trailerAdmitted: 0, proseOnlyAdmitted: 0, admittedProduct: 0, unadmittedProduct: 1 });
  });

  // The population is defined over commits that touch code the density measurement would read. A
  // docs-only or test-only commit is counted in `commits` but must stay out of BOTH arms, or the
  // feasibility verdict is computed over a population the density figure never sees.
  it("keeps a commit touching no product source out of both arms", () => {
    const docs = censusOfLog(commit(AI_TRAILER, "docs: update README", ["README.md", "docs/design/x.md"]));
    expect(docs).toMatchObject({ commits: 1, trailerAdmitted: 1, productCommits: 0, admittedProduct: 0, unadmittedProduct: 0 });

    const tests = censusOfLog(commit(HUMAN_TRAILER, "test: cover the rounding", ["src/lib/totals.test.ts"]));
    expect(tests).toMatchObject({ commits: 1, productCommits: 0, unadmittedProduct: 0 });
  });

  it("accumulates a mixed history into the two arms the feasibility verdict reads", () => {
    const log = [
      commit(AI_TRAILER, "feat: a", ["src/a.ts"]),
      commit(AI_TRAILER, "feat: b", ["src/b.tsx"]),
      commit(HUMAN_TRAILER, "feat: c", ["src/c.ts"]),
      commit(HUMAN_TRAILER, "docs: d", ["CHANGELOG.md"]),
    ].join("");
    expect(censusOfLog(log)).toMatchObject({ commits: 4, productCommits: 3, trailerAdmitted: 2, admittedProduct: 2, unadmittedProduct: 1 });
  });

  it("reports nothing for an empty history rather than inventing a commit", () => {
    expect(censusOfLog("")).toMatchObject({ commits: 0, productCommits: 0, admittedProduct: 0, unadmittedProduct: 0 });
  });
});

// Every case above builds its `git log` text by string-replacing CENSUS_FORMAT — a format change
// moves fixture and parser together, so a real divergence between what git actually PRINTS for
// `%(trailers:...)` and what the fixture assumes it prints stays invisible. This describe block runs
// the real command against a real local repo instead: no network (git init + commit is entirely
// local), under a second. If a git version ever renders the trailers placeholder or the sentinel
// format differently than the synthesized fixtures assume, this is the only case that would fail.
describe("censusOfLog against a REAL `git log` invocation, not a synthesized fixture", () => {
  it("reproduces the trailer/prose/unadmitted split off real git output", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-genai-admission-real-"));
    try {
      const git = (...args: string[]): string => execFileSync("git", args, { cwd: dir }).toString();
      git("init", "-q");
      git("config", "user.email", "test@example.com");
      git("config", "user.name", "Test");

      writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
      git("add", "a.ts");
      git("commit", "-q", "-m", "feat: a\n\nCo-authored-by: Claude <noreply@anthropic.com>");

      writeFileSync(join(dir, "b.ts"), "export const b = 2;\n");
      git("add", "b.ts");
      git("commit", "-q", "-m", "fix: rewrote this with ChatGPT's help");

      writeFileSync(join(dir, "c.ts"), "export const c = 3;\n");
      git("add", "c.ts");
      git("commit", "-q", "-m", "fix: c\n\nCo-authored-by: Dana Rivera <dana@example.com>");

      const log = execFileSync("git", ["-C", dir, "log", "--no-merges", "--name-only", `--format=${CENSUS_FORMAT}`]).toString();
      const c = censusOfLog(log);
      expect(c).toMatchObject({
        commits: 3,
        productCommits: 3,
        trailerAdmitted: 1,
        proseOnlyAdmitted: 1,
        admittedProduct: 2,
        unadmittedProduct: 1,
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// Same shape as `commit`, for the --density pass's format (sha after the FILES sentinel, no
// --name-only output). Built from ADMISSION_FORMAT for the same anti-drift reason.
const admissionRecord = (trailers: string, message: string, sha: string): string =>
  ADMISSION_FORMAT.replace("%n%(trailers:key=Co-authored-by,valueonly,separator=%x2C)%n", `\n${trailers}\n`)
    .replace("%n%B%n", `\n${message}\n`)
    .replace("%n%H", `\n${sha}`) + "\n";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);

describe("admittedCommits", () => {
  it("returns only the shas whose own commit declared GenAI, by trailer or by message", () => {
    const log = [
      admissionRecord(AI_TRAILER, "feat: a", SHA_A),
      admissionRecord(HUMAN_TRAILER, "fix: b", SHA_B),
      admissionRecord(HUMAN_TRAILER, "chore: drafted with Copilot", "c".repeat(40)),
    ].join("");
    const admitted = admittedCommits(log);
    expect(admitted.has(SHA_A)).toBe(true);
    expect(admitted.has("c".repeat(40))).toBe(true);
    // The load-bearing assertion: a commit with a human co-author and no mention must NOT be in the
    // admitted arm. If it leaks in, every line it wrote is scored as AI-authored.
    expect(admitted.has(SHA_B)).toBe(false);
    expect(admitted.size).toBe(2);
  });

  it("is empty for a history with no declaration at all", () => {
    expect(admittedCommits(admissionRecord(HUMAN_TRAILER, "fix: b", SHA_B)).size).toBe(0);
  });
});

describe("blameLineShas", () => {
  // One sha per LINE, in file order — the density pass indexes into this array by the finding's
  // line number, so an off-by-one or a collapsed group attributes findings to the wrong arm.
  const porcelain = [
    `${SHA_A} 1 1 2`,
    "author Dana",
    "\tconst a = 1;",
    `${SHA_A} 2 2`,
    "author Dana",
    "\tconst b = 2;",
    `${SHA_B} 7 3 1`,
    "author Robin",
    "\tconst c = 3;",
  ].join("\n");

  it("yields one sha per line, preserving order and repeating within a group", () => {
    expect(blameLineShas(porcelain)).toEqual([SHA_A, SHA_A, SHA_B]);
  });

  it("does not mistake the file's own content for a blame header", () => {
    const withDecoyContent = [`${SHA_A} 1 1 1`, "author Dana", `\t// see ${SHA_B} 9 9 9`].join("\n");
    expect(blameLineShas(withDecoyContent)).toEqual([SHA_A]);
  });

  it("returns nothing for empty blame output rather than a phantom line", () => {
    expect(blameLineShas("")).toEqual([]);
  });
});

describe("density", () => {
  it("normalises findings per KLOC of the arm's own attributed lines", () => {
    expect(density(5, 10_000)).toBe(0.5);
  });

  it("returns null rather than dividing by an empty arm", () => {
    expect(density(3, 0)).toBeNull();
  });
});

// The census's own first-revision bug scored every repo at 0 trailer admissions and exited 0 with a
// plausible table (see this file's header comment). This guard is the fix for the residual: an
// all-zero run must fail loud rather than render as a clean negative result.
describe("allZeroAdmissionError", () => {
  it("flags a run where NOTHING admitted across the whole corpus as broken, not empty", () => {
    const msg = allZeroAdmissionError(0, 20_000, 18);
    expect(msg).not.toBeNull();
    expect(msg).toContain("0 of 20000 commits");
    expect(msg).toContain("18 repos");
  });

  it("passes through a run with at least one real admission", () => {
    expect(allZeroAdmissionError(1, 20_000, 18)).toBeNull();
  });
});
