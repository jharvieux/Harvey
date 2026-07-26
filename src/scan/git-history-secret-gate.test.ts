import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { buildGitHistoryFixture, scoreGitHistoryResults, type TruffleHogGitResult } from "./git-history-secret-gate.js";

// Real `trufflehog 3.96.0 git --no-verification --results=unverified --json` capture against a
// throwaway repo built like buildGitHistoryFixture (see the sibling PROVENANCE.md). The real run
// emits exactly this one record for the planted PAT and NOTHING for the benign file.
const positiveCapture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./__fixtures__/trufflehog-git-history/trufflehog-3.96.0-git-history.json", import.meta.url)),
    "utf8",
  ),
) as TruffleHogGitResult[];

const scratches: string[] = [];
afterEach(() => {
  for (const s of scratches.splice(0)) rmSync(s, { recursive: true, force: true });
});

describe("scoreGitHistoryResults — pure scoring against recorded trufflehog output", () => {
  it("passes when the planted secret is caught and the benign file draws nothing", () => {
    const score = scoreGitHistoryResults(positiveCapture);
    expect(score.pass).toBe(true);
    expect(score.positiveCaught).toBe(true);
    expect(score.negativeClear).toBe(true);
  });

  it("fails when the planted secret is missed (git-history recovery regressed)", () => {
    const score = scoreGitHistoryResults([]);
    expect(score.pass).toBe(false);
    expect(score.positiveCaught).toBe(false);
    expect(score.detail).toContain("MISSED");
  });

  it("fails when the benign add/remove is flagged (a free-count false positive)", () => {
    // The captured positive record, plus a benign-file hit. A real trufflehog run never emits the
    // second record (its absence is the negative control); this synthetic hit exists only to prove
    // scoring REJECTS a benign-file match, so it stays a hand-built control by necessity.
    const results: TruffleHogGitResult[] = [
      ...positiveCapture,
      { DetectorName: "Generic", SourceMetadata: { Data: { Git: { file: "lib/build-info.js", commit: "def456" } } } },
    ];
    const score = scoreGitHistoryResults(results);
    expect(score.pass).toBe(false);
    expect(score.negativeClear).toBe(false);
    expect(score.detail).toContain("FALSE POSITIVE");
  });
});

describe("buildGitHistoryFixture — the throwaway repo shape (no trufflehog binary needed)", () => {
  it("commits the secret then removes it, so HEAD carries neither planted file", () => {
    const { dir, cleanup } = buildGitHistoryFixture();
    scratches.push(dir);
    try {
      const head = execFileSync("git", ["-C", dir, "ls-tree", "-r", "--name-only", "HEAD"], { encoding: "utf8" });
      expect(head).not.toContain("lib/leaked-token.js");
      expect(head).not.toContain("lib/build-info.js");

      // Both files must still be reachable via history (that's the whole point of the fixture).
      const log = execFileSync("git", ["-C", dir, "log", "--all", "--oneline", "--name-only"], { encoding: "utf8" });
      expect(log).toContain("lib/leaked-token.js");
      expect(log).toContain("lib/build-info.js");
    } finally {
      cleanup();
    }
  });
});
