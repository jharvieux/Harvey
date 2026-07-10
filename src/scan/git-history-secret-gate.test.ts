import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { buildGitHistoryFixture, scoreGitHistoryResults, type TruffleHogGitResult } from "./git-history-secret-gate.js";

const scratches: string[] = [];
afterEach(() => {
  for (const s of scratches.splice(0)) rmSync(s, { recursive: true, force: true });
});

describe("scoreGitHistoryResults — pure scoring against recorded trufflehog output", () => {
  it("passes when the planted secret is caught and the benign file draws nothing", () => {
    const results: TruffleHogGitResult[] = [
      { DetectorName: "Github", SourceMetadata: { Data: { Git: { file: "lib/leaked-token.js", commit: "abc123" } } } },
    ];
    const score = scoreGitHistoryResults(results);
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
    const results: TruffleHogGitResult[] = [
      { DetectorName: "Github", SourceMetadata: { Data: { Git: { file: "lib/leaked-token.js", commit: "abc123" } } } },
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
