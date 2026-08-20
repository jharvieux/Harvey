import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildGitHistoryFixture,
  gateResultFromRun,
  runTruffleHogGitJson,
  scoreGitHistoryResults,
  type TruffleHogGitResult,
} from "./git-history-secret-gate.js";

// Real `trufflehog 3.96.0 git --no-verification --results=unverified --json` capture against a
// throwaway repo built like buildGitHistoryFixture (see the sibling PROVENANCE.md). The real run
// emits exactly this one record for the planted PAT and NOTHING for the benign file.
const positiveCapture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./__fixtures__/trufflehog-git-history/trufflehog-3.97.0-git-history.json", import.meta.url)),
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

// #1757 site 1. The guard is on the RUN, so it is exercised against a real child process: a stub
// `trufflehog` on PATH that emits the captured positive record and then chooses its exit status.
// The pre-#1757 code took stdout from a failed run with no check at all, so the "emits the positive
// then dies" case below scored pass=true — a crashed history walk reporting a caught secret and a
// clear negative.
function stubTruffleHog(script: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-th-stub-"));
  scratches.push(dir);
  writeFileSync(join(dir, "trufflehog"), `#!/bin/sh\n${script}\n`, { mode: 0o755 });
  return dir;
}

const withStub = <T>(dir: string, fn: () => T): T => {
  const path = process.env["PATH"];
  process.env["PATH"] = `${dir}:${path ?? ""}`;
  try {
    return fn();
  } finally {
    process.env["PATH"] = path;
  }
};

const RECORD = JSON.stringify(positiveCapture[0]);

describe("runTruffleHogGitJson — an incomplete run is not a clean scan (#1757)", () => {
  it("disables the mutable self-updater before scanning", () => {
    const stub = stubTruffleHog('[ "$1" = "--no-update" ] || exit 9\nexit 0');
    expect(withStub(stub, () => runTruffleHogGitJson("/tmp/does-not-matter")).failure).toBeUndefined();
  });

  it("parses a completed run", () => {
    const stub = stubTruffleHog(`echo '${RECORD}'\nexit 0`);
    const run = withStub(stub, () => runTruffleHogGitJson("/tmp/does-not-matter"));
    expect(run.failure).toBeUndefined();
    expect(gateResultFromRun(run).pass).toBe(true);
  });

  it("refuses a run that emitted the planted secret and THEN died — the case the old guard passed", () => {
    const stub = stubTruffleHog(`echo '${RECORD}'\nexit 3`);
    const run = withStub(stub, () => runTruffleHogGitJson("/tmp/does-not-matter"));
    expect(run.failure).toContain("exited with code 3");
    expect(run.records).toEqual([]);

    const gate = gateResultFromRun(run);
    expect(gate.pass).toBe(false);
    expect(gate.detail).toContain("NOT SCORED");
    expect(gate.detail).toContain("exited with code 3");
  });

  it("refuses a run killed by a signal", () => {
    const stub = stubTruffleHog(`echo '${RECORD}'\nkill -9 $$`);
    const run = withStub(stub, () => runTruffleHogGitJson("/tmp/does-not-matter"));
    expect(run.failure).toMatch(/killed by signal SIGKILL|exited with code/);
    expect(gateResultFromRun(run).pass).toBe(false);
  });

  it("refuses a clean exit whose stream does not parse, instead of throwing out of the gate", () => {
    const stub = stubTruffleHog(`echo '{"DetectorName": "Github"'\nexit 0`);
    const run = withStub(stub, () => runTruffleHogGitJson("/tmp/does-not-matter"));
    expect(run.failure).toContain("did not parse");
    expect(gateResultFromRun(run).pass).toBe(false);
  });

  it("reports a missing binary rather than reading it as an empty, clean scan", () => {
    const empty = mkdtempSync(join(tmpdir(), "harvey-empty-path-"));
    scratches.push(empty);
    const path = process.env["PATH"];
    process.env["PATH"] = empty;
    try {
      const run = runTruffleHogGitJson("/tmp/does-not-matter");
      expect(run.failure).toContain("could not be run");
      expect(gateResultFromRun(run).pass).toBe(false);
    } finally {
      process.env["PATH"] = path;
    }
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
