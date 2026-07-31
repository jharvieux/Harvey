import { spawn } from "node:child_process";
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

// #1511/#1512: ci.yml's heavy-cli job runs 3 matrix shards, each independently calling
// .github/actions/alert-issue on failure. All three raced `find_open` (gh issue list) against
// `gh issue create` and opened two tracker issues for one failure. This test exercises the ACTUAL
// shared script (find-or-update.sh) under real OS-level concurrency — genuine background bash
// processes racing a mocked `gh` — rather than asserting anything about the logic by inspection.
//
// The mock `gh` (test-fixtures/mock-gh.sh) is backed by a JSON "issue store" file, guarded by an
// mkdir-based spinlock so each individual mock call is atomic like a real GitHub API request, while
// the gap BETWEEN calls (list, then create) is exactly where the real race lives. `gh issue list`
// blocks on a per-call-index BARRIER until MOCK_GH_BARRIER racers have all reached THAT SAME call
// (1st = find_open's pre-create check, 2nd = reconcile_duplicates' post-create read), so every
// racer's check happens before any racer's act, and every racer's reconcile happens after every
// racer's create — reproducing the race, and its convergence, BY CONSTRUCTION rather than by luck.
// Two weaker designs were tried and measured unreliable first; see mock-gh.sh's header for the
// numbers and why each one failed.

const ACTION_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", ".github", "actions", "alert-issue");
const FIND_OR_UPDATE_SH = join(ACTION_DIR, "find-or-update.sh");
const MOCK_GH_SH = join(ACTION_DIR, "test-fixtures", "mock-gh.sh");
const PRE_FIX_SH = join(ACTION_DIR, "test-fixtures", "pre-1511-find-or-update.sh");

interface Fixture {
  dir: string;
  mockGhDir: string;
  store: string;
}

function makeFixture(): Fixture {
  const dir = mkdtempSync(join(tmpdir(), "alert-issue-race-"));
  const mockGhDir = join(dir, "bin");
  mkdirSync(mockGhDir);
  const ghPath = join(mockGhDir, "gh");
  copyFileSync(MOCK_GH_SH, ghPath);
  chmodSync(ghPath, 0o755);
  const store = join(dir, "store.json");
  writeFileSync(store, "[]");
  return { dir, mockGhDir, store };
}

function readStore(store: string): Array<{ number: number; state: string; comments: number }> {
  return JSON.parse(readFileSync(store, "utf8"));
}

/**
 * Runs one `find_or_update real "<title>" "<body>"` invocation as a genuine child bash process.
 * `racerId` must be unique per concurrently-running racer — it is how the mock `gh` recognizes
 * "this racer's 2nd list call", since $PPID is a different, freshly-forked subshell on every single
 * pipe/command-substitution call and does not identify the racer (see mock-gh.sh's header).
 */
function runRacer(fixture: Fixture, functionsFile: string, barrierCount: number, racerId: number): Promise<void> {
  return new Promise((res, rej) => {
    const script = [
      "set -euo pipefail",
      'MARKER="ci-test-alert"',
      'SUFFIX=" - drill"',
      `source "${functionsFile}"`,
      'find_or_update real "Test alert" "body text"',
    ].join("\n");
    const child = spawn("bash", ["-c", script], {
      env: {
        ...process.env,
        PATH: `${fixture.mockGhDir}:${process.env.PATH}`,
        MOCK_GH_STORE: fixture.store,
        MOCK_GH_BARRIER: String(barrierCount),
        RACER_ID: String(racerId),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => (code === 0 ? res() : rej(new Error(`racer exited ${code}: ${stderr}`))));
  });
}

describe("alert-issue duplicate-alarm race (#1511/#1512)", () => {
  let fixture: Fixture | undefined;

  afterEach(() => {
    if (fixture) rmSync(fixture.dir, { recursive: true, force: true });
    fixture = undefined;
  });

  it("sanity: a single find_or_update call against the real script creates exactly one issue", async () => {
    fixture = makeFixture();
    await runRacer(fixture, FIND_OR_UPDATE_SH, 0, 0);
    const issues = readStore(fixture.store);
    expect(issues.filter((i) => i.state === "open")).toHaveLength(1);
    expect(issues).toHaveLength(1);
  });

  it("FALSIFIER: the pre-fix logic really does produce duplicate issues under real concurrency", async () => {
    fixture = makeFixture();
    // 5 genuine background bash processes, launched together, all delayed identically on their
    // first `gh issue list` so all 5 observe "nothing open" before any of them creates.
    await Promise.all(Array.from({ length: 5 }, (_, i) => runRacer(fixture!, PRE_FIX_SH, 5, i)));
    const openCount = readStore(fixture.store).filter((i) => i.state === "open").length;
    // This is the bug reproducing, not a property of the harness: with no reconcile step, every
    // racer that saw an empty list creates its own issue.
    expect(openCount).toBe(5);
  });

  it("the shipped find-or-update.sh converges the same 5 racers on exactly ONE open issue", async () => {
    fixture = makeFixture();
    await Promise.all(Array.from({ length: 5 }, (_, i) => runRacer(fixture!, FIND_OR_UPDATE_SH, 5, i)));
    const issues = readStore(fixture.store);
    expect(issues.filter((i) => i.state === "open")).toHaveLength(1);
    // All 5 issues still exist (created, then reconciled) — this is convergence, not silent
    // deletion: 4 got commented-and-closed as duplicates, not erased.
    expect(issues).toHaveLength(5);
    expect(issues.filter((i) => i.comments > 0)).not.toHaveLength(0);
  });
});
