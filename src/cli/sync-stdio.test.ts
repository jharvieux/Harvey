// #1758 — proven through the PROCESS, because the defect does not exist inside one. Writes to a
// pipe are only asynchronous across a real fd, so an in-process assertion could not see this.
//
// Both directions on purpose. A "marker survived" test proves nothing alone — a run whose output
// was never truncated in the first place satisfies it. The negative control is the whole point:
// it fails the way CI failed, so deleting sync-stdio.ts's body turns this file red (#1628/#1738 —
// 223 of 384 corpus positives once had no failing direction, which is how this class hides).

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SYNC_STDIO = pathToFileURL(join(REPO_ROOT, "src", "cli", "sync-stdio.ts")).href;
const MARKER = "THE-VERDICT-LINE";
// Comfortably past a 64 KiB pipe buffer, so the queue is guaranteed non-empty at exit. The volume
// is what makes the negative control deterministic rather than a coin flip.
const FILLER_LINES = 20000;

const dir = mkdtempSync(join(tmpdir(), "harvey-sync-stdio-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** A CLI whose last act is to print a verdict and exit non-zero — the shape of every gate here. */
function fixture(withGuard: boolean): string {
  const file = join(dir, `${withGuard ? "guarded" : "bare"}.ts`);
  writeFileSync(
    file,
    [
      withGuard ? `import "${SYNC_STDIO}";` : "",
      `for (let i = 0; i < ${FILLER_LINES}; i++) console.log(\`filler \${i} \${"x".repeat(60)}\`);`,
      `console.log("${MARKER}");`,
      "process.exit(1);",
    ].join("\n"),
  );
  return file;
}

// A reader that does not drain immediately is what makes this deterministic, and it is also what
// actually happens: the parent is a busy CI runner or a vitest worker, not an idle pipe. Attaching
// the reader late guarantees the OS pipe buffer is full and the write queue non-empty at exit, so
// the unguarded run loses its tail every time instead of most times. An earlier version of this
// file read immediately and the negative control passed alone but went green under parallel load —
// a flaky guard against a flaky test, which is worth nothing.
const READ_AFTER_MS = 400;

/** stdio exactly as validate-calibration.test.ts and every CI step spawn a gate. */
function runPiped(file: string): Promise<{ code: number | null; out: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [file], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.setEncoding("utf8");
    // Same protocol for both directions, so the only variable is the guard itself.
    setTimeout(() => child.stdout.on("data", (d: string) => (out += d)), READ_AFTER_MS);
    child.on("error", rej);
    child.on("close", (code) => res({ code, out }));
  });
}

describe("sync-stdio — a verdict printed before process.exit() survives a piped stdout (#1758)", () => {
  it("NEGATIVE CONTROL: without the guard, the last line before exit is discarded", async () => {
    const bare = fixture(false);
    const runs = [await runPiped(bare), await runPiped(bare)];

    // The exit code always survives — that is exactly why this is dangerous. A gate reports
    // failure while the sentence explaining it is gone, which reads as a crash.
    expect(runs.map((r) => r.code)).toEqual([1, 1]);
    for (const [i, r] of runs.entries()) {
      expect(
        r.out,
        `run ${i + 1} of the UNGUARDED fixture kept its final line. If this stops failing, the truncation this module exists to prevent is no longer reproducible here and the guarded test below proves nothing — investigate before deleting either.`,
      ).not.toContain(MARKER);
    }
  }, 60000);

  it("with the guard imported, the verdict survives every run", async () => {
    const guarded = fixture(true);
    const runs = [await runPiped(guarded), await runPiped(guarded)];

    expect(runs.map((r) => r.code)).toEqual([1, 1]);
    for (const [i, r] of runs.entries()) {
      expect(r.out, `run ${i + 1} lost its verdict line despite the guard`).toContain(MARKER);
    }
  }, 60000);
});

// A one-time sweep of 58 files decays the moment someone adds the 59th. Discovery-backed, not a
// checked-in list: the population is recomputed from the tree every run, so a NEW exiting CLI fails
// here instead of shipping with a droppable verdict. Same posture as the #1330 conditional-scan
// registry — an unregistered module fails loud rather than being assumed covered.
describe("every CLI that exits non-zero imports the guard (#1758)", () => {
  // A module imported by other src files is not a program: its entry point already installed the
  // guard before anything could write. `args.ts` is the only one today — it is imported by 10 CLIs
  // and by no test as an entry. A file that STOPS being a library shows up as a failure here.
  const LIBRARIES = new Set(["src/cli/args.ts"]);

  it("has no unguarded exiting CLI", () => {
    const files = execFileSync("git", ["grep", "-l", "process\\.exit([1-9]", "--", "src/cli/*.ts"], { cwd: REPO_ROOT, encoding: "utf8" })
      .trim()
      .split("\n")
      .filter((f) => !f.includes(".test."));

    // If this ever reads 0, the grep stopped matching and the check below would pass vacuously —
    // the shape #1388/#1509 exist to prevent. The population is the measurement.
    expect(files.length, "no exiting CLI found at all — the discovery grep is broken, not the tree").toBeGreaterThan(20);

    const unguarded = files.filter((f) => !LIBRARIES.has(f) && !readFileSync(join(REPO_ROOT, f), "utf8").includes('import "./sync-stdio.js";'));
    expect(
      unguarded,
      `these CLIs call process.exit() with a non-zero code but do not import ./sync-stdio.js, so whatever they print last can be discarded when stdout is a pipe (#1758). Add the import as the FIRST import, or add the file to LIBRARIES if it is not a program.`,
    ).toEqual([]);
  });

  it("NEGATIVE CONTROL: the sweep would notice an unguarded file", () => {
    // Proves the assertion above is capable of failing — the filter, not just the list it produced.
    const pretendUnguarded = ["src/cli/made-up-gate.ts"].filter((f) => !LIBRARIES.has(f) && !"a file with no guard import".includes('import "./sync-stdio.js";'));
    expect(pretendUnguarded).toEqual(["src/cli/made-up-gate.ts"]);
  });
});
