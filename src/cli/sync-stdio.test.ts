// #1758 — proven through the PROCESS, because the defect does not exist inside one. Writes to a
// pipe are only asynchronous across a real fd, so an in-process assertion could not see this.
//
// Both directions on purpose. A "marker survived" test proves nothing alone — a run whose output
// was never truncated in the first place satisfies it. The negative control is the whole point:
// it fails the way CI failed, so deleting sync-stdio.ts's body turns this file red (#1628/#1738 —
// 223 of 384 corpus positives once had no failing direction, which is how this class hides).

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import {
  cliTypeScriptFiles,
  discoverExitingCliFiles,
  unguardedExitingCliFiles,
} from "./verify-sync-stdio.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SYNC_STDIO = pathToFileURL(join(REPO_ROOT, "src", "cli", "sync-stdio.ts")).href;
const CLI_DIR = join(REPO_ROOT, "src", "cli");
const VERIFY_SYNC_STDIO = join(CLI_DIR, "verify-sync-stdio.ts");
const MARKER = "THE-VERDICT-LINE";
const SYNC_STDIO_IMPORT = 'import "./sync-stdio.js";';
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

// The reader must be SLOW, not ABSENT. That distinction is the whole history of this file.
//
// Backpressure needs a reader that drains more slowly than the child writes, so the OS pipe buffer
// stays full and the write queue is non-empty when `process.exit()` fires. Two earlier designs got
// this wrong in opposite directions, and both passed for the wrong reason:
//
//   1. DELAY FROM spawn() (#1768). `tsx` boots in 300-600ms, so the timer routinely expired before
//      the child wrote anything; the reader was already draining and nothing was queued.
//      MEASURED: 3 failures in 6 runs — an intermittently-wrong control.
//   2. DELAY FROM THE FIRST BYTE (#1780's first fix). Worse: the unguarded child exits ~142ms after
//      spawn, long before first-byte+300ms, so the parent captured ZERO bytes — 24/24 runs — and
//      `not.toContain(MARKER)` was satisfied by the EMPTY STRING. Proved vacuous rather than merely
//      indirect: with 100 filler lines (7107 bytes, entirely inside the 64KiB pipe buffer, so
//      NOTHING is truncated) the control still passed. A deterministically-wrong control.
//
// So: keep the stream paused and pull a small chunk on an interval. The child is throttled, the
// buffer stays full, and we still capture the early output — which is what lets the assertions below
// tell a TRUNCATED capture from an ABSENT one.
const READ_CHUNK_BYTES = 4096;
const READ_TICK_MS = 5;

/** stdio exactly as validate-calibration.test.ts and every CI step spawn a gate. */
function runPiped(file: string): Promise<{ code: number | null; out: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [file], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.setEncoding("utf8");
    // No `data` handler: the stream stays paused and only this timer moves bytes, which is the
    // throttle. Same protocol in both directions, so the only variable remains the guard itself.
    const pump = setInterval(() => {
      const chunk = child.stdout.read(READ_CHUNK_BYTES) as string | null;
      if (chunk !== null) out += chunk;
    }, READ_TICK_MS);

    // Resolve only once BOTH the exit code and the end of stdout are in hand. Waiting on `end`
    // alone lost the code (`[1, null]`) and waiting on `exit` alone stranded a paused stream, which
    // truncated the GUARDED run and made the guard look broken. Neither event orders reliably: the
    // `end`-first interleaving never occurred in 20 local macOS runs and DID occur on Linux CI, so
    // this is a barrier rather than a preference about which fires first.
    let code: number | null = null;
    let exited = false;
    let ended = false;
    const settle = (): void => {
      if (exited && ended) res({ code, out });
    };

    child.on("exit", (c) => {
      code = c;
      exited = true;
      // The process is gone, so nothing more can be queued — the throttle has done its job and the
      // rest can come at full speed.
      clearInterval(pump);
      child.stdout.on("data", (d: string) => (out += d));
      child.stdout.resume();
      settle();
    });
    child.stdout.on("end", () => {
      ended = true;
      settle();
    });
    child.on("error", (e) => {
      clearInterval(pump);
      rej(e);
    });
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
      // THIS ASSERTION IS THE POINT. `not.toContain` is satisfied by the empty string, so without a
      // non-empty floor an ABSENT capture is indistinguishable from a TRUNCATED one — and a reader
      // that never attached would score as proof of the very defect it failed to observe. #1780's
      // first fix passed 24/24 that way. Truncation means we saw the head and lost the tail.
      expect(
        r.out.length,
        `run ${i + 1} of the UNGUARDED fixture captured NOTHING. That is not truncation, it is a reader that never drained — the control would be green whether or not the defect exists. Fix the reader, do not relax this.`,
      ).toBeGreaterThan(0);
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
  const LIBRARIES = new Set([join(CLI_DIR, "args.ts")]);

  it("has no unguarded exiting CLI", () => {
    const files = cliTypeScriptFiles(CLI_DIR);
    const exiting = discoverExitingCliFiles(files, LIBRARIES, (file) => readFileSync(file, "utf8"));

    // If this ever reads 0, discovery stopped matching and the check below would pass vacuously —
    // the shape #1388/#1509 exist to prevent. The population is the measurement.
    expect(exiting.length, "no exiting CLI found at all — syntax discovery is broken, not the tree").toBeGreaterThan(20);

    const unguarded = unguardedExitingCliFiles(files, LIBRARIES, (file) => readFileSync(file, "utf8"));
    expect(
      unguarded,
      `these CLIs call process.exit() with a non-zero code but do not import ./sync-stdio.js, so whatever they print last can be discarded when stdout is a pipe (#1758). Add the import as the FIRST import, or add the file to LIBRARIES if it is not a program.`,
    ).toEqual([]);
  });

  it("NEGATIVE CONTROL: the sweep would notice an unguarded file", () => {
    // Exercise the SAME filter as the tree assertion with independent sources. Exact membership
    // proves both directions: the bare program must be included, while a guarded program and the
    // named library must be excluded. Returning [] or every input therefore reddens this test.
    const bare = join(CLI_DIR, "made-up-bare-gate.ts");
    const guarded = join(CLI_DIR, "made-up-guarded-gate.ts");
    const library = join(CLI_DIR, "args.ts");
    const sources = new Map([
      [bare, "process.exit(1);"],
      [guarded, `${SYNC_STDIO_IMPORT}\nprocess.exit(1);`],
      [library, "process.exit(1);"],
    ]);

    const pretendUnguarded = unguardedExitingCliFiles([bare, guarded, library], LIBRARIES, (file) => sources.get(file) ?? "");

    expect(pretendUnguarded).toEqual([bare]);
  });

  it("discovers exit variants and first-import violations from planted source files", () => {
    const fixtureDir = mkdtempSync(join(tmpdir(), "harvey-sync-stdio-discovery-"));
    try {
      const files = {
        "dynamic.ts": 'import "./sync-stdio.js";\nprocess.exit(code);\n',
        "exit-code.ts": 'import "./sync-stdio.js";\nprocess.exitCode = 1;\n',
        "literal.ts": 'import "./sync-stdio.js";\nprocess.exit(1);\n',
        "library.ts": "process.exit(1);\n",
        "late.ts": 'import { readFileSync } from "node:fs";\nimport "./sync-stdio.js";\nprocess.exit(1);\n',
        "comment-only.ts": '// import "./sync-stdio.js";\nprocess.exit(1);\n',
        "zero.ts": "process.exit(0);\n",
      };
      for (const [name, source] of Object.entries(files)) writeFileSync(join(fixtureDir, name), source);
      const sourceFiles = cliTypeScriptFiles(fixtureDir);
      const libraries = new Set([join(fixtureDir, "library.ts")]);
      const read = (file: string) => readFileSync(file, "utf8");
      expect(discoverExitingCliFiles(sourceFiles, libraries, read).map((file) => file.split("/").pop())).toEqual([
        "comment-only.ts", "dynamic.ts", "exit-code.ts", "late.ts", "literal.ts",
      ]);
      expect(unguardedExitingCliFiles(sourceFiles, libraries, read).map((file) => file.split("/").pop())).toEqual([
        "comment-only.ts", "late.ts",
      ]);

      const result = spawnSync("node_modules/.bin/tsx", [VERIFY_SYNC_STDIO, fixtureDir, join(fixtureDir, "library.ts")], {
        cwd: REPO_ROOT,
        encoding: "utf8",
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("comment-only.ts");
      expect(result.stderr).toContain("late.ts");
    } finally {
      rmSync(fixtureDir, { recursive: true, force: true });
    }
  });
});
