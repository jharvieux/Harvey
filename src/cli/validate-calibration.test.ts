// #1628 — the calibration gate's own failing direction, proven through the PROCESS, not from
// inside it.
//
// `validate-calibration` grew an in-run negative control (`REVIEW-TIER RECALL GATE`) that calls
// fatalRecallMisses — the same function the verdict calls — so softening the rule reddens the gate.
// That covers the rule. It leaves the WIRING uncovered: dropping `recallMisses.length === 0` out of the
// `gatePass` conjunction would leave the control printing FIRED and the process exiting 0, which is
// exactly the "reports, with no failing direction" shape #1628 is about, one layer out. These two runs close
// that: a clean run must exit 0, and a run with one caught review-tier positive deliberately
// darkened must exit 1 and say which row went dark.
//
// Both directions on purpose. A seeded run that exits 1 proves nothing on its own — a gate that
// always fails would satisfy it.

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-calibration.ts");

function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
// The gate runs the real mechanical scan. osv-scanner is included because its absence changes the
// finding set (a DEP-OSV-00 disclosure row appears), and a control whose input set shifts under it
// is not a control. Skipped with a named reason rather than passing silently — the CI heavy-cli job
// installs all four, which is where this is expected to execute.
const MECHANICAL_BINARIES_PRESENT = ["semgrep", "trufflehog", "gitleaks", "osv-scanner"].every(hasBinary);
if (!MECHANICAL_BINARIES_PRESENT) {
  console.warn("⚠ validate-calibration.test.ts SKIPPED: semgrep/trufflehog/gitleaks/osv-scanner are not all on PATH, so the gate cannot run.");
}

// Awaited spawn, never execFileSync: the standing constraint for every file in HEAVY_CLI_TESTS is
// that no single blocking window may approach vitest's hardcoded 60s worker→main ack (#1120/#1134).
function run(args: string[], env?: NodeJS.ProcessEnv): Promise<{ code: number; out: string }> {
  return new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"], env: env ?? process.env });
    let out = "";
    // setEncoding, never `out += <Buffer>`: string-concatenating a Buffer decodes THAT CHUNK in
    // isolation, so a multi-byte character straddling a chunk boundary decodes to U+FFFD on both
    // sides and the assembled string no longer contains it. Every verdict this file asserts on
    // carries an em dash. MEASURED 2026-07-31: one em dash lost out of 40000 across 36 chunks with
    // the concat form, zero with a decoder. Not established as the cause of any observed failure —
    // recorded here because the corruption is real and the fix is the correct spelling either way.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.stderr.on("data", (d: string) => (out += d));
    child.on("error", rej);
    child.on("close", (code) => res({ code: code ?? -1, out }));
  });
}

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("validate-calibration exits 1 on a review-tier recall regression (#1628)", () => {
  it("exits 0 on the committed corpus, and reports the review-tier population it now holds fatal", async () => {
    const { code, out } = await run([]);
    expect(out).toMatch(/REVIEW-TIER RECALL GATE \(#1628, \d+ review-tier positives now fatal on a miss\).*FIRED/);
    expect(out).toContain("GATE PASS");
    expect(code).toBe(0);
  }, 180000);

  it("exits 1 when one caught review-tier positive is darkened, naming the row", async () => {
    const { code, out } = await run(["--seed-dark-review"]);
    const seeded = /--seed-dark-review: dropping every finding that scores (\S+)/.exec(out)?.[1];
    // Exit 2 is the CLI's "could not plant anything" code, kept distinct so a control that failed
    // for its own reasons can never be read as the regression it was meant to plant.
    expect(code, `--seed-dark-review could not plant a victim:\n${out.slice(-2000)}`).not.toBe(2);
    expect(seeded, "the seeded run must name the row it darkened").toBeTruthy();
    // Two assertions, because the one below reports its two failure modes identically and the
    // difference between them is the whole diagnosis. The seeded row is ALWAYS first — every stage
    // from mechanicalCorpus() through buildCoverageMatrix() to fatalRecallMisses() is order-
    // preserving and the victim is the first caught review-tier positive in corpus order — so a
    // missing substring never means "the gate named a different row". It means the verdict line was
    // not printed at all: the run ended between its measuring phase and its verdict. The three
    // pre-fix shard-2 occurrences (30672048114@df87ef1, 30674508595@434ca81, and
    // 30674590006@09f1035) all ended with exit 1 and output truncated at the liveness receipt,
    // establishing real process-tail loss rather than a wrong seeded row or a flaky assertion.
    // c180bcc/PR1768 landed the stdio-drain fix after those occurrences; the operator ruling is
    // to document this fixed-before-quarantine sequence here, rather than quarantine the test.
    const verdict = "GATE FAIL — review-tier positives not caught by any rule (#1628)";
    expect(out, `the gate exited ${code} without printing a "${verdict}" line at all — it did not reach its verdict. Last 2000 chars of its output:\n${out.slice(-2000)}`).toContain(verdict);
    expect(out).toContain(`${verdict}: ${seeded}`);
    expect(out).not.toContain("GATE PASS");
    expect(code).toBe(1);
  }, 180000);

  // #1664: the wiring of the SCAN-DID-NOT-RUN halt, proven through the process like the two runs
  // above — the unit tests on scanDidNotRun cover the predicate, and #1407's lesson is that a
  // library-level proof leaves the CLI's own call unguarded. The shim replays the live crash shape
  // (valid empty envelope on stdout, non-zero exit, `semgrep-core exited with -10!` in errors[]):
  // before the halt, that run rendered a full recall table reading "113 rules have never been shown
  // to work" over a scan that never ran.
  it("exits 2 and renders NO recall table when semgrep crashes instead of completing (#1664)", async () => {
    const shimDir = mkdtempSync(join(tmpdir(), "harvey-semgrep-shim-"));
    try {
      writeFileSync(
        join(shimDir, "semgrep"),
        '#!/bin/bash\necho \'{"version":"1.164.0","results":[],"errors":[{"code":2,"level":"error","type":"SemgrepError","message":"semgrep-core exited with -10!"}],"paths":{"scanned":[],"skipped":[]}}\'\nexit 2\n',
        { mode: 0o755 },
      );
      const { code, out } = await run([], { ...process.env, PATH: `${shimDir}:${process.env.PATH ?? ""}` });
      expect(out).toContain("THE SCAN DID NOT RUN");
      expect(out).toContain("semgrep-core exited with -10!");
      expect(out, "a gate that cannot measure must not report a measurement").not.toContain("Calibration coverage matrix");
      expect(out).not.toContain("GATE PASS");
      expect(code).toBe(2);
    } finally {
      rmSync(shimDir, { recursive: true, force: true });
    }
  }, 180000);
});
