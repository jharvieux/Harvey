// The jscpd (M4 duplication) process invocation, extracted from src/cli/quality-scan.ts (#1305) so
// the free tier can grade duplication too. src/quality-scan.ts is declared pure-transforms-only, and
// process invocation belongs in src/scan/**, so it lives here — one invocation, two callers.
//
// The body below is the CLI's runJscpd verbatim; its comments are the root-cause record for #948 and
// #931 and are load-bearing, so they travel with the code rather than being summarised.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { JSCPD_IGNORE_GLOBS, jscpdAnalysedNothingReason, type JscpdReport } from "../quality-scan.js";

// node_modules/.bin shim (not require.resolve — jscpd's package.json "exports" map doesn't expose
// its bin script as an importable subpath).
const JSCPD_BIN = join(resolve(dirname(fileURLToPath(import.meta.url)), "..", ".."), "node_modules", ".bin", "jscpd");

interface JscpdRunOptions {
  timeoutMs: number;
  // Comparable source files under this scope, counted by the CALLER's own walk. Used only to tell a
  // legitimately-empty scan ("fewer than 2 files to compare") from jscpd analysing nothing — the two
  // are indistinguishable from jscpd's output alone (#931).
  sourceFileCount: () => number;
  jscpdBin?: string;
}

export function runJscpd(dir: string, opts: JscpdRunOptions): JscpdReport {
  const bin = opts.jscpdBin ?? JSCPD_BIN;
  const outDir = mkdtempSync(join(tmpdir(), "harvey-jscpd-"));
  try {
    // --threshold 100 overrides any client .jscpd.json so the scan never exits
    // non-zero on us — we want the raw report, not jscpd's own pass/fail gate.
    // JSCPD_IGNORE_GLOBS excludes generated/vendored/demo paths (M4-N-GENERATED, issue #72;
    // extended per #232) that aren't hand-maintained duplication.
    //
    // #948 (root-caused by instrumenting jscpd 4.2.5 + @jscpd/finder/fast-glob directly against a
    // real clone of documenso, the #931 repro): TWO cwd/path-relativity bugs compounded into the
    // "empty file list at some absolute paths" symptom.
    //  1. jscpd resolves its `.jscpd.json` auto-discovery AND (separately, via its own
    //     src/init/ignore.ts — a second, less-anchored .gitignore reader than the one
    //     @jscpd/finder uses for the scanned dir itself) a `.gitignore` at `process.cwd()` of the
    //     CHILD PROCESS — not the `dir` argument. Without an explicit `cwd`, the child inherits
    //     whatever cwd the calling Node process has (typically Harvey's own repo root), so it can
    //     pick up the WRONG repo's config/gitignore entirely. Fixed by `cwd: dir` below.
    //  2. Independent of (1): when the scanned PATH ITSELF is an absolute string, fast-glob (inside
    //     @jscpd/finder's getFilesToDetect) matches every gitignore-derived ignore glob against the
    //     FULL ABSOLUTE PATH, not path-relative-to-the-scan-root. A gitignore entry with no slash
    //     (e.g. documenso's own "tmp") is — CORRECTLY, per git's own semantics for a bare name —
    //     converted to an ANY-DEPTH "**/tmp/**" glob. Once matched against the full absolute path,
    //     that glob also matches any ANCESTOR directory literally named "tmp" — which is exactly
    //     what a scratch clone under `/tmp` (Linux's `os.tmpdir()`; macOS's is `/var/folders/.../T`,
    //     which is why this reproduced on ubuntu-latest but not on the one measured macOS run under
    //     a shallow scratch path, #931) sits inside — silently excluding the ENTIRE scanned tree.
    //     MEASURED: `getFilesToDetect({ path: [absoluteDir], gitignore: true, absolute: true })`
    //     against a real documenso clone under a `tmp`-prefixed scratch path returns 0 files;
    //     the identical call with `path: ["."]` (cwd already pinned to the scan root) returns 2334.
    //     Fixed by scanning "." instead of the absolute `dir` (cwd: dir anchors it) — fast-glob then
    //     matches everything relative-to-scan-root, so an ignore glob can only match WITHIN the
    //     scanned tree, never an ancestor directory of wherever that tree happens to be checked out.
    execFileSync(
      bin,
      [".", "--reporters", "json", "--output", outDir, "--threshold", "100", "--silent", "--noTips", "--ignore", JSCPD_IGNORE_GLOBS.join(",")],
      { cwd: dir, stdio: ["ignore", "ignore", "pipe"], timeout: opts.timeoutMs, killSignal: "SIGKILL" },
    );
    const reportPath = join(outDir, "jscpd-report.json");
    // #505: per-workspace scopes surface a case a whole-repo run rarely hit — a workspace with
    // fewer than 2 comparable source files. jscpd exits 0 but writes NO report file at all (there
    // was nothing to compare), which is a clean zero-duplicates scan, not a coverage gap.
    // #931: that same missing-report shape is indistinguishable from "jscpd analysed nothing" —
    // the caller's source-file count walks the same skip rules JSCPD_IGNORE_GLOBS encode, so it's a
    // reasonable proxy for whether this scope actually had anything to compare, independent of
    // jscpd's own file discovery. jscpdAnalysedNothingReason throws that distinction; a thrown
    // reason here is caught by the caller's try/catch and folded into its gap disclosure — partial
    // with a reason, never a silent clean 0%.
    if (!existsSync(reportPath)) {
      const reason = jscpdAnalysedNothingReason(opts.sourceFileCount());
      if (!reason) return { statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 0 } }, duplicates: [] };
      throw new Error(reason);
    }
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as JscpdReport;
    // jscpd (now scanning "." from cwd: dir, #948) reports paths relative to the scan root already
    // in most cases, but normalize defensively: resolve against `dir` explicitly (not the ambient
    // process.cwd(), which need not equal `dir` — the exact class of bug this fix removes) so the
    // report never leaks local filesystem layout regardless of which form jscpd emits.
    for (const dup of report.duplicates) {
      dup.firstFile.name = relative(dir, resolve(dir, dup.firstFile.name));
      dup.secondFile.name = relative(dir, resolve(dir, dup.secondFile.name));
    }
    return report;
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}
