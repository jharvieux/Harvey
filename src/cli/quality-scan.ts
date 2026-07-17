// M4 (jscpd duplication) + M5 (knip dead code) wiring — runs both against a
// target repo using Harvey's own installed tooling (no install needed in the
// client repo) and shapes the output into Finding[] for §3b of the report.
// Merge the result into the engagement's findings.json alongside the M1/M2/M3
// findings and meta, then `pnpm validate:findings`.
//
//   pnpm quality-scan <target-dir> [--out findings.quality.json]

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { divergedCloneFindings, type SecurityPathFile } from "../diverged-clones.js";
import type { Finding } from "../findings.js";
import {
  duplicationSummary,
  JSCPD_IGNORE_GLOBS,
  jscpdToFindings,
  knipToFindings,
  knipUnavailableFinding,
  touchesSecurityPath,
  touchesTenantSupabasePath,
  type JscpdReport,
  type KnipReport,
} from "../quality-scan.js";

// node_modules/.bin shims (not require.resolve — jscpd/knip's package.json
// "exports" maps don't expose their bin scripts as importable subpaths).
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const jscpdBin = join(repoRoot, "node_modules", ".bin", "jscpd");
const knipBin = join(repoRoot, "node_modules", ".bin", "knip");

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm quality-scan <target-dir> [--out findings.quality.json]");
  process.exit(2);
}

const targetDir = resolve(targetArg);

function runJscpd(dir: string): JscpdReport {
  const outDir = mkdtempSync(join(tmpdir(), "harvey-jscpd-"));
  // --threshold 100 overrides any client .jscpd.json so the scan never exits
  // non-zero on us — we want the raw report, not jscpd's own pass/fail gate.
  // JSCPD_IGNORE_GLOBS excludes generated/vendored/demo paths (M4-N-GENERATED, issue #72;
  // extended per #232) that aren't hand-maintained duplication.
  execFileSync(
    jscpdBin,
    [dir, "--reporters", "json", "--output", outDir, "--threshold", "100", "--absolute", "--silent", "--noTips", "--ignore", JSCPD_IGNORE_GLOBS.join(",")],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const report = JSON.parse(readFileSync(join(outDir, "jscpd-report.json"), "utf8")) as JscpdReport;
  rmSync(outDir, { recursive: true, force: true });
  // jscpd's json reporter emits paths relative to --output by default even
  // with --absolute in some versions' clone entries; normalize to relative-
  // to-target so the report doesn't leak local filesystem layout.
  for (const dup of report.duplicates) {
    dup.firstFile.name = relative(dir, resolve(dup.firstFile.name));
    dup.secondFile.name = relative(dir, resolve(dup.secondFile.name));
  }
  return report;
}

function runKnip(dir: string): KnipReport {
  const out = execFileSync(knipBin, ["--reporter", "json", "--no-exit-code"], {
    cwd: dir,
    stdio: ["ignore", "pipe", "inherit"],
  });
  return JSON.parse(out.toString("utf8")) as KnipReport;
}

function lineCount(dir: string, relPath: string): number | undefined {
  try {
    return readFileSync(join(dir, relPath), "utf8").split("\n").length;
  } catch {
    return undefined;
  }
}

// #360/#399: collect the security-relevant source subset for the diverged-clone pass. Skips the
// same generated/vendored/build shapes JSCPD_IGNORE_GLOBS excludes from M4, plus tests — a
// drifted copy inside a test file is not a per-handler authorization drift, and test suites
// legitimately repeat near-identical setup. A file is admitted on EITHER signal: its path names
// an auth/guard/middleware/security concern (touchesSecurityPath, v1/#360), or its body scopes a
// supabase query by a tenant key regardless of path (touchesTenantSupabasePath, v2/#399) — the
// per-entity lib/ai/tools/*/lib/stores/* copy-paste vein #399 measured outside the v1 vocabulary.
const SKIP_DIRS = new Set(["node_modules", "dist", "build", ".next", ".git", "generated", "vendor", "patches", "__tests__", "e2e"]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_FILE = /(\.gen\.ts|\.test\.|\.spec\.)|^(database\.types|types_db)\.ts$/;

function securityPathFiles(dir: string, rel = ""): SecurityPathFile[] {
  const files: SecurityPathFile[] = [];
  for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.includes("demo")) files.push(...securityPathFiles(dir, relPath));
    } else if (SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      if (touchesSecurityPath(relPath)) {
        files.push({ path: relPath, source: readFileSync(join(dir, relPath), "utf8") });
      } else {
        const source = readFileSync(join(dir, relPath), "utf8");
        if (touchesTenantSupabasePath(source)) files.push({ path: relPath, source });
      }
    }
  }
  return files;
}

const jscpdReport = runJscpd(targetDir);

// #360/#399: the Type-3 near-miss layer jscpd structurally cannot provide — diverged copies of
// security checks. Scoped to securityPathFiles's admitted subset (touchesSecurityPath OR
// touchesTenantSupabasePath).
const divergedFindings = divergedCloneFindings(securityPathFiles(targetDir));

// #223: M4 has no dependency on M5 — a knip failure (most commonly the target's own
// node_modules isn't installed, so it can't resolve config/plugin imports) must not cost the
// engagement its jscpd findings too. Caught here so main flow always has a duplication result.
let knipReport: KnipReport | undefined;
let knipFailure: string | undefined;
try {
  knipReport = runKnip(targetDir);
} catch (err) {
  knipFailure = err instanceof Error ? err.message : String(err);
  console.error(`⚠ knip failed — M5 dead-code coverage skipped for this run: ${knipFailure}`);
}

const fileLineCounts: Record<string, number> = {};
if (knipReport) {
  for (const file of knipReport.files) {
    const n = lineCount(targetDir, file);
    if (n !== undefined) fileLineCounts[file] = n;
  }
}

const findings: Finding[] = [
  ...jscpdToFindings(jscpdReport),
  ...divergedFindings,
  ...(knipReport ? knipToFindings(knipReport, fileLineCounts) : [knipUnavailableFinding(knipFailure ?? "unknown error")]),
];

const dup = duplicationSummary(jscpdReport);
console.error(
  `M4 duplication: ${dup.percentage}% (${dup.duplicatedLines}/${dup.totalLines} lines) — ${jscpdReport.duplicates.length} clone cluster(s), ${dup.subThresholdCloneCount} sub-threshold small clone(s) disclosed in M4-00 (#365), ${divergedFindings.length} diverged security-path clone pair(s) (#360, review tier)`,
);
if (knipReport) {
  console.error(
    `M5 dead code: ${knipReport.files.length} unused file(s), ${knipReport.issues.filter((i) => i.exports.length + i.types.length > 0).length} file(s) with unused exports`,
  );
} else {
  console.error("M5 dead code: skipped (knip failed — see warning above)");
}

const json = JSON.stringify(findings, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote ${findings.length} findings to ${outPath}`);
} else {
  console.log(json);
}
