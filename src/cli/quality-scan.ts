// M4 (jscpd duplication) + M5 (knip dead code) wiring — runs both against a
// target repo using Harvey's own installed tooling (no install needed in the
// client repo) and shapes the output into Finding[] for §3b of the report.
// Merge the result into the engagement's findings.json alongside the M1/M2/M3
// findings and meta, then `pnpm validate:findings`.
//
//   pnpm quality-scan <target-dir> [--out findings.quality.json]

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import {
  duplicationSummary,
  jscpdToFindings,
  knipToFindings,
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
  execFileSync(
    jscpdBin,
    [dir, "--reporters", "json", "--output", outDir, "--threshold", "100", "--absolute", "--silent", "--noTips", "--ignore", "**/node_modules/**,**/dist/**,**/.next/**"],
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

const jscpdReport = runJscpd(targetDir);
const knipReport = runKnip(targetDir);

const fileLineCounts: Record<string, number> = {};
for (const file of knipReport.files) {
  const n = lineCount(targetDir, file);
  if (n !== undefined) fileLineCounts[file] = n;
}

const findings: Finding[] = [...jscpdToFindings(jscpdReport), ...knipToFindings(knipReport, fileLineCounts)];

const dup = duplicationSummary(jscpdReport);
console.error(
  `M4 duplication: ${dup.percentage}% (${dup.duplicatedLines}/${dup.totalLines} lines) — ${jscpdReport.duplicates.length} clone cluster(s)`,
);
console.error(
  `M5 dead code: ${knipReport.files.length} unused file(s), ${knipReport.issues.filter((i) => i.exports.length + i.types.length > 0).length} file(s) with unused exports`,
);

const json = JSON.stringify(findings, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote ${findings.length} findings to ${outPath}`);
} else {
  console.log(json);
}
