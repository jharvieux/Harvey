// SecBench.js external recall gate (#879). Scores Harvey's MECHANICAL tier against the SecBench.js
// benchmark (~600 real npm CVEs, five server-side-JS classes) and reports a per-tier recall number.
//
//   pnpm exec tsx src/cli/validate-secbench.ts --dir <secbench-checkout> \
//       --osv-report <osv-scanner recursive JSON over the lockfile tree> [--semgrep-json <precomputed>]
//
// Why two inputs, not one live run (the honest harness shape): SecBench ships no lockfiles, so the
// dependency-CVE (SCA) pathway needs a package-lock generated per entry (`npm install
// --package-lock-only`) before osv-scanner can read it — a heavy, network-bound step run OUT of
// this process (see docs/design/secbench-recall-measurement.md for the exact commands), its JSON
// fed in via --osv-report exactly as hotspot-scan.ts takes vitals' report off-band (#314). The
// source-pattern (semgrep) pathway IS run live here (fast, offline) — or read from --semgrep-json.
//
// This gate reports RECALL only. SecBench has no benign negatives, so precision/FPR are not
// measurable from it — the vibe-dummy FP oracle stays the precision gate (the issue's guardrail).

import { execFileSync } from "node:child_process";
import { arg, assertKnownFlags } from "./args.js";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import type { OsvScanResult } from "../scan/dependencies.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  indexOsvByEntry,
  loadSecbenchCorpus,
  recallPct,
  scoreLibrarySource,
  scoreSecbench,
  SECBENCH_CLASSES,
  SECBENCH_PIN,
  SECBENCH_REPO,
} from "../scan/secbench.js";

const FLAGS = [
  "--dir",
  "--target",
  "--library-source-tree",
  "--lockfile-tree",
  "--osv-report",
  "--semgrep-json",
] as const;

assertKnownFlags(FLAGS);
const dir = arg("--dir") ?? arg("--target");
if (!dir) {
  console.error(
    `Usage: validate-secbench --dir <secbench-checkout> --osv-report <osv.json> [--semgrep-json <sg.json>]\n` +
      `Clone the benchmark at the pinned commit first:\n` +
      `  git clone https://github.com/${SECBENCH_REPO} && git -C SecBench.js checkout ${SECBENCH_PIN}\n` +
      `Then generate a package-lock per entry and run osv-scanner recursively — see\n` +
      `docs/design/secbench-recall-measurement.md for the exact reproduction commands.`,
  );
  process.exit(2);
}

const fs = { readdirSync: (p: string) => readdirSync(p), readFileSync: (p: string) => readFileSync(p, "utf8"), existsSync };
const entries = loadSecbenchCorpus(dir, fs);

// Fail loud on a partial load: a class folder that didn't parse must be visible, never a quiet
// smaller denominator (the coverage guard).
const loadedClasses = new Set(entries.map((e) => e.cls));
const missingClasses = SECBENCH_CLASSES.filter((c) => !loadedClasses.has(c));
if (entries.length === 0 || missingClasses.length) {
  console.error(`SecBench load incomplete — ${entries.length} entries, missing classes: ${missingClasses.join(", ") || "none"}. Is --dir a SecBench.js checkout?`);
  process.exit(2);
}

// --- Source-pattern (semgrep) pathway ---------------------------------------------------------
// The full mechanical semgrep config (harvey-* custom rules + the registry security packs), the
// same set runMechanicalScan runs. Read a precomputed JSON if given, else run it live.
interface SemgrepJson { results?: { check_id?: string; path?: string }[] }
function runSemgrepOverClasses(root: string): SemgrepJson {
  const customRules = new URL("../scan/rules/semgrep/", import.meta.url).pathname;
  const classDirs = SECBENCH_CLASSES.map((c) => `${root}/${c}`).filter(existsSync);
  const args = [
    "--config", "p/typescript", "--config", "p/react", "--config", "p/nextjs",
    "--config", "p/owasp-top-ten", "--config", "p/secrets", "--config", "p/security-audit",
    "--config", customRules, "--exclude", "node_modules", "--json", "--quiet", ...classDirs,
  ];
  let out: string;
  try {
    out = execFileSync("semgrep", args, { encoding: "utf8", maxBuffer: 1024 * 1024 * 256 });
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else throw err;
  }
  return JSON.parse(out) as SemgrepJson;
}

const semgrepJsonPath = arg("--semgrep-json");
const semgrep: SemgrepJson = semgrepJsonPath
  ? (JSON.parse(readFileSync(semgrepJsonPath, "utf8")) as SemgrepJson)
  : runSemgrepOverClasses(dir);
const semgrepHitKeys = new Set<string>();
for (const r of semgrep.results ?? []) {
  const m = (r.path ?? "").match(/([^/]+)\/([^/]+)\/[^/]+$/);
  if (m && (SECBENCH_CLASSES as readonly string[]).includes(m[1]!)) semgrepHitKeys.add(`${m[1]}/${m[2]}`);
}

// --- Dependency-CVE (SCA / osv-scanner) pathway ------------------------------------------------
const osvReportPath = arg("--osv-report");
if (!osvReportPath || !existsSync(osvReportPath)) {
  console.error(`--osv-report <path> is required (osv-scanner --format json -r over the generated lockfile tree). See docs/design/secbench-recall-measurement.md.`);
  process.exit(2);
}
const osvReport = JSON.parse(readFileSync(osvReportPath, "utf8")) as OsvScanResult;
const osvIndex = indexOsvByEntry(osvReport);

// Installable set = entries whose package-lock was generated. Derived from the lockfile tree
// (<tree>/<class>/<slug>/package-lock.json), NOT from the osv report — osv omits clean lockfiles,
// so using its keys as the denominator would drop every real miss and inflate recall (#879).
const lockTree = arg("--lockfile-tree");
if (!lockTree || !existsSync(lockTree)) {
  console.error(`--lockfile-tree <dir> is required: the tree of generated package-locks (<class>/<slug>/package-lock.json). See docs/design/secbench-recall-measurement.md.`);
  process.exit(2);
}
const installableKeys = new Set<string>();
for (const cls of SECBENCH_CLASSES) {
  const clsDir = `${lockTree}/${cls}`;
  if (!existsSync(clsDir)) continue;
  for (const slug of readdirSync(clsDir)) {
    const lf = `${clsDir}/${slug}/package-lock.json`;
    if (existsSync(lf) && statSync(lf).isFile()) installableKeys.add(`${cls}/${slug}`);
  }
}

const { perClass, all } = scoreSecbench(entries, osvIndex, installableKeys, semgrepHitKeys);

console.log(`SecBench.js recall — ${SECBENCH_REPO} @ ${SECBENCH_PIN.slice(0, 10)}`);
console.log(`${entries.length} entries loaded across ${SECBENCH_CLASSES.length} classes.\n`);

const pad = (s: string, n: number) => s.padEnd(n);
console.log(pad("class", 20) + pad("entries", 9) + pad("scored", 8) + pad("SCA-recall", 24) + "exact-CVE");
const rows = [...perClass, all];
for (const r of rows) {
  const scaAny = `${r.scaFlagged}/${r.installable} (${recallPct(r.scaFlagged, r.installable)})`;
  const scaExact = `${r.scaExact}/${r.installable} (${recallPct(r.scaExact, r.installable)})`;
  const label = r.cls === "ALL" ? "── ALL ──" : r.cls;
  console.log(pad(label, 20) + pad(String(r.total), 9) + pad(String(r.installable), 8) + pad(scaAny, 24) + scaExact);
}

console.log(`\nSource-pattern (semgrep) pathway — harvey-* rules + registry OWASP/security packs:`);
console.log(`  ${all.semgrepHits}/${entries.length} entries drew ANY source-security finding.`);
if (all.semgrepHits === 0) {
  console.log(
    `  MEASURED ZERO. SecBench's sink is in library code (node_modules — not scanned) and its exploit\n` +
      `  is a jest test with no HTTP request source, so Harvey's taint rules cannot fire. SecBench is a\n` +
      `  KNOWN-VULNERABLE-DEPENDENCY corpus: Harvey scores it via its SCA tier, not its 92 source rules.`,
  );
}

const notInstallable = all.notInstallable;
if (notInstallable) {
  console.log(
    `\nDeclared gap (coverage guard): ${notInstallable}/${entries.length} entries have NO osv data — their\n` +
      `pinned package/version no longer resolves from the npm registry, so no lockfile could be generated.\n` +
      `Excluded from the SCA-recall denominator (an env gap, not a detector miss), never silently dropped.`,
  );
}

// --- Library-internal SOURCE pathway (#946) --------------------------------------------------
// The semgrep pass above scans the EXPLOIT DIRS with the request-sourced rules and scores 0 by
// construction (the vuln is in the target package's own source, under node_modules, not scanned).
// The harvey-lib-* rules (library-taint.yml) treat a public library entry-point PARAMETER as the
// taint source, so they score the axis SecBench actually exercises — but they must scan the INSTALLED
// TARGET-PACKAGE SOURCE. That source is a heavy, network-bound `npm install` per entry, run OUT of
// this process into <tree>/<class>/<slug>/node_modules/<pkg> (the same off-band shape as --osv-report
// / --lockfile-tree). Optional: only runs when --library-source-tree is provided.
const libTree = arg("--library-source-tree");
if (libTree && existsSync(libTree)) {
  const libRules = join(dirname(fileURLToPath(import.meta.url)), "..", "scan", "rules", "semgrep", "library-taint.yml");
  const scannedKeys = new Set<string>();
  const libHitKeys = new Set<string>();
  for (const e of entries) {
    if (!e.pkg) continue; // multi-dep entries have no single target-package source to scope to
    const pkgDir = join(libTree, e.cls, e.slug, "node_modules", ...e.pkg.split("/"));
    if (!existsSync(pkgDir)) continue;
    scannedKeys.add(e.key);
    let out: string;
    try {
      out = execFileSync("semgrep", ["--config", libRules, "--exclude", "node_modules", "--json", "--quiet", pkgDir], { encoding: "utf8", maxBuffer: 1024 * 1024 * 128 });
    } catch (err) {
      const se = err as { stdout?: string };
      if (typeof se.stdout === "string" && se.stdout.length > 0) out = se.stdout;
      else throw err;
    }
    if (((JSON.parse(out) as SemgrepJson).results ?? []).length > 0) libHitKeys.add(e.key);
  }
  const lib = scoreLibrarySource(entries, scannedKeys, libHitKeys);
  console.log(`\nLibrary-internal SOURCE pathway (#946) — harvey-lib-* parameter-sourced taint over each entry's INSTALLED target-package source:`);
  console.log(pad("class", 20) + pad("scanned", 9) + "lib-source recall");
  for (const r of [...lib.perClass, lib.all]) {
    if (r.cls !== "ALL" && r.scanned === 0) continue;
    const label = r.cls === "ALL" ? "── ALL ──" : r.cls;
    console.log(pad(label, 20) + pad(String(r.scanned), 9) + `${r.libFlagged}/${r.scanned} (${recallPct(r.libFlagged, r.scanned)})`);
  }
  console.log(
    `  This is the LIBRARY-INTERNAL source axis (#946), REPORTED DISTINCTLY from the SCA number and the\n` +
      `  request-sourced 0/${entries.length} above. Recall is bounded by OSS Semgrep's intra-procedural taint (#873):\n` +
      `  a param reaching the sink only across a helper-function boundary is not followed.`,
  );
} else if (libTree) {
  console.log(`\n--library-source-tree ${libTree} does not exist — skipping the library-internal source pathway (#946).`);
}

console.log(
  `\nFREE/MECHANICAL-TIER RECALL (for #868): the mechanical tier's SecBench recall is the SCA number\n` +
    `above — ${all.scaFlagged}/${all.installable} (${recallPct(all.scaFlagged, all.installable)}) of installable entries flagged as known-vulnerable. The request-sourced\n` +
    `detector recall is a MEASURED 0/${entries.length}; the LIBRARY-INTERNAL source recall (#946) is reported above when\n` +
    `--library-source-tree is provided. These are separate tiers and must not be blended.`,
);
