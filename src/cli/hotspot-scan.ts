// M3 hotspot scan (#363) — runs the vitals plugin's `report --json` against a target repo (or
// consumes a pre-captured report) and shapes it into the M3 deliverable: the ranked hotspot
// table, the deterministic boolean-fact Finding[] (truck-factor-1, co-change coupling,
// AI-authored+high-churn — src/hotspot-scan.ts::toFactFindings), the top-K hotspot file list
// M8's `--hotspots` flag consumes, and the mechanical cross-reference of other modules' findings
// against the top-K (a security/perf finding on a hotspot is top remediation priority).
//
// vitals is an EXTERNAL plugin, not a dependency of this repo (CLAUDE.md M3 row: run, don't
// build), and `vitals_cli.py` is often NOT on PATH in agent sandboxes (#314) — pass --report
// with a captured `vitals_cli.py report --json <dir>` output in that case. vitals does NOT need a
// pre-captured `.vitals` store: `report` computes churn×complexity directly from git, so it runs
// on a cold target (a fresh `.vitals`-less repo) as long as the plugin itself is installed.
//
// #808: the installed vitals is asserted to report EXPECTED_VITALS_VERSION before its report is
// trusted — a mismatch fails loud with expected/actual, not a downstream array-missing error.
// #807 reduced tier: when the vitals plugin is entirely UNAVAILABLE, this does not fail — Harvey
// computes its own churn×complexity ranking from git history + a complexity proxy, prints an
// "M3 REDUCED TIER" banner, and marks the artifact `reduced:true` so callers disclose it as
// `partial` (ranked table only; no coupling / knowledge-risk / AI-provenance). It still fails loud
// if neither vitals nor git history is available.
//
//   pnpm exec tsx src/cli/hotspot-scan.ts <target-dir> [--report <vitals.json>]
//     [--out <m3.json>] [--hotspots-out <file>] [--findings <file>]... [--top <k>]
//
// (No `pnpm hotspot-scan` alias yet — adding one edits package.json, which is operator-owned.)
//
// --findings: a Finding[] JSON file from another module's scan (the `pnpm detect-static <t>
//   --out` format, M7/M9 — or any bare Finding[] export from M1). Repeatable. Findings whose
//   location sits on a top-K hotspot come back annotated and reordered to the front in --out's
//   `crossReferenced` block.
// --hotspots-out: newline-separated top-K file list — the exact format
//   `pnpm mutation-scan <t> --hotspots <file>` reads for M8's surviving-mutant cross-reference.
//
// Thin untested I/O wrapper per the repo convention — the transforms are the tested pure
// functions in src/hotspot-scan.ts.

import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { homedir } from "node:os";
import type { Finding } from "../findings.js";
import { writePassArtifact } from "../audit-pass-artifact.js";
import { buildFallbackReport, buildM3PassArtifact, capScopeFinding, complexityProxy, crossReferenceHotspots, fallbackQualifyingCount, type FallbackFile, isUnranked, rankHotspots, toFactFindings, topKFiles, vitalsScope, type VitalsReport } from "../hotspot-scan.js";

// #808: the vitals version src/hotspot-scan.ts's VitalsReport shape is verified against (#94/#369).
// A mismatch fails loud with expected/actual BEFORE the report schema-drift check, so version drift
// is reported as such rather than as a generic array-missing error.
const EXPECTED_VITALS_VERSION = "0.2.0";

// Source-file extensions the reduced tier (#807) counts for churn/complexity. Mirrors the intent of
// vitals' own is_source_file gate — enough to keep the churn×complexity ranking on real code.
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|java|rs|php|c|cc|cpp|h|hpp|cs|swift|kt|scala)$/;

const args = process.argv.slice(2);

function arg(flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

// Discover vitals_cli.py in Claude Code plugin install locations (#507).
// Checks:
// 1. ~/.claude/plugins/marketplaces/vitals/scripts/vitals_cli.py
// 2. ~/.claude/plugins/cache/vitals/*/scripts/vitals_cli.py
// Returns the path if found, undefined otherwise.
function discoverVitalsCli(): string | undefined {
  const home = homedir();
  const pluginsDir = resolve(home, ".claude/plugins");

  // Check marketplaces location
  const marketplaceScript = resolve(pluginsDir, "marketplaces/vitals/scripts/vitals_cli.py");
  if (existsSync(marketplaceScript)) {
    return marketplaceScript;
  }

  // Check cache location with versioned directories
  const cacheVitalsDir = resolve(pluginsDir, "cache/vitals");
  if (existsSync(cacheVitalsDir)) {
    try {
      const versions = readNamesSafe(cacheVitalsDir);
      for (const version of versions) {
        const cacheScript = resolve(cacheVitalsDir, version, "vitals/scripts/vitals_cli.py");
        if (existsSync(cacheScript)) {
          return cacheScript;
        }
      }
    } catch {
      // If cache directory doesn't exist or can't be read, continue to PATH check
    }
  }

  return undefined;
}

// Positional target-dir: the first bare token, expected before any flags (matches
// src/cli/mutation-scan.ts's convention — usage is always `<target-dir> [--flags...]`).
const targetArg = args.find((a) => !a.startsWith("--"));

if (!targetArg) {
  console.error("usage: pnpm exec tsx src/cli/hotspot-scan.ts <target-dir> [--report <vitals.json>] [--out <m3.json>] [--hotspots-out <file>] [--findings <file>]... [--top <k>] [--artifacts-dir <dir>]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const reportPath = arg("--report");
const outPath = arg("--out");
const hotspotsOutPath = arg("--hotspots-out");
// #1364: writes M3.pass.json directly (the #416 durable-artifact convention), so a captured/replayed
// vitals pass records itself without a separate `record-pass` hand-off.
const artifactsDirPath = arg("--artifacts-dir");
const topK = Number(arg("--top") ?? 10);
const findingsPaths = args.flatMap((a, i) => (a === "--findings" && args[i + 1] ? [args[i + 1]!] : []));

function parseReport(raw: string): VitalsReport {
  const parsed = JSON.parse(raw) as VitalsReport;
  // Fail loud on schema drift: a report without these arrays is not the verified #94 shape.
  const missing = (["hotspots", "coupling", "knowledge_risk"] as const).filter((k) => !Array.isArray(parsed[k]));
  if (missing.length) {
    console.error(`✗ vitals report is missing expected array(s): ${missing.join(", ")} — schema drift from the #94-verified vitals ${EXPECTED_VITALS_VERSION} shape; re-verify src/hotspot-scan.ts against the installed vitals version`);
    process.exit(1);
  }
  return parsed;
}

// #808: run vitals' `version` subcommand and fail loud on drift. ENOENT (binary/python absent) means
// "not installed" — the caller falls back to the reduced tier; any other error, or a version other
// than EXPECTED, is a broken contract and exits.
function checkVersion(bin: string, prefixArgs: string[]): "ok" | "absent" {
  let out: string;
  try {
    out = execFileSync(bin, [...prefixArgs, "version"], { cwd: targetDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    const e = err as { code?: string; stderr?: string; message?: string };
    if (e.code === "ENOENT") return "absent";
    console.error(`✗ vitals \`version\` check failed: ${e.stderr || e.message} — Harvey's M3 is verified against vitals ${EXPECTED_VITALS_VERSION}; this install's CLI contract differs`);
    process.exit(1);
  }
  const actual = out.match(/v?(\d+\.\d+\.\d+)/)?.[1];
  if (actual !== EXPECTED_VITALS_VERSION) {
    console.error(`✗ vitals version mismatch: expected ${EXPECTED_VITALS_VERSION}, got ${actual ?? (out.trim() || "(no version string)")}`);
    console.error(`  Harvey's M3 report schema (src/hotspot-scan.ts) is verified against vitals ${EXPECTED_VITALS_VERSION}; re-verify the schema against this version before running M3.`);
    process.exit(1);
  }
  return "ok";
}

// Resolves how to invoke a version-verified vitals: on PATH, else via a discovered plugin install.
// Returns undefined when neither is present/runnable, so the caller drops to the reduced tier.
// `scriptPath` (#1290) is the on-disk vitals_cli.py whose SIBLING MODULES deriveCouplingTotal
// imports — undefined when vitals resolved off PATH with no plugin install to point at, in which
// case the coupling denominator is disclosed as underivable rather than guessed.
function resolveVitals(): { bin: string; prefixArgs: string[]; scriptPath?: string } | undefined {
  const pluginPath = discoverVitalsCli();
  if (checkVersion("vitals_cli.py", []) === "ok") return { bin: "vitals_cli.py", prefixArgs: [], scriptPath: pluginPath };
  if (pluginPath && checkVersion("python3", [pluginPath]) === "ok") {
    console.log(`✓ Found vitals_cli.py at ${pluginPath}`);
    return { bin: "python3", prefixArgs: [pluginPath], scriptPath: pluginPath };
  }
  return undefined;
}

// #1290: vitals emits `coupling_data[:5]` (vitals_cli.py:305) and never the pre-cap total, so a
// 5-row list is indistinguishable from "exactly 5 coupled pairs exist in this repo". #1075 recorded
// that as undisclosable because vitals truncates upstream. It is not: the plugin ships the function
// that produced the list, beside the CLI Harvey already spawns.
//
// This calls the plugin's OWN `git_analysis.get_co_change_coupling` with the arguments vitals_cli.py
// itself passes (:122-124 — days=180, min_support=2) and re-applies vitals' own `is_source_file`
// filter (:125-130), so the number is vitals', not a re-implementation that could drift from it.
// scope_path is derived the same way run_report derives it (:64-83): relpath of the target from the
// repo root, or None when they are the same directory.
//
// MEASURED 2026-07-28 against this repo: 10 pairs pre-cap vs the 5 vitals reports, in 0.207s.
function deriveCouplingTotal(scriptPath: string): { total: number } | { unavailable: string } {
  const py = [
    "import sys, os, json",
    `sys.path.insert(0, ${JSON.stringify(dirname(scriptPath))})`,
    "import git_analysis as g",
    `target = ${JSON.stringify(targetDir)}`,
    "root = g.get_repo_root(target)",
    "if root is None: raise SystemExit('not a git checkout')",
    "scope = os.path.relpath(os.path.abspath(target), root)",
    "if scope == '.': scope = None",
    "raw = g.get_co_change_coupling(root, days=180, min_support=2, scope_path=scope)",
    "print(len([c for c in raw if g.is_source_file(c['file_a']) and g.is_source_file(c['file_b'])]))",
  ].join("\n");
  let out: string;
  try {
    out = execFileSync("python3", ["-c", py], { cwd: targetDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    return { unavailable: `re-running vitals' own get_co_change_coupling failed: ${(e.stderr || e.message || "").trim().split("\n").pop()}` };
  }
  const total = Number(out.trim());
  if (!Number.isInteger(total)) return { unavailable: `vitals' get_co_change_coupling returned unparseable output: ${JSON.stringify(out.trim().slice(0, 120))}` };
  return { total };
}

// #807 reduced tier: Harvey computes the churn×complexity ranking itself from git when vitals is not
// installed. churn = per-file change count over 90 days (git log); complexity = complexityProxy over
// the current file. Fails loud (exit 1) if the target is not a git checkout — with neither vitals nor
// git there is no basis for a ranking, and a silent empty table would read as a clean bill of health.
// #1075 point 4: also returns the PRE-slice qualifying count (fallbackQualifyingCount) so the CLI can
// print "showing top N of M" instead of the post-truncation row count buildFallbackReport returns.
function buildReducedReport(): { report: VitalsReport; qualifying: number } {
  let log: string;
  try {
    log = execFileSync("git", ["log", "--since=90 days ago", "--name-only", "--pretty=format:"], { cwd: targetDir, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    console.error(`✗ M3 reduced tier: vitals plugin unavailable AND \`git log\` failed in ${targetDir} (not a git checkout, or git missing): ${e.stderr || e.message}`);
    console.error(`  M3 cannot produce a hotspot ranking with neither vitals nor git history. Install the vitals plugin, or run against a git checkout.`);
    process.exit(1);
  }
  const churn = new Map<string, number>();
  for (const line of log.split("\n")) {
    const f = line.trim();
    if (f && SOURCE_EXT.test(f)) churn.set(f, (churn.get(f) ?? 0) + 1);
  }
  const files: FallbackFile[] = [];
  for (const [file, changes] of churn) {
    if (changes < 2) continue; // below the churn gate — skip reading (buildFallbackReport re-gates)
    let src: string;
    try {
      src = readFileSync(resolve(targetDir, file), "utf8");
    } catch {
      continue; // renamed/deleted since — no current content to score
    }
    files.push({ file_path: file, changes, complexity: complexityProxy(src) });
  }
  return { report: buildFallbackReport(files, Math.max(topK, 50)), qualifying: fallbackQualifyingCount(files) };
}

type LoadedReport = { report: VitalsReport; reduced: boolean; qualifying?: number; coupling: { total: number } | { unavailable: string } };

// A pre-captured --report is deliberately NOT re-derived against the target's CURRENT git state:
// the coupling total would then describe a different repository state than the report it bounds.
const CAPTURED_REPORT = "the report was supplied pre-captured via --report, so the pre-cap total cannot be recomputed against the state it was captured from";
const NO_PLUGIN_DIR = "vitals resolved off PATH with no plugin install beside it, so its git_analysis module could not be imported";

function loadReport(): LoadedReport {
  if (reportPath) {
    return { report: parseReport(readFileSync(resolve(reportPath), "utf8")), reduced: false, coupling: { unavailable: CAPTURED_REPORT } };
  }
  const vitals = resolveVitals();
  if (!vitals) {
    const { report, qualifying } = buildReducedReport();
    return { report, reduced: true, qualifying, coupling: { unavailable: "the reduced M3 tier computes no coupling at all" } };
  }
  let raw: string;
  try {
    // maxBuffer: vitals' --json carries a file_health entry per scored file, so the payload scales
    // with the repo. Node's 1MB default made M3 unrunnable against Harvey's own checkout — MEASURED
    // 2026-07-28 on `main` @8d7bd1a: `✗ vitals report failed: spawnSync python3 ENOBUFS`, the report
    // being 1.2MB. Matches the ceiling buildReducedReport already uses for `git log`.
    raw = execFileSync(vitals.bin, [...vitals.prefixArgs, "report", "--json", targetDir], { cwd: targetDir, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    console.error(`✗ vitals report failed: ${e.stderr || e.message}`);
    process.exit(1);
  }
  return {
    report: parseReport(raw),
    reduced: false,
    coupling: vitals.scriptPath ? deriveCouplingTotal(vitals.scriptPath) : { unavailable: NO_PLUGIN_DIR },
  };
}

const { report, reduced, qualifying, coupling } = loadReport();
if (reduced) {
  console.log("⚠ M3 REDUCED TIER (vitals plugin unavailable) — Harvey-computed churn×complexity ranking from git history only.");
  console.log("  NOT assessed in this tier: file health, co-change coupling, knowledge-risk (truck-factor), AI-provenance. Install the vitals plugin for the full M3 signal.");
}
// #1075 point 1: vitals' own "complexity-only" mode (no git in the target) sets churn=0 for every
// file, so every hotspot's risk_score is 0.0 — the "ranking" below is filesystem-walk order, not a
// churn×complexity ranking. Checked on risk_score directly (isUnranked), not just `mode`, so a
// pre-#1075 capture with no `mode` field is still caught.
const unranked = isUnranked(report);
const ranked = rankHotspots(report);
const top = unranked ? [] : topKFiles(report, topK);
const findings = toFactFindings(report);
// #1075 point 3 disclosed vitals' own caps but with no denominators ("capped at the first 50 source
// files"), so a reader could not tell 50-of-52 from 50-of-1792. #1290 replaces the hedge with the
// measured "N of M" per cap — and, because a console line reaches no client, ships the same three
// statements as a Finding (M3-SCOPE-00) that travels in --out and the pass artifact. #1112's
// correction survives inside vitalsScope: the knowledge denominator follows vitals' own branch
// (churning-with-complexity when any file cleared the gate, all tracked source files otherwise).
// The reduced tier is excluded because none of vitals' caps applies to a Harvey-computed ranking.
const scopeFinding = reduced ? undefined : capScopeFinding(report, "total" in coupling ? coupling.total : undefined, "unavailable" in coupling ? coupling.unavailable : "");
if (scopeFinding) findings.push(scopeFinding);

// #1290: the FULL tier truncates too and never said so — vitals slices `hotspots[:10]` off a
// population it emits in full as file_health, so "(10 rows, worst first)" read as a whole-repo
// table while 304 scored files were dropped (measured on this repo 2026-07-28). Both truncated
// forms keep the "(showing top N of M files" prefix src/audit-runners.ts:246 parses the ranked-row
// count out of.
const scoredFiles = vitalsScope(report).scored;
const rowsTruncated = reduced && qualifying !== undefined && qualifying > ranked.length;
const scoredTruncated = !reduced && scoredFiles !== undefined && scoredFiles > ranked.length;
console.log(
  rowsTruncated
    ? `M3 hotspot table — ${targetDir} (showing top ${ranked.length} of ${qualifying} files that cleared the churn gate, worst first)`
    : scoredTruncated
      ? `M3 hotspot table — ${targetDir} (showing top ${ranked.length} of ${scoredFiles} files vitals scored, worst first)`
      : `M3 hotspot table — ${targetDir} (${ranked.length} rows, worst first)`,
);
if (unranked) {
  // "M3 UNRANKED" is matched by src/audit-runners.ts to record this run `partial` (mirrors "M3
  // REDUCED TIER" for #807) — keep this exact string if the wording changes.
  console.log(
    `  ⚠ M3 UNRANKED: ${report.mode === "complexity-only" ? 'vitals ran in "complexity-only" mode — the target has no git history, so churn is 0 for every file and' : "every row scored"} risk_score 0.0. The table below is filesystem-walk order, NOT a churn×complexity ranking — it will NOT be used for cross-module hotspot enrichment or the M3 cross-reference below.`,
  );
}
console.log("  risk   health  churn   changes  complexity  file");
for (const row of ranked) {
  console.log(`  ${String(row.risk_score).padStart(6)} ${String(row.health).padStart(6)}  ${row.churn_label.padEnd(6)} ${String(row.changes).padStart(8)} ${String(row.complexity_score).padStart(11)}  ${row.file_path}`);
}

if (report.overall_health !== undefined) {
  console.log(`\nOverall codebase health: ${report.overall_health.toFixed(1)}/10 (vitals' own weighted roll-up over every analysed file, not just the table above)`);
}
if (report.trends) {
  console.log(`Trend vs. prior snapshot (${report.trends.days_since}d ago): ${report.trends.overall_delta >= 0 ? "+" : ""}${report.trends.overall_delta} overall, ${report.trends.degrading.length} file(s) degrading, ${report.trends.improving.length} improving.`);
} else if (report.trends === null) {
  console.log("Trend vs. prior snapshot: none — first vitals run against this target (no prior .vitals snapshot to compare).");
}

const byTaxonomy = new Map<string, number>();
for (const f of findings) byTaxonomy.set(f.taxonomy, (byTaxonomy.get(f.taxonomy) ?? 0) + 1);
console.log(`\n${findings.length} M3 finding(s):`);
for (const [tax, count] of byTaxonomy) console.log(`  ${count}× ${tax}`);
// Fail-loud doctrine: an absent sub-signal is stated, never silently omitted.
if (!report.provenance) {
  console.log("  AI-provenance: NOT ASSESSED — report has no provenance key (pre-0.2.0 vitals capture?)");
} else if (!report.provenance.has_data) {
  console.log("  AI-provenance: no data — no .vitals provenance DB in the target (vitals capture hooks not installed, or no AI edits logged)");
}
if (scopeFinding) console.log(`  ${scopeFinding.evidence.split("\n").join("\n  ")}`);

let crossReferenced: ReturnType<typeof crossReferenceHotspots> | undefined;
if (findingsPaths.length) {
  const external: Finding[] = findingsPaths.flatMap((p) => {
    const parsed = JSON.parse(readFileSync(resolve(p), "utf8")) as unknown;
    if (!Array.isArray(parsed)) {
      console.error(`✗ ${p}: expected a bare Finding[] array (the \`pnpm detect-static --out\` format)`);
      process.exit(1);
    }
    return parsed as Finding[];
  });
  crossReferenced = crossReferenceHotspots(external, report, topK);
  console.log(
    unranked
      ? `\nCross-reference: SKIPPED — the hotspot ranking is unranked (see above), so no finding is stamped "top remediation priority" against it.`
      : `\nCross-reference: ${crossReferenced.hotspotFindingIds.length} of ${external.length} finding(s) sit on a top-${topK} hotspot — flagged top remediation priority:`,
  );
  if (!unranked) for (const id of crossReferenced.hotspotFindingIds) console.log(`  ${id}`);
}

if (hotspotsOutPath) {
  writeFileSync(hotspotsOutPath, `${top.join("\n")}\n`);
  console.log(
    unranked
      ? `\nhotspot file list → ${hotspotsOutPath} is EMPTY (ranking unranked — see above), so no downstream consumer (M8 --hotspots, cross-module enrichment) will tag anything against it`
      : `\ntop-${topK} hotspot file list → ${hotspotsOutPath} (feed to \`pnpm mutation-scan <t> --hotspots ${hotspotsOutPath}\`)`,
  );
}

if (outPath) {
  const partialReasons: string[] = [];
  if (reduced) partialReasons.push("vitals plugin unavailable — reduced M3 tier: churn×complexity ranking only, no coupling/knowledge-risk/AI-provenance");
  if (unranked) partialReasons.push(`ranking unranked — ${report.mode === "complexity-only" ? "vitals ran in complexity-only mode (no git history in the target)" : "every hotspot row scored risk_score 0.0"}; the table is filesystem-walk order and was excluded from cross-module hotspot enrichment/cross-reference`);

  const artifact = {
    target: targetDir,
    mode: report.mode,
    overallHealth: report.overall_health,
    topK: top,
    hotspots: ranked,
    findings,
    crossReferenced,
    ...(rowsTruncated ? { qualifyingFileCount: qualifying } : {}),
    ...(reduced ? { reduced: true } : {}),
    ...(unranked ? { unranked: true } : {}),
    ...(partialReasons.length ? { partialReason: partialReasons.join(" | ") } : {}),
  };
  writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`\nM3 artifact → ${outPath} — merge \`findings\` (and \`crossReferenced.findings\`) into the engagement findings.json for report-template/`);
}

if (artifactsDirPath) {
  const tier = reduced ? "reduced" : unranked ? "unranked" : "full";
  const passArtifact = buildM3PassArtifact({ targetDir, findings, hotspots: top, rankedCount: ranked.length, tier, generatedAt: new Date().toISOString() });
  const path = writePassArtifact(artifactsDirPath, passArtifact);
  console.log(`\nM3 pass artifact → ${path} (run-audit --artifacts-dir ${artifactsDirPath} derives M3 ran from it)`);
}
