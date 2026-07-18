// M3 hotspot scan (#363) — runs the vitals plugin's `report --json` against a target repo (or
// consumes a pre-captured report) and shapes it into the M3 deliverable: the ranked hotspot
// table, the deterministic boolean-fact Finding[] (truck-factor-1, co-change coupling,
// AI-authored+high-churn — src/hotspot-scan.ts::toFactFindings), the top-K hotspot file list
// M8's `--hotspots` flag consumes, and the mechanical cross-reference of other modules' findings
// against the top-K (a security/perf finding on a hotspot is top remediation priority).
//
// vitals is an EXTERNAL plugin, not a dependency of this repo (CLAUDE.md M3 row: run, don't
// build), and `vitals_cli.py` is often NOT on PATH in agent sandboxes (#314) — pass --report
// with a captured `vitals_cli.py report --json <dir>` output in that case.
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

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { homedir } from "node:os";
import type { Finding } from "../findings.js";
import { crossReferenceHotspots, rankHotspots, toFactFindings, topKFiles, type VitalsReport } from "../hotspot-scan.js";

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
      const versions = readdirSync(cacheVitalsDir);
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
  console.error("usage: pnpm exec tsx src/cli/hotspot-scan.ts <target-dir> [--report <vitals.json>] [--out <m3.json>] [--hotspots-out <file>] [--findings <file>]... [--top <k>]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const reportPath = arg("--report");
const outPath = arg("--out");
const hotspotsOutPath = arg("--hotspots-out");
const topK = Number(arg("--top") ?? 10);
const findingsPaths = args.flatMap((a, i) => (a === "--findings" && args[i + 1] ? [args[i + 1]!] : []));

function loadReport(): VitalsReport {
  let raw: string;
  if (reportPath) {
    raw = readFileSync(resolve(reportPath), "utf8");
  } else {
    // Try PATH first (existing behavior)
    const attemptedPaths: string[] = ["vitals_cli.py on PATH"];
    try {
      raw = execFileSync("vitals_cli.py", ["report", "--json", targetDir], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      const e = err as { code?: string; stderr?: string; message?: string };

      // Try plugin discovery locations if PATH failed
      if (e.code === "ENOENT") {
        const pluginPath = discoverVitalsCli();
        if (pluginPath) {
          try {
            raw = execFileSync("python3", [pluginPath, "report", "--json", targetDir], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
            console.log(`✓ Found vitals_cli.py at ${pluginPath}`);
          } catch (err2) {
            const e2 = err2 as { stderr?: string; message?: string };
            const detail = e2.stderr || e2.message || "vitals_cli.py failed";
            attemptedPaths.push(pluginPath);
            console.error(`✗ vitals_cli.py found at ${pluginPath} but failed: ${detail}`);
            console.error(`  Searched locations: ${attemptedPaths.join(", ")}`);
            process.exit(1);
          }
        } else {
          const detail = "vitals_cli.py not found on PATH or in plugin install locations (#507)";
          const pluginLocations = [
            `${homedir()}/.claude/plugins/marketplaces/vitals/scripts/vitals_cli.py`,
            `${homedir()}/.claude/plugins/cache/vitals/*/scripts/vitals_cli.py`,
          ];
          console.error(`✗ ${detail}`);
          console.error(`  Searched locations: ${attemptedPaths.concat(pluginLocations).join(", ")}`);
          console.error(`  Solutions:`);
          console.error(`    1. Install vitals plugin: follow https://github.com/vitals-ai/vitals docs`);
          console.error(`    2. Or run vitals locally and pass the capture: --report <vitals.json>`);
          process.exit(1);
        }
      } else {
        const detail = e.stderr || e.message || "vitals_cli.py failed";
        console.error(`✗ vitals_cli.py error: ${detail}`);
        console.error(`  Searched locations: ${attemptedPaths.join(", ")}`);
        process.exit(1);
      }
    }
  }
  const parsed = JSON.parse(raw) as VitalsReport;
  // Fail loud on schema drift: a report without these arrays is not the verified #94 shape.
  const missing = (["hotspots", "coupling", "knowledge_risk"] as const).filter((k) => !Array.isArray(parsed[k]));
  if (missing.length) {
    console.error(`✗ vitals report is missing expected array(s): ${missing.join(", ")} — schema drift from the #94-verified vitals 0.2.0 shape; re-verify src/hotspot-scan.ts against the installed vitals version`);
    process.exit(1);
  }
  return parsed;
}

const report = loadReport();
const ranked = rankHotspots(report);
const top = topKFiles(report, topK);
const findings = toFactFindings(report);

console.log(`M3 hotspot table — ${targetDir} (${ranked.length} rows, worst first)`);
console.log("  risk   health  churn   changes  complexity  file");
for (const row of ranked) {
  console.log(`  ${String(row.risk_score).padStart(6)} ${String(row.health).padStart(6)}  ${row.churn_label.padEnd(6)} ${String(row.changes).padStart(8)} ${String(row.complexity_score).padStart(11)}  ${row.file_path}`);
}

const byTaxonomy = new Map<string, number>();
for (const f of findings) byTaxonomy.set(f.taxonomy, (byTaxonomy.get(f.taxonomy) ?? 0) + 1);
console.log(`\n${findings.length} M3 boolean-fact finding(s):`);
for (const [tax, count] of byTaxonomy) console.log(`  ${count}× ${tax}`);
// Fail-loud doctrine: an absent sub-signal is stated, never silently omitted.
if (!report.provenance) {
  console.log("  AI-provenance: NOT ASSESSED — report has no provenance key (pre-0.2.0 vitals capture?)");
} else if (!report.provenance.has_data) {
  console.log("  AI-provenance: no data — no .vitals provenance DB in the target (vitals capture hooks not installed, or no AI edits logged)");
}

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
  console.log(`\nCross-reference: ${crossReferenced.hotspotFindingIds.length} of ${external.length} finding(s) sit on a top-${topK} hotspot — flagged top remediation priority:`);
  for (const id of crossReferenced.hotspotFindingIds) console.log(`  ${id}`);
}

if (hotspotsOutPath) {
  writeFileSync(hotspotsOutPath, `${top.join("\n")}\n`);
  console.log(`\ntop-${topK} hotspot file list → ${hotspotsOutPath} (feed to \`pnpm mutation-scan <t> --hotspots ${hotspotsOutPath}\`)`);
}

if (outPath) {
  const artifact = { target: targetDir, topK: top, hotspots: ranked, findings, crossReferenced };
  writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`\nM3 artifact → ${outPath} — merge \`findings\` (and \`crossReferenced.findings\`) into the engagement findings.json for report-template/`);
}
