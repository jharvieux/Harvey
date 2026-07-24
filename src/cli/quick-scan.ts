// harvey quick-scan — the free freemium tier. Runs the mechanical scan layer locally
// (src/scan/mechanical.ts) against a target directory and prints the free-tier DIAGNOSIS:
// grade, counts, located findings + a plain-English risk line each, and ONE fully-revealed
// sample finding with its fix. The remediation for every other finding, the deep scan,
// the re-scan diff, and the exportable report are gated behind the paid unlock.
//
//   pnpm quick-scan --dir <path> [--bundle <path>] [--tenant-key <column>]
//                    [--tenant-mode per-tenant|per-user] [--json] [--out <file>]
//                    [--findings-out <file>] [--sarif-out <file>] [--sbom-out <file>]
//
// --sbom-out (#887): a CycloneDX 1.5 SBOM of the target's dependencies — the procurement artifact
// buyers ask for contractually. Built from the target's lockfile (src/sbom.ts); when the tree
// cannot be resolved the document says so in its own compositions/properties AND the CLI prints
// the reason, so an incomplete inventory is never handed over looking complete.
//
// --sarif-out (#867): the raw mechanical Finding[] as SARIF 2.1.0, for GitHub code scanning or an
// ASPM the client already runs. quick-scan has NO coverage ledger to export — it is one tier of one
// module — so the SARIF carries an explicit "no ledger, and here is the scope this actually covers"
// notification rather than presenting a mechanical scan as a completed audit.
//
// --findings-out (#528): write the RAW mechanical Finding[] (the input to the free report, before
// the free/paid gating) as a JSON array — the machine-readable feed the orchestrator's M1 probe
// reads to detect coverage-disclosure findings (e.g. SEC-TH-GH-00, git-history tier unassessed).
// Distinct from --out, which writes the gated free diagnosis.
//
// Privacy: the scan runs locally and NO SOURCE CODE leaves the machine. Two mechanical
// checks make network calls that send non-source data only — TruffleHog (--only-verified)
// sends secret hashes to verify liveness, OSV sends dependency coordinates to match CVEs.
// Neither uploads your code. The DEEP scan (paid) is the only tier that needs code egress.
//
// --tenant-key / --tenant-mode (#280): the same declaration detect-deeper.ts (connected tier)
// accepts, so the static RLS-tenancy review (SB-RLS-TENANCY-MODEL) can be told the app's tenancy
// convention instead of only inferring it from a fixed candidate-column list.

import { writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { runMechanicalScan } from "../scan/mechanical.js";
import { relativizeScanScope } from "../scan/scan-scope.js";
import { buildSbom } from "../sbom.js";
import { buildQuickScanReport, HANDROLLED_FILES_SHOWN, HANDROLLED_SECTION_BLURB, HANDROLLED_SECTION_TITLE, type QuickScanReport } from "../quick-scan.js";
import { toSarif } from "../sarif.js";

// What a quick-scan SARIF export does and does not cover. Stated in the export itself because a
// SARIF file outlives the terminal session that produced it: an importer who sees only results has
// no way to know nine of the ten modules were never attempted.
const QUICK_SCAN_SARIF_SCOPE =
  "This is a free quick-scan (M1 mechanical tier only), not a Harvey audit. It covers dependency, " +
  "secret, and dangerous-config hygiene plus static indicators. The other nine audit modules " +
  "(M2 pen-test, M3 hotspots, M4 duplication, M5 dead code, M6 maintainability, M7 performance, " +
  "M8 test quality, M9 App Router boundaries, M10 data classification) and the live/LLM tiers of " +
  "M1 were NOT run. Absence of a result here is not evidence of absence of a problem. " +
  "Run `run-audit <target> --sarif-out <file>` for an export carrying a real per-module ledger.";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function tenantMode(raw: string | undefined): "per-tenant" | "per-user" | undefined {
  if (raw === undefined || raw === "per-tenant" || raw === "per-user") return raw;
  console.error(`--tenant-mode must be "per-tenant" or "per-user", got "${raw}"`);
  process.exit(2);
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Perf", "Info", "Watch"] as const;

function wrap(text: string, indent: string): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let line = "";
  for (const w of words) {
    if (line && `${line} ${w}`.length > 78) {
      lines.push(indent + line);
      line = w;
    } else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(indent + line);
  return lines;
}

function render(r: QuickScanReport): string {
  const lines: string[] = [];
  lines.push("");
  // Two-part headline (#227): the grade never appears without its scope, and the risk
  // disclosure sits directly under it — a hygiene grade read as a security verdict is the
  // failure mode this tier exists to avoid.
  lines.push(`  Harvey Quick Scan — Hygiene Grade ${r.grade}  (${r.score}/100)`);
  lines.push(`  Scope: ${r.gradeScope}`);
  lines.push("  Ran 100% locally. No source code left your machine.");
  lines.push("");
  lines.push(...wrap(r.riskDisclosure, "  "));
  lines.push("");

  if (r.total === 0) {
    lines.push("  No hygiene issues found — nothing mechanically verifiable to fix.");
  } else {
    const counts = SEVERITY_ORDER.filter((s) => r.countsBySeverity[s] > 0)
      .map((s) => `${r.countsBySeverity[s]} ${s}`)
      .join(", ");
    lines.push(`  ${r.total} verified hygiene issue${r.total === 1 ? "" : "s"}: ${counts}`);
    lines.push(`  By category: ${r.categories.map((c) => `${c.count}× ${c.category}`).join(", ")}`);
    lines.push("");

    lines.push("  What's wrong and where:");
    for (const f of r.findings) {
      lines.push(`    [${f.severity}] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push(`      Why it matters: ${f.risk}`);
      lines.push("");
    }
  }

  if (r.indicators.length > 0) {
    lines.push("  ── Potential issues — confirmed or cleared in the deep scan ─────────────");
    lines.push("  Spotted in your source. NOT counted in the grade: these need a live database");
    lines.push("  to confirm, and we don't guess.");
    lines.push("");
    for (const f of r.indicators) {
      lines.push(`    [${f.severity}?] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push(`      Why it matters if real: ${f.risk}`);
      lines.push("");
    }
  }

  if (r.informational.length > 0) {
    lines.push("  ── Informational — not graded ─────────────");
    lines.push("  Facts we verified but won't grade you on: dependency versions matching a");
    lines.push("  published CVE range (a version match is not proof of exploitability) and");
    lines.push("  credential-shaped strings in docs/example deployment files (near-certainly");
    lines.push("  placeholders, stated per finding). The deep scan triages each one.");
    // #874: the list is ordered by whether your code actually imports the package. Say so, or the
    // ordering looks arbitrary — and say what it is NOT, or "not imported" reads as "safe".
    lines.push("  CVE rows are ordered by reachability: packages your code imports first.");
    lines.push("");
    // Deliberately labeled [Info] rather than each row's underlying severity: an ungraded row
    // printed "[Critical]" would talk over the section's own "not graded" framing (#213).
    for (const f of r.informational) {
      lines.push(`    [Info] ${f.title}`);
      lines.push(`      ${f.location}`);
      if (f.reachability) lines.push(...wrap(`Reachability (${f.reachability.status}): ${f.reachability.justification}`, "      "));
      lines.push("");
    }
  }

  if (r.handrolled.length > 0) {
    lines.push(`  ── ${HANDROLLED_SECTION_TITLE} ─────────────`);
    lines.push(...wrap(HANDROLLED_SECTION_BLURB, "  "));
    lines.push("");
    for (const c of r.handrolled) {
      const fileCount = c.files.length;
      lines.push(`    ${c.shape} — ${c.total} place${c.total === 1 ? "" : "s"} in ${fileCount} file${fileCount === 1 ? "" : "s"}`);
      for (const f of c.files.slice(0, HANDROLLED_FILES_SHOWN)) {
        lines.push(`      ${f.locations[0]}${f.locations.length > 1 ? ` (${f.locations.length} places in this file)` : ""}`);
      }
      // The volume cap never truncates silently: what isn't printed is counted out loud,
      // and every location is in the --json report.
      const hidden = c.files.slice(HANDROLLED_FILES_SHOWN);
      if (hidden.length > 0) {
        const hiddenPlaces = hidden.reduce((sum, f) => sum + f.locations.length, 0);
        lines.push(`      … and ${hidden.length} more file${hidden.length === 1 ? "" : "s"} (${hiddenPlaces} more place${hiddenPlaces === 1 ? "" : "s"}) — every location is in the --json output`);
      }
      lines.push("");
    }
  }

  if (r.total === 0 && r.indicators.length === 0 && r.informational.length === 0 && r.handrolled.length === 0) {
    lines.push("  Re-scan after your next release and we'll diff it against this run.");
    lines.push("");
  }

  if (r.sample) {
    lines.push("  ── Sample fix (one finding, fully revealed) ─────────────");
    lines.push(`  [${r.sample.severity}] ${r.sample.title}`);
    lines.push(`    ${r.sample.location}`);
    lines.push(`    Fix: ${r.sample.fix}`);
    lines.push("  This is what the unlock delivers — for every finding above.");
    lines.push("");
  }

  lines.push("  Unlock to get:");
  for (const g of r.gated) lines.push(`    • ${g}`);
  if (r.reviewTierExcluded > 0) {
    lines.push("");
    lines.push(
      `  (${r.reviewTierExcluded} lower-confidence signal${r.reviewTierExcluded === 1 ? "" : "s"} were found and ` +
        "deliberately left out of your grade — triaged in the deep scan, never counted here.)",
    );
  }
  lines.push("");
  return lines.join("\n");
}

async function main(): Promise<void> {
  const dir = arg("--dir") ?? process.cwd();
  const bundle = arg("--bundle");
  const tenantKey = arg("--tenant-key");
  const mode = tenantMode(arg("--tenant-mode"));
  const tenancyOverride = tenantKey || mode ? { tenantKey, mode } : undefined;
  // #933: runMechanicalScan walks a scratch copy of the target (src/scan/scan-scope.ts, #101),
  // so every raw location carries that run's mkdtemp `harvey-scan-scope-*` prefix. Relativized
  // HERE, before any consumer below (the free report, --findings-out, the handrolled grouping,
  // SARIF) — quick-scan is the client-facing free report; a per-run/per-machine scratch path in
  // front of every finding location is unreadable and looks like a leaked internal path.
  const rawFindings = (await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride, handrolledIndicators: true })).map((f) => ({
    ...f,
    location: relativizeScanScope(f.location),
  }));
  const report = buildQuickScanReport(rawFindings);

  const findingsOut = arg("--findings-out");
  if (findingsOut) writeFileSync(findingsOut, `${JSON.stringify(rawFindings, null, 2)}\n`);

  const sarifOut = arg("--sarif-out");
  if (sarifOut) {
    const sarif = toSarif(rawFindings, { coverageAbsent: QUICK_SCAN_SARIF_SCOPE }, { baseUri: dir });
    writeFileSync(sarifOut, `${JSON.stringify(sarif, null, 2)}\n`);
    console.error(`SARIF 2.1.0 (${rawFindings.length} result(s)) → ${sarifOut}`);
  }

  const sbomOut = arg("--sbom-out");
  if (sbomOut) {
    const { bom, warning } = buildSbom(dir, { targetName: basename(resolve(dir)) });
    writeFileSync(sbomOut, `${JSON.stringify(bom, null, 2)}\n`);
    console.error(`CycloneDX SBOM (${(bom as { components: unknown[] }).components.length} component(s)) → ${sbomOut}`);
    if (warning) console.error(`⚠ SBOM is not a complete inventory: ${warning}`);
  }

  const out = arg("--out");
  const body = process.argv.includes("--json") ? JSON.stringify(report, null, 2) : render(report);
  if (out) writeFileSync(out, body);
  else console.log(body);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
