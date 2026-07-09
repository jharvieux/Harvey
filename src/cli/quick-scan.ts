// harvey quick-scan — the free freemium tier. Runs the mechanical scan layer locally
// (src/scan/mechanical.ts) against a target directory and prints the free-tier DIAGNOSIS:
// grade, counts, located findings + a plain-English risk line each, and ONE fully-revealed
// sample finding with its fix. The remediation for every other finding, the deep scan,
// monitoring, and the exportable report are gated behind the paid unlock.
//
//   pnpm quick-scan --dir <path> [--bundle <path>] [--json] [--out <file>]
//
// Privacy: the scan runs locally and NO SOURCE CODE leaves the machine. Two mechanical
// checks make network calls that send non-source data only — TruffleHog (--only-verified)
// sends secret hashes to verify liveness, OSV sends dependency coordinates to match CVEs.
// Neither uploads your code. The DEEP scan (paid) is the only tier that needs code egress.

import { writeFileSync } from "node:fs";
import { runMechanicalScan } from "../scan/mechanical.js";
import { buildQuickScanReport, type QuickScanReport } from "../quick-scan.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Perf", "Info", "Watch"] as const;

function render(r: QuickScanReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  Harvey Quick Scan — Grade ${r.grade}  (${r.score}/100)`);
  lines.push("  Ran 100% locally. No source code left your machine.");
  lines.push("");

  if (r.total === 0) {
    lines.push("  No verified issues found. Clean scan.");
    lines.push("  Stay clean on every push — monitoring is part of the paid unlock.");
    lines.push("");
    return lines.join("\n");
  }

  const counts = SEVERITY_ORDER.filter((s) => r.countsBySeverity[s] > 0)
    .map((s) => `${r.countsBySeverity[s]} ${s}`)
    .join(", ");
  lines.push(`  ${r.total} verified issue${r.total === 1 ? "" : "s"}: ${counts}`);
  lines.push(`  By category: ${r.categories.map((c) => `${c.count}× ${c.category}`).join(", ")}`);
  lines.push("");

  lines.push("  What's wrong and where:");
  for (const f of r.findings) {
    lines.push(`    [${f.severity}] ${f.title}`);
    lines.push(`      ${f.location}`);
    lines.push(`      Why it matters: ${f.risk}`);
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
  const report = buildQuickScanReport(await runMechanicalScan({ dir, bundleDir: bundle }));

  const out = arg("--out");
  const body = process.argv.includes("--json") ? JSON.stringify(report, null, 2) : render(report);
  if (out) writeFileSync(out, body);
  else console.log(body);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
