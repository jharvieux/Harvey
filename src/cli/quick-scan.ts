// harvey quick-scan — the free freemium tier. Runs the mechanical scan layer locally
// (src/scan/mechanical.ts) against a target directory and prints the free-tier DIAGNOSIS:
// grade, counts, located findings + a plain-English risk line each, and ONE fully-revealed
// sample finding with its fix. The remediation for every other finding, the deep scan,
// monitoring, and the exportable report are gated behind the paid unlock.
//
//   pnpm quick-scan --dir <path> [--bundle <path>] [--tenant-key <column>]
//                    [--tenant-mode per-tenant|per-user] [--json] [--out <file>]
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
import { runMechanicalScan } from "../scan/mechanical.js";
import { buildQuickScanReport, type QuickScanReport } from "../quick-scan.js";

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
    lines.push("  Outdated dependencies matching a published CVE range. A version match is not");
    lines.push("  proof of exploitability, so these don't move your grade — the deep scan triages");
    lines.push("  each one against how you actually deploy.");
    lines.push("");
    for (const f of r.informational) {
      lines.push(`    [Info] ${f.title}`);
      lines.push(`      ${f.location}`);
      lines.push("");
    }
  }

  if (r.total === 0 && r.indicators.length === 0 && r.informational.length === 0) {
    lines.push("  Stay clean on every push — monitoring is part of the paid unlock.");
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
  const report = buildQuickScanReport(await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride }));

  const out = arg("--out");
  const body = process.argv.includes("--json") ? JSON.stringify(report, null, 2) : render(report);
  if (out) writeFileSync(out, body);
  else console.log(body);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
