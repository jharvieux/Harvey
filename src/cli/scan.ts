// Scan CLI entry point.
//   pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]
//     [--tenant-key <column>] [--tenant-mode per-tenant|per-user] [--out <file>]
//   pnpm exec tsx src/cli/scan.ts --supabase <project-ref|local> [--functions <dir>] [--out <file>]
//
// --supabase against a hosted project needs SUPABASE_ACCESS_TOKEN (a Management API personal
// access token) in the environment; `--supabase local` targets a `supabase start` stack and
// needs none. --functions <dir> points at the client repo's supabase/functions directory to
// also run the edge-function secret/webhook-signature checks. See src/scan/supabase.ts.
//
// Prints a Finding[] JSON array to stdout (or writes it to --out).

import { writeFileSync } from "node:fs";
import type { Finding } from "../findings.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { runSupabaseScan } from "../scan/supabase.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function tenantMode(raw: string | undefined): "per-tenant" | "per-user" | undefined {
  if (raw === undefined || raw === "per-tenant" || raw === "per-user") return raw;
  console.error(`--tenant-mode must be "per-tenant" or "per-user", got "${raw}"`);
  process.exit(2);
}

function emit(findings: Finding[]): void {
  const json = JSON.stringify(findings, null, 2);
  const out = arg("--out");
  if (out) writeFileSync(out, json);
  else console.log(json);
}

async function main(): Promise<void> {
  if (process.argv.includes("--mechanical")) {
    const dir = arg("--dir") ?? process.cwd();
    const bundle = arg("--bundle");
    const tenantKey = arg("--tenant-key");
    const mode = tenantMode(arg("--tenant-mode"));
    const tenancyOverride = tenantKey || mode ? { tenantKey, mode } : undefined;
    emit(await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride }));
    return;
  }

  const supabaseTarget = arg("--supabase");
  if (supabaseTarget) {
    const functionsDir = arg("--functions");
    const findings =
      supabaseTarget === "local"
        ? await runSupabaseScan({ local: true, functionsDir })
        : await runSupabaseScan({ projectRef: supabaseTarget, functionsDir });
    emit(findings);
    return;
  }

  console.error("usage: scan --mechanical --dir <path> [--bundle <path>] [--out <file>]");
  console.error("       scan --supabase <project-ref|local> [--functions <dir>] [--out <file>]");
  process.exit(2);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
