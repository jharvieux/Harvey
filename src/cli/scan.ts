// Scan CLI entry point.
//   pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]
//     [--tenant-key <column>] [--tenant-mode per-tenant|per-user] [--out <file>]
//   pnpm exec tsx src/cli/scan.ts --supabase <project-ref|local> [--functions <dir>]
//     [--gotrue-url <url> --gotrue-anon-key <key>] [--out <file>]
//
// --supabase against a hosted project needs SUPABASE_ACCESS_TOKEN (a Management API personal
// access token) in the environment; `--supabase local` targets a `supabase start` stack and
// needs none. --functions <dir> points at the client repo's supabase/functions directory to
// also run the edge-function secret/webhook-signature checks. --gotrue-url/--gotrue-anon-key
// (pass both, or neither — #1298) probe a self-hosted GoTrue instance's /health and /settings
// endpoints for the two version-gated CVE checks (checkGotrueVersion); hosted Supabase
// auto-patches GoTrue so this only matters for self-hosted deployments. See src/scan/supabase.ts.
//
// Prints a Finding[] JSON array to stdout (or writes it to --out).

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags, targetDir } from "./args.js";
import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { runSupabaseScan } from "../scan/supabase.js";

const FLAGS = [
  "--bundle",
  "--dir",
  "--target",
  "--functions",
  "--gotrue-anon-key",
  "--gotrue-url",
  "--mechanical",
  "--out",
  "--supabase",
  "--tenant-key",
  "--tenant-mode",
] as const;

function tenantMode(raw: string | undefined): "per-tenant" | "per-user" | undefined {
  if (raw === undefined || raw === "per-tenant" || raw === "per-user") return raw;
  console.error(`--tenant-mode must be "per-tenant" or "per-user", got "${raw}"`);
  process.exit(2);
}

// #1298: --gotrue-url and --gotrue-anon-key must arrive together — one without the other can
// never form a valid probe target, so fail loud rather than silently skip the CVE checks.
export function gotrueProbeArg(argv: string[] = process.argv): { authUrl: string; anonKey: string } | undefined {
  const authUrl = arg("--gotrue-url", argv);
  const anonKey = arg("--gotrue-anon-key", argv);
  if (!authUrl && !anonKey) return undefined;
  if (!authUrl || !anonKey) {
    console.error("--gotrue-url and --gotrue-anon-key must be passed together.");
    process.exit(2);
  }
  return { authUrl, anonKey };
}

function emit(findings: Finding[]): void {
  // #975 — declare AST/connected-tier detector CWEs (Supabase static/config/advisor rows).
  const json = JSON.stringify(enrichFindingsCwe(findings), null, 2);
  const out = arg("--out");
  if (out) writeFileSync(out, json);
  else console.log(json);
}

async function main(): Promise<void> {
  if (process.argv.includes("--mechanical")) {
    assertKnownFlags(FLAGS);
    const dir = targetDir();
    const bundle = arg("--bundle");
    const tenantKey = arg("--tenant-key");
    const mode = tenantMode(arg("--tenant-mode"));
    const tenancyOverride = tenantKey || mode ? { tenantKey, mode } : undefined;
    emit(await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride }));
    return;
  }

  const supabaseTarget = arg("--supabase");
  if (supabaseTarget) {
    assertKnownFlags(FLAGS);
    const functionsDir = arg("--functions");
    const gotrueProbe = gotrueProbeArg();
    const findings =
      supabaseTarget === "local"
        ? await runSupabaseScan({ local: true, functionsDir, gotrueProbe })
        : await runSupabaseScan({ projectRef: supabaseTarget, functionsDir, gotrueProbe });
    emit(findings);
    return;
  }

  console.error("usage: scan --mechanical --dir <path> [--bundle <path>] [--out <file>]");
  console.error(
    "       scan --supabase <project-ref|local> [--functions <dir>] [--gotrue-url <url> --gotrue-anon-key <key>] [--out <file>]",
  );
  process.exit(2);
}

// Guarded so scan.test.ts can import gotrueProbeArg without the CLI's argv-driven main() firing
// on import (same pattern as dry-run-scorecard.ts/pentest.ts).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
