// Scan CLI entry point.
//   pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]
//     [--tenant-key <column>] [--tenant-mode per-tenant|per-user] [--auth-guards a,b] [--out <file>]
//   pnpm exec tsx src/cli/scan.ts --supabase <project-ref|local> [--functions <dir>] [--migrations <dir>]
//     [--gotrue-url <url> --gotrue-anon-key <key>] [--out <file>]
//
// --supabase against a hosted project needs SUPABASE_ACCESS_TOKEN (a Management API personal
// access token) in the environment; `--supabase local` targets a `supabase start` stack and
// needs none. --functions <dir> points at the client repo's supabase/functions directory to
// also run the edge-function secret/webhook-signature checks. --gotrue-url/--gotrue-anon-key
// (pass both, or neither — #1298) probe a self-hosted GoTrue instance's /health and /settings
// endpoints for the two version-gated CVE checks (checkGotrueVersion); hosted Supabase
// auto-patches GoTrue so this only matters for self-hosted deployments. See src/scan/supabase.ts.
// --migrations <dir> points at the client repo's supabase/migrations (or the repo root above it) and
// turns on the prod-vs-migration drift comparison (#1280). Without it the scan still reports the
// topic, as an SB-DRIFT-00 not-assessed row — never as silence.
// --rest-url <url> (local mode only, #1494) probes the project's own PostgREST surface for its
// exposed-schema allow-list — no Management API credential needed. Defaults to the local stack's
// own REST URL (http://127.0.0.1:54321/rest/v1); pass an unreachable value to force the pre-#1494
// 3-omission SB-SCOPE-00 disclosure instead.
//
// Record the run into the engagement's artifacts dir so M2's scope statement can say drift WAS
// observed on this engagement rather than pointing at a row elsewhere in the report (#1280):
//   scan --supabase <ref> --migrations <dir> --out connected.json
//   pnpm record-pass --module M1 --pass connected --target <dir> --findings connected.json --out <artifacts-dir>
//
// Prints a Finding[] JSON array to stdout (or writes it to --out).

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { arg, assertKnownFlags, targetDir } from "./args.js";
import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { LOCAL_REST_URL, runSupabaseScan } from "../scan/supabase.js";

const FLAGS = [
  "--auth-guards",
  "--bundle",
  "--dir",
  "--target",
  "--functions",
  "--gotrue-anon-key",
  "--gotrue-url",
  "--mechanical",
  "--migrations",
  "--out",
  "--rest-url",
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
    // #126 option (2), finally shipped by #1300: names the engagement knows are guards but whose
    // house style neither the built-in list nor the project-aware discovery recognises.
    const authGuards = arg("--auth-guards")?.split(",").map((n) => n.trim()).filter((n) => n.length > 0);
    emit(await runMechanicalScan({ dir, bundleDir: bundle, tenancyOverride, authGuards }));
    return;
  }

  const supabaseTarget = arg("--supabase");
  if (supabaseTarget) {
    assertKnownFlags(FLAGS);
    const functionsDir = arg("--functions");
    const migrationsDir = arg("--migrations");
    const gotrueProbe = gotrueProbeArg();
    // #1494 — local mode defaults to probing the local stack's own REST surface unless overridden;
    // hosted mode already answers these two checks through the Management API and ignores it.
    const restUrl = arg("--rest-url") ?? LOCAL_REST_URL;
    const findings =
      supabaseTarget === "local"
        ? await runSupabaseScan({ local: true, functionsDir, migrationsDir, gotrueProbe, restUrl })
        : await runSupabaseScan({ projectRef: supabaseTarget, functionsDir, migrationsDir, gotrueProbe });
    emit(findings);
    return;
  }

  console.error("usage: scan --mechanical --dir <path> [--bundle <path>] [--out <file>]");
  console.error(
    "       scan --supabase <project-ref|local> [--functions <dir>] [--migrations <dir>] [--gotrue-url <url> --gotrue-anon-key <key>] [--rest-url <url>] [--out <file>]",
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
