// Static Supabase-config checks read from COMMITTED files (B13, #71) — no live project needed, so
// these run in the mechanical scan / free-count gate (unlike supabase-config.ts, which scores
// live-fetched Advisor/Management-API inputs at connected tier). Two checks:
//   - checkMigrationRlsStatic: `create table public.X` in supabase/migrations/*.sql with no
//     matching `enable row level security` anywhere — the static path for P-RLS-DISABLED, which
//     was connected-tier only. High precision: both signals are exact DDL, the enable-check is
//     aggregated across the WHOLE migration set (a table enabled in a LATER migration, or a
//     service-only deny-all table with RLS on + zero policies, is cleared), and views are ignored.
//   - checkEdgeFunctionVerifyJwt: `[functions.X] verify_jwt = false` in supabase/config.toml — an
//     Edge Function callable without a valid JWT. Review: a webhook that HMAC-verifies its own
//     payload legitimately disables verify_jwt.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

const CREATE_TABLE = /create\s+table\s+(?:if\s+not\s+exists\s+)?public\.([a-z0-9_]+)/gi;
const ENABLE_RLS = /alter\s+table\s+(?:only\s+)?public\.([a-z0-9_]+)\s+enable\s+row\s+level\s+security/gi;

interface CreatedTable {
  name: string;
  file: string; // path relative to the scanned dir
  line: number;
}

export function checkMigrationRlsStatic(dir: string): Finding[] {
  const migrationsDir = join(dir, "supabase", "migrations");
  if (!existsSync(migrationsDir)) return [];

  const created = new Map<string, CreatedTable>();
  const enabled = new Set<string>();

  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    const raw = readFileSync(join(migrationsDir, file), "utf8");
    // Strip comments so commented-out DDL (e.g. an "intentionally NO enable RLS" note that quotes
    // the statement it's warning about) can't register as a real create/enable. Keep line count
    // stable by blanking rather than deleting, so the create-site line number stays accurate.
    const sql = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/--[^\n]*/g, "");
    const rel = relative(dir, join(migrationsDir, file));
    for (const m of sql.matchAll(CREATE_TABLE)) {
      const name = m[1]!.toLowerCase();
      if (!created.has(name)) {
        const line = sql.slice(0, m.index).split("\n").length;
        created.set(name, { name, file: rel, line });
      }
    }
    for (const m of sql.matchAll(ENABLE_RLS)) enabled.add(m[1]!.toLowerCase());
  }

  return [...created.values()]
    .filter((t) => !enabled.has(t.name))
    .map((t) =>
      mechanicalFinding({
        id: `SB-RLS-STATIC-${t.name}`,
        title: `public.${t.name} is created but never gets RLS enabled in any migration`,
        severity: "Critical",
        category: "Supabase config",
        taxonomy: "Migration table without RLS (static)",
        location: `${t.file}:${t.line}`,
        evidence: `create table public.${t.name} has no matching "alter table public.${t.name} enable row level security" anywhere in supabase/migrations/.`,
        impact: "A public-schema table with RLS off is auto-exposed via PostgREST — every row is readable/writable by anyone holding the anon key, with no per-row restriction.",
        fix: "Add `alter table public." + t.name + " enable row level security;` plus policies, or move the table out of the exposed public schema.",
        precisionTier: "high",
      }),
    );
}

const FUNCTIONS_HEADER = /^\s*\[functions\.([a-z0-9_-]+)\]/i;
const VERIFY_JWT_FALSE = /^\s*verify_jwt\s*=\s*false\b/i;
const TABLE_HEADER = /^\s*\[/;

// Parse supabase/config.toml for [functions.X] tables that set verify_jwt = false.
export function checkEdgeFunctionVerifyJwt(dir: string): Finding[] {
  const configPath = join(dir, "supabase", "config.toml");
  if (!existsSync(configPath)) return [];

  const findings: Finding[] = [];
  let currentFn: string | undefined;
  const lines = readFileSync(configPath, "utf8").split("\n");
  lines.forEach((line, i) => {
    const header = FUNCTIONS_HEADER.exec(line);
    if (header) {
      currentFn = header[1];
      return;
    }
    if (TABLE_HEADER.test(line)) currentFn = undefined;
    if (currentFn && VERIFY_JWT_FALSE.test(line)) {
      findings.push(
        mechanicalFinding({
          id: `SB-EDGEFN-VERIFYJWT-${currentFn}`,
          title: `Edge Function "${currentFn}" has verify_jwt = false`,
          severity: "Medium",
          category: "Supabase config",
          taxonomy: "Edge Function verify_jwt disabled",
          location: `supabase/config.toml:${i + 1}`,
          evidence: `[functions.${currentFn}] sets verify_jwt = false — the function accepts requests with no valid JWT.`,
          impact: "If the handler does privileged (service-role) work, an unauthenticated caller who finds the URL can invoke it.",
          fix: "Set verify_jwt = true, or if this is a webhook, verify the provider's HMAC signature inside the handler.",
          precisionTier: "review",
        }),
      );
      currentFn = undefined;
    }
  });
  return findings;
}
